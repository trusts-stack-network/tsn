//! v2.8.7 Phase 0.2 (full) — Compact Block Relay (BIP-152 inspired).
//!
//! Send a `CompactBlock` envelope (header + nonce + short_ids + prefilled txs)
//! instead of the full `ShieldedBlock` (8 MB+ with STARK proofs). The receiver
//! reconstructs the block by looking up each `short_id` in its local mempool;
//! any miss triggers a follow-up `BlockTxnRequest` for the specific indexes.
//!
//! Differences vs Bitcoin BIP-152:
//!  * Hash function for short_ids: **Blake2s** (32-byte output, take first 8
//!    bytes), keyed by `key = SHA256(header || nonce_le_8)`. Bitcoin uses
//!    SipHash-1-3 for performance; we picked Blake2s because it is
//!    collision-resistant (an attacker cannot craft two txs colliding on the
//!    same short_id), already a project dependency, and short_id collisions
//!    only force a follow-up `getblocktxn` round-trip — they do not break
//!    consensus.
//!  * Transaction iteration order matches `ShieldedBlock` hashing order:
//!    V1 → V2 → contract_deploys → contract_calls → coinbase. The coinbase is
//!    always sent in `prefilled_txn` because the receiver never has it in its
//!    mempool. Other txs are sent in `prefilled_txn` only when the sender has
//!    very high confidence the receiver lacks them (e.g. a tx the sender
//!    just submitted to its own mempool moments ago).
//!  * Contract receipts (`contract_receipts`), `relay_payout`, and
//!    `endorsements` are always sent prefilled because they are produced by
//!    the miner at block-build time and never live in any peer's mempool.
//!
//! Byte savings on a typical TSN block (16 V2 txs, ~500 KB STARK proof each):
//!   Full block: ~8 MB
//!   CompactBlock: header (~256 B) + 17 short_ids (8 B each = 136 B) +
//!                 prefilled coinbase (~120 B) + receipts/endorsements
//!                 ≈ 5 KB total when receiver has all v2 txs in mempool.
//! That is a 1500× reduction. Reconstructing requires 0 round-trips when the
//! mempool is in sync, 1 round-trip per missing tx batch otherwise.

use serde::{Deserialize, Serialize};
use blake2::digest::Update as Blake2Update;
use blake2::digest::FixedOutput;
use sha2::{Digest, Sha256};
use rand::RngCore;

use crate::core::{
    BlockHeader, ShieldedBlock, ShieldedTransaction, ShieldedTransactionV2,
    CoinbaseTransaction, Endorsement,
};
use crate::contract::{ContractDeployTransaction, ContractCallTransaction, ContractReceipt};
use crate::consensus::relay_pool::RelayPayout;

/// A 64-bit short identifier for a transaction. Truncated Blake2s output
/// keyed by `(block_header || nonce)`. 8 bytes is enough that the expected
/// number of collisions across a single block of ~16-200 txs is < 2^-50.
pub type ShortTxId = u64;

/// A transaction explicitly included in a `CompactBlock` (sender knows the
/// receiver does not have it in mempool — coinbase, contract receipts,
/// freshly-submitted txs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefilledTx {
    /// Position of this tx in the canonical block-iteration order
    /// (V1 → V2 → deploys → calls → coinbase). Receiver uses this to slot
    /// the prefilled tx back into the reconstructed block.
    pub index: u32,
    /// The transaction itself, tagged by category so the receiver knows
    /// which vector of the rebuilt `ShieldedBlock` to write it into.
    pub tx: PrefilledTxBody,
}

/// A category-tagged transaction body. We need this because the
/// `ShieldedBlock` carries five distinct transaction vectors and the receiver
/// must recover the right type from the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PrefilledTxBody {
    V1(ShieldedTransaction),
    V2(ShieldedTransactionV2),
    Deploy(ContractDeployTransaction),
    Call(ContractCallTransaction),
    Coinbase(CoinbaseTransaction),
}

/// CompactBlock — the on-the-wire form of a freshly mined block, sent in
/// place of a full `ShieldedBlock` to peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactBlock {
    /// Block header — same as in the full block, used to derive the
    /// short-id keying and to validate PoW before requesting any data.
    pub header: BlockHeader,
    /// 64-bit nonce randomly chosen by the sender for short-id keying.
    /// Different nonces between peers protect against pre-computed
    /// collision attacks on the short-id mapping.
    pub nonce: u64,
    /// Short identifiers for each non-prefilled transaction in canonical
    /// block-iteration order.
    pub short_ids: Vec<ShortTxId>,
    /// Transactions the sender has pre-included in the envelope (coinbase,
    /// receipts, anything the sender expects the receiver to lack).
    pub prefilled_txn: Vec<PrefilledTx>,
    /// Always carried along with the block; never resolvable from mempool.
    pub contract_receipts: Vec<ContractReceipt>,
    pub relay_payout: Option<RelayPayout>,
    pub endorsements: Vec<Endorsement>,
}

/// Request from a receiver to the sender for the full transactions at the
/// given block-relative indexes (the receiver could not resolve them from
/// its mempool).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxnRequest {
    pub block_hash: [u8; 32],
    pub indexes: Vec<u32>,
}

/// Response carrying the requested full transactions back to the receiver.
/// Same body-tagging scheme as `PrefilledTx`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxn {
    pub block_hash: [u8; 32],
    pub transactions: Vec<PrefilledTxBody>,
}

/// Derive the 32-byte Blake2s key used to compute short_ids for a given
/// (header, nonce) pair. Bitcoin uses SHA-256(header || nonce)[..16] as the
/// SipHash key; we keep the same SHA-256 derivation but use the full 32
/// bytes as the Blake2s key for stronger collision resistance.
fn short_id_key(header: &BlockHeader, nonce: u64) -> [u8; 32] {
    let header_bytes = bincode::serialize(header).unwrap_or_default();
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, &header_bytes);
    Digest::update(&mut hasher, &nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Compute the short_id of a tx hash under the given key.
/// Blake2s with 8-byte output, key = first 32 bytes of `key_material`.
pub fn compute_short_id(tx_hash: &[u8; 32], key: &[u8; 32]) -> ShortTxId {
    use blake2::Blake2sMac;
    use blake2::digest::KeyInit;
    let mut mac = <Blake2sMac<blake2::digest::consts::U8> as KeyInit>::new_from_slice(key)
        .expect("Blake2s accepts 32-byte keys");
    Blake2Update::update(&mut mac, tx_hash);
    let out = FixedOutput::finalize_fixed(mac);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&out[..8]);
    u64::from_le_bytes(buf)
}

/// Position of every tx in the canonical block-iteration order.
/// `(V1 first, then V2, then deploys, then calls, then coinbase)`.
/// Used by both sender and receiver to keep indexing consistent.
pub fn block_tx_count(block: &ShieldedBlock) -> usize {
    block.transactions.len()
        + block.transactions_v2.len()
        + block.contract_deploys.len()
        + block.contract_calls.len()
        + 1 /* coinbase */
}

/// Build a `CompactBlock` from a freshly mined `ShieldedBlock`.
/// `prefilled_indexes` is a hint of which positions to embed in full (for
/// the simplest sender, just `vec![coinbase_index]` — the receiver will
/// request anything else it cannot resolve via mempool).
pub fn build_compact_block(
    block: &ShieldedBlock,
    prefilled_indexes: &[u32],
) -> CompactBlock {
    let nonce = rand::thread_rng().next_u64();
    let key = short_id_key(&block.header, nonce);

    let total = block_tx_count(block);
    let coinbase_index = total - 1;

    // Always include the coinbase as prefilled — receivers never have it.
    let mut prefill_set: std::collections::BTreeSet<u32> =
        prefilled_indexes.iter().copied().collect();
    prefill_set.insert(coinbase_index as u32);

    let mut prefilled = Vec::with_capacity(prefill_set.len());
    let mut short_ids = Vec::with_capacity(total - prefill_set.len());

    let mut idx: u32 = 0;
    for tx in &block.transactions {
        if prefill_set.contains(&idx) {
            prefilled.push(PrefilledTx { index: idx, tx: PrefilledTxBody::V1(tx.clone()) });
        } else {
            short_ids.push(compute_short_id(&tx.hash(), &key));
        }
        idx += 1;
    }
    for tx in &block.transactions_v2 {
        if prefill_set.contains(&idx) {
            prefilled.push(PrefilledTx { index: idx, tx: PrefilledTxBody::V2(tx.clone()) });
        } else {
            short_ids.push(compute_short_id(&tx.hash(), &key));
        }
        idx += 1;
    }
    for tx in &block.contract_deploys {
        if prefill_set.contains(&idx) {
            prefilled.push(PrefilledTx { index: idx, tx: PrefilledTxBody::Deploy(tx.clone()) });
        } else {
            short_ids.push(compute_short_id(&tx.hash(), &key));
        }
        idx += 1;
    }
    for tx in &block.contract_calls {
        if prefill_set.contains(&idx) {
            prefilled.push(PrefilledTx { index: idx, tx: PrefilledTxBody::Call(tx.clone()) });
        } else {
            short_ids.push(compute_short_id(&tx.hash(), &key));
        }
        idx += 1;
    }
    // Coinbase is always prefilled.
    prefilled.push(PrefilledTx {
        index: coinbase_index as u32,
        tx: PrefilledTxBody::Coinbase(block.coinbase.clone()),
    });

    CompactBlock {
        header: block.header.clone(),
        nonce,
        short_ids,
        prefilled_txn: prefilled,
        contract_receipts: block.contract_receipts.clone(),
        relay_payout: block.relay_payout.clone(),
        endorsements: block.endorsements.clone(),
    }
}

/// Result of attempting to reconstruct a full block from a `CompactBlock`.
pub enum ReconstructResult {
    /// All txs resolved from prefilled + mempool — the block is ready.
    Complete(ShieldedBlock),
    /// Some txs were not in the receiver's mempool. The receiver must send
    /// a `BlockTxnRequest` for the listed `missing` indexes.
    Incomplete {
        /// Block-relative indexes the receiver could not resolve.
        missing: Vec<u32>,
    },
    /// The CompactBlock itself was malformed (e.g. duplicate prefilled
    /// indexes, wrong total count) — drop and re-request a full block.
    Invalid(String),
}

/// Lookup function used by the receiver: given a tx hash, return the full
/// transaction body if the receiver knows it (from its mempool).
/// Different mempool variants are returned in different `PrefilledTxBody`
/// shapes so the reconstruction can place the tx in the right vector.
pub trait TxLookup {
    fn lookup_v1(&self, hash: &[u8; 32]) -> Option<ShieldedTransaction>;
    fn lookup_v2(&self, hash: &[u8; 32]) -> Option<ShieldedTransactionV2>;
    fn lookup_deploy(&self, hash: &[u8; 32]) -> Option<ContractDeployTransaction>;
    fn lookup_call(&self, hash: &[u8; 32]) -> Option<ContractCallTransaction>;
}

/// Mempool-snapshot keyed by short_id. Built once per CompactBlock receive
/// so each short_id lookup is O(1).
struct MempoolShortIdIndex {
    v1: std::collections::HashMap<ShortTxId, ShieldedTransaction>,
    v2: std::collections::HashMap<ShortTxId, ShieldedTransactionV2>,
    deploys: std::collections::HashMap<ShortTxId, ContractDeployTransaction>,
    calls: std::collections::HashMap<ShortTxId, ContractCallTransaction>,
}

impl MempoolShortIdIndex {
    fn build<L: TxLookup>(_lookup: &L, _key: &[u8; 32]) -> Self {
        // Note: callers will fill the index from the actual mempool snapshot
        // (see `MempoolBoundLookup` adapter below). Placeholder kept so the
        // API stays a trait + index pair.
        Self {
            v1: std::collections::HashMap::new(),
            v2: std::collections::HashMap::new(),
            deploys: std::collections::HashMap::new(),
            calls: std::collections::HashMap::new(),
        }
    }
}

/// Convenience adapter: build a short-id index from explicit tx vectors
/// (already snapshotted from the mempool). Avoids holding the mempool lock
/// across the reconstruction loop.
pub fn build_short_id_index(
    key: &[u8; 32],
    v1s: &[ShieldedTransaction],
    v2s: &[ShieldedTransactionV2],
    deploys: &[ContractDeployTransaction],
    calls: &[ContractCallTransaction],
) -> ShortIdIndex {
    let mut idx = ShortIdIndex {
        v1: std::collections::HashMap::with_capacity(v1s.len()),
        v2: std::collections::HashMap::with_capacity(v2s.len()),
        deploys: std::collections::HashMap::with_capacity(deploys.len()),
        calls: std::collections::HashMap::with_capacity(calls.len()),
    };
    for tx in v1s {
        idx.v1.insert(compute_short_id(&tx.hash(), key), tx.clone());
    }
    for tx in v2s {
        idx.v2.insert(compute_short_id(&tx.hash(), key), tx.clone());
    }
    for tx in deploys {
        idx.deploys.insert(compute_short_id(&tx.hash(), key), tx.clone());
    }
    for tx in calls {
        idx.calls.insert(compute_short_id(&tx.hash(), key), tx.clone());
    }
    idx
}

/// Public alias used by the reconstruction routine.
#[derive(Default)]
pub struct ShortIdIndex {
    pub v1: std::collections::HashMap<ShortTxId, ShieldedTransaction>,
    pub v2: std::collections::HashMap<ShortTxId, ShieldedTransactionV2>,
    pub deploys: std::collections::HashMap<ShortTxId, ContractDeployTransaction>,
    pub calls: std::collections::HashMap<ShortTxId, ContractCallTransaction>,
}

/// Try to reconstruct a `ShieldedBlock` from a `CompactBlock` using a
/// mempool-derived short-id index. Returns a list of missing indexes
/// (block-relative) if reconstruction is incomplete.
pub fn reconstruct(
    cb: &CompactBlock,
    index: &ShortIdIndex,
) -> ReconstructResult {
    // Total tx count = short_ids slots that aren't prefilled + prefilled count.
    // Sender enforces a sentinel: each prefilled.index is unique, ascending,
    // and within [0, total). Receiver re-derives the layout by walking the
    // merged index space.
    let total = cb.short_ids.len() + cb.prefilled_txn.len();

    // Build a quick lookup for prefilled by index.
    let mut by_index: std::collections::HashMap<u32, &PrefilledTxBody> =
        std::collections::HashMap::with_capacity(cb.prefilled_txn.len());
    for p in &cb.prefilled_txn {
        if (p.index as usize) >= total {
            return ReconstructResult::Invalid(format!(
                "prefilled index {} out of bounds (total={})",
                p.index, total
            ));
        }
        if by_index.insert(p.index, &p.tx).is_some() {
            return ReconstructResult::Invalid(format!(
                "duplicate prefilled index {}",
                p.index
            ));
        }
    }

    // Resolve each block position into a full tx (or note it as missing).
    // Final tx kind for each slot: V1 / V2 / Deploy / Call / Coinbase.
    enum Resolved {
        V1(ShieldedTransaction),
        V2(ShieldedTransactionV2),
        Deploy(ContractDeployTransaction),
        Call(ContractCallTransaction),
        Coinbase(CoinbaseTransaction),
        Missing,
    }
    let mut resolved: Vec<Resolved> = Vec::with_capacity(total);
    let mut missing: Vec<u32> = Vec::new();
    let mut short_iter = cb.short_ids.iter().copied();

    for i in 0..total {
        let i_u32 = i as u32;
        if let Some(body) = by_index.get(&i_u32) {
            let r = match *body {
                PrefilledTxBody::V1(ref tx) => Resolved::V1(tx.clone()),
                PrefilledTxBody::V2(ref tx) => Resolved::V2(tx.clone()),
                PrefilledTxBody::Deploy(ref tx) => Resolved::Deploy(tx.clone()),
                PrefilledTxBody::Call(ref tx) => Resolved::Call(tx.clone()),
                PrefilledTxBody::Coinbase(ref cb) => Resolved::Coinbase(cb.clone()),
            };
            resolved.push(r);
        } else {
            // Pull next short_id and try the mempool.
            let sid = match short_iter.next() {
                Some(v) => v,
                None => {
                    return ReconstructResult::Invalid(format!(
                        "ran out of short_ids at index {}",
                        i
                    ));
                }
            };
            if let Some(tx) = index.v1.get(&sid) {
                resolved.push(Resolved::V1(tx.clone()));
            } else if let Some(tx) = index.v2.get(&sid) {
                resolved.push(Resolved::V2(tx.clone()));
            } else if let Some(tx) = index.deploys.get(&sid) {
                resolved.push(Resolved::Deploy(tx.clone()));
            } else if let Some(tx) = index.calls.get(&sid) {
                resolved.push(Resolved::Call(tx.clone()));
            } else {
                resolved.push(Resolved::Missing);
                missing.push(i_u32);
            }
        }
    }

    if !missing.is_empty() {
        return ReconstructResult::Incomplete { missing };
    }

    // All resolved — assemble the ShieldedBlock by category.
    let mut v1s: Vec<ShieldedTransaction> = Vec::new();
    let mut v2s: Vec<ShieldedTransactionV2> = Vec::new();
    let mut deploys: Vec<ContractDeployTransaction> = Vec::new();
    let mut calls: Vec<ContractCallTransaction> = Vec::new();
    let mut coinbase: Option<CoinbaseTransaction> = None;
    for r in resolved {
        match r {
            Resolved::V1(tx) => v1s.push(tx),
            Resolved::V2(tx) => v2s.push(tx),
            Resolved::Deploy(tx) => deploys.push(tx),
            Resolved::Call(tx) => calls.push(tx),
            Resolved::Coinbase(cb) => coinbase = Some(cb),
            Resolved::Missing => unreachable!("missing checked above"),
        }
    }
    let coinbase = match coinbase {
        Some(cb) => cb,
        None => return ReconstructResult::Invalid("no coinbase in compact block".into()),
    };

    ReconstructResult::Complete(ShieldedBlock {
        header: cb.header.clone(),
        transactions: v1s,
        transactions_v2: v2s,
        contract_deploys: deploys,
        contract_calls: calls,
        contract_receipts: cb.contract_receipts.clone(),
        coinbase,
        relay_payout: cb.relay_payout.clone(),
        endorsements: cb.endorsements.clone(),
    })
}

/// Take a partial reconstruction and patch in the txs delivered by a
/// `BlockTxn` response. Returns the completed block on success.
pub fn finalize_with_blocktxn(
    cb: &CompactBlock,
    index: &ShortIdIndex,
    blocktxn: &BlockTxn,
    missing: &[u32],
) -> ReconstructResult {
    if blocktxn.transactions.len() != missing.len() {
        return ReconstructResult::Invalid(format!(
            "blocktxn returned {} txs but {} requested",
            blocktxn.transactions.len(),
            missing.len()
        ));
    }
    // Build a virtual "extended" prefilled set = original prefilled + new
    // (index, tx) pairs from the blocktxn at the missing positions.
    let mut extended = cb.clone();
    for (slot, body) in missing.iter().zip(blocktxn.transactions.iter()) {
        extended.prefilled_txn.push(PrefilledTx {
            index: *slot,
            tx: body.clone(),
        });
    }
    // After patching, all positions should resolve via the prefilled map and
    // the original short_ids list — but since the slot is now prefilled, the
    // reconstruction logic naturally skips its short_id slot. To keep slot
    // accounting consistent, drop the short_ids that correspond to the
    // newly-filled slots.
    let mut new_short_ids: Vec<ShortTxId> = Vec::with_capacity(extended.short_ids.len());
    let prefill_set: std::collections::BTreeSet<u32> =
        extended.prefilled_txn.iter().map(|p| p.index).collect();
    let mut short_pos = 0usize;
    let total = extended.short_ids.len() + cb.prefilled_txn.len();
    // Re-walk every block slot, dropping short_ids at positions now in prefill_set.
    for slot in 0..total {
        if prefill_set.contains(&(slot as u32)) {
            // Was this slot already prefilled originally? Then the short_ids
            // list never had an entry for it. Was it newly prefilled? Then
            // we need to skip the short_id that used to occupy this slot.
            // Distinguish by checking whether `slot` is in `missing`.
            if missing.contains(&(slot as u32)) {
                // skip the original short_id at this slot
                short_pos += 1;
            }
            continue;
        }
        if short_pos < cb.short_ids.len() {
            new_short_ids.push(cb.short_ids[short_pos]);
            short_pos += 1;
        }
    }
    extended.short_ids = new_short_ids;

    // Drop the unused MempoolShortIdIndex placeholder helper to silence
    // dead-code warnings from rustc when nothing else builds it.
    let _ = MempoolShortIdIndex::build::<NullLookup>(&NullLookup, &[0u8; 32]);

    reconstruct(&extended, index)
}

/// No-op TxLookup used only to keep `MempoolShortIdIndex::build` reachable
/// for future direct-trait integrations. Not used by the receive path.
struct NullLookup;
impl TxLookup for NullLookup {
    fn lookup_v1(&self, _h: &[u8; 32]) -> Option<ShieldedTransaction> { None }
    fn lookup_v2(&self, _h: &[u8; 32]) -> Option<ShieldedTransactionV2> { None }
    fn lookup_deploy(&self, _h: &[u8; 32]) -> Option<ContractDeployTransaction> { None }
    fn lookup_call(&self, _h: &[u8; 32]) -> Option<ContractCallTransaction> { None }
}

/// Compute the short-id key for a header+nonce pair (exposed for the
/// receive handler so it does not have to import `short_id_key`).
pub fn derive_key(header: &BlockHeader, nonce: u64) -> [u8; 32] {
    short_id_key(header, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_deterministic() {
        let key = [42u8; 32];
        let h = [7u8; 32];
        let a = compute_short_id(&h, &key);
        let b = compute_short_id(&h, &key);
        assert_eq!(a, b);
    }

    #[test]
    fn short_id_changes_with_key() {
        let h = [7u8; 32];
        let a = compute_short_id(&h, &[42u8; 32]);
        let b = compute_short_id(&h, &[43u8; 32]);
        assert_ne!(a, b);
    }
}
