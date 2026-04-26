//! Relay Pool reward distribution (v2.4.0, Phase 5).
//!
//! A block mined under v2.3.x split its reward as 92% miner / 5% dev fee /
//! 3% "relay pool". The relay-pool slice was defined in config but burned in
//! practice — the coins existed nowhere on chain. v2.4.0 turns that slice into
//! a real, distributed reward, paid to seed/relay nodes proportionally to
//! their observable contribution to network health.
//!
//! Architecture at a glance:
//!   * An on-chain accumulator (`RelayPool`) collects 3% of every block
//!     reward between two payout boundaries (`PAYOUT_INTERVAL` = 1000 blocks).
//!   * Every payout boundary emits a single `RelayPayout` transaction that
//!     distributes the accumulator across eligible relays.
//!   * Eligibility is gated by three objective checks (snapshot confirmation,
//!     version floor, height sync). Scoring is a weighted sum of three
//!     observables (blocks relayed, snapshots served, inverse latency).
//!
//! This module is PURE logic — no I/O, no async. Integration with the
//! block validator happens in Phase 7 when the hard-fork is cut to
//! `tsn-testnet-v6`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Constants
// ============================================================================

/// Payout cadence: one distribution every 1000 finalized blocks.
pub const PAYOUT_INTERVAL: u64 = 1000;

/// Maximum height gap tolerated for a relay to be considered "in sync".
/// A relay behind by more than 2 blocks at the payout boundary is skipped.
pub const HEIGHT_SYNC_TOLERANCE: u64 = 2;

/// Maximum number of blocks since last heartbeat for a relay to be counted
/// "still alive". Tuned to the snapshot cadence: a seed that missed an
/// entire snapshot window should not collect rewards for it.
pub const MAX_STALE_BLOCKS: u64 = PAYOUT_INTERVAL / 2;

/// Scoring weights — tuned so that the three observables contribute roughly
/// equally to a well-behaved relay's total. Each observable is normalized
/// relative to the leader before weighting, so the absolute value of the
/// weights only matters in proportion.
pub const W_BLOCKS_RELAYED: u64 = 40;
pub const W_SNAPSHOTS_SERVED: u64 = 40;
pub const W_INVERSE_LATENCY: u64 = 20;

// ============================================================================
// Data types
// ============================================================================

/// Observables collected locally by each node about each relay peer, to be
/// aggregated cross-node at payout time. All counters are monotonic over the
/// current payout window (reset at each payout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayMetrics {
    /// Blake2s-256 hash of the relay's ML-DSA-65 public key — same format as
    /// `miner_pk_hash` in coinbase so that one relay can also be a miner.
    #[serde(with = "hex_array_32")]
    pub pk_hash: [u8; 32],
    /// Number of distinct blocks this relay was observed gossiping.
    pub blocks_relayed: u64,
    /// Number of snapshot requests this relay answered (served the tarball).
    pub snapshots_served: u64,
    /// Sum of observed response latencies in milliseconds. Mean is computed
    /// lazily via `blocks_relayed + snapshots_served` as denominator.
    pub latency_ms_sum: u64,
    /// Whether this relay confirmed the last published snapshot. A `false`
    /// disqualifies it from the current window's payout regardless of score.
    pub snapshot_confirmed: bool,
    /// Last block height at which this relay was observed online.
    pub last_seen_height: u64,
    /// Advertised binary version (from /tip or Identify). Compared against
    /// `MINIMUM_VERSION` during eligibility check.
    pub version: String,
}

impl RelayMetrics {
    /// Mean response latency (ms). 0 if no observations yet.
    pub fn avg_latency_ms(&self) -> u64 {
        let n = self.blocks_relayed.saturating_add(self.snapshots_served);
        if n == 0 {
            0
        } else {
            self.latency_ms_sum / n
        }
    }
}

mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// The running relay-pool accumulator. Lives in the consensus state and is
/// advanced by each accepted block.
///
/// v2.5.3 hard-fork rework: the pool now tracks per-recipient shares rather
/// than a single lump sum. On every accepted block, `accumulate_from_block`
/// splits the block's 3% slice equally across the block's endorsement signers
/// (pk_hash derived from each endorsement's ML-DSA-65 pub_key). Unassigned
/// amounts (block with zero endorsements, or division residues) accumulate in
/// `unallocated` and flow to DEV_TREASURY at payout time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayPool {
    /// Residual slice that has no recipient attribution — blocks mined with
    /// zero endorsements, and integer-division residues. Flows to DEV_TREASURY
    /// at payout time.
    #[serde(alias = "balance")]
    pub unallocated: u64,
    /// Per-relay cumulative share since last payout. Key = Blake2s256(pub_key).
    #[serde(default)]
    pub per_recipient: BTreeMap<[u8; 32], u64>,
    /// The block height at which the previous payout was made (0 = never).
    pub last_payout_height: u64,
}

impl RelayPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total coins held in the pool (sum of unallocated + all per-recipient).
    /// Equivalent to the legacy `balance` field semantically.
    pub fn total(&self) -> u64 {
        let recipients: u64 = self.per_recipient.values().copied().sum();
        self.unallocated.saturating_add(recipients)
    }

    /// Legacy alias for callers that still read the aggregate amount.
    pub fn balance(&self) -> u64 {
        self.total()
    }

    /// Accumulate a block's 3% slice, attributing equal shares to each
    /// endorsement signer. If the block carried no endorsements, the full
    /// slice lands in `unallocated` (flows to DEV_TREASURY at payout).
    /// Integer-division residues also go to `unallocated`.
    ///
    /// This is the v2.5.3 replacement for `accumulate(amount)` — callers with
    /// access to the block's endorsement list MUST use this variant; the
    /// legacy `accumulate` is kept for codepaths that do not yet carry the
    /// block context (e.g. pre-v2.5.3 replays) and treats every amount as
    /// unallocated.
    pub fn accumulate_from_block(&mut self, block_3pct: u64, endorsement_pk_hashes: &[[u8; 32]]) {
        if block_3pct == 0 {
            return;
        }
        // Deduplicate — a malicious block that carries the same pk_hash twice
        // must not double-count. Validation is expected to reject such blocks
        // but defense-in-depth here is cheap.
        let mut unique: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        for pk in endorsement_pk_hashes {
            unique.insert(*pk);
        }
        if unique.is_empty() {
            self.unallocated = self.unallocated.saturating_add(block_3pct);
            return;
        }
        let n = unique.len() as u64;
        let share = block_3pct / n;
        let distributed = share.saturating_mul(n);
        let residue = block_3pct.saturating_sub(distributed);
        for pk in &unique {
            let slot = self.per_recipient.entry(*pk).or_insert(0);
            *slot = slot.saturating_add(share);
        }
        if residue > 0 {
            self.unallocated = self.unallocated.saturating_add(residue);
        }
    }

    /// Legacy single-lump accumulator — the amount is treated as unallocated
    /// (no per-recipient attribution). Kept for pre-v2.5.3 replay paths; new
    /// code should call `accumulate_from_block` instead.
    pub fn accumulate(&mut self, amount: u64) {
        self.unallocated = self.unallocated.saturating_add(amount);
    }

    /// Returns true if a payout is due at `current_height`. Payouts happen
    /// at every multiple of `PAYOUT_INTERVAL` strictly greater than
    /// `last_payout_height`.
    pub fn is_payout_due(&self, current_height: u64) -> bool {
        current_height > 0
            && current_height % PAYOUT_INTERVAL == 0
            && current_height > self.last_payout_height
    }

    /// Drain the pool — returns the total accumulated amount and resets both
    /// `unallocated` and `per_recipient` to empty. Caller is responsible for
    /// constructing the `RelayPayout` tx and updating `last_payout_height`
    /// after on-chain confirmation.
    pub fn drain(&mut self, current_height: u64) -> u64 {
        let amount = self.total();
        self.unallocated = 0;
        self.per_recipient.clear();
        self.last_payout_height = current_height;
        amount
    }

    /// v2.5.3 — build the payout transaction from the current per-recipient
    /// state. Applies the 30% cap per relay per window (overflow flows to
    /// DEV_TREASURY). If every relay's accumulated share is zero and there
    /// are no recipients, the full `unallocated` slice goes to DEV_TREASURY.
    ///
    /// Returns the built `RelayPayout`. The pool itself is NOT drained here —
    /// callers (see state.rs::apply_relay_payout) must apply the payout AND
    /// call `drain` to reset the accumulator.
    pub fn build_payout_v2(
        &self,
        current_height: u64,
        dev_treasury_pk_hash: [u8; 32],
    ) -> RelayPayout {
        let total = self.total();
        let cap = total.saturating_mul(CAP_PERCENT_PER_RELAY as u64) / 100;

        let mut entries: Vec<PayoutEntry> = Vec::new();
        let mut dev_overflow: u64 = self.unallocated;

        for (pk, amt) in &self.per_recipient {
            let capped = std::cmp::min(*amt, cap);
            let overflow = amt.saturating_sub(capped);
            if capped > 0 {
                entries.push(PayoutEntry { recipient: *pk, amount: capped });
            }
            dev_overflow = dev_overflow.saturating_add(overflow);
        }

        if dev_overflow > 0 {
            // If DEV_TREASURY already appears as a recipient (unlikely but
            // possible if a relay publishes with the dev pk), merge amounts.
            if let Some(existing) = entries.iter_mut().find(|e| e.recipient == dev_treasury_pk_hash) {
                existing.amount = existing.amount.saturating_add(dev_overflow);
            } else {
                entries.push(PayoutEntry {
                    recipient: dev_treasury_pk_hash,
                    amount: dev_overflow,
                });
            }
        }

        // Deterministic ordering — two independent nodes must produce byte-
        // identical payouts.
        entries.sort_by_key(|e| e.recipient);

        let distributed: u64 = entries.iter().map(|e| e.amount).sum();
        RelayPayout {
            height: current_height,
            pool_total: distributed,
            entries,
        }
    }
}

/// v2.5.3 — maximum share of the pool any single relay can collect in one
/// payout window. Overflow above this cap flows to DEV_TREASURY. Prevents
/// a single well-connected relay from monopolising the reward.
pub const CAP_PERCENT_PER_RELAY: u8 = 30;

/// A single payout entry — how much `recipient` receives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutEntry {
    #[serde(with = "hex_array_32")]
    pub recipient: [u8; 32],
    pub amount: u64,
}

/// The payout transaction. Emitted once per `PAYOUT_INTERVAL`, at the boundary
/// block. Carries the list of per-relay payouts and the pool total (which
/// MUST equal the sum of entries plus rounding residue kept in the pool).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPayout {
    /// Block height at which this payout is issued.
    pub height: u64,
    /// Total amount drained from the pool for this payout (≥ sum(entries)).
    pub pool_total: u64,
    /// Per-relay payouts, sorted by `recipient` (deterministic).
    pub entries: Vec<PayoutEntry>,
}

impl RelayPayout {
    /// Sum of per-entry amounts — the amount actually distributed.
    pub fn distributed(&self) -> u64 {
        self.entries.iter().map(|e| e.amount).sum()
    }

    /// Residue = pool_total − distributed. Carries over into the next pool
    /// window if > 0 (division rounding on very small pools).
    pub fn residue(&self) -> u64 {
        self.pool_total.saturating_sub(self.distributed())
    }

    /// Canonical serialization for hashing / signing. Uses `bincode` via
    /// serde_json in this first implementation — Phase 6 will tighten this
    /// to a stable binary format when we wire the consensus check.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // JSON is stable enough for the current cross-node sanity check; the
        // consensus-critical hash commitment lives in the block header (to
        // be added in Phase 7).
        serde_json::to_vec(self).expect("RelayPayout JSON serialization is infallible")
    }
}

// ============================================================================
// Eligibility
// ============================================================================

/// Filters a set of metrics to those eligible for the current payout.
///
/// `current_height` is the payout boundary block height.
/// `network_height` is the consensus (median-of-peers) tip — used to decide
/// whether a relay is "in sync".
/// `minimum_version` is `crate::network::version_check::MINIMUM_VERSION`.
pub fn filter_eligible<'a>(
    metrics: &'a [RelayMetrics],
    current_height: u64,
    network_height: u64,
    minimum_version: &str,
) -> Vec<&'a RelayMetrics> {
    metrics
        .iter()
        .filter(|m| is_eligible(m, current_height, network_height, minimum_version))
        .collect()
}

/// Single-relay eligibility check — the three gates listed in the module doc.
pub fn is_eligible(
    m: &RelayMetrics,
    current_height: u64,
    network_height: u64,
    minimum_version: &str,
) -> bool {
    // Gate 1: confirmed the published snapshot for this window.
    if !m.snapshot_confirmed {
        return false;
    }
    // Gate 2: running at or above the minimum version.
    if !version_at_or_above(&m.version, minimum_version) {
        return false;
    }
    // Gate 3: height within sync tolerance of network, and seen recently.
    let gap = network_height.saturating_sub(m.last_seen_height);
    if gap > HEIGHT_SYNC_TOLERANCE {
        return false;
    }
    let stale_for = current_height.saturating_sub(m.last_seen_height);
    if stale_for > MAX_STALE_BLOCKS {
        return false;
    }
    true
}

/// Naive semver comparison: splits `a.b.c[.d]` on `.`, parses each component
/// as u32, pads with zeros, compares lexicographically. Sufficient for our
/// internal version strings; not a full semver parser.
fn version_at_or_above(version: &str, minimum: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.')
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let mut v = parse(version);
    let mut m = parse(minimum);
    while v.len() < m.len() { v.push(0); }
    while m.len() < v.len() { m.push(0); }
    v >= m
}

// ============================================================================
// Scoring
// ============================================================================

/// Raw score per relay in deterministic order (sorted by pk_hash).
///
/// A relay's score is the weighted sum of three normalized observables:
///   * blocks_relayed / max_blocks_relayed  × W_BLOCKS_RELAYED
///   * snapshots_served / max_snapshots_served × W_SNAPSHOTS_SERVED
///   * (1 − avg_latency / max_avg_latency) × W_INVERSE_LATENCY
///
/// Normalization is over the eligible set, not global history — each payout
/// window scores relative to the current leader.
pub fn compute_scores(eligible: &[&RelayMetrics]) -> Vec<([u8; 32], u64)> {
    if eligible.is_empty() {
        return Vec::new();
    }

    let max_blocks = eligible.iter().map(|m| m.blocks_relayed).max().unwrap_or(0).max(1);
    let max_snaps = eligible.iter().map(|m| m.snapshots_served).max().unwrap_or(0).max(1);
    let max_lat = eligible.iter().map(|m| m.avg_latency_ms()).max().unwrap_or(0);
    let min_lat = eligible.iter().map(|m| m.avg_latency_ms()).min().unwrap_or(0);
    let lat_spread = max_lat.saturating_sub(min_lat);

    // BTreeMap gives us deterministic iteration by pk_hash for payout ordering.
    let mut scores: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for m in eligible {
        let blocks_term = (m.blocks_relayed * W_BLOCKS_RELAYED) / max_blocks;
        let snaps_term = (m.snapshots_served * W_SNAPSHOTS_SERVED) / max_snaps;
        // Inverse latency: faster relays score higher.
        //   * When all relays share the same latency (including the single-
        //     relay case), they tie at the top → everyone gets full weight.
        //   * Otherwise, the fastest gets full weight, the slowest gets 0,
        //     the middle gets a proportional share across the spread.
        let lat = m.avg_latency_ms();
        let inv_lat_term = if lat_spread == 0 {
            W_INVERSE_LATENCY
        } else {
            (W_INVERSE_LATENCY * (max_lat.saturating_sub(lat))) / lat_spread
        };
        let total = blocks_term + snaps_term + inv_lat_term;
        scores.insert(m.pk_hash, total);
    }
    scores.into_iter().collect()
}

// ============================================================================
// Payout math
// ============================================================================

/// Distribute `pool_total` across scored relays, proportionally to score.
/// Leftover integer rounding is returned as the last tuple element (residue).
///
/// The output entries are ordered by `recipient` (BTreeMap order), matching
/// [`compute_scores`]'s ordering, so two independent nodes will produce the
/// same `RelayPayout` bit-for-bit.
pub fn compute_payouts(
    scored: &[([u8; 32], u64)],
    pool_total: u64,
) -> (Vec<PayoutEntry>, u64) {
    if scored.is_empty() || pool_total == 0 {
        return (Vec::new(), pool_total);
    }

    let sum_scores: u64 = scored.iter().map(|(_, s)| *s).sum();
    if sum_scores == 0 {
        // All eligible relays scored 0 — treat as no distribution this window.
        return (Vec::new(), pool_total);
    }

    let mut entries: Vec<PayoutEntry> = Vec::with_capacity(scored.len());
    let mut distributed: u64 = 0;

    for (pk, score) in scored {
        // Use 128-bit intermediate to avoid overflow on large pools.
        let share: u64 = ((pool_total as u128) * (*score as u128) / (sum_scores as u128)) as u64;
        if share > 0 {
            entries.push(PayoutEntry { recipient: *pk, amount: share });
            distributed = distributed.saturating_add(share);
        }
    }

    let residue = pool_total.saturating_sub(distributed);
    (entries, residue)
}

/// High-level orchestrator: from raw metrics + pool total, produce the
/// `RelayPayout` transaction for `current_height`. Returns `None` when no
/// eligible relays exist (caller carries the pool over).
pub fn build_relay_payout(
    metrics: &[RelayMetrics],
    pool_total: u64,
    current_height: u64,
    network_height: u64,
    minimum_version: &str,
) -> Option<RelayPayout> {
    if pool_total == 0 {
        return None;
    }
    let eligible = filter_eligible(metrics, current_height, network_height, minimum_version);
    if eligible.is_empty() {
        return None;
    }
    let scored = compute_scores(&eligible);
    let (entries, _residue) = compute_payouts(&scored, pool_total);
    if entries.is_empty() {
        return None;
    }
    let distributed: u64 = entries.iter().map(|e| e.amount).sum();
    Some(RelayPayout {
        height: current_height,
        pool_total: distributed, // residue stays in the pool for next window
        entries,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn m_default(byte: u8) -> RelayMetrics {
        RelayMetrics {
            pk_hash: pk(byte),
            blocks_relayed: 100,
            snapshots_served: 2,
            latency_ms_sum: 500,
            snapshot_confirmed: true,
            last_seen_height: 1000,
            version: "2.4.0".to_string(),
        }
    }

    // ---- RelayPool accumulator ----

    #[test]
    fn accumulator_starts_empty() {
        let p = RelayPool::new();
        assert_eq!(p.balance(), 0);
        assert_eq!(p.unallocated, 0);
        assert!(p.per_recipient.is_empty());
        assert_eq!(p.last_payout_height, 0);
    }

    #[test]
    fn accumulator_adds() {
        let mut p = RelayPool::new();
        p.accumulate(150);
        p.accumulate(50);
        assert_eq!(p.balance(), 200);
        assert_eq!(p.unallocated, 200); // legacy accumulate = all unallocated
    }

    #[test]
    fn accumulator_saturates_on_overflow() {
        let mut p = RelayPool::new();
        p.unallocated = u64::MAX - 10;
        p.accumulate(100);
        assert_eq!(p.balance(), u64::MAX);
    }

    // ---- v2.5.3 per-block accumulator ----

    #[test]
    fn accumulate_from_block_no_endorsements_all_unallocated() {
        let mut p = RelayPool::new();
        p.accumulate_from_block(1000, &[]);
        assert_eq!(p.unallocated, 1000);
        assert!(p.per_recipient.is_empty());
    }

    #[test]
    fn accumulate_from_block_splits_across_endorsers() {
        let mut p = RelayPool::new();
        let pks = vec![pk(1), pk(2), pk(3), pk(4)];
        p.accumulate_from_block(1000, &pks);
        // 1000 / 4 = 250 each, no residue
        for k in &pks {
            assert_eq!(*p.per_recipient.get(k).unwrap(), 250);
        }
        assert_eq!(p.unallocated, 0);
        assert_eq!(p.balance(), 1000);
    }

    #[test]
    fn accumulate_from_block_residue_goes_to_unallocated() {
        let mut p = RelayPool::new();
        let pks = vec![pk(1), pk(2), pk(3)];
        p.accumulate_from_block(1000, &pks);
        // 1000 / 3 = 333 each, residue 1
        for k in &pks {
            assert_eq!(*p.per_recipient.get(k).unwrap(), 333);
        }
        assert_eq!(p.unallocated, 1);
        assert_eq!(p.balance(), 1000);
    }

    #[test]
    fn accumulate_from_block_dedup_duplicates() {
        // A malicious block that carries the same pk_hash twice must not
        // double-count; shares are distributed over the UNIQUE set.
        let mut p = RelayPool::new();
        let pks = vec![pk(1), pk(1), pk(2)];
        p.accumulate_from_block(1000, &pks);
        // unique set = {pk(1), pk(2)} → 500 each
        assert_eq!(*p.per_recipient.get(&pk(1)).unwrap(), 500);
        assert_eq!(*p.per_recipient.get(&pk(2)).unwrap(), 500);
        assert_eq!(p.balance(), 1000);
    }

    #[test]
    fn accumulate_from_block_across_multiple_blocks() {
        let mut p = RelayPool::new();
        p.accumulate_from_block(1000, &[pk(1), pk(2)]);         // 500+500
        p.accumulate_from_block(1000, &[pk(1)]);                 // 1000 to pk(1)
        p.accumulate_from_block(600, &[]);                       // 600 to unallocated
        assert_eq!(*p.per_recipient.get(&pk(1)).unwrap(), 1500);
        assert_eq!(*p.per_recipient.get(&pk(2)).unwrap(), 500);
        assert_eq!(p.unallocated, 600);
        assert_eq!(p.balance(), 2600);
    }

    // ---- v2.5.3 build_payout_v2 ----

    #[test]
    fn build_payout_v2_empty_pool_still_lists_dev() {
        let p = RelayPool::new();
        let payout = p.build_payout_v2(1000, pk(99));
        assert_eq!(payout.height, 1000);
        // Empty pool → 0 entries (no dev_treasury entry when dev_overflow=0)
        assert_eq!(payout.pool_total, 0);
        assert!(payout.entries.is_empty());
    }

    #[test]
    fn build_payout_v2_zero_endorsements_all_to_dev() {
        let mut p = RelayPool::new();
        p.accumulate_from_block(1500, &[]); // no endorsers
        let dev = pk(99);
        let payout = p.build_payout_v2(1000, dev);
        assert_eq!(payout.entries.len(), 1);
        assert_eq!(payout.entries[0].recipient, dev);
        assert_eq!(payout.entries[0].amount, 1500);
    }

    #[test]
    fn build_payout_v2_cap_30pct_redirects_overflow_to_dev() {
        // Single relay earns 90% → cap at 30% → overflow 60% to dev.
        let mut p = RelayPool::new();
        p.per_recipient.insert(pk(1), 900);
        p.per_recipient.insert(pk(2), 100);
        let dev = pk(99);
        let payout = p.build_payout_v2(1000, dev);
        // total=1000, cap=300. pk(1) gets capped=300, overflow=600.
        // pk(2) gets 100 (< cap).
        // dev gets 600.
        let a = payout.entries.iter().find(|e| e.recipient == pk(1)).unwrap();
        let b = payout.entries.iter().find(|e| e.recipient == pk(2)).unwrap();
        let d = payout.entries.iter().find(|e| e.recipient == dev).unwrap();
        assert_eq!(a.amount, 300);
        assert_eq!(b.amount, 100);
        assert_eq!(d.amount, 600);
    }

    #[test]
    fn build_payout_v2_deterministic_order_by_pk() {
        let mut p = RelayPool::new();
        p.per_recipient.insert(pk(50), 100);
        p.per_recipient.insert(pk(10), 100);
        p.per_recipient.insert(pk(30), 100);
        let payout = p.build_payout_v2(1000, pk(99));
        // Must be sorted by recipient
        for window in payout.entries.windows(2) {
            assert!(window[0].recipient <= window[1].recipient);
        }
    }

    #[test]
    fn payout_due_only_at_interval_boundary() {
        let p = RelayPool::new();
        assert!(!p.is_payout_due(0));
        assert!(!p.is_payout_due(999));
        assert!(p.is_payout_due(1000));
        assert!(!p.is_payout_due(1500));
        assert!(p.is_payout_due(2000));
    }

    #[test]
    fn payout_not_due_if_same_height_already_paid() {
        let mut p = RelayPool::new();
        p.last_payout_height = 1000;
        assert!(!p.is_payout_due(1000));
        assert!(p.is_payout_due(2000));
    }

    #[test]
    fn drain_resets_balance_and_records_height() {
        let mut p = RelayPool::new();
        p.unallocated = 12345;
        let drained = p.drain(1000);
        assert_eq!(drained, 12345);
        assert_eq!(p.balance(), 0);
        assert_eq!(p.unallocated, 0);
        assert_eq!(p.last_payout_height, 1000);
    }

    #[test]
    fn drain_clears_per_recipient_too() {
        let mut p = RelayPool::new();
        p.accumulate_from_block(1000, &[pk(1), pk(2)]);
        let drained = p.drain(2000);
        assert_eq!(drained, 1000);
        assert!(p.per_recipient.is_empty());
        assert_eq!(p.unallocated, 0);
        assert_eq!(p.last_payout_height, 2000);
    }

    // ---- Eligibility ----

    #[test]
    fn eligible_when_all_gates_pass() {
        let m = m_default(1);
        assert!(is_eligible(&m, 1000, 1000, "2.4.0"));
    }

    #[test]
    fn not_eligible_without_snapshot_confirmation() {
        let mut m = m_default(1);
        m.snapshot_confirmed = false;
        assert!(!is_eligible(&m, 1000, 1000, "2.4.0"));
    }

    #[test]
    fn not_eligible_if_version_below_minimum() {
        let mut m = m_default(1);
        m.version = "2.3.5".to_string();
        assert!(!is_eligible(&m, 1000, 1000, "2.4.0"));
    }

    #[test]
    fn eligible_if_version_above_minimum() {
        let mut m = m_default(1);
        m.version = "2.5.0".to_string();
        assert!(is_eligible(&m, 1000, 1000, "2.4.0"));
    }

    #[test]
    fn not_eligible_if_height_behind_tolerance() {
        let mut m = m_default(1);
        m.last_seen_height = 1000 - HEIGHT_SYNC_TOLERANCE - 1;
        assert!(!is_eligible(&m, 1000, 1000, "2.4.0"));
    }

    #[test]
    fn not_eligible_if_stale() {
        let mut m = m_default(1);
        m.last_seen_height = 1; // last seen long ago
        assert!(!is_eligible(&m, 1000, 1, "2.4.0"),
            "stale relay should be rejected even if network claims h=1");
    }

    #[test]
    fn filter_keeps_only_eligible() {
        let mut good = m_default(1);
        good.pk_hash = pk(1);
        let mut bad_unconfirmed = m_default(2);
        bad_unconfirmed.pk_hash = pk(2);
        bad_unconfirmed.snapshot_confirmed = false;
        let mut bad_version = m_default(3);
        bad_version.pk_hash = pk(3);
        bad_version.version = "2.3.0".to_string();

        let all = vec![good.clone(), bad_unconfirmed, bad_version];
        let filtered = filter_eligible(&all, 1000, 1000, "2.4.0");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].pk_hash, pk(1));
    }

    // ---- Scoring ----

    #[test]
    fn scoring_empty_returns_empty() {
        assert!(compute_scores(&[]).is_empty());
    }

    #[test]
    fn single_relay_gets_full_weight() {
        let m = m_default(1);
        let scores = compute_scores(&[&m]);
        assert_eq!(scores.len(), 1);
        let (_pk, s) = scores[0];
        // Max in every dimension → W_BLOCKS + W_SNAPSHOTS + W_INVERSE_LATENCY.
        assert_eq!(s, W_BLOCKS_RELAYED + W_SNAPSHOTS_SERVED + W_INVERSE_LATENCY);
    }

    #[test]
    fn scoring_is_deterministic_order() {
        // Two identical inputs in different orders produce same output order.
        let m1 = m_default(1);
        let m2 = m_default(2);
        let a = compute_scores(&[&m1, &m2]);
        let b = compute_scores(&[&m2, &m1]);
        assert_eq!(a, b);
        // Ordered by pk_hash: pk(1) before pk(2).
        assert_eq!(a[0].0, pk(1));
        assert_eq!(a[1].0, pk(2));
    }

    #[test]
    fn more_blocks_relayed_produces_higher_score() {
        let mut a = m_default(1);
        let mut b = m_default(2);
        a.blocks_relayed = 10;
        b.blocks_relayed = 1000;
        let scores = compute_scores(&[&a, &b]);
        let score_a = scores.iter().find(|(k, _)| *k == pk(1)).unwrap().1;
        let score_b = scores.iter().find(|(k, _)| *k == pk(2)).unwrap().1;
        assert!(score_b > score_a, "heavier relayer should score higher");
    }

    #[test]
    fn lower_latency_produces_higher_score() {
        let mut fast = m_default(1);
        let mut slow = m_default(2);
        // Same blocks_relayed, same snapshots, different latency totals.
        fast.latency_ms_sum = 100;  // avg 100/102 ≈ 0
        slow.latency_ms_sum = 50000; // avg ≈ 490
        let scores = compute_scores(&[&fast, &slow]);
        let score_fast = scores.iter().find(|(k, _)| *k == pk(1)).unwrap().1;
        let score_slow = scores.iter().find(|(k, _)| *k == pk(2)).unwrap().1;
        assert!(score_fast > score_slow, "lower latency should score higher");
    }

    // ---- Payout math ----

    #[test]
    fn payout_empty_scores_carries_full_pool() {
        let (entries, residue) = compute_payouts(&[], 10000);
        assert!(entries.is_empty());
        assert_eq!(residue, 10000);
    }

    #[test]
    fn payout_zero_pool_no_entries() {
        let scored = vec![(pk(1), 50), (pk(2), 50)];
        let (entries, residue) = compute_payouts(&scored, 0);
        assert!(entries.is_empty());
        assert_eq!(residue, 0);
    }

    #[test]
    fn payout_proportional_to_score() {
        let scored = vec![(pk(1), 30), (pk(2), 70)];
        let (entries, residue) = compute_payouts(&scored, 1000);
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.recipient == pk(1)).unwrap();
        let b = entries.iter().find(|e| e.recipient == pk(2)).unwrap();
        assert_eq!(a.amount, 300);
        assert_eq!(b.amount, 700);
        assert_eq!(residue, 0);
    }

    #[test]
    fn payout_rounding_residue_kept() {
        // Pool of 10 coins across 3 equal-score relays: 10/3=3, residue 1.
        let scored = vec![(pk(1), 1), (pk(2), 1), (pk(3), 1)];
        let (entries, residue) = compute_payouts(&scored, 10);
        assert_eq!(entries.iter().map(|e| e.amount).sum::<u64>(), 9);
        assert_eq!(residue, 1);
    }

    #[test]
    fn payout_single_eligible_gets_everything() {
        let scored = vec![(pk(1), 42)];
        let (entries, residue) = compute_payouts(&scored, 5000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].amount, 5000);
        assert_eq!(residue, 0);
    }

    #[test]
    fn payout_all_zero_scores_no_distribution() {
        let scored = vec![(pk(1), 0), (pk(2), 0)];
        let (entries, residue) = compute_payouts(&scored, 1000);
        assert!(entries.is_empty());
        assert_eq!(residue, 1000);
    }

    // ---- Orchestrator ----

    #[test]
    fn build_payout_end_to_end() {
        let metrics = vec![
            m_default(1),                           // eligible
            {
                let mut m = m_default(2);
                m.snapshot_confirmed = false;       // excluded
                m
            },
            {
                let mut m = m_default(3);
                m.blocks_relayed = 500;             // eligible, higher score
                m
            },
        ];
        let payout = build_relay_payout(&metrics, 1000, 1000, 1000, "2.4.0").unwrap();
        assert_eq!(payout.height, 1000);
        assert_eq!(payout.entries.len(), 2);
        let total: u64 = payout.entries.iter().map(|e| e.amount).sum();
        assert!(total <= 1000); // rounding may leave residue
        assert_eq!(payout.pool_total, total);
        // pk(3) has 5x blocks_relayed of pk(1) → higher amount
        let amt_1 = payout.entries.iter().find(|e| e.recipient == pk(1)).unwrap().amount;
        let amt_3 = payout.entries.iter().find(|e| e.recipient == pk(3)).unwrap().amount;
        assert!(amt_3 > amt_1);
    }

    #[test]
    fn build_payout_returns_none_when_nobody_eligible() {
        let mut m = m_default(1);
        m.snapshot_confirmed = false;
        assert!(build_relay_payout(&[m], 1000, 1000, 1000, "2.4.0").is_none());
    }

    #[test]
    fn build_payout_returns_none_when_pool_empty() {
        let m = m_default(1);
        assert!(build_relay_payout(&[m], 0, 1000, 1000, "2.4.0").is_none());
    }

    #[test]
    fn relay_payout_canonical_bytes_deterministic() {
        let payout = RelayPayout {
            height: 1000,
            pool_total: 1000,
            entries: vec![
                PayoutEntry { recipient: pk(1), amount: 400 },
                PayoutEntry { recipient: pk(2), amount: 600 },
            ],
        };
        let a = payout.canonical_bytes();
        let b = payout.canonical_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn relay_payout_serde_round_trip() {
        let payout = RelayPayout {
            height: 2000,
            pool_total: 1500,
            entries: vec![
                PayoutEntry { recipient: pk(7), amount: 1000 },
                PayoutEntry { recipient: pk(42), amount: 500 },
            ],
        };
        let bytes = payout.canonical_bytes();
        let restored: RelayPayout = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payout, restored);
    }

    #[test]
    fn relay_metrics_avg_latency_division() {
        let mut m = m_default(1);
        m.latency_ms_sum = 1000;
        m.blocks_relayed = 4;
        m.snapshots_served = 1;
        // 1000 ms / (4+1) = 200 ms
        assert_eq!(m.avg_latency_ms(), 200);

        // Zero-observation case returns 0 rather than dividing by zero.
        let fresh = RelayMetrics::default();
        assert_eq!(fresh.avg_latency_ms(), 0);
    }

    #[test]
    fn version_compare_handles_mixed_lengths() {
        assert!(version_at_or_above("2.4.0", "2.4.0"));
        assert!(version_at_or_above("2.4.0", "2.3.9"));
        assert!(version_at_or_above("2.4", "2.4.0"));       // 2.4 == 2.4.0
        assert!(!version_at_or_above("2.3.9", "2.4.0"));
        assert!(version_at_or_above("2.4.0.1", "2.4.0"));   // pre-release in 4-tuple
        assert!(version_at_or_above("10.0.0", "2.4.0"));    // no lexical bug
    }
}
