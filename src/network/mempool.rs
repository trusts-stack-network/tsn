//! Transaction mempool for shielded transactions.
//!
//! Supports both V1 (legacy) and V2 (post-quantum) transactions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

use crate::core::{ShieldedState, ShieldedTransaction, Transaction};
use crate::contract::{ContractDeployTransaction, ContractCallTransaction};

/// Maximum number of transactions in the mempool.
const MAX_MEMPOOL_SIZE: usize = 5000;

/// Minimum transaction fee (anti-spam). 1000 sats.
const MIN_TX_FEE: u64 = 1000;

/// Maximum age of a transaction in seconds (1 hour).
const MAX_TX_AGE_SECS: u64 = 3600;

/// v2.7.0 Phase 1.4 — cost-bounded mempool (Zcash ZIP-401 style).
/// Total mempool weight cap, in arbitrary "weight units". Once the running
/// total reaches this, lower-fee txs are evicted to make room.
pub const MEMPOOL_COST_LIMIT: u64 = 80_000_000;
/// Floor for the per-tx weight contribution. A V2 STARK proof tx is already
/// 250+ KB, so this floor only matters for tiny V1 spends; it makes single-byte
/// dust look as expensive as a small block of bytes.
pub const MEMPOOL_MIN_WEIGHT: u64 = 10_000;
/// Penalty added to the weight of any tx whose `fee < CONVENTIONAL_FEE`. The
/// effect is to reserve mempool capacity for properly-fee'd txs under load.
pub const MEMPOOL_LOW_FEE_PENALTY: u64 = 40_000;
/// Conventional fee floor — txs at or above this fee are not penalised.
pub const CONVENTIONAL_FEE: u64 = MIN_TX_FEE * 5;
/// Capacity of the `RecentlyEvicted` cache. Entries above this drop on LRU.
pub const RECENTLY_EVICTED_CAPACITY: usize = 40_000;
/// Time-to-live for a `RecentlyEvicted` entry. Within the TTL the same hash
/// is rejected on re-submission, blocking trivial re-flood attacks.
pub const RECENTLY_EVICTED_TTL_SECS: u64 = 60 * 60;
/// v2.7.0 Phase 1.5 — ZIP-317-style mining template caps. The "actions" of
/// a tx are its spend+output count; the network bounds the total count of
/// underpaying actions per block to keep validation time predictable.
pub const BLOCK_UNPAID_ACTION_LIMIT: usize = 50;
/// v2.7.0 Phase 1.5 — ceiling on the count of high-fee V2 transactions a
/// single block template considers. High-fee txs are taken in fee-rate order;
/// excess txs roll over to subsequent blocks.
pub const BLOCK_HIGH_FEE_TX_LIMIT: usize = 200;

/// Compute the ZIP-401-style weight of a transaction. The weight floors at
/// `MEMPOOL_MIN_WEIGHT`, plus a `MEMPOOL_LOW_FEE_PENALTY` if the fee is below
/// the conventional floor.
fn tx_weight(size: usize, fee: u64) -> u64 {
    let base = (size as u64).max(MEMPOOL_MIN_WEIGHT);
    if fee < CONVENTIONAL_FEE {
        base.saturating_add(MEMPOOL_LOW_FEE_PENALTY)
    } else {
        base
    }
}

/// Transaction metadata for eviction decisions.
#[derive(Debug, Clone)]
struct TxMeta {
    fee: u64,
    added_at: u64,
    /// v2.7.0 Phase 1.4 — cached weight contribution to the mempool cost
    /// budget. Stored at insert so `total_cost` is an O(1) sum.
    cost: u64,
}

/// The mempool holds pending shielded transactions waiting to be mined.
#[derive(Debug, Default)]
pub struct Mempool {
    /// Pending V1 transactions by hash (for mining compatibility).
    v1_transactions: HashMap<[u8; 32], ShieldedTransaction>,
    /// Pending V2/Migration transactions by hash.
    v2_transactions: HashMap<[u8; 32], Transaction>,
    /// Pending contract deploy transactions by hash.
    contract_deploys: HashMap<[u8; 32], ContractDeployTransaction>,
    /// Pending contract call transactions by hash.
    contract_calls: HashMap<[u8; 32], ContractCallTransaction>,
    /// Pending nullifiers (to detect double-spends before confirmation).
    pending_nullifiers: HashSet<[u8; 32]>,
    /// Transaction metadata for eviction (fee + timestamp).
    tx_meta: HashMap<[u8; 32], TxMeta>,
    /// v2.7.0 Phase 1.4 — cumulative cost of all entries in `tx_meta` (sum
    /// of `TxMeta::cost`). Maintained incrementally on insert/remove so the
    /// hot path doesn't re-iterate the map.
    total_cost: u64,
    /// v2.7.0 Phase 1.4 — RecentlyEvicted hashes with the instant they were
    /// evicted at. Re-submission of any of these inside the TTL is rejected,
    /// so a peer cannot trivially re-flood the mempool with the same tx.
    /// FIFO order preserved by `recently_evicted_order` lets us prune the
    /// oldest entry in O(1) when the cap is reached.
    recently_evicted: HashMap<[u8; 32], Instant>,
    recently_evicted_order: VecDeque<[u8; 32]>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            v1_transactions: HashMap::new(),
            v2_transactions: HashMap::new(),
            contract_deploys: HashMap::new(),
            contract_calls: HashMap::new(),
            pending_nullifiers: HashSet::new(),
            tx_meta: HashMap::new(),
            total_cost: 0,
            recently_evicted: HashMap::new(),
            recently_evicted_order: VecDeque::new(),
        }
    }

    /// v2.7.0 Phase 1.4 — record a freshly-evicted hash in the RecentlyEvicted
    /// cache. Drops the oldest entry if at capacity.
    fn mark_evicted(&mut self, hash: [u8; 32]) {
        if self.recently_evicted.contains_key(&hash) {
            return;
        }
        if self.recently_evicted.len() >= RECENTLY_EVICTED_CAPACITY {
            if let Some(oldest) = self.recently_evicted_order.pop_front() {
                self.recently_evicted.remove(&oldest);
            }
        }
        self.recently_evicted.insert(hash, Instant::now());
        self.recently_evicted_order.push_back(hash);
    }

    /// v2.7.0 Phase 1.4 — true if the hash was evicted in the last
    /// `RECENTLY_EVICTED_TTL_SECS` seconds. Lazily prunes expired entries.
    fn is_recently_evicted(&mut self, hash: &[u8; 32]) -> bool {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(RECENTLY_EVICTED_TTL_SECS);
        if let Some(at) = self.recently_evicted.get(hash) {
            if now.duration_since(*at) <= ttl {
                return true;
            }
            // Expired — drop it.
            self.recently_evicted.remove(hash);
            // Lazy: leave the order queue alone; expired hashes drop on next
            // capacity prune.
        }
        false
    }

    /// v2.7.0 Phase 1.4 — current total weight of the mempool.
    pub fn total_cost(&self) -> u64 {
        self.total_cost
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    /// Total transaction count across all types.
    fn total_count(&self) -> usize {
        self.v1_transactions.len() + self.v2_transactions.len()
            + self.contract_deploys.len() + self.contract_calls.len()
    }

    /// Evict the lowest-fee transaction to make room. Returns the evicted
    /// hash on success — the caller can record it in RecentlyEvicted.
    fn evict_lowest_fee(&mut self) -> Option<[u8; 32]> {
        // Find the tx with the lowest fee. Tie-break on highest weight (drop
        // the bulkiest first) to free as much budget as possible per eviction.
        let lowest = self.tx_meta.iter()
            .min_by(|(_, a), (_, b)| {
                a.fee.cmp(&b.fee)
                    .then_with(|| b.cost.cmp(&a.cost))
            })
            .map(|(hash, _)| *hash);

        if let Some(hash) = lowest {
            self.remove(&hash);
            self.remove_v2(&hash);
            self.remove_contract_tx(&hash);
            // remove() / remove_v2() already remove the meta entry and
            // decrement total_cost; this is a defensive cleanup for txs that
            // were not in any of the typed maps (shouldn't happen).
            if let Some(meta) = self.tx_meta.remove(&hash) {
                self.total_cost = self.total_cost.saturating_sub(meta.cost);
            }
            self.mark_evicted(hash);
            Some(hash)
        } else {
            None
        }
    }

    /// Evict transactions older than MAX_TX_AGE_SECS. Returns count removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = Self::now_secs();
        let expired: Vec<[u8; 32]> = self.tx_meta.iter()
            .filter(|(_, meta)| now.saturating_sub(meta.added_at) > MAX_TX_AGE_SECS)
            .map(|(hash, _)| *hash)
            .collect();

        let count = expired.len();
        for hash in &expired {
            self.remove(hash);
            self.remove_v2(hash);
            self.remove_contract_tx(hash);
            if let Some(meta) = self.tx_meta.remove(hash) {
                self.total_cost = self.total_cost.saturating_sub(meta.cost);
            }
            // Expired entries are not RecentlyEvicted candidates — they died
            // by age, not by replacement. A re-submission is fine and may
            // legitimately succeed if anchors are still valid.
        }
        if count > 0 {
            info!("Mempool: evicted {} expired transactions", count);
        }
        count
    }

    /// Add a V1 transaction to the mempool.
    /// Returns false if transaction already exists, would cause double-spend,
    /// fee is too low, or mempool is full and can't evict.
    pub fn add(&mut self, tx: ShieldedTransaction) -> bool {
        let hash = tx.hash();
        if self.v1_transactions.contains_key(&hash) || self.v2_transactions.contains_key(&hash) {
            return false;
        }

        // v2.7.0 Phase 1.4 — RecentlyEvicted gate.
        if self.is_recently_evicted(&hash) {
            warn!(
                "Mempool: rejected tx {} — recently evicted (TTL {}s)",
                hex::encode(&hash[..8]), RECENTLY_EVICTED_TTL_SECS
            );
            return false;
        }

        // Enforce minimum fee
        if tx.fee < MIN_TX_FEE {
            warn!("Mempool: rejected tx {} — fee {} < min {}", hex::encode(&hash[..4]), tx.fee, MIN_TX_FEE);
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(&nullifier.0) {
                return false; // Double-spend attempt
            }
        }

        let cost = tx_weight(tx.size(), tx.fee);

        // v2.7.0 Phase 1.4 — combined size + cost cap. Evict expired first,
        // then lowest-fee until both caps are satisfied or eviction fails.
        if self.total_count() >= MAX_MEMPOOL_SIZE
            || self.total_cost.saturating_add(cost) > MEMPOOL_COST_LIMIT
        {
            self.evict_expired();
            while self.total_count() >= MAX_MEMPOOL_SIZE
                || self.total_cost.saturating_add(cost) > MEMPOOL_COST_LIMIT
            {
                let min_fee = self.tx_meta.values().map(|m| m.fee).min().unwrap_or(0);
                if tx.fee <= min_fee {
                    warn!("Mempool full: rejected tx {} (fee {} <= min {}, cost_after={})", hex::encode(&hash[..4]), tx.fee, min_fee, self.total_cost.saturating_add(cost));
                    return false;
                }
                if self.evict_lowest_fee().is_none() {
                    return false;
                }
            }
        }

        let fee = tx.fee;

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(nullifier.0);
        }

        self.v1_transactions.insert(hash, tx);
        self.tx_meta.insert(hash, TxMeta { fee, added_at: Self::now_secs(), cost });
        self.total_cost = self.total_cost.saturating_add(cost);
        true
    }

    /// Add a V2 or Migration transaction to the mempool.
    /// Returns false if transaction already exists, would cause double-spend,
    /// fee is too low, or mempool is full and can't evict.
    pub fn add_v2(&mut self, tx: Transaction) -> bool {
        let hash = tx.hash();
        if self.v1_transactions.contains_key(&hash) {
            warn!("Mempool: rejected v2 tx {} — hash already in v1 mempool", hex::encode(&hash[..8]));
            return false;
        }
        if self.v2_transactions.contains_key(&hash) {
            warn!("Mempool: rejected v2 tx {} — hash already in v2 mempool (duplicate submit)", hex::encode(&hash[..8]));
            return false;
        }

        // v2.7.0 Phase 1.4 — RecentlyEvicted gate.
        if self.is_recently_evicted(&hash) {
            warn!(
                "Mempool: rejected v2 tx {} — recently evicted (TTL {}s)",
                hex::encode(&hash[..8]), RECENTLY_EVICTED_TTL_SECS
            );
            return false;
        }

        let fee = tx.fee();

        // Enforce minimum fee
        if fee < MIN_TX_FEE {
            warn!("Mempool: rejected v2 tx {} — fee {} < min {}", hex::encode(&hash[..8]), fee, MIN_TX_FEE);
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(&nullifier) {
                warn!(
                    "Mempool: rejected v2 tx {} — nullifier {} conflicts with pending tx",
                    hex::encode(&hash[..8]),
                    hex::encode(&nullifier[..8]),
                );
                return false; // Double-spend attempt
            }
        }

        let size = match &tx {
            Transaction::V2(v2) => v2.size(),
            Transaction::V1(v1) => v1.size(),
            // Other variants do not expose a size accessor; charge the floor.
            _ => MEMPOOL_MIN_WEIGHT as usize,
        };
        let cost = tx_weight(size, fee);

        // v2.7.0 Phase 1.4 — combined size + cost cap, weighted eviction.
        if self.total_count() >= MAX_MEMPOOL_SIZE
            || self.total_cost.saturating_add(cost) > MEMPOOL_COST_LIMIT
        {
            self.evict_expired();
            while self.total_count() >= MAX_MEMPOOL_SIZE
                || self.total_cost.saturating_add(cost) > MEMPOOL_COST_LIMIT
            {
                let min_fee = self.tx_meta.values().map(|m| m.fee).min().unwrap_or(0);
                if fee <= min_fee {
                    warn!("Mempool full: rejected v2 tx {} (fee {} <= min {}, cost_after={})", hex::encode(&hash[..4]), fee, min_fee, self.total_cost.saturating_add(cost));
                    return false;
                }
                if self.evict_lowest_fee().is_none() {
                    return false;
                }
            }
        }

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(nullifier);
        }

        self.v2_transactions.insert(hash, tx);
        self.tx_meta.insert(hash, TxMeta { fee, added_at: Self::now_secs(), cost });
        self.total_cost = self.total_cost.saturating_add(cost);
        true
    }

    /// Remove a V1 transaction from the mempool.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<ShieldedTransaction> {
        if let Some(tx) = self.v1_transactions.remove(hash) {
            // Remove associated nullifiers
            for nullifier in tx.nullifiers() {
                self.pending_nullifiers.remove(&nullifier.0);
            }
            if let Some(meta) = self.tx_meta.remove(hash) {
                self.total_cost = self.total_cost.saturating_sub(meta.cost);
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Remove a V2 transaction from the mempool.
    pub fn remove_v2(&mut self, hash: &[u8; 32]) -> Option<Transaction> {
        if let Some(tx) = self.v2_transactions.remove(hash) {
            // Remove associated nullifiers
            for nullifier in tx.nullifiers() {
                self.pending_nullifiers.remove(&nullifier);
            }
            if let Some(meta) = self.tx_meta.remove(hash) {
                self.total_cost = self.total_cost.saturating_sub(meta.cost);
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Get a V1 transaction by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&ShieldedTransaction> {
        self.v1_transactions.get(hash)
    }

    /// Get a V2 transaction by hash.
    pub fn get_v2(&self, hash: &[u8; 32]) -> Option<&Transaction> {
        self.v2_transactions.get(hash)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.v1_transactions.contains_key(hash) || self.v2_transactions.contains_key(hash)
    }

    /// Check if a nullifier is pending in the mempool.
    pub fn has_pending_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.pending_nullifiers.contains(nullifier)
    }

    /// Get all V1 transactions, sorted by fee (highest first).
    pub fn get_transactions(&self, limit: usize) -> Vec<ShieldedTransaction> {
        let mut txs: Vec<_> = self.v1_transactions.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Get all V2 transactions, sorted by fee (highest first).
    pub fn get_v2_transactions(&self, limit: usize) -> Vec<Transaction> {
        let mut txs: Vec<_> = self.v2_transactions.values().cloned().collect();
        txs.sort_by(|a, b| b.fee().cmp(&a.fee()));
        txs.truncate(limit);
        txs
    }

    /// Get only ShieldedTransactionV2 transactions for mining.
    pub fn get_shielded_v2_transactions(&self, limit: usize) -> Vec<crate::core::ShieldedTransactionV2> {
        use crate::core::Transaction as TxEnum;
        let mut txs: Vec<_> = self.v2_transactions.values()
            .filter_map(|tx| match tx {
                TxEnum::V2(v2) => Some(v2.clone()),
                _ => None,
            })
            .collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// v2.7.0 Phase 1.5 — Build the V2 transaction set for a block template
    /// using a ZIP-317-style two-phase selection:
    ///   1. **High-fee phase** — every tx whose `fee >= CONVENTIONAL_FEE` is
    ///      considered, ranked by descending fee-per-action (= fee divided by
    ///      spend+output count, roughly proportional to validation cost). The
    ///      first `max_high_fee_tx` are admitted unconditionally.
    ///   2. **Underpaying phase** — remaining tx with `fee < CONVENTIONAL_FEE`
    ///      are admitted in fee-per-action order until the cumulative action
    ///      count reaches `max_unpaid_actions`. This keeps validation cost
    ///      bounded under spam while still letting low-fee tx eventually
    ///      land.
    /// The returned vector is ordered so that high-fee tx appear first, which
    /// also matches the order in which validators replay them when computing
    /// state_root.
    pub fn get_shielded_v2_for_block(
        &self,
        max_high_fee_tx: usize,
        max_unpaid_actions: usize,
    ) -> Vec<crate::core::ShieldedTransactionV2> {
        use crate::core::Transaction as TxEnum;

        fn actions(tx: &crate::core::ShieldedTransactionV2) -> usize {
            tx.spends.len() + tx.outputs.len()
        }
        // fee per action, scaled to keep precision in integer space.
        fn fee_rate(tx: &crate::core::ShieldedTransactionV2) -> u128 {
            let a = actions(tx).max(1) as u128;
            (tx.fee as u128).saturating_mul(1_000_000) / a
        }

        let mut high: Vec<crate::core::ShieldedTransactionV2> = Vec::new();
        let mut low: Vec<crate::core::ShieldedTransactionV2> = Vec::new();
        for tx in self.v2_transactions.values() {
            if let TxEnum::V2(v2) = tx {
                if v2.fee >= CONVENTIONAL_FEE {
                    high.push(v2.clone());
                } else {
                    low.push(v2.clone());
                }
            }
        }

        high.sort_by(|a, b| fee_rate(b).cmp(&fee_rate(a)));
        if high.len() > max_high_fee_tx {
            high.truncate(max_high_fee_tx);
        }

        low.sort_by(|a, b| fee_rate(b).cmp(&fee_rate(a)));
        let mut budget = max_unpaid_actions;
        let mut admitted_low: Vec<crate::core::ShieldedTransactionV2> = Vec::new();
        for tx in low.into_iter() {
            let cost = actions(&tx);
            if cost > budget {
                continue;
            }
            budget -= cost;
            admitted_low.push(tx);
        }

        let mut out = high;
        out.append(&mut admitted_low);
        out
    }

    /// Number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.v1_transactions.len() + self.v2_transactions.len()
            + self.contract_deploys.len() + self.contract_calls.len()
    }

    /// Number of V2 transactions that have been sitting in the mempool for
    /// at least `min_age_secs`. Used by the Phase 3 V2 inclusion rule to
    /// compute the validator-side `expected_min_v2`.
    ///
    /// Transactions under `min_age_secs` are excluded — they give the miner
    /// the grace window needed to account for gossip propagation lag.
    pub fn v2_count_older_than(&self, min_age_secs: u64, now_secs: u64) -> usize {
        self.v2_transactions
            .keys()
            .filter(|hash| {
                self.tx_meta
                    .get(*hash)
                    .map(|m| now_secs.saturating_sub(m.added_at) >= min_age_secs)
                    .unwrap_or(false)
            })
            .count()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.v1_transactions.is_empty() && self.v2_transactions.is_empty()
            && self.contract_deploys.is_empty() && self.contract_calls.is_empty()
    }

    /// Remove transactions that are now in a block.
    pub fn remove_confirmed(&mut self, tx_hashes: &[[u8; 32]]) {
        for hash in tx_hashes {
            self.remove(hash);
            self.remove_v2(hash);
            self.remove_contract_tx(hash);
        }
    }

    /// Remove transactions with nullifiers that are now spent on-chain.
    pub fn remove_spent_nullifiers(&mut self, spent_nullifiers: &[[u8; 32]]) {
        let mut to_remove_v1 = Vec::new();
        let mut to_remove_v2 = Vec::new();

        for (hash, tx) in &self.v1_transactions {
            for nullifier in tx.nullifiers() {
                if spent_nullifiers.contains(&nullifier.0) {
                    to_remove_v1.push(*hash);
                    break;
                }
            }
        }

        for (hash, tx) in &self.v2_transactions {
            for nullifier in tx.nullifiers() {
                if spent_nullifiers.contains(&nullifier) {
                    to_remove_v2.push(*hash);
                    break;
                }
            }
        }

        for hash in to_remove_v1 {
            self.remove(&hash);
        }
        for hash in to_remove_v2 {
            self.remove_v2(&hash);
        }
    }

    /// Add a contract deploy transaction.
    pub fn add_contract_deploy(&mut self, tx: ContractDeployTransaction) -> bool {
        let hash = tx.hash();
        if self.contract_deploys.contains_key(&hash) {
            return false;
        }
        self.contract_deploys.insert(hash, tx);
        true
    }

    /// Add a contract call transaction.
    pub fn add_contract_call(&mut self, tx: ContractCallTransaction) -> bool {
        let hash = tx.hash();
        if self.contract_calls.contains_key(&hash) {
            return false;
        }
        self.contract_calls.insert(hash, tx);
        true
    }

    /// Get pending contract deploy transactions sorted by fee (highest first).
    pub fn get_contract_deploys(&self, limit: usize) -> Vec<ContractDeployTransaction> {
        let mut txs: Vec<_> = self.contract_deploys.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Get pending contract call transactions sorted by fee (highest first).
    pub fn get_contract_calls(&self, limit: usize) -> Vec<ContractCallTransaction> {
        let mut txs: Vec<_> = self.contract_calls.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Remove a confirmed contract transaction by hash.
    pub fn remove_contract_tx(&mut self, hash: &[u8; 32]) {
        self.contract_deploys.remove(hash);
        self.contract_calls.remove(hash);
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.v1_transactions.clear();
        self.v2_transactions.clear();
        self.contract_deploys.clear();
        self.contract_calls.clear();
        self.pending_nullifiers.clear();
        self.tx_meta.clear();
        self.total_cost = 0;
        // RecentlyEvicted is intentionally preserved across `clear()` so a
        // mempool flush (e.g. after a reorg) doesn't reopen the spam window.
    }

    /// Re-validate all V1 transactions against the current chain state.
    /// Returns the number of transactions removed.
    pub fn revalidate(&mut self, state: &ShieldedState) -> usize {
        let mut invalid_hashes = Vec::new();

        for (hash, tx) in &self.v1_transactions {
            // Check anchors are still valid
            for anchor in tx.anchors() {
                if !state.is_valid_anchor(anchor) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }

            // Check nullifiers aren't spent
            for nullifier in tx.nullifiers() {
                if state.is_nullifier_spent(nullifier) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }
        }

        // v2.5.4 Bug #7 fix — V2 transactions were NOT revalidated here, so a
        // zombie V2 tx whose nullifier was mined in a concurrent block stayed
        // in the mempool forever and was re-selected on every block template,
        // causing every subsequent mined block to fail locally with "Nullifier
        // already spent" (observed on EPYC2 miner after consolidation). Mirror
        // the V1 check for V2 spends.
        for (hash, tx) in &self.v2_transactions {
            // The mempool's `v2_transactions` map stores the `Transaction`
            // enum; extract the underlying `ShieldedTransactionV2` variant.
            let v2 = match tx {
                crate::core::Transaction::V2(v2) => v2,
                _ => continue,
            };
            for spend in &v2.spends {
                // V2 spend.nullifier is [u8; 32]; wrap into Nullifier for the
                // common spent-set check.
                let n = crate::crypto::nullifier::Nullifier(spend.nullifier);
                if state.is_nullifier_spent(&n) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }
        }

        let removed = invalid_hashes.len();
        for hash in invalid_hashes {
            self.remove(&hash);
        }

        removed
    }

    /// Get all transaction hashes.
    pub fn get_hashes(&self) -> Vec<[u8; 32]> {
        let mut hashes: Vec<_> = self.v1_transactions.keys().cloned().collect();
        hashes.extend(self.v2_transactions.keys().cloned());
        hashes.extend(self.contract_deploys.keys().cloned());
        hashes.extend(self.contract_calls.keys().cloned());
        hashes
    }

    /// Get total fees in the mempool.
    pub fn total_fees(&self) -> u64 {
        let v1_fees: u64 = self.v1_transactions.values().map(|tx| tx.fee).sum();
        let v2_fees: u64 = self.v2_transactions.values().map(|tx| tx.fee()).sum();
        let deploy_fees: u64 = self.contract_deploys.values().map(|tx| tx.fee).sum();
        let call_fees: u64 = self.contract_calls.values().map(|tx| tx.fee).sum();
        v1_fees + v2_fees + deploy_fees + call_fees
    }

    /// Get the pending nullifiers set (for conflict checking).
    pub fn pending_nullifiers(&self) -> &HashSet<[u8; 32]> {
        &self.pending_nullifiers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BindingSignature;

    fn dummy_v1_tx(fee: u64) -> ShieldedTransaction {
        ShieldedTransaction::new(vec![], vec![], fee, BindingSignature::new(vec![1; 64]))
    }

    #[test]
    fn test_mempool_add_and_get() {
        let mut mempool = Mempool::new();

        let tx = dummy_v1_tx(5000); // Above MIN_TX_FEE
        let hash = tx.hash();

        assert!(mempool.add(tx));
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_rejects_low_fee() {
        let mut mempool = Mempool::new();
        let tx = dummy_v1_tx(500); // Below MIN_TX_FEE
        assert!(!mempool.add(tx));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_no_duplicates() {
        let mut mempool = Mempool::new();

        let tx = dummy_v1_tx(5000);
        assert!(mempool.add(tx.clone()));
        assert!(!mempool.add(tx)); // Should fail, duplicate
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_sorted_by_fee() {
        let mut mempool = Mempool::new();

        let tx1 = dummy_v1_tx(1000);
        let tx2 = dummy_v1_tx(5000);
        let tx3 = dummy_v1_tx(3000);

        mempool.add(tx1);
        mempool.add(tx2);
        mempool.add(tx3);

        let txs = mempool.get_transactions(10);
        assert_eq!(txs[0].fee, 5000);
        assert_eq!(txs[1].fee, 3000);
        assert_eq!(txs[2].fee, 1000);
    }

    #[test]
    fn test_mempool_total_fees() {
        let mut mempool = Mempool::new();

        mempool.add(dummy_v1_tx(10000));
        mempool.add(dummy_v1_tx(20000));
        mempool.add(dummy_v1_tx(30000));

        assert_eq!(mempool.total_fees(), 60000);
    }
}
