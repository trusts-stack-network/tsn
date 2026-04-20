//! Soft ban list for miners that consistently violate the V2 inclusion rule.
//!
//! See `consensus::v2_inclusion` for the rule itself. When a miner's block
//! fails validation AND the miner's previous N blocks also failed, the node
//! adds the miner's `pk_hash` to a time-bounded ban set. Subsequent blocks
//! whose coinbase `miner_pk_hash` is in the set are rejected outright until
//! the ban expires.
//!
//! The ban is local to each node's observation — there is no gossip layer
//! for bans in this release. In practice a miner banned by the majority of
//! seeds loses reward landing reliably enough.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Duration of a single ban in blocks. 1 hour at ~15s/block ≈ 240 blocks.
pub const BAN_DURATION_BLOCKS: u64 = 240;

/// Number of consecutive V2 inclusion violations before a ban is triggered.
/// Matches the grace window of `V2_GRACE_BLOCKS` — a miner that violates
/// three blocks in a row has clearly ignored the rule, not just lagged.
pub const BAN_THRESHOLD_OFFENSES: u32 = 3;

/// A single ban entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanEntry {
    /// Block height at which the ban expires.
    pub until_height: u64,
    /// Running count of observed offenses (reset when the ban is cleared).
    pub offense_count: u32,
    /// Last block height at which an offense was recorded.
    pub last_offense_height: u64,
    /// Human-readable reason for logging/debugging.
    pub reason: String,
}

/// Set of currently banned miners, keyed by `miner_pk_hash` (hex-encoded
/// for JSON portability).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BannedMiners {
    /// Hex-encoded `miner_pk_hash` → ban entry.
    pub entries: HashMap<String, BanEntry>,
}

impl BannedMiners {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(pk_hash: &[u8; 32]) -> String {
        hex::encode(pk_hash)
    }

    /// Record a V2 inclusion violation. Returns `true` if the miner is now
    /// banned (threshold reached) or was already banned and is still under
    /// penalty; `false` otherwise.
    pub fn record_offense(
        &mut self,
        pk_hash: &[u8; 32],
        current_height: u64,
        reason: impl Into<String>,
    ) -> bool {
        let key = Self::key(pk_hash);
        let entry = self.entries.entry(key).or_insert_with(|| BanEntry {
            until_height: 0,
            offense_count: 0,
            last_offense_height: 0,
            reason: String::new(),
        });

        // If the miner is currently banned, surface that without mutating
        // the offense counter — one ban window is punishment enough.
        if entry.until_height > current_height {
            return true;
        }

        entry.offense_count = entry.offense_count.saturating_add(1);
        entry.last_offense_height = current_height;
        entry.reason = reason.into();

        if entry.offense_count >= BAN_THRESHOLD_OFFENSES {
            entry.until_height = current_height.saturating_add(BAN_DURATION_BLOCKS);
            true
        } else {
            false
        }
    }

    /// Forgive an accumulated (but non-banned) offense counter. Called when a
    /// miner produces a correctly-behaved block — consecutive violations are
    /// what triggers a ban, so a compliant block resets the tally.
    pub fn record_compliant_block(&mut self, pk_hash: &[u8; 32], current_height: u64) {
        let key = Self::key(pk_hash);
        if let Some(entry) = self.entries.get_mut(&key) {
            // Only reset offenses; do not cut short an active ban.
            if entry.until_height <= current_height {
                entry.offense_count = 0;
                entry.last_offense_height = 0;
                entry.reason.clear();
            }
        }
    }

    /// Return `true` if this miner is currently banned at the given height.
    pub fn is_banned(&self, pk_hash: &[u8; 32], current_height: u64) -> bool {
        self.entries
            .get(&Self::key(pk_hash))
            .map(|entry| entry.until_height > current_height)
            .unwrap_or(false)
    }

    /// Drop entries whose ban has expired AND whose offense counter is 0.
    /// Active bans and lingering (sub-threshold) offense tallies are kept
    /// — the latter so that spaced-out repeat offenders still hit the
    /// threshold eventually.
    pub fn expire_at(&mut self, current_height: u64) {
        self.entries.retain(|_, entry| {
            entry.until_height > current_height || entry.offense_count > 0
        });
    }

    /// Read a ban set from JSON on disk. Missing file → empty set (not an
    /// error): a fresh node simply has nothing to remember yet.
    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path)?;
        let parsed: Self = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(parsed)
    }

    /// Atomic write: dump to `<path>.tmp` then rename into place.
    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let path = path.as_ref();
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Current number of entries (active bans + pending offense tallies).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [1u8; 32];
    const BOB: [u8; 32] = [2u8; 32];

    #[test]
    fn new_is_empty() {
        let bm = BannedMiners::new();
        assert!(bm.is_empty());
        assert!(!bm.is_banned(&ALICE, 100));
    }

    #[test]
    fn single_offense_does_not_ban() {
        let mut bm = BannedMiners::new();
        let banned = bm.record_offense(&ALICE, 100, "test");
        assert!(!banned);
        assert!(!bm.is_banned(&ALICE, 100));
    }

    #[test]
    fn threshold_offenses_trigger_ban() {
        let mut bm = BannedMiners::new();
        assert!(!bm.record_offense(&ALICE, 100, "r1"));
        assert!(!bm.record_offense(&ALICE, 101, "r2"));
        assert!(bm.record_offense(&ALICE, 102, "r3")); // threshold
        assert!(bm.is_banned(&ALICE, 102));
        assert!(bm.is_banned(&ALICE, 102 + BAN_DURATION_BLOCKS - 1));
        assert!(!bm.is_banned(&ALICE, 102 + BAN_DURATION_BLOCKS)); // expired
    }

    #[test]
    fn compliant_block_resets_offense_counter() {
        let mut bm = BannedMiners::new();
        bm.record_offense(&ALICE, 100, "r1");
        bm.record_offense(&ALICE, 101, "r2");
        assert_eq!(bm.entries.get(&BannedMiners::key(&ALICE)).unwrap().offense_count, 2);

        bm.record_compliant_block(&ALICE, 102);
        assert_eq!(bm.entries.get(&BannedMiners::key(&ALICE)).unwrap().offense_count, 0);

        // Next offense is again just offense #1, not #3.
        assert!(!bm.record_offense(&ALICE, 103, "r3"));
        assert!(!bm.is_banned(&ALICE, 103));
    }

    #[test]
    fn compliant_block_does_not_cut_active_ban_short() {
        let mut bm = BannedMiners::new();
        bm.record_offense(&ALICE, 100, "r1");
        bm.record_offense(&ALICE, 101, "r2");
        bm.record_offense(&ALICE, 102, "r3"); // banned

        // A later correctly-attributed block from Alice should NOT clear the
        // ban (prevents a banned miner from 'paying their way out' by
        // sprinkling one compliant block in the ban window).
        bm.record_compliant_block(&ALICE, 150);
        assert!(bm.is_banned(&ALICE, 150));
    }

    #[test]
    fn independent_miners_do_not_affect_each_other() {
        let mut bm = BannedMiners::new();
        bm.record_offense(&ALICE, 100, "a1");
        bm.record_offense(&ALICE, 101, "a2");
        bm.record_offense(&ALICE, 102, "a3");
        assert!(bm.is_banned(&ALICE, 102));
        assert!(!bm.is_banned(&BOB, 102));
    }

    #[test]
    fn offense_during_active_ban_does_not_extend_it() {
        let mut bm = BannedMiners::new();
        bm.record_offense(&ALICE, 100, "r1");
        bm.record_offense(&ALICE, 101, "r2");
        bm.record_offense(&ALICE, 102, "r3");
        let original_until = bm.entries.get(&BannedMiners::key(&ALICE)).unwrap().until_height;

        // Add more offenses while banned — ban window stays the same.
        bm.record_offense(&ALICE, 110, "r4");
        let after = bm.entries.get(&BannedMiners::key(&ALICE)).unwrap().until_height;
        assert_eq!(original_until, after);
    }

    #[test]
    fn expire_at_drops_fully_expired_entries() {
        let mut bm = BannedMiners::new();
        bm.record_offense(&ALICE, 100, "r1");
        bm.record_offense(&ALICE, 101, "r2");
        bm.record_offense(&ALICE, 102, "r3"); // banned
        assert_eq!(bm.len(), 1);

        let tip = 102 + BAN_DURATION_BLOCKS + 1;

        // Ban expired AND offense_count still > 0 — kept (repeat-offender trace).
        bm.expire_at(tip);
        assert_eq!(bm.len(), 1);

        // After a compliant block, tally resets → next expire_at drops it.
        bm.record_compliant_block(&ALICE, tip);
        bm.expire_at(tip);
        assert_eq!(bm.len(), 0);
    }

    #[test]
    fn persistence_round_trip() {
        let mut bm = BannedMiners::new();
        bm.record_offense(&ALICE, 100, "r1");
        bm.record_offense(&ALICE, 101, "r2");
        bm.record_offense(&ALICE, 102, "expected 5 got 0");
        bm.record_offense(&BOB, 105, "under_committed");

        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join(format!("tsn_banned_miners_test_{}.json", std::process::id()));

        bm.save_to_disk(&path).unwrap();
        let restored = BannedMiners::load_from_disk(&path).unwrap();

        assert_eq!(restored.len(), 2);
        assert!(restored.is_banned(&ALICE, 102));
        assert!(!restored.is_banned(&BOB, 105));
        assert_eq!(
            restored.entries.get(&BannedMiners::key(&ALICE)).unwrap().reason,
            "expected 5 got 0"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_missing_file_returns_empty_not_error() {
        let path = std::env::temp_dir().join(format!(
            "tsn_banned_miners_missing_{}.json",
            std::process::id()
        ));
        // Ensure it does not exist
        std::fs::remove_file(&path).ok();
        let bm = BannedMiners::load_from_disk(&path).unwrap();
        assert!(bm.is_empty());
    }
}
