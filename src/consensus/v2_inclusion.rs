//! Mandatory V2 transaction inclusion rule (Option B — stronger variant).
//!
//! Enforces that miners include post-quantum (V2) transactions from the mempool
//! when such transactions are available. The header commits to a `min_v2_count`
//! which is (a) bound into the PoW hash (see `BlockHeader`), and (b) compared
//! against each validator's own deterministic view of the V2 mempool backlog.
//!
//! A miner that consistently produces empty-V2 blocks while the mempool holds
//! V2 transactions is flagged for a soft ban at the consensus layer
//! (see `consensus::banned_miners`).

use crate::consensus::banned_miners::BannedMiners;
use crate::core::ShieldedBlock;
use crate::network::mempool::Mempool;

/// Maximum number of V2 transactions a miner is expected to commit to in a
/// single block. Larger mempool backlogs are capped at this value so a sudden
/// flood cannot stall the chain: miners keep draining by `V2_INCLUSION_CAP`
/// blocks per block. Matches the practical V2 capacity per block.
pub const V2_INCLUSION_CAP: u16 = 16;

/// Grace window in blocks — a V2 transaction that sits in the mempool for
/// fewer than `V2_GRACE_BLOCKS` blocks does not yet count against the
/// expected_min_v2 budget. This gives the miner a fair window to catch up
/// before being penalized for natural gossip lag.
pub const V2_GRACE_BLOCKS: u64 = 3;

/// Errors returned by [`validate_v2_inclusion`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2InclusionError {
    /// The header's `min_v2_count` is lower than the value this validator
    /// derived from its own mempool view — the miner under-committed.
    UnderCommitted { header_value: u16, expected: u16 },
    /// The block includes fewer V2 transactions than its own header commits
    /// to — the miner failed to honour its own engagement.
    MissingV2 { committed: u16, included: u16 },
}

impl std::fmt::Display for V2InclusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnderCommitted { header_value, expected } => {
                write!(f, "block header min_v2_count={} is below the validator-derived expected {}",
                    header_value, expected)
            }
            Self::MissingV2 { committed, included } => {
                write!(f, "block commits to min_v2_count={} but includes only {} V2 transactions",
                    committed, included)
            }
        }
    }
}

impl std::error::Error for V2InclusionError {}

/// Compute the expected minimum V2 count from a validator's view.
///
/// `v2_pending_old_enough` is the number of V2 transactions in the mempool
/// that have been waiting for `> V2_GRACE_BLOCKS` blocks — these are the
/// transactions a miner cannot excuse with mesh lag.
///
/// The result is clamped to `V2_INCLUSION_CAP`.
pub fn expected_min_v2(v2_pending_old_enough: usize) -> u16 {
    let raw = v2_pending_old_enough.min(V2_INCLUSION_CAP as usize);
    raw as u16
}

/// Pure validation rule on the three observable counts.
///
/// - `committed`: the value in `block.header.min_v2_count`.
/// - `included`: how many V2 transactions the block actually carries.
/// - `expected`: what this validator computed from its own mempool at the
///   parent of this block.
///
/// The rule has two independent branches:
///
/// 1. `committed >= expected` — a miner cannot under-commit vs. the
///    validator's view. This binds the miner's attestation to what the
///    network observes.
/// 2. `included >= committed` — the miner must honour its own commitment.
///    Under-delivery is impossible because `committed` is PoW-signed.
pub fn check_counts(
    committed: u16,
    included: usize,
    expected: u16,
) -> Result<(), V2InclusionError> {
    if committed < expected {
        return Err(V2InclusionError::UnderCommitted {
            header_value: committed,
            expected,
        });
    }
    let included_u16 = included.min(u16::MAX as usize) as u16;
    if included_u16 < committed {
        return Err(V2InclusionError::MissingV2 {
            committed,
            included: included_u16,
        });
    }
    Ok(())
}

/// Validate the V2 inclusion commitment of a block.
///
/// `expected` is the value computed by the local validator via
/// [`expected_min_v2`] for the state at the PARENT of `block`.
pub fn validate_v2_inclusion(
    block: &ShieldedBlock,
    expected: u16,
) -> Result<(), V2InclusionError> {
    check_counts(
        block.header.min_v2_count,
        block.transactions_v2.len(),
        expected,
    )
}

/// Outcome of the block-acceptance-time enforcement decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementOutcome {
    /// The block is compliant — caller may proceed with normal acceptance.
    Accept,
    /// The miner's pk_hash is currently banned — reject the block, do not
    /// increment the offense counter (one ban window is punishment enough).
    RejectBanned { until_height: u64 },
    /// The block failed the V2 inclusion check. The offense has been recorded
    /// against the miner's pk_hash. `now_banned=true` means the threshold was
    /// reached and the miner is now under an active ban.
    RejectV2Violation { error: V2InclusionError, now_banned: bool },
}

impl EnforcementOutcome {
    pub fn is_accept(&self) -> bool { matches!(self, Self::Accept) }
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Accept => None,
            Self::RejectBanned { until_height } =>
                Some(format!("miner banned until height {}", until_height)),
            Self::RejectV2Violation { error, now_banned } =>
                Some(format!("{} (miner now banned: {})", error, now_banned)),
        }
    }
}

/// Integrated enforcement at block-acceptance time.
///
/// Runs three checks in order:
///   1. Is `miner_pk_hash` currently banned? → reject.
///   2. Does `block.header.min_v2_count` / `transactions_v2.len()` satisfy
///      the validator's mempool-derived expected value? → reject + record
///      offense + possibly ban on threshold.
///   3. If everything checks out, `record_compliant_block` resets the
///      miner's offense tally (Accept).
///
/// Mutates `banned_miners` on offenses and compliant blocks. The caller is
/// responsible for persisting the updated set to disk.
pub fn enforce_at_acceptance(
    block: &ShieldedBlock,
    mempool: &Mempool,
    banned_miners: &mut BannedMiners,
    current_height: u64,
    now_secs: u64,
) -> EnforcementOutcome {
    let miner_pk = block.coinbase.miner_pk_hash;

    // Genesis and pre-attribution blocks carry [0u8; 32]; skip the policy
    // for them — there is no miner to hold accountable.
    let is_attributed = miner_pk != [0u8; 32];

    if is_attributed && banned_miners.is_banned(&miner_pk, current_height) {
        let until = banned_miners
            .entries
            .get(&hex::encode(miner_pk))
            .map(|e| e.until_height)
            .unwrap_or(current_height);
        return EnforcementOutcome::RejectBanned { until_height: until };
    }

    let grace_secs = V2_GRACE_BLOCKS.saturating_mul(crate::consensus::TARGET_BLOCK_TIME_SECS);
    let old_enough = mempool.v2_count_older_than(grace_secs, now_secs);
    let expected = expected_min_v2(old_enough);

    match validate_v2_inclusion(block, expected) {
        Ok(()) => {
            if is_attributed {
                banned_miners.record_compliant_block(&miner_pk, current_height);
            }
            EnforcementOutcome::Accept
        }
        Err(error) => {
            let now_banned = if is_attributed {
                banned_miners.record_offense(&miner_pk, current_height, error.to_string())
            } else {
                false
            };
            EnforcementOutcome::RejectV2Violation { error, now_banned }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_min_v2_clamps_to_cap() {
        assert_eq!(expected_min_v2(0), 0);
        assert_eq!(expected_min_v2(5), 5);
        assert_eq!(expected_min_v2(V2_INCLUSION_CAP as usize), V2_INCLUSION_CAP);
        assert_eq!(expected_min_v2(V2_INCLUSION_CAP as usize + 100), V2_INCLUSION_CAP);
        assert_eq!(expected_min_v2(10_000), V2_INCLUSION_CAP);
    }

    #[test]
    fn ok_when_commit_meets_expected_and_included_meets_commit() {
        assert!(check_counts(3, 5, 3).is_ok()); // tight match
        assert!(check_counts(3, 5, 2).is_ok()); // over-commit fine
        assert!(check_counts(3, 5, 0).is_ok()); // no expectation
        assert!(check_counts(0, 0, 0).is_ok()); // empty mempool, empty block
    }

    #[test]
    fn rejects_when_header_under_commits() {
        let err = check_counts(2, 5, 5).unwrap_err();
        assert_eq!(err, V2InclusionError::UnderCommitted { header_value: 2, expected: 5 });
    }

    #[test]
    fn rejects_when_block_includes_fewer_v2_than_committed() {
        let err = check_counts(5, 3, 5).unwrap_err();
        assert_eq!(err, V2InclusionError::MissingV2 { committed: 5, included: 3 });
    }

    #[test]
    fn miner_cannot_under_commit_then_fill() {
        // Miner claims 0 but mempool says 4 — reject even if they actually
        // include 4 (they tried to hide the commitment).
        let err = check_counts(0, 4, 4).unwrap_err();
        assert_eq!(err, V2InclusionError::UnderCommitted { header_value: 0, expected: 4 });
    }

    #[test]
    fn zero_included_with_zero_committed_and_nonzero_expected_rejects_via_under_commit_first() {
        // Under-commit is checked before missing-V2. A block with 0/0/N>0
        // surfaces as UnderCommitted (committed < expected), not MissingV2.
        let err = check_counts(0, 0, 3).unwrap_err();
        assert_eq!(err, V2InclusionError::UnderCommitted { header_value: 0, expected: 3 });
    }

    #[test]
    fn u16_overflow_clamped() {
        // A block stuffed with > u16::MAX V2 txs is impossible in practice
        // (block size limits) but the rule must stay sound.
        let err = check_counts(u16::MAX, 3, u16::MAX).unwrap_err();
        assert_eq!(err, V2InclusionError::MissingV2 { committed: u16::MAX, included: 3 });
    }

    // ------------------------------------------------------------------
    // enforce_at_acceptance — integration-ish tests that exercise the
    // full policy with a real Mempool + BannedMiners but without a live
    // chain. Uses a minimal hand-built ShieldedBlock.
    // ------------------------------------------------------------------

    use crate::core::{CoinbaseTransaction, BlockHeader};
    use crate::crypto::{commitment::NoteCommitment, note::EncryptedNote};

    const MINER_A: [u8; 32] = [0xAAu8; 32];
    const MINER_B: [u8; 32] = [0xBBu8; 32];

    fn make_block(min_v2_count: u16, miner_pk_hash: [u8; 32]) -> ShieldedBlock {
        // Build a minimal well-formed block. `transactions_v2` is always
        // empty: the enforcement policy tests only need to distinguish
        // "block has 0 V2 txs" from "mempool requires N V2 txs" and we
        // deliberately avoid fabricating fake ShieldedTransactionV2 values
        // (their STARK `transaction_proof` field is non-trivial to mock).
        let mut coinbase = CoinbaseTransaction::new(
            NoteCommitment([0u8; 32]),
            [0u8; 32],
            EncryptedNote { ciphertext: vec![0; 64], ephemeral_pk: vec![0; 32] },
            100,
            1,
        );
        coinbase.miner_pk_hash = miner_pk_hash;
        let header = BlockHeader {
            version: 3,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            commitment_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 1,
            difficulty: 1,
            min_v2_count,
            nonce: [0u8; 64],
        };
        ShieldedBlock {
            header,
            transactions: vec![],
            transactions_v2: vec![],
            contract_deploys: vec![],
            contract_calls: vec![],
            contract_receipts: vec![],
            coinbase,
            relay_payout: None,
        }
    }

    #[test]
    fn enforce_accept_with_empty_mempool() {
        let mempool = Mempool::new();
        let mut banned = BannedMiners::new();
        let block = make_block(0, MINER_A);
        let outcome = enforce_at_acceptance(&block, &mempool, &mut banned, 100, 1000);
        assert_eq!(outcome, EnforcementOutcome::Accept);
        assert!(!banned.is_banned(&MINER_A, 100));
    }

    #[test]
    fn enforce_accept_resets_prior_offense_tally() {
        let mempool = Mempool::new();
        let mut banned = BannedMiners::new();
        banned.record_offense(&MINER_A, 98, "prior");
        banned.record_offense(&MINER_A, 99, "prior2");
        // Compliant block → tally reset to 0.
        let block = make_block(0, MINER_A);
        let outcome = enforce_at_acceptance(&block, &mempool, &mut banned, 100, 1000);
        assert_eq!(outcome, EnforcementOutcome::Accept);
        assert_eq!(
            banned.entries.get(&hex::encode(MINER_A)).unwrap().offense_count,
            0
        );
    }

    #[test]
    fn enforce_rejects_banned_miner_without_incrementing_offense() {
        let mempool = Mempool::new();
        let mut banned = BannedMiners::new();
        banned.record_offense(&MINER_A, 100, "o1");
        banned.record_offense(&MINER_A, 101, "o2");
        banned.record_offense(&MINER_A, 102, "o3"); // banned
        let offenses_before = banned.entries.get(&hex::encode(MINER_A)).unwrap().offense_count;

        let block = make_block(0, MINER_A);
        let outcome = enforce_at_acceptance(&block, &mempool, &mut banned, 103, 1000);
        assert!(matches!(outcome, EnforcementOutcome::RejectBanned { .. }));

        // Offense count must NOT increment while ban is active.
        let offenses_after = banned.entries.get(&hex::encode(MINER_A)).unwrap().offense_count;
        assert_eq!(offenses_before, offenses_after);
    }

    #[test]
    fn enforce_ignores_genesis_miner_pk() {
        let mempool = Mempool::new();
        let mut banned = BannedMiners::new();
        // Genesis block: miner_pk_hash = [0u8; 32]. Policy must not ban it.
        let block = make_block(0, [0u8; 32]);
        let outcome = enforce_at_acceptance(&block, &mempool, &mut banned, 0, 1000);
        assert_eq!(outcome, EnforcementOutcome::Accept);
        assert!(banned.is_empty());
    }

    #[test]
    fn enforce_independence_between_miners() {
        let mempool = Mempool::new();
        let mut banned = BannedMiners::new();
        banned.record_offense(&MINER_A, 100, "o1");
        banned.record_offense(&MINER_A, 101, "o2");
        banned.record_offense(&MINER_A, 102, "o3"); // A banned

        // B mines a clean block → should be accepted regardless of A's status.
        let block_b = make_block(0, MINER_B);
        let outcome = enforce_at_acceptance(&block_b, &mempool, &mut banned, 103, 1000);
        assert_eq!(outcome, EnforcementOutcome::Accept);
        assert!(!banned.is_banned(&MINER_B, 103));
    }
}
