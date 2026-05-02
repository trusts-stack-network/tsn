/// Network configuration constants
///
/// IMPORTANT: All nodes must use the same GENESIS_DIFFICULTY
/// to have compatible genesis blocks and sync properly.

/// The difficulty used for the genesis block.
/// This MUST be the same for all nodes on the network.
/// Changing this creates an incompatible chain.
/// Numeric difficulty: hash_prefix (u64 big-endian) must be < u64::MAX / difficulty.
pub const GENESIS_DIFFICULTY: u64 = 1_000_001;

/// Minimum time between consecutive blocks (seconds).
/// Blocks with timestamp < prev_block_timestamp + this value are rejected by ALL nodes.
/// This is a consensus rule — ensures propagation time between blocks regardless of hashrate.
/// With 8s minimum and 10s target, there's always 8+ seconds for block propagation.
pub const MIN_BLOCK_INTERVAL_SECS: u64 = 8;

/// Activation height for Poseidon Goldilocks PoW hash.
/// Blocks at height >= this value use Poseidon over GoldilocksField (plonky2).
/// Blocks below this height use legacy BN254 Poseidon (light-poseidon).
///
/// Currently 0 because v0.3.0 was deployed as a fresh chain (testnet phase).
/// For a future mainnet hard fork, set this to the fork height and add `height`
/// to BlockHeader so validation can route to the correct hash function.
pub const POSEIDON2_ACTIVATION_HEIGHT: u64 = 0;

/// Activation height for Poseidon2 (plonky3) PoW hash.
/// Blocks at height >= this value use Poseidon2 over GoldilocksField (p3-poseidon2).
/// Blocks between POSEIDON2_ACTIVATION_HEIGHT and this value use Poseidon v1 (plonky2).
///
/// Set to current chain height + ~200 blocks to give all nodes time to upgrade.
/// All nodes MUST upgrade to v0.4.0 before this height is reached.
pub const POSEIDON2_V2_ACTIVATION_HEIGHT: u64 = 0;

/// Default seed nodes for the TSN network.
/// v2.3.9 — Migrated from hardcoded IPs to DNS names. The A-records live
/// under the `tsnchain.com` zone so operators can rotate a seed's hosting
/// without shipping a new binary. `nexus` is the primary relay; `seed1..4`
/// are the supporting seeds. If DNS resolution fails at bootstrap, libp2p
/// Kademlia discovery will still find peers through any reachable seed,
/// and the node keeps working via cached peers after the first sync.
pub const SEED_NODES: &[&str] = &[
    "http://nexus.tsnchain.com:9333",
    "http://seed1.tsnchain.com:9333",
    "http://seed2.tsnchain.com:9333",
    "http://seed3.tsnchain.com:9333",
    "http://seed4.tsnchain.com:9333",
];

/// Whitelisted IPs — only these can connect via HTTP API and P2P.
/// Set to empty to allow all connections (open network).
/// Used during testing to isolate our nodes from external miners.
pub const WHITELISTED_IPS: &[&str] = &[
    // Empty — open network. Version check + protocol magic enforce compatibility.
];

/// Check if an IP is whitelisted. Returns true if whitelist is empty (open network).
pub fn is_ip_whitelisted(ip: &str) -> bool {
    if WHITELISTED_IPS.is_empty() {
        return true;
    }
    WHITELISTED_IPS.iter().any(|w| ip.starts_with(w))
}

/// Network name for identification
pub const NETWORK_NAME: &str = "tsn-testnet-v12";

/// Hardcoded checkpoints for fast-sync verification.
/// After downloading blocks in trusted mode, the node verifies that these
/// block hashes match. If any mismatch is found, the chain is rejected.
/// Updated with each release.
/// Fast-sync checkpoints — will be populated after chain stabilizes.
pub const FAST_SYNC_CHECKPOINTS: &[(u64, &str)] = &[];

/// Default port for nodes
pub const DEFAULT_PORT: u16 = 9333;

/// v2.8.4 Phase 1 (Iron Fish core): minimum confirmations a note needs before
/// it is spendable by the wallet. Mirrors Iron Fish DEFAULT_CONFIRMATIONS = 2.
/// A note created at height H is selectable for sending only when chain.tip >= H + MIN_SPEND_CONFIRMATIONS.
/// Eliminates "Invalid anchor (not a recent root)" errors caused by reorgs
/// invalidating notes that were spent right at the tip.
pub const MIN_SPEND_CONFIRMATIONS: u64 = 2;

/// Initial block reward in base units (50 coins)
pub const BLOCK_REWARD: u64 = 50_000_000_000;

/// Coin decimals (1 coin = 10^9 base units)
pub const COIN_DECIMALS: u32 = 9;

/// Halving interval in blocks.
/// At ~10s/block: 4_200_000 blocks ≈ 16 months per halving era.
/// Supply max reached in ~10 years. Schedule: 50 → 25 → 12.5 → 6.25 → ... TSN/block.
pub const HALVING_INTERVAL: u64 = 4_200_000;

/// Calculate the block reward at a given height, accounting for halving.
/// Reward halves every HALVING_INTERVAL blocks.
/// Returns 0 once all halvings reduce the reward below 1 base unit.
pub fn block_reward_at_height(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    BLOCK_REWARD >> halvings
}

// ============================================================================
// Block Reward Distribution
// ============================================================================
//
// Split: 92% miner, 5% dev fees, 3% relay pool
// Total = 100%. NO PREMINE — treasury only accumulates through mining.
// Relay pool: distributed to active relay nodes proportionally to uptime.
// ============================================================================

/// Dev fees percentage (5% of block reward to treasury).
pub const DEV_FEE_PERCENT: u64 = 5;

/// Relay pool percentage (3% of block reward to relay nodes).
pub const RELAY_POOL_PERCENT: u64 = 3;

/// Dev treasury pk_hash (Blake2s256 hash of ML-DSA-65 public key).
/// This is the PUBLIC hash — safe to include in code.
/// Private keys are held offline by the treasury operator and MUST NEVER be committed.
/// Address: 1d923ecba7891a3c4bce0c65da2e1036099a4c52
pub const DEV_TREASURY_PK_HASH: [u8; 32] = [
    0x06, 0xde, 0x72, 0xf4, 0xe7, 0x28, 0xaf, 0x0c,
    0x71, 0x8b, 0xeb, 0x01, 0x31, 0x3c, 0x70, 0xe9,
    0xb3, 0xa4, 0x10, 0xf4, 0x45, 0x43, 0x89, 0xce,
    0x22, 0xb7, 0xbe, 0x2a, 0xfd, 0x88, 0xa0, 0x01,
];

/// Calculate miner reward from total reward (92%).
/// Miner gets total - dev_fee - relay_pool.
pub fn miner_reward(total_reward: u64) -> u64 {
    total_reward * (100 - DEV_FEE_PERCENT - RELAY_POOL_PERCENT) / 100
}

/// Calculate dev fees from total reward (5%).
/// Uses: ensures no rounding loss by computing last.
pub fn dev_fee(total_reward: u64) -> u64 {
    total_reward * DEV_FEE_PERCENT / 100
}

/// Calculate relay pool share from total reward (3%).
/// Remainder goes here to avoid rounding loss.
pub fn relay_pool(total_reward: u64) -> u64 {
    total_reward - miner_reward(total_reward) - dev_fee(total_reward)
}

/// Get seed nodes from environment or use defaults
pub fn get_seed_nodes() -> Vec<String> {
    // Check for TSN_SEEDS environment variable (comma-separated URLs)
    if let Ok(seeds) = std::env::var("TSN_SEEDS") {
        seeds
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        SEED_NODES.iter().map(|s| s.to_string()).collect()
    }
}

/// Get the port from environment or use default
pub fn get_port() -> u16 {
    std::env::var("TSN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Get the data directory from environment or use default
pub fn get_data_dir() -> String {
    std::env::var("TSN_DATA_DIR").unwrap_or_else(|_| "./data".to_string())
}

/// Get mining address from environment (optional)
pub fn get_mining_address() -> Option<String> {
    std::env::var("TSN_MINE_ADDRESS").ok()
}

// ============================================================================
// Assume-Valid Checkpoints
// ============================================================================
//
// Assume-valid allows faster initial sync by skipping ZK proof verification
// for blocks before a known-good checkpoint. The block structure, PoW, and
// state transitions are still fully validated - only the expensive STARK/Groth16
// proof verification is skipped.
//
// This is the same approach used by Bitcoin Core since 0.14.0.
//
// To update: Set ASSUME_VALID_HEIGHT to a recent block height and
// ASSUME_VALID_HASH to that block's hash. Nodes will skip proof verification
// for blocks at or below this height.

/// Height of the assume-valid checkpoint.
/// Blocks at or below this height skip ZK proof verification during sync.
/// Set to 0 to disable assume-valid (verify all proofs).
pub const ASSUME_VALID_HEIGHT: u64 = 0;

/// Block hash at the assume-valid height (hex string).
/// Used to verify we're on the correct chain before trusting the checkpoint.
/// Only relevant when ASSUME_VALID_HEIGHT > 0.
pub const ASSUME_VALID_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Check if assume-valid is enabled.
pub fn is_assume_valid_enabled() -> bool {
    ASSUME_VALID_HEIGHT > 0 && !is_assume_valid_disabled_by_env()
}

/// Check if assume-valid is disabled via environment variable.
/// Set TSN_FULL_VERIFY=1 to force full verification of all proofs.
pub fn is_assume_valid_disabled_by_env() -> bool {
    std::env::var("TSN_FULL_VERIFY")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Get the assume-valid configuration.
pub fn get_assume_valid_config() -> (u64, String) {
    (ASSUME_VALID_HEIGHT, ASSUME_VALID_HASH.to_string())
}

// ============================================================================
// Faucet Configuration
// ============================================================================

/// Daily faucet limit in base units (50 TSN = 50 * 10^9)
pub const FAUCET_DAILY_LIMIT: u64 = 50_000_000_000;

/// Faucet cooldown period in seconds (24 hours)
pub const FAUCET_COOLDOWN_SECONDS: u64 = 86400;

/// Transaction fee for faucet distributions (0.001 TSN)
pub const FAUCET_TX_FEE: u64 = 1_000_000;

/// Balance threshold for low balance warning (1000 TSN)
pub const FAUCET_LOW_BALANCE_THRESHOLD: u64 = 1_000_000_000_000;

/// Token value for game-based faucet (5 TSN per token)
pub const FAUCET_TOKEN_VALUE: u64 = 5_000_000_000;

/// Maximum tokens collectible in faucet game
pub const FAUCET_MAX_TOKENS: u8 = 10;

/// Minimum tokens required to claim from game (at least 1 token)
pub const FAUCET_MIN_TOKENS: u8 = 1;

// ============================================================================
// Checkpoint Finality Configuration
// ============================================================================

/// Checkpoint interval in blocks. Every CHECKPOINT_INTERVAL blocks, the
/// node requests a quorum vote from `TRUSTED_CHECKPOINT_VOTERS`. Only when
/// the quorum agrees on the same hash at that height does the checkpoint
/// finalize. Without a quorum, the candidate height is retried later.
pub const CHECKPOINT_INTERVAL: u64 = 100;

/// v2.8.9 — auto-checkpoint per-node is REPLACED by a peer-consensus vote.
/// `CHECKPOINT_ENABLED = false` keeps the rejection path that refuses
/// rollbacks below a confirmed checkpoint, but the *creation* of a new
/// checkpoint now requires quorum agreement (see TRUSTED_CHECKPOINT_VOTERS
/// / CHECKPOINT_QUORUM and `consensus::checkpoint_vote`).
///
/// Background: prior versions self-checkpointed each node independently at
/// every height % CHECKPOINT_INTERVAL == 0. When two nodes had divergent
/// blocks in the immediate run-up to the checkpoint height (e.g. during a
/// rolling deploy or a network blip), each node finalized its own branch
/// hash at the same height — and from that moment they could never
/// reconcile, because rollback below `last_checkpoint_height` is rejected.
/// On 2026-04-27, node-1 self-checkpointed at h=13800 with a hash that
/// disagreed with the other 4 seeds, and the network split permanently
/// until intervention.
pub const CHECKPOINT_ENABLED: bool = false;

/// v2.8.9 — Trusted voters for the auto-checkpoint quorum. The node polls
/// `block/height/{N}` on each of these endpoints when a candidate
/// checkpoint height is reached. If at least `CHECKPOINT_QUORUM` of them
/// return the same hash that this node has at height N, the checkpoint
/// finalizes and rollbacks below it are rejected.
///
/// This list is the TSN team's controlled infrastructure. As the network
/// matures, future binary releases will ADD entries (community partners,
/// elected miners) gated by `TRUSTED_VOTERS_V2_ACTIVATION_HEIGHT`-style
/// activation switches, not REPLACE the original entries.
pub const TRUSTED_CHECKPOINT_VOTERS: &[&str] = &[
    "http://nexus.tsnchain.com:9333",
    "http://seed1.tsnchain.com:9333",
    "http://seed2.tsnchain.com:9333",
    "http://seed3.tsnchain.com:9333",
    "http://seed4.tsnchain.com:9333",
];

/// v2.9.8 — Quorum threshold expressed as a percentage of the trusted-voter
/// set, so the rule scales naturally when voters are added later. The
/// finalize requirement is `ceil(voters * percent / 100)` voters in agreement.
///
/// Examples for 80%:
///   - 5 voters  -> 4 (5 * 80 / 100 = 4.0 exact)
///   - 7 voters  -> 6 (7 * 80 = 560, ceil(560/100) = 6)
///   - 8 voters  -> 7 (8 * 80 = 640, ceil(640/100) = 7)
///   - 10 voters -> 8 (10 * 80 / 100 = 8.0 exact)
pub const CHECKPOINT_QUORUM_PERCENT: usize = 80;

/// v2.9.8 — Effective quorum threshold for the current voter set.
/// Computed from `TRUSTED_CHECKPOINT_VOTERS.len()` so a future voter-set
/// widening (current 4 seeds + nexus -> + N community relays) auto-adjusts
/// the bar without a separate constant bump and a redeploy. Ceil
/// rounding so 80% of 8 = 7, not 6.
///
/// `TRUSTED_CHECKPOINT_VOTERS.len()` is const-eval since Rust 1.39, so this
/// is itself const and existing `if agree >= CHECKPOINT_QUORUM` call sites
/// (with no parentheses) keep compiling.
pub const CHECKPOINT_QUORUM: usize =
    (TRUSTED_CHECKPOINT_VOTERS.len() * CHECKPOINT_QUORUM_PERCENT + 99) / 100;

/// v2.8.9 — per-voter HTTP timeout when collecting checkpoint votes. Short
/// enough that an unreachable voter does not stall the whole vote, long
/// enough to absorb normal WAN latency.
pub const CHECKPOINT_VOTE_TIMEOUT_SECS: u64 = 8;

/// v2.8.9 — interval between checkpoint vote attempts (background loop).
/// On each tick, if the chain tip has progressed past the next candidate
/// checkpoint height and that height is not yet finalized, a vote round
/// runs. Smaller values converge checkpoints faster after a tip change at
/// a cost of more polling traffic.
pub const CHECKPOINT_VOTE_TICK_SECS: u64 = 15;

/// v2.8.9 — anti-DoS cap on the count of `short_ids` carried in a single
/// `CompactBlock` (`/cmpct_block`). Honest blocks have at most ~200 v2
/// transactions today; 1000 leaves comfortable headroom. Above this cap
/// the receiver drops the envelope without building the mempool index,
/// blocking the "combinatorial bomb" DoS variant of BIP-152.
pub const MAX_COMPACT_SHORT_IDS: usize = 1000;

/// v2.8.9 — anti-DoS rate limit on inbound `/cmpct_block` per source IP.
/// 5 envelopes per 60-second window is roughly 5× the natural block rate
/// and absorbs honest peer retries; sustained load above this from a
/// single IP is rejected with HTTP 429.
pub const COMPACT_BLOCK_RATE_LIMIT: usize = 5;
pub const COMPACT_BLOCK_RATE_WINDOW_SECS: u64 = 60;

/// Maximum reorg depth allowed. Any reorg deeper than this is rejected outright.
/// Inspired by Dilithion's MAX_REORG_DEPTH = 100.
pub const MAX_REORG_DEPTH: u64 = 100;

/// v2.9.13 — when the sync loop fails to apply blocks because of "Reorg too
/// deep" / missing-parent errors this many times in a row, the node assumes
/// its post-fast-sync DB is unrecoverable from the current peer set and
/// triggers an automatic `reset_for_snapshot_resync()` to fast-sync from a
/// fresh snapshot. Without this auto-recovery (v2.9.12 and earlier) the
/// node sat stuck broadcasting tip announcements but accepting no new
/// blocks, requiring manual `/admin/force-resync` intervention.
pub const AUTO_FORCE_RESYNC_THRESHOLD: u64 = 5;

/// Cooldown between auto force-resyncs. A snapshot fetch + import takes
/// ~30 s, and we don't want a spurious failure to retrigger the wipe
/// during that window. Anything above ~120 s is safe.
pub const AUTO_FORCE_RESYNC_COOLDOWN_SECS: u64 = 180;

/// Interval between automatic signed snapshot exports (in blocks).
/// A snapshot is triggered when a new multiple of this interval becomes finalized
/// (i.e. tip >= multiple + MAX_REORG_DEPTH). With 10s blocks, 500 blocks ~ 1.4h,
/// producing roughly 16-20 snapshots per day.
///
/// v2.5.6: reduced from 1000 → 500 after the 2026-04-24 rollback incident. A user
/// who loses coins because the nearest recoverable snapshot is 1000 blocks behind
/// is unacceptable on mainnet; 500 caps the worst-case recovery gap.
pub const SNAPSHOT_MANIFEST_INTERVAL: u64 = 500;

/// Hardcoded checkpoints — blocks that MUST be in the canonical chain.
/// Any chain that doesn't include these exact hashes at these heights is rejected.
/// This prevents fork chains (e.g. mined from genesis at low difficulty) from
/// overtaking the legitimate chain via cumulative_work.
/// Format: (height, block_hash_hex)
///
/// NOTE: Dynamic checkpoints (every CHECKPOINT_INTERVAL blocks) are computed
/// automatically at startup from the existing chain and updated as new blocks
/// arrive. They persist across restarts. Hardcoded checkpoints are only needed
/// for bootstrap protection on a brand-new node with no chain data.
///
/// v1.5.0: Populated from the canonical chain on 2 April 2026.
/// Any node whose chain doesn't match these hashes at these heights will
/// be forced to re-sync from peers at startup.
/// v2.0.9: Checkpoints for the new chain (genesis reset April 11, 2026).
/// These protect against alternative chain attacks and speed up initial sync.
// v2.0.9: Checkpoints cleared after genesis reset (commitment_root fix).
// Will be re-added once the chain stabilizes with 100+ blocks.
// Genesis hash is verified separately via EXPECTED_GENESIS_HASH.
pub const HARDCODED_CHECKPOINTS: &[(u64, &str)] = &[];

// ============================================================================
// Genesis Verification
// ============================================================================

/// Expected genesis block hash (hex). All nodes MUST produce this exact genesis.
/// If a node's genesis hash differs, it means incompatible parameters and the node
/// must not start. This prevents silent chain forks from misconfigured genesis.
///
/// Set to empty string to disable verification (first launch / testnet reset).
/// Reset after PoW refactor to numeric difficulty + 64-byte nonce.
/// Updated for v1.0.0: matches genesis produced by all live nodes.
/// Previous value (42b5af19...) was from dev environment with different parameters.
/// Genesis hash — all nodes MUST produce this exact genesis to join the network.
/// v2.0.0: New genesis for testnet-v2 reset (Poseidon2 from height 0, open network).
/// Previous values: "8b6f36..." (v0.7.1), "42b5af..." (dev)
/// v2.1.6: New genesis for testnet-v3 reset (clean restart April 15, 2026).
/// Previous value: "9055172503147d90..." (testnet-v2)
/// v2.2.0: New genesis for testnet-v4 reset (wallet rewrite, April 16, 2026).
/// Previous value: "" (testnet-v3, unlocked)
/// v2.3.5: New genesis for testnet-v5 reset (chain fork recovery, April 19, 2026).
/// v2.6.0: New genesis for testnet-v12 reset (April 24, 2026 — clean restart after
/// a day of cascading forks from stuck rollback-guard nodes).
/// Previous value (testnet-v11): "d387692f5be4c655b79cd8c14e9cd6d83957805c056166de4e68e12db41e3aaf"
/// v2.9.19: Pinned testnet-v12 genesis after 8 days of network operation.
/// Confirmed identical on seed-1, seed-2, node-1 at block height 0.
/// Without this pin, nodes booting fresh would have NO check that they
/// joined the canonical chain — community nodes could fast-sync from a
/// fork and never realize it. The mismatch is now caught at startup
/// AND in the version_gate_middleware (X-TSN-Genesis header check).
pub const EXPECTED_GENESIS_HASH: &str =
    "007870623724127ccf467b74041c3fed0e3569f02c66414a3018d7c04856e38d";
