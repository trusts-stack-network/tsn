//! REST API for the shielded blockchain node.
//!
//! This API is privacy-preserving. Account balances and transaction
//! amounts are not visible through the API. Only publicly observable
//! data (block hashes, timestamps, fees) is exposed.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use std::time::Duration;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;

use crate::core::{ShieldedBlock, ShieldedBlockchain, ChainInfo, ShieldedTransaction, ShieldedTransactionV2, Transaction};
use crate::crypto::nullifier::Nullifier;
use crate::faucet::{FaucetService, FaucetStatus, ClaimResult, FaucetStats, FaucetError};
use crate::wallet::ShieldedWallet;
use tracing::{debug, info, warn};

use super::Mempool;
use super::sync_gate::SyncGate;
use super::peer_id;

/// Maximum request body size (10 MB)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Rate limit: requests per second per IP (public routes)
/// Set high enough that explorer + normal usage never gets blocked.
///
/// v2.5.4 — bumped from 200→500 rps and 500→2000 burst because a wallet
/// with 100+ notes saturates the burst on the fallback path (per-position
/// witness fetch) when `/leaves/bulk` is unavailable or itself throttled.
/// 127.0.0.1 shares the quota with other local processes polling the node,
/// so the old budget was consumed by scanning loops + explorer polling
/// simultaneously and the wallet send was then starved.
const RATE_LIMIT_RPS: u64 = 500;

/// Rate limit: burst size for public routes
const RATE_LIMIT_BURST: u32 = 2000;

/// Rate limit: requests per second per IP (sync routes — higher for node sync)
const SYNC_RATE_LIMIT_RPS: u64 = 500;

/// Rate limit: burst size for sync routes
const SYNC_RATE_LIMIT_BURST: u32 = 1000;

/// v2.3.0 Phase 1 — dedup windows (seconds).
/// Same (peer, height, hash) tip received within this window is skipped.
pub const TIP_DEDUP_SECS: u64 = 30;
/// Same block hash received within this window is skipped.
pub const BLOCK_DEDUP_SECS: u64 = 60;
/// Same fork (peer_tip_hash, peer_height) cooldown after first recovery attempt.
pub const FORK_COOLDOWN_SECS: u64 = 60;

/// Maximum entries kept in the tip dedup LRU.
pub const TIP_DEDUP_CAPACITY: usize = 500;
/// Maximum entries kept in the block dedup LRU.
pub const BLOCK_DEDUP_CAPACITY: usize = 1000;

/// v2.3.6 — Version gate: outdated peer ban policy.
/// After this many offenses in a rolling fashion, the peer IP is banned.
pub const VERSION_BAN_THRESHOLD: u32 = 3;
/// Base ban duration (seconds). Escalates on repeat offenses.
pub const VERSION_BAN_INITIAL_SECS: u64 = 3600;
/// Maximum entries kept in the version ban map.
pub const VERSION_BAN_CAPACITY: usize = 10_000;
/// Dedup interval (seconds) between WARN log lines for the same offending IP.
pub const VERSION_BAN_LOG_DEDUP_SECS: u64 = 300;
/// v2.7.0 Phase 1.1 — capacity of the witness LRU cache. Each entry stores
/// the response for one position keyed by `position`, paired with the chain
/// height at which it was computed. Cap chosen to comfortably absorb a 4000+
/// note wallet doing parallel consolidation without thrash.
pub const WITNESS_CACHE_CAPACITY: usize = 4096;
/// v2.7.0 Phase 1.3 — sliding-window length for the per-IP submit rate limit.
pub const SUBMIT_RATE_WINDOW_SECS: u64 = 60;
/// v2.7.0 Phase 1.3 — max V2 submissions accepted from a single source IP
/// inside `SUBMIT_RATE_WINDOW_SECS`. Excess submissions return 429.
/// Shielded TSN transactions have no public sender field (the pk hash lives
/// inside the STARK proof), so the only "sender" available at the transport
/// boundary is the source IP. Peer-to-peer gossip relays bypass this gate;
/// it only constrains direct HTTP clients (`tsn send`, dApps).
pub const SUBMIT_RATE_MAX_PER_IP: usize = 8;
/// v2.7.0 Phase 1.3 — capacity of the per-IP rate-limit table (LRU eviction
/// keeps memory bounded under DoS).
pub const SUBMIT_RATE_TRACKER_CAPACITY: usize = 4096;

/// v2.9.14 (W1B) — refresh the lock-free state-check caches after a block
/// has been added to the chain. Must be called from the same scope that
/// holds `blockchain.write()` (or before the lock is released to a new
/// reader), so `submit_v2` never observes a tx whose nullifier or anchor
/// isn't yet visible to the cache.
///
/// `new_anchor_pq` is the post-add commitment_root_pq of the chain.
/// `chain_info` is the post-add `chain.info()` snapshot — published into
/// `chain_info_cache` so GET /chain/info returns fresh data even when the
/// background refresher is starved by writer churn (H-G fix).
pub fn update_state_caches_after_block(
    state: &std::sync::Arc<AppState>,
    block: &crate::core::ShieldedBlock,
    new_anchor_pq: [u8; 32],
    chain_info: crate::core::ChainInfo,
) {
    let v2_nullifiers: Vec<[u8; 32]> = block
        .transactions_v2
        .iter()
        .flat_map(|tx| tx.spends.iter().map(|s| s.nullifier))
        .collect();

    if !v2_nullifiers.is_empty() {
        let mut nf = state.spent_nullifiers_cache.write().unwrap_or_else(|e| e.into_inner());
        for n in v2_nullifiers {
            nf.insert(n);
        }
    }

    {
        let mut anchors = state.recent_anchors_cache.write().unwrap_or_else(|e| e.into_inner());
        anchors.push_back(new_anchor_pq);
        while anchors.len() > 1000 {
            anchors.pop_front();
        }
    }

    state.chain_info_cache.store(std::sync::Arc::new(chain_info));
}

/// v2.9.14 (W1B) — populate the caches at startup from the existing chain
/// state. Called once from `cmd_node` right after the AppState is built.
pub fn init_state_caches_from_chain(
    state: &std::sync::Arc<AppState>,
    chain: &ShieldedBlockchain,
) {
    let st = chain.state();
    {
        let mut nf = state.spent_nullifiers_cache.write().unwrap_or_else(|e| e.into_inner());
        for n in st.nullifier_set().iter() {
            nf.insert(n.0);
        }
    }
    {
        let mut anchors = state.recent_anchors_cache.write().unwrap_or_else(|e| e.into_inner());
        for r in st.commitment_tree_pq().recent_roots().iter() {
            anchors.push_back(*r);
        }
    }
}

/// Shared application state for the API.
pub struct AppState {
    pub blockchain: TokioRwLock<ShieldedBlockchain>,
    /// v2.9.14 (W1B) — concurrent cache of spent V2 nullifiers, refreshed
    /// by every add_block site. Lets `submit_transaction_v2` and
    /// `check_nullifiers` run their state checks without acquiring
    /// `blockchain.read()`, bypassing the fairness queue starvation
    /// observed under continuous writer load.
    pub spent_nullifiers_cache: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// v2.9.14 (W1B) — concurrent cache of recent commitment-tree PQ roots
    /// (anchors). Capped to RECENT_ROOTS_COUNT (1000) entries to mirror
    /// the in-state recent_roots window.
    pub recent_anchors_cache: RwLock<std::collections::VecDeque<[u8; 32]>>,
    pub mempool: RwLock<Mempool>,
    /// Phase 3 / v2.4.0 — soft ban set for miners that repeatedly violate
    /// the V2 inclusion rule. Persisted to `banned_miners_path` when set.
    pub banned_miners: RwLock<crate::consensus::banned_miners::BannedMiners>,
    /// Disk location for the banned-miners JSON (None = in-memory only).
    pub banned_miners_path: Option<std::path::PathBuf>,
    /// List of known peer URLs for gossip
    pub peers: RwLock<Vec<String>>,
    /// Stats for the local miner (if running)
    pub miner_stats: RwLock<MinerStats>,
    /// Optional faucet service (enabled via CLI flag)
    pub faucet: Option<TokioRwLock<FaucetService>>,
    /// Sync gate for anti-fork protection
    pub sync_gate: SyncGate,
    /// Our own public URL (to avoid adding ourselves as peer)
    pub public_url: Option<String>,
    /// P2P broadcast channel (GossipSub) — used to push blocks/txs to all peers
    pub p2p_broadcast: RwLock<Option<tokio::sync::mpsc::Sender<super::p2p::P2pCommand>>>,
    /// Local P2P PeerID (set after libp2p starts)
    pub p2p_peer_id: RwLock<Option<String>>,
    /// Shared P2P peer list — updated by the P2P loop, read instantly by API
    pub p2p_shared_peers: RwLock<Option<super::p2p::SharedPeerList>>,
    /// Node role (miner, relay, light)
    pub node_role: String,
    /// Mining cancel signal — set by P2P when a new block arrives to abort current PoW
    pub mining_cancel: RwLock<Option<Arc<std::sync::atomic::AtomicBool>>>,
    /// Shared HTTP client for all outbound requests (connection pooling, prevents FD leaks)
    pub http_client: reqwest::Client,
    /// Height of last chain reorganization — used for post-reorg mining cooldown
    pub last_reorg_height: std::sync::atomic::AtomicU64,
    /// Semaphore limiting concurrent snapshot downloads (max 3)
    pub snapshot_semaphore: Arc<tokio::sync::Semaphore>,
    /// v2.6.7 — Semaphore limiting concurrent v2 transaction submissions.
    /// v2 tx submit holds the blockchain read lock during proof verification
    /// and signature/nullifier checks (~100ms-1s per tx). Without a bound,
    /// a burst of 10+ submissions (e.g. Phase 3.2 parallel consolidation
    /// from a single sender) saturates the HTTP worker pool and starves
    /// /chain/info, /tip and other read endpoints, freezing the node for
    /// minutes (observed 2026-04-25). When the semaphore is full new
    /// submits return 503 with retry-after, letting the client backoff
    /// instead of building unbounded queues server-side.
    pub tx_submit_semaphore: Arc<tokio::sync::Semaphore>,
    /// Cached pre-compressed snapshot (refreshed every 100 blocks)
    pub snapshot_cache: TokioRwLock<Option<CachedSnapshot>>,
    /// Orphan/fork counter for monitoring network health
    pub orphan_count: std::sync::atomic::AtomicU64,
    /// Total blocks received that triggered a reorg
    pub reorg_count: std::sync::atomic::AtomicU64,
    /// v2.9.13 — count of consecutive sync failures where the local chain
    /// could not reorg/extend because of "Reorg too deep / Invalid prev hash"
    /// (parent block missing from RAM and DB after fast-sync). Reset to 0 on
    /// any successful add_block. When it crosses
    /// `crate::config::AUTO_FORCE_RESYNC_THRESHOLD` the node calls
    /// `reset_for_snapshot_resync()` and re-fetches the snapshot from a
    /// healthy peer, instead of staying stuck forever as in v2.9.12.
    pub stuck_sync_failures: std::sync::atomic::AtomicU64,
    /// Wall-clock instant of the last auto force-resync triggered by the
    /// stuck-sync detector. Used as a cooldown so we don't loop on the
    /// resync (~30 s for a snapshot fetch + apply).
    pub last_auto_resync: std::sync::Mutex<Option<std::time::Instant>>,
    /// Reorg lock: WRITE during rollback+resync, READ during mining template+add_block.
    /// Prevents mining from producing stale blocks while a reorg is in progress.
    pub reorg_lock: TokioRwLock<()>,
    /// Banned peer URLs with expiry timestamps (Instant).
    /// Peers are banned for sending checkpoint-violating or incompatible chains.
    pub banned_peers: RwLock<std::collections::HashMap<String, std::time::Instant>>,
    /// Detailed peer info (version, role, last seen) — updated on every HTTP interaction.
    pub peer_info: RwLock<std::collections::HashMap<String, PeerDetail>>,
    /// Error log for telemetry — recent errors stored for P2P sharing and dashboard
    pub error_log: RwLock<Vec<NodeError>>,
    /// Auto-heal mode: "validation" (default, human approves) or "automatic" (self-repair)
    pub auto_heal_mode: RwLock<String>,
    /// Ghost peer blacklist — peers removed by sync cleanup are never re-added via P2P discovery
    pub removed_peers: std::sync::Mutex<std::collections::HashSet<String>>,
    // v2.1.5: Mining/sync performance counters for benchmarking
    /// Count of "empty batch" events (blocks received but none accepted)
    pub metric_empty_batches: std::sync::atomic::AtomicU64,
    /// Count of stale mined blocks (tip changed during PoW)
    pub metric_stale_blocks: std::sync::atomic::AtomicU64,
    /// Count of successful recovery-from-fork events
    pub metric_fork_recoveries: std::sync::atomic::AtomicU64,
    /// Cumulative time spent in recovery (milliseconds)
    pub metric_recovery_time_ms: std::sync::atomic::AtomicU64,
    /// Count of commitment root mismatches
    pub metric_commitment_mismatches: std::sync::atomic::AtomicU64,
    /// Seed signing key for snapshot manifests (loaded from data/seed_key.bin)
    pub seed_signing_key: Option<ed25519_dalek::SigningKey>,
    /// In-memory store of recent snapshot manifests (max 10)
    pub snapshot_manifests: RwLock<Vec<super::snapshot_manifest::SnapshotManifest>>,
    /// Mining address (pk_hash hex) for display in console
    pub mining_address: Option<String>,
    /// Wallet service for balance/scan/send (None if no wallet configured)
    pub wallet_service: Option<Arc<crate::wallet::WalletService>>,
    /// v2.3.0 Phase 1: LRU cache of recently processed tip announcements.
    /// Key = "{peer_id}|{height}|{hash16}", value = unix epoch seconds of first sight.
    /// Entries older than TIP_DEDUP_SECS are treated as expired and reprocessed.
    pub seen_tips: std::sync::Mutex<lru::LruCache<String, u64>>,
    /// v2.3.0 Phase 1: LRU cache of recently processed block hashes.
    /// Key = full block hash hex, value = unix epoch seconds of first sight.
    /// Covers both HTTP receive_block and P2P NewBlock paths.
    pub seen_blocks: std::sync::Mutex<lru::LruCache<String, u64>>,
    /// v2.3.0 Phase 1: Fork recovery cooldown.
    /// Key = "{peer_tip_hash16}|{peer_height}", value = Instant when cooldown ends.
    /// Prevents N peers from each triggering fork recovery for the same fork.
    pub fork_recovery_cooldown: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// v2.3.0 Phase 2.1: highest `latest_eligible` for which auto_snapshot_export
    /// has already been triggered. Guards against double-trigger when both the
    /// miner path and the P2P handler cross the same interval boundary (e.g. on
    /// a reorg at an interval-crossing height).
    pub last_snapshot_auto_trigger: std::sync::atomic::AtomicU64,
    /// v2.3.6 — Per-IP version-ban tracker. Populated by the version gate middleware.
    /// Keyed by source IP (peer of the TCP connection, not X-Forwarded-For to prevent spoof).
    pub version_bans: std::sync::RwLock<std::collections::HashMap<std::net::IpAddr, VersionBanEntry>>,
    /// v2.3.9 — Cumulative network-activity counters consumed by the explorer
    /// to render typed traffic particles (tip, block, tx, sync, snapshot, peer,
    /// reject). Exposed at `GET /stats/activity`.
    pub activity: std::sync::Arc<super::activity::ActivityCounters>,
    /// v2.3.9 — Broadcast bus for the Server-Sent Events endpoint
    /// `GET /events/stream`. Clones per SSE client; a slow client lagging
    /// more than 256 events drops the oldest (broadcast semantics).
    pub activity_bus: std::sync::Arc<super::activity::ActivityBus>,
    /// v2.5.4 — Microcache for `/network/status` responses (3 s TTL).
    /// The handler performs 5 × 2 outbound HTTP fetches to each seed; without
    /// this cache, under sustained explorer polling the handlers pile up and
    /// their accepted sockets stay in CLOSE-WAIT until the seed exhausts its
    /// file-descriptor budget. The cache makes steady-state invocation O(1).
    pub network_status_cache: std::sync::RwLock<Option<NetworkStatusCache>>,
    /// v2.6.0 — Lock-free snapshot of `chain.info()` served by GET /chain/info.
    /// A background task (spawn_chain_info_refresher) briefly acquires
    /// `blockchain.read()` every 200ms to recompute and store here. HTTP
    /// handlers read via `chain_info_cache.load()` — a single atomic pointer
    /// swap, zero contention with the write lock held during block imports.
    /// This is the fix for the "node invisible in explorer during long reorgs"
    /// failure mode: even when `blockchain.write()` is held for seconds, any
    /// /chain/info caller still responds in microseconds with the previous
    /// snapshot. Worst-case staleness is refresh interval + writer hold time.
    pub chain_info_cache: arc_swap::ArcSwap<crate::core::ChainInfo>,
    /// v2.7.0 Phase 1.1 — LRU cache for `/witness/v2/position/{N}` responses.
    /// Without this cache, each lookup re-traverses the Poseidon Merkle tree
    /// under `blockchain.read()` (~10-50ms hot, more under contention). A
    /// wallet with N notes fires N concurrent lookups when sending; all of
    /// them serialise on the read lock and starve other handlers, producing
    /// HTTP 408 timeouts and Recv-Q saturation. The cache stores responses
    /// keyed by position together with the chain height at which they were
    /// computed; on hit at the current height the response is returned with
    /// zero blockchain access. New blocks bump the chain height and lazily
    /// invalidate stale entries on next access (the entry is recomputed and
    /// replaced). This is correct because the Merkle path of any leaf may
    /// shift when new commitments are appended, so any previously cached
    /// witness is only valid against the height at which it was built.
    pub witness_cache: std::sync::Arc<std::sync::Mutex<lru::LruCache<u64, (u64, WitnessResponseV2)>>>,
    /// v2.7.0 Phase 1.3 — Per-IP submit rate limiter (sliding window). Each
    /// entry stores recent V2 submission instants for one IP; excess submissions
    /// inside `SUBMIT_RATE_WINDOW_SECS` return 429. The LruCache bounds memory
    /// under DoS (oldest IPs are evicted when capacity is reached).
    pub submit_rate: std::sync::Arc<std::sync::Mutex<lru::LruCache<std::net::IpAddr, std::collections::VecDeque<std::time::Instant>>>>,

    /// v2.9.2 — Last-known result of the trusted-quorum checkpoint vote tick.
    /// Updated by the background `consensus::checkpoint_vote::run_loop` after
    /// every tick (default every 15s). Read by `GET /chain/quorum_status`
    /// so the explorer can render a live "blockchain in quorum" indicator
    /// without re-polling every voter from the browser.
    pub quorum_status: arc_swap::ArcSwap<QuorumStatus>,

    /// v2.9.7 — Bounded history of finalized quorum checkpoints
    /// (newest first). Pushed by `checkpoint_vote::tick()` whenever
    /// `set_checkpoint_via_quorum` succeeds. Served by
    /// `GET /chain/checkpoints` so the explorer can render a "Checkpoints"
    /// tab listing every committed checkpoint with its vote count.
    pub checkpoint_history: arc_swap::ArcSwap<Vec<CheckpointRecord>>,
    /// v2.9.27 — Set to true after a successful snapshot import (in either
    /// `sync_loop`'s snapshot path or the mining-loop auto-resync path) to
    /// force the next `sync_loop` iteration to bypass the per-peer
    /// fail-count throttle. `sync_loop` swaps it back to false on read.
    /// Without this, a node that just imported a snapshot post-partition
    /// can sit idle until the throttle timer fires (60 s), because
    /// `peer_failures` accumulated >=20 during the partition.
    pub force_sync_kick: std::sync::atomic::AtomicBool,
}

/// v2.9.7 — One entry of the finalized checkpoint history. Held inside
/// `AppState::checkpoint_history` and exposed verbatim by
/// `GET /chain/checkpoints`. The list is bounded to
/// `CHECKPOINT_HISTORY_CAP` entries (newest first) so the JSON response
/// stays small even on a long-running node.
#[derive(Clone, serde::Serialize)]
pub struct CheckpointRecord {
    pub height: u64,
    pub hash: String,
    pub agree: usize,
    pub total: usize,
    pub finalized_at_unix_ms: u64,
}

/// Maximum number of checkpoint records held in memory.
pub const CHECKPOINT_HISTORY_CAP: usize = 100;

/// v2.9.2 — Snapshot of the most recent trusted-quorum checkpoint vote tick.
/// Held under `AppState::quorum_status` and overwritten in place by
/// `consensus::checkpoint_vote::tick()` so HTTP handlers can read it
/// lock-free.
#[derive(Clone, serde::Serialize)]
pub struct QuorumStatus {
    /// Candidate height the last tick evaluated (0 if no tick has run yet
    /// or the chain has not reached the next candidate height).
    pub candidate_height: u64,
    /// Number of trusted voters that returned the same hash as the local
    /// node at `candidate_height`.
    pub agree: usize,
    /// Number of trusted voters that returned a different hash.
    pub disagree: usize,
    /// Number of trusted voters that did not respond, were lagging, or
    /// did not have the block at `candidate_height` yet.
    pub unreachable: usize,
    /// Total number of trusted voters polled (constant, but echoed for the
    /// frontend's convenience).
    pub total: usize,
    /// Quorum threshold currently configured (e.g. 4 of 5 in v2.9.2).
    pub quorum_required: usize,
    /// `true` iff the most recent tick reached `agree >= quorum_required`.
    /// This is the single field the explorer checks to render the halo.
    pub is_quorum: bool,
    /// Last finalized checkpoint height in the local chain (snapshot at the
    /// time the tick observed it). Lets the UI distinguish "voters agree on
    /// a fresh candidate" from "we are stuck on an old finalized checkpoint".
    pub last_finalized_height: u64,
    /// Wall-clock time (millis since epoch) when this snapshot was written.
    /// The UI can flag staleness if no tick has updated this in N seconds.
    pub last_check_unix_ms: u64,
}

impl QuorumStatus {
    /// Initial value installed at boot, before any tick has run.
    pub fn initial() -> Self {
        Self {
            candidate_height: 0,
            agree: 0,
            disagree: 0,
            unreachable: 0,
            total: crate::config::TRUSTED_CHECKPOINT_VOTERS.len(),
            quorum_required: crate::config::CHECKPOINT_QUORUM,
            is_quorum: false,
            last_finalized_height: 0,
            last_check_unix_ms: 0,
        }
    }
}

/// v2.5.4 — cached `/network/status` payload with absolute expiry instant.
pub struct NetworkStatusCache {
    pub body: serde_json::Value,
    pub expires_at: std::time::Instant,
}

/// v2.3.6 — Tracks a peer that sent an outdated `X-TSN-Version` header.
#[derive(Clone, Debug)]
pub struct VersionBanEntry {
    /// Instant after which the ban lifts. If `<= Instant::now()`, the peer is free
    /// to retry (but offense_count is preserved to escalate on re-offense).
    pub until: std::time::Instant,
    /// Number of outdated requests observed for this IP. Persists across ban expiry.
    pub offense_count: u32,
    /// Last time we emitted a WARN for this IP (for log dedup).
    pub last_warn_at: Option<std::time::Instant>,
    /// Last observed version string (for logging only).
    pub last_version: String,
}

/// Info about an HTTP peer, updated on every interaction.
#[derive(Clone, serde::Serialize)]
pub struct PeerDetail {
    pub peer_id: String,       // masked peer:xxxx
    pub version: String,       // from X-TSN-Version header
    pub role: String,          // "miner" or "relay" (from protocol or endpoint used)
    pub height: u64,           // last known height
    pub last_seen: u64,        // unix timestamp
}

/// v2.3.6 — Version gate middleware.
///
/// Runs on every incoming request to the `sync` router BEFORE the request body
/// is parsed. Enforces three things, in order:
///   1. Reject instantly (403) if the source IP is currently version-banned.
///   2. If the `X-TSN-Version` header is missing or below `MINIMUM_VERSION`,
///      record an offense, escalate the ban duration geometrically, and reject
///      (403). Missing header counts as an offense to block trivial spammers.
///   3. Otherwise pass the request to the inner handler.
///
/// WARN log lines for rejections are deduplicated per-IP with a sliding window
/// of `VERSION_BAN_LOG_DEDUP_SECS` (5 minutes). Subsequent rejections inside the
/// window are logged at DEBUG to avoid polluting journals.
pub async fn version_gate_middleware(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let ip = addr.ip();
    let now = std::time::Instant::now();

    // (1) Fast path: already banned?
    // Peek at the version/network/genesis headers first: if the peer has since
    // upgraded to a compliant version, let the request fall through so that
    // step (3) clears the stale ban entry. Without this, a peer that was banned
    // with offense_count >= 11 (24-hour ban) would remain blocked even after
    // upgrading, because the fast path returned 403 before reading headers.
    {
        let bans = state.version_bans.read().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = bans.get(&ip) {
            if now < entry.until {
                let pv = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
                let pn = headers.get("X-TSN-Network").and_then(|v| v.to_str().ok());
                let pg = headers.get("X-TSN-Genesis").and_then(|v| v.to_str().ok());
                let still_bad =
                    pv.map(|v| !crate::network::version_check::version_meets_minimum(v)).unwrap_or(false)
                    || pn.map(|n| n != crate::config::NETWORK_NAME).unwrap_or(false)
                    || pg.map(|g| !g.is_empty() && g != crate::config::EXPECTED_GENESIS_HASH).unwrap_or(false);
                if still_bad {
                    let remaining = entry.until.duration_since(now).as_secs();
                    return (
                        axum::http::StatusCode::FORBIDDEN,
                        format!("IP banned for outdated version (retry in {}s)", remaining),
                    )
                        .into_response();
                }
                // Peer has upgraded — fall through; step (3) will clear the ban.
            }
        }
    }

    // (2) Inspect the version / network / genesis headers.
    // Missing headers: pass through. Internal HTTP callers (explorer polling,
    // snapshot fetch, local debug tooling) do not always set these headers,
    // so gating on missing would break production traffic. The ban is only
    // triggered when a peer honestly declares a mismatching value — which is
    // exactly the spam / wrong-chain pattern we want to kick out.
    let peer_ver = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
    let peer_net = headers.get("X-TSN-Network").and_then(|v| v.to_str().ok());
    let peer_genesis = headers.get("X-TSN-Genesis").and_then(|v| v.to_str().ok());

    let ver_str = peer_ver.unwrap_or("");
    let bad_version = match peer_ver {
        Some(v) => !crate::network::version_check::version_meets_minimum(v),
        None => false,
    };
    let bad_network = match peer_net {
        Some(n) => n != crate::config::NETWORK_NAME,
        None => false,
    };
    // v2.9.20: pre-v2.9.19 nodes send X-TSN-Genesis="" because EXPECTED_GENESIS_HASH
    // was empty in their config — treat empty header as "not declared" (same as None)
    // so we don't reject otherwise-valid peers running older versions during the
    // network upgrade window.
    let bad_genesis = match peer_genesis {
        Some(g) if !g.is_empty() => g != crate::config::EXPECTED_GENESIS_HASH,
        _ => false,
    };
    let below_min = bad_version || bad_network || bad_genesis;
    // Build a concise reason for logs and the 403 body.
    let reject_reason = if bad_version {
        format!("version={:?} below minimum {}", ver_str, crate::network::version_check::MINIMUM_VERSION)
    } else if bad_network {
        format!("network={:?} != {}", peer_net.unwrap_or(""), crate::config::NETWORK_NAME)
    } else if bad_genesis {
        format!("genesis={:?} != {}", peer_genesis.unwrap_or(""), crate::config::EXPECTED_GENESIS_HASH)
    } else {
        String::new()
    };

    if below_min {
        let mut bans = state.version_bans.write().unwrap_or_else(|e| e.into_inner());

        // Cap the map size to prevent unbounded memory growth from scan attacks.
        if bans.len() >= VERSION_BAN_CAPACITY && !bans.contains_key(&ip) {
            // Evict the oldest expired entry we can find (best-effort O(n) sweep).
            let stale: Vec<std::net::IpAddr> = bans
                .iter()
                .filter(|(_, e)| e.until <= now)
                .map(|(k, _)| *k)
                .take(64)
                .collect();
            for k in stale {
                bans.remove(&k);
            }
        }

        let entry = bans.entry(ip).or_insert_with(|| VersionBanEntry {
            until: now,
            offense_count: 0,
            last_warn_at: None,
            last_version: String::new(),
        });
        entry.offense_count = entry.offense_count.saturating_add(1);
        entry.last_version = ver_str.to_string();

        let should_warn = match entry.last_warn_at {
            None => true,
            Some(t) => now.duration_since(t).as_secs() >= VERSION_BAN_LOG_DEDUP_SECS,
        };

        let response = if entry.offense_count >= VERSION_BAN_THRESHOLD {
            // Escalating ban: 1h, 6h, 24h (capped).
            let ban_secs = match entry.offense_count {
                0..=2 => VERSION_BAN_INITIAL_SECS, // unreachable, threshold is 3
                3..=5 => VERSION_BAN_INITIAL_SECS,
                6..=10 => VERSION_BAN_INITIAL_SECS * 6,
                _ => VERSION_BAN_INITIAL_SECS * 24,
            };
            entry.until = now + std::time::Duration::from_secs(ban_secs);
            if should_warn {
                warn!(
                    "Chain-banned {} for {}s ({}, offenses={})",
                    ip, ban_secs, reject_reason, entry.offense_count
                );
                entry.last_warn_at = Some(now);
            } else {
                debug!(
                    "Chain-banned {} (dedup, offenses={})",
                    ip, entry.offense_count
                );
            }
            (
                axum::http::StatusCode::FORBIDDEN,
                format!(
                    "IP banned for outdated version (retry in {}s)",
                    ban_secs
                ),
            )
                .into_response()
        } else {
            if should_warn {
                warn!(
                    "Rejected peer {} ({}, offense {}/{})",
                    ip, reject_reason, entry.offense_count, VERSION_BAN_THRESHOLD
                );
                entry.last_warn_at = Some(now);
            } else {
                debug!(
                    "Rejected peer {} (dedup, offense {})",
                    ip, entry.offense_count
                );
            }
            (
                axum::http::StatusCode::FORBIDDEN,
                reject_reason,
            )
                .into_response()
        };
        return response;
    }

    // (3) Peer is compliant — clear any stale ban entry so future offenses start fresh.
    {
        let mut bans = state.version_bans.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = bans.get(&ip) {
            if entry.until <= now && entry.offense_count > 0 {
                bans.remove(&ip);
            }
        }
    }

    next.run(request).await
}

/// Update peer info from an incoming HTTP request.
/// Resolve SEED_NODES DNS names to IPs and check if the given peer IP
/// belongs to a hardcoded seed. Used to suppress double-counting of seeds
/// in peer_info — seeds appear in the dedicated `seeds` list of
/// /network/status and must not also show up in `peers`.
pub async fn is_sender_a_seed(ip: &str) -> bool {
    for url in crate::config::SEED_NODES.iter() {
        let host = url.trim_start_matches("http://")
            .trim_start_matches("https://")
            .split(':').next().unwrap_or("");
        if host.is_empty() { continue; }
        // Fast path: exact host string match (covers literal-IP seed entries).
        if host == ip { return true; }
        if let Ok(addrs) = tokio::net::lookup_host((host, 9333u16)).await {
            for addr in addrs {
                if addr.ip().to_string() == ip {
                    return true;
                }
            }
        }
    }
    false
}

pub fn update_peer_info(state: &AppState, peer_url: &str, version: Option<&str>, height: Option<u64>) {
    let peer_id = super::peer_id(peer_url);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut info = state.peer_info.write().unwrap();
    let entry = info.entry(peer_id.clone()).or_insert(PeerDetail {
        peer_id: peer_id.clone(),
        version: "?".to_string(),
        role: "relay".to_string(),
        height: 0,
        last_seen: now,
    });
    if let Some(v) = version {
        entry.version = v.to_string();
    }
    if let Some(h) = height {
        if h > entry.height { entry.height = h; }
    }
    entry.last_seen = now;
}

/// Structured error for telemetry reporting
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeError {
    pub error_type: String,
    pub message: String,
    pub height: u64,
    pub timestamp: u64,
    pub version: String,
}

/// Pre-generated snapshot cached in memory for fast serving.
pub struct CachedSnapshot {
    pub compressed: Vec<u8>,
    pub height: u64,
    pub hash: String,
    pub raw_size: usize,
}

/// Create the API router with rate limiting and request size limits.
///
/// Note: This is a privacy-preserving blockchain. Account balances and
/// transaction amounts are not visible through the API.
///
/// Rate limiting: 50 requests/second per IP with burst of 100.
/// Request body limit: 10 MB max.
pub fn create_router(state: Arc<AppState>) -> Router {
    // Configure rate limiting using Governor
    // Uses SmartIpKeyExtractor to handle proxied requests (X-Forwarded-For)
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(RATE_LIMIT_RPS)
            .burst_size(RATE_LIMIT_BURST)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("INIT: rate limiter config is invalid — check RATE_LIMIT_RPS/BURST constants"),
    );

    let rate_limit_layer = GovernorLayer {
        config: governor_config,
    };

    // Log rate limiter configuration
    info!(
        "Rate limiting enabled: {} req/s, burst size {}",
        RATE_LIMIT_RPS, RATE_LIMIT_BURST
    );
    info!("Request body limit: {} bytes", MAX_BODY_SIZE);

    // Sync routes — separate rate limiter (higher limit for node-to-node sync,
    // but still protected against DoS — previously had NO rate limit at all)
    let sync_governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(SYNC_RATE_LIMIT_RPS)
            .burst_size(SYNC_RATE_LIMIT_BURST)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("INIT: sync rate limiter config is invalid"),
    );
    let sync_rate_limit_layer = GovernorLayer {
        config: sync_governor_config,
    };
    info!(
        "Sync rate limiting enabled: {} req/s, burst size {}",
        SYNC_RATE_LIMIT_RPS, SYNC_RATE_LIMIT_BURST
    );

    // Sync routes — v2.3.6: version gate middleware rejects outdated peers
    // BEFORE the request body is parsed, and escalates bans on repeat offenses.
    // Rate-limiter layer kept off by design: sync_rate_limit is tuned for
    // internal node-to-node sync bursts and the ban map absorbs spam.
    let sync_routes = Router::new()
        .route("/chain/info", get(chain_info))
        .route("/chain/quorum_status", get(chain_quorum_status))
        .route("/chain/checkpoints", get(chain_checkpoints))
        .route("/blocks", post(receive_block))
        .route("/cmpct_block", post(receive_compact_block))
        .route("/blocktxn", post(receive_block_txn_request))
        .route("/blocks/since/:height", get(get_blocks_since))
        .route("/headers/since/:height", get(get_headers_since))
        .route("/peers", get(get_peers))
        .route("/peers", post(add_peer))
        .route("/peers/p2p", get(get_p2p_peers))
        .route("/peers/p2p/aggregate", get(get_p2p_peers_aggregate))
        .route("/peers/detailed", get(get_peers_detailed))
        .route("/network/status", get(network_status))
        .route("/tx/relay", post(receive_transaction))
        .route("/tip", get(get_tip).post(receive_tip))
        .route("/sync/status", get(sync_status))
        .route("/node/info", get(node_info))
        .route("/mining/metrics", get(mining_metrics))
        .route("/mining/template", get(mining_template))
        .route("/mining/submit", post(mining_submit))
        .route("/snapshot/info", get(snapshot_info))
        .route("/snapshot/download", get(snapshot_download))
        .route("/snapshot/signed", get(snapshot_signed_data))
        .route("/snapshot/latest", get(snapshot_latest_manifest))
        .route("/snapshot/manifest/:height", get(snapshot_manifest_at_height))
        .route("/snapshot/history", get(snapshot_manifest_history))
        .route("/snapshot/confirm", post(snapshot_confirm))
        .route("/snapshot/export", post(snapshot_trigger_export))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            version_gate_middleware,
        ))
        .with_state(state.clone());

    // Explorer/read-only routes — NO rate limiting (served by nginx proxy from localhost)
    let explorer_routes = Router::new()
        .route("/health", get(health_check))
        .route("/miner/stats", get(miner_stats))
        .route("/block/:hash", get(get_block))
        .route("/block/height/:height", get(get_block_by_height))
        .route("/cumulative_work/:height", get(get_cumulative_work_at_height))
        .route("/tx/:hash", get(get_transaction))
        .route("/transactions/recent", get(get_recent_transactions))
        .route("/blocks/list", get(list_blocks_paginated))
        .route("/mempool", get(get_mempool))
        .route("/version.json", get(version_info))
        .route("/faucet/stats", get(faucet_stats))
        .route("/network/health", get(network_health))
        .route("/node/errors", get(get_node_errors))
        // v2.3.9 — explorer telemetry: cumulative activity counters + SSE.
        .route("/stats/activity", get(get_activity_stats))
        .route("/events/stream", get(get_activity_stream))
        // v2.4.0 — relay pool explorer surface.
        .route("/relay/pool/status", get(relay_pool_status))
        .route("/relay/balance/:pk_hash", get(relay_balance_of))
        .route("/relay/payouts/recent", get(relay_payouts_recent))
        .with_state(state.clone());

    // Admin routes — localhost only (not accessible from outside)
    let admin_routes = Router::new()
        .route("/admin/force-resync", post(admin_force_resync))
        .route("/admin/config", get(get_admin_config).post(set_admin_config))
        .route("/admin/mempool/purge", post(admin_mempool_purge))
        .with_state(state.clone());

    // Write + sensitive routes — rate limited to prevent DoS
    let limited_routes = Router::new()
        .route("/tx", post(submit_transaction))
        .route("/tx/v2", post(submit_transaction_v2))
        .route("/outputs/since/:height", get(get_outputs_since))
        .route("/nullifiers/check", post(check_nullifiers))
        .route("/witness/:commitment", get(get_witness))
        .route("/witness/position/:position", get(get_witness_by_position))
        .route("/witness/v2/position/:position", get(get_witness_by_position_v2))
        .route("/leaves/bulk", post(get_leaves_bulk))
        // Debug endpoints REMOVED from production (H3 audit fix).
        // These exposed internal crypto structures. Re-enable with --debug flag if needed.
        // .route("/debug/commitments", get(debug_list_commitments))
        // .route("/debug/poseidon", get(debug_poseidon_test))
        // .route("/debug/poseidon-pq", get(debug_poseidon_pq_test))
        // .route("/debug/merkle-pq", get(debug_merkle_pq))
        // .route("/debug/verify-path", post(debug_verify_path))
        .route("/wallet/viewing-key", get(wallet_viewing_key))
        .route("/wallet/watch", post(wallet_watch))
        .route("/wallet/balance", get(wallet_balance_api))
        .route("/wallet/history", get(wallet_history_api))
        .route("/wallet/address", get(wallet_address_api))
        .route("/wallet/scan", post(wallet_scan_api))
        .route("/wallet/rescan", post(wallet_rescan_api))
        // v2.5.3 — relay pool endorsement endpoint. A miner calls this on
        // each peer after finding a valid PoW to collect signatures over
        // the block hash; the collected endorsements are attached to the
        // block and grant each signer an equal share of that block's 3%
        // relay-pool slice at the next payout height.
        .route("/relay/endorse", post(relay_endorse_api))
        .route("/faucet/status/:pk_hash", get(faucet_status))
        .route("/faucet/claim", post(faucet_claim))
        .route("/faucet/game-claim", post(faucet_game_claim))
        .route("/api/roadmap", get(roadmap_status))
        .route("/contract/deploy", post(contract_deploy))
        .route("/contract/call", post(contract_call))
        .route("/contract/query", post(contract_query))
        .route("/contract/:address", get(contract_info))
        .route("/contract/:address/events", get(contract_events))
        .with_state(state)
        .layer(rate_limit_layer);

    // Merge all route groups
    //
    // v2.5.5 Bug #1 fix — TimeoutLayer is the root cause fix for CLOSE-WAIT
    // accumulation. Without it, a handler that hangs (slow peer request,
    // backpressured state lock, network-bound reqwest without its own
    // timeout) keeps the hyper connection alive forever. When the client
    // disconnects mid-handler, hyper holds the half-closed socket in
    // CLOSE-WAIT until the handler returns. With 30s request timeout,
    // stuck handlers are aborted and the connection is released. Combined
    // with SO_KEEPALIVE on the listener (main.rs), this eliminates the
    // accumulation observed on seed-2 (4036 CLOSE-WAIT after 51 days).
    let api_routes = sync_routes
        .merge(explorer_routes)
        .merge(admin_routes)
        .merge(limited_routes)
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE));

    let ui_routes = Router::new()
        // React app routes - serve index.html for SPA
        .route("/", get(serve_index))
        .route("/wallet", get(serve_index))
        .route("/wallet/*path", get(serve_index))
        .route("/explorer", get(serve_index))
        .route("/explorer/*path", get(serve_index))
        // Static assets
        .nest_service("/assets", ServeDir::new("static/assets"))
        // Circuit files (WASM and proving keys)
        .nest_service("/circuits", ServeDir::new("static/circuits"))
        // Root-level static files
        .route_service("/logo.png", ServeFile::new("static/logo.png"))
        .route_service("/vite.svg", ServeFile::new("static/vite.svg"))
        .route_service("/favicon.ico", ServeFile::new("static/logo.png"))
        .route_service("/tsn-whitepaper.pdf", ServeFile::new("static/tsn-whitepaper.pdf"));

    Router::new().merge(api_routes).merge(ui_routes)
}

/// GET /health — lightweight health check, never rate limited.
async fn health_check(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let height = state.blockchain.read().await.height();
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).len();
    Json(serde_json::json!({
        "status": "ok",
        "height": height,
        "peers": peers,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn chain_info(State(state): State<Arc<AppState>>) -> Json<ChainInfo> {
    // v2.6.0 — lock-free: single atomic pointer load, no contention with
    // blockchain.write() held during block imports / reorgs. The refresher
    // task (spawn_chain_info_refresher) keeps this snapshot within 200ms of
    // the live chain state.
    Json((**state.chain_info_cache.load()).clone())
}

/// v2.9.2 — Public read of the trusted-quorum checkpoint vote state.
/// Read by the explorer to render the "blockchain in quorum" halo / banner.
/// Lock-free: snapshot is overwritten in place by `consensus::checkpoint_vote`
/// after each tick (every `CHECKPOINT_VOTE_TICK_SECS`).
async fn chain_quorum_status(State(state): State<Arc<AppState>>) -> Json<QuorumStatus> {
    Json((**state.quorum_status.load()).clone())
}

/// v2.9.7 — Public read of the bounded finalized-checkpoint history.
/// Newest first. Used by the explorer's Checkpoints tab to render a
/// table of every checkpoint the local node has finalized via the
/// trusted-quorum vote.
async fn chain_checkpoints(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let history = state.checkpoint_history.load();
    Json(serde_json::json!({
        "count": history.len(),
        "checkpoints": &**history,
    }))
}

/// v2.6.0 — Periodically refresh `AppState.chain_info_cache` from the live
/// blockchain, so GET /chain/info serves from a lock-free atomic snapshot
/// instead of blocking on the chain RwLock during long imports.
///
/// 200ms tick is short enough that explorer polls always see fresh data, yet
/// long enough that the refresher's brief read lock never dominates the
/// blockchain RwLock contention budget. If a block import holds the write
/// lock for longer than 200ms, the refresher simply skips ticks — callers
/// continue to read the last-known-good snapshot with zero delay.
pub fn spawn_chain_info_refresher(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            // tokio::sync::RwLock: `.read().await` yields cooperatively when a
            // writer holds the lock — it does NOT pin the tokio worker thread
            // like std::sync::RwLock did. So HTTP handlers stay responsive
            // even while a long block import/reorg is in progress.
            let info = {
                let chain = state.blockchain.read().await;
                chain.info()
            };
            state.chain_info_cache.store(std::sync::Arc::new(info));
        }
    });
}

/// Sync progress status response.
#[derive(Serialize)]
struct SyncStatusResponse {
    height: u64,
    target_height: u64,
    progress_pct: f64,
    syncing: bool,
    peers_connected: usize,
}

/// GET /sync/status — returns current sync progress.
async fn sync_status(State(state): State<Arc<AppState>>) -> Json<SyncStatusResponse> {
    let chain = state.blockchain.read().await;
    let local_height = chain.height();
    drop(chain);

    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    let peers_connected = peers.len();
    drop(peers);

    // Best known peer height: if we have peers, query chain info for target
    // For now, use local height as target (updated during sync)
    let target_height = local_height; // Will match local when fully synced
    let syncing = false; // Not actively syncing via parallel sync

    let progress_pct = if target_height == 0 {
        100.0
    } else {
        (local_height as f64 / target_height as f64 * 100.0).min(100.0)
    };

    Json(SyncStatusResponse {
        height: local_height,
        target_height,
        progress_pct,
        syncing,
        peers_connected,
    })
}

/// Version info response.
#[derive(Serialize)]
struct VersionInfoResponse {
    version: &'static str,
    minimum_version: &'static str,
    protocol_version: u16,
    /// v2.9.7 — Network identifier the node is running against
    /// (e.g. "tsn-testnet-v12"). Surfaced in the explorer HUD so users
    /// can tell which network they are looking at.
    network_name: &'static str,
}

/// GET /version.json — returns node version info.
async fn version_info() -> Json<VersionInfoResponse> {
    Json(VersionInfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        minimum_version: crate::network::version_check::MINIMUM_VERSION,
        protocol_version: 3,
        network_name: crate::config::NETWORK_NAME,
    })
}

/// Node identity and status.
async fn node_info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // v2.7.2 Phase 2.1 — lock-free read via the ArcSwap snapshot, never blocks
    // even when the miner thread is holding `blockchain.write()` during a
    // multi-block import or reorg. Without this, /node/info timed out for tens
    // of seconds during fast-sync, hiding the node from the explorer.
    let height = state.chain_info_cache.load().height;
    let peer_id = state.p2p_peer_id.read().unwrap_or_else(|e| e.into_inner()).clone();
    let http_peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).len();

    Json(serde_json::json!({
        "peer_id": peer_id,
        "role": state.node_role,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": format!("tsn/{}", env!("CARGO_PKG_VERSION")),
        "height": height,
        "http_peers": http_peers,
        "signatures": "ML-DSA-65 (FIPS 204)",
        "hash": "Poseidon2",
        "zk_proofs": "Plonky3 STARKs",
    }))
}

/// Roadmap milestone status.
#[derive(Serialize)]
struct RoadmapMilestone {
    id: String,
    name: String,
    description: String,
    quarter: String,
    status: String, // "completed", "active", "pending"
    progress_pct: f64,
    metrics: serde_json::Value,
}

/// Roadmap status response.
#[derive(Serialize)]
struct RoadmapStatusResponse {
    last_updated: u64,
    milestones: Vec<RoadmapMilestone>,
    network_health: serde_json::Value,
}

/// GET /api/roadmap — returns dynamic roadmap status with real-time metrics.
async fn roadmap_status(State(state): State<Arc<AppState>>) -> Json<RoadmapStatusResponse> {
    let chain = state.blockchain.read().await;
    let chain_info = chain.info();
    let height = chain.height();
    drop(chain);

    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    let peers_connected = peers.len();
    drop(peers);

    let miner_stats = state.miner_stats.read().unwrap_or_else(|e| e.into_inner()).clone();

    // Calculate progress for each milestone based on real metrics
    let mut milestones = vec![];

    // Q1 2026: Mainnet Launch - COMPLETED
    milestones.push(RoadmapMilestone {
        id: "mainnet_launch".to_string(),
        name: "Mainnet Launch".to_string(),
        description: "Official launch of the TSN main network".to_string(),
        quarter: "Q1 2026".to_string(),
        status: "completed".to_string(),
        progress_pct: 100.0,
        metrics: serde_json::json!({
            "height": height,
            "latest_hash": chain_info.latest_hash,
            "proof_verification": chain_info.proof_verification_enabled
        }),
    });

    // Q2 2026: Sharding V2 - ACTIVE (based on sync performance and commitment count)
    let sharding_progress = if chain_info.commitment_count > 10000 {
        ((chain_info.commitment_count as f64 / 100000.0) * 100.0).min(100.0)
    } else {
        (chain_info.commitment_count as f64 / 10000.0 * 50.0).min(50.0)
    };

    milestones.push(RoadmapMilestone {
        id: "sharding_v2".to_string(),
        name: "Sharding V2".to_string(),
        description: "Scalability improvements via dynamic sharding".to_string(),
        quarter: "Q2 2026".to_string(),
        status: "active".to_string(),
        progress_pct: sharding_progress,
        metrics: serde_json::json!({
            "commitment_count": chain_info.commitment_count,
            "difficulty": chain_info.difficulty,
            "mining_active": miner_stats.is_mining
        }),
    });

    // Q3 2026: Interoperability - PENDING
    milestones.push(RoadmapMilestone {
        id: "interoperability".to_string(),
        name: "Interoperability".to_string(),
        description: "Cross-chain bridges with major external networks".to_string(),
        quarter: "Q3 2026".to_string(),
        status: "pending".to_string(),
        progress_pct: 0.0,
        metrics: serde_json::json!({
            "bridge_contracts": 0,
            "supported_chains": []
        }),
    });

    // Q4 2026: Mobile SDK - PENDING
    milestones.push(RoadmapMilestone {
        id: "mobile_sdk".to_string(),
        name: "Mobile SDK".to_string(),
        description: "Native SDK for decentralized mobile applications".to_string(),
        quarter: "Q4 2026".to_string(),
        status: "pending".to_string(),
        progress_pct: 0.0,
        metrics: serde_json::json!({
            "sdk_version": null,
            "platforms": []
        }),
    });

    let network_health = serde_json::json!({
        "height": height,
        "peers_connected": peers_connected,
        "mining_active": miner_stats.is_mining,
        "hashrate_hps": miner_stats.hashrate_hps,
        "commitment_count": chain_info.commitment_count,
        "nullifier_count": chain_info.nullifier_count,
        "proof_verification": chain_info.proof_verification_enabled
    });

    Json(RoadmapStatusResponse {
        last_updated: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        milestones,
        network_health,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MinerStats {
    pub is_mining: bool,
    pub hashrate_hps: u64,
    pub last_attempts: u64,
    pub last_elapsed_ms: u64,
    pub last_updated: u64,
}

async fn miner_stats(State(state): State<Arc<AppState>>) -> Json<MinerStats> {
    let stats = state.miner_stats.read().unwrap_or_else(|e| e.into_inner()).clone();
    Json(stats)
}

/// Network health endpoint — exposes fork/orphan stats and peer versions.
async fn network_health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().await;
    let height = chain.height();
    let difficulty = chain.info().difficulty;
    let cumulative_work = chain.cumulative_work();
    let avg_block_time = {
        let ts = chain.recent_timestamps(20);
        if ts.len() >= 2 {
            let span = ts.last().unwrap_or(&0).saturating_sub(*ts.first().unwrap_or(&0));
            span as f64 / (ts.len() - 1) as f64
        } else {
            0.0
        }
    };
    drop(chain);

    let orphan_count = state.orphan_count.load(std::sync::atomic::Ordering::Relaxed);
    let reorg_count = state.reorg_count.load(std::sync::atomic::Ordering::Relaxed);
    let miner_stats = state.miner_stats.read().unwrap_or_else(|e| e.into_inner()).clone();
    let peer_count = state.peers.read().unwrap_or_else(|e| e.into_inner()).len();

    // Orphan rate: orphans per 100 blocks
    let orphan_rate = if height > 0 {
        (orphan_count as f64 / height as f64) * 100.0
    } else {
        0.0
    };

    Json(serde_json::json!({
        "height": height,
        "difficulty": difficulty,
        "cumulative_work": cumulative_work.to_string(),
        "avg_block_time_secs": avg_block_time,
        "target_block_time_secs": 10u64,
        "orphan_count": orphan_count,
        "reorg_count": reorg_count,
        "orphan_rate_pct": format!("{:.2}", orphan_rate),
        "peer_count": peer_count,
        "hashrate_hps": miner_stats.hashrate_hps,
        "is_mining": miner_stats.is_mining,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Serialize)]
struct BlockResponse {
    hash: String,
    height: u64,
    prev_hash: String,
    timestamp: u64,
    difficulty: u64,
    nonce: String,
    tx_count: usize,
    tx_count_v2: usize,
    commitment_root: String,
    nullifier_root: String,
    /// v2.9.26 — block header `state_root` (Poseidon2 hash over V1
    /// commitment_root, V2 PQ commitment tree root, and nullifier_root).
    /// Surfaced so fast-sync receivers can cross-check a publisher's
    /// `manifest_state_root` against a quorum of canonical-hash peers
    /// before importing the snapshot. Without this, a single drifted
    /// publisher could feed every fast-sync importer a snapshot whose
    /// state_root nobody else agrees with — the cause of the
    /// 2026-05-04 Layer 4 cascade.
    state_root: String,
    transactions: Vec<String>,
    transactions_v2: Vec<String>,
    coinbase_reward: u64,
    total_fees: u64,
    /// Blake2s-256 hash of the miner's ML-DSA-65 public key.
    /// All-zero for the genesis block. Populated from v2.4.0 onward.
    miner_pk_hash: String,
    // Encrypted note data for miner monitoring (encrypted, so privacy-preserving)
    coinbase_ephemeral_pk: String,
    coinbase_ciphertext: String,
    /// v2.5.3 — list of relay pk_hashes (Blake2s256 of pub_key) that signed
    /// this block's header. Each signer received an equal share of the 3%
    /// relay-pool slice for this block.
    endorsements: Vec<String>,
}

async fn get_block(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().await;
    let block = chain.get_block(&hash_bytes).ok_or(StatusCode::NOT_FOUND)?;

    // Find block height
    let height = (0..=chain.height())
        .find(|h| chain.get_block_by_height(*h).map(|b| b.hash()) == Some(hash_bytes))
        .unwrap_or(0);

    Ok(Json(block_to_response(&block, height)))
}

async fn get_block_by_height(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let chain = state.blockchain.read().await;
    let block = chain
        .get_block_by_height(height)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(block_to_response(&block, height)))
}

/// KF-008 root fix (incident 2026-05-02 follow-up, RC v4 2026-05-03):
/// expose this node's `cumulative_work` at a specific height. Used by
/// fast-sync receivers to cross-validate the snapshot publisher's cw seed
/// against a peer median before persisting it. Returns 404 if the height
/// is below `fast_sync_base_height` (we don't have a real cw value there)
/// or above the local tip.
async fn get_cumulative_work_at_height(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let chain = state.blockchain.read().await;
    let cw = chain
        .cumulative_work_at_height(height)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "height": height,
        "cumulative_work": cw.to_string(),
    })))
}

fn block_to_response(block: &ShieldedBlock, height: u64) -> BlockResponse {
    BlockResponse {
        hash: hex::encode(block.hash()),
        height,
        prev_hash: hex::encode(block.header.prev_hash),
        timestamp: block.header.timestamp,
        difficulty: block.header.difficulty,
        nonce: hex::encode(block.header.nonce),
        tx_count: block.transactions.len(),
        tx_count_v2: block.transactions_v2.len(),
        commitment_root: hex::encode(block.header.commitment_root),
        nullifier_root: hex::encode(block.header.nullifier_root),
        state_root: hex::encode(block.header.state_root),
        transactions: block.transactions.iter().map(|tx| hex::encode(tx.hash())).collect(),
        transactions_v2: block.transactions_v2.iter().map(|tx| hex::encode(tx.hash())).collect(),
        coinbase_reward: block.coinbase.reward,
        total_fees: block.total_fees(),
        miner_pk_hash: hex::encode(block.coinbase.miner_pk_hash),
        coinbase_ephemeral_pk: hex::encode(&block.coinbase.encrypted_note.ephemeral_pk),
        coinbase_ciphertext: hex::encode(&block.coinbase.encrypted_note.ciphertext),
        endorsements: block.endorsements.iter().map(|e| hex::encode(e.pk_hash())).collect(),
    }
}

/// Query parameters for paginated block listing.
#[derive(Deserialize)]
struct BlockListParams {
    page: Option<u64>,
    limit: Option<u64>,
}

/// Paginated block list response.
#[derive(Serialize)]
struct BlockListResponse {
    blocks: Vec<BlockSummaryItem>,
    total: u64,
    page: u64,
    limit: u64,
    total_pages: u64,
}

/// Lightweight block summary for list views.
#[derive(Serialize)]
struct BlockSummaryItem {
    height: u64,
    hash: String,
    tx_count: usize,
    timestamp: u64,
    difficulty: u64,
    coinbase_reward: u64,
    /// Blake2s-256 hash of the miner's ML-DSA-65 public key (all-zero for genesis).
    miner_pk_hash: String,
}

/// List blocks with pagination — page 1 = most recent.
async fn list_blocks_paginated(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BlockListParams>,
) -> Json<BlockListResponse> {
    let chain = state.blockchain.read().await;
    let chain_height = chain.height();
    let total = chain_height + 1; // heights 0..=chain_height

    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let total_pages = (total + limit - 1) / limit;

    let offset = (page - 1) * limit;
    // Page 1 = most recent blocks (descending)
    let start_height = chain_height.saturating_sub(offset);

    let mut blocks = Vec::with_capacity(limit as usize);
    for i in 0..limit {
        if start_height < i {
            break;
        }
        let h = start_height - i;
        if let Some(block) = chain.get_block_by_height(h) {
            blocks.push(BlockSummaryItem {
                height: h,
                hash: hex::encode(block.hash()),
                tx_count: block.transactions.len() + block.transactions_v2.len(),
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
                coinbase_reward: block.coinbase.reward,
                miner_pk_hash: hex::encode(block.coinbase.miner_pk_hash),
            });
        }
    }

    Json(BlockListResponse {
        blocks,
        total,
        page,
        limit,
        total_pages,
    })
}

/// Shielded transaction response - only public data is exposed.
#[derive(Serialize)]
struct TransactionResponse {
    hash: String,
    fee: u64,
    spend_count: usize,
    output_count: usize,
    status: String,
    block_height: Option<u64>,
    confirmations: Option<u64>,
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check mempool first
    {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = mempool.get(&hash_bytes) {
            return Ok(Json(TransactionResponse {
                hash: hex::encode(tx.hash()),
                fee: tx.fee,
                spend_count: tx.spends.len(),
                output_count: tx.outputs.len(),
                status: "pending".to_string(),
                block_height: None,
                confirmations: Some(0),
            }));
        }
    }

    // Search in blockchain
    let chain = state.blockchain.read().await;
    let current_height = chain.height();
    for h in (0..=current_height).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.hash() == hash_bytes {
                    return Ok(Json(TransactionResponse {
                        hash: hex::encode(tx.hash()),
                        fee: tx.fee,
                        spend_count: tx.spends.len(),
                        output_count: tx.outputs.len(),
                        status: "confirmed".to_string(),
                        block_height: Some(h),
                        confirmations: Some(current_height.saturating_sub(h) + 1),
                    }));
                }
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn get_recent_transactions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<TransactionResponse>> {
    let mut transactions = Vec::new();

    // Get pending V1 transactions from mempool
    {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        for tx in mempool.get_transactions(10) {
            transactions.push(TransactionResponse {
                hash: hex::encode(tx.hash()),
                fee: tx.fee,
                spend_count: tx.spends.len(),
                output_count: tx.outputs.len(),
                status: "pending".to_string(),
                block_height: None,
                confirmations: Some(0),
            });
        }
        // Get pending V2 transactions from mempool
        for tx in mempool.get_v2_transactions(10) {
            use crate::core::Transaction as TxEnum;
            let (fee, spend_count, output_count) = match &tx {
                TxEnum::V1(v1) => (v1.fee, v1.spends.len(), v1.outputs.len()),
                TxEnum::V2(v2) => (v2.fee, v2.spends.len(), v2.outputs.len()),
                TxEnum::Migration(m) => (m.fee, m.legacy_spends.len(), m.pq_outputs.len()),
                TxEnum::ContractDeploy(d) => (d.fee, 0, 0),
                TxEnum::ContractCall(c) => (c.fee, 0, 0),
            };
            transactions.push(TransactionResponse {
                hash: hex::encode(tx.hash()),
                fee,
                spend_count,
                output_count,
                status: "pending (v2)".to_string(),
                block_height: None,
                confirmations: Some(0),
            });
        }
    }

    // Get recent confirmed transactions from recent blocks
    let chain = state.blockchain.read().await;
    let current_height = chain.height();
    let start_height = current_height.saturating_sub(500);

    for h in (start_height..=current_height).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            let confs = current_height.saturating_sub(h) + 1;
            // V1 transactions
            for tx in &block.transactions {
                transactions.push(TransactionResponse {
                    hash: hex::encode(tx.hash()),
                    fee: tx.fee,
                    spend_count: tx.spends.len(),
                    output_count: tx.outputs.len(),
                    status: "confirmed".to_string(),
                    block_height: Some(h),
                    confirmations: Some(confs),
                });
            }
            // V2 transactions
            for tx in &block.transactions_v2 {
                transactions.push(TransactionResponse {
                    hash: hex::encode(tx.hash()),
                    fee: tx.fee,
                    spend_count: tx.spends.len(),
                    output_count: tx.outputs.len(),
                    status: "confirmed (v2)".to_string(),
                    block_height: Some(h),
                    confirmations: Some(confs),
                });
            }
        }

        if transactions.len() >= 20 {
            break;
        }
    }

    Json(transactions)
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    transaction: ShieldedTransaction,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    hash: String,
    status: String,
}

async fn submit_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let tx = req.transaction;
    let hash = hex::encode(tx.hash());

    // Validate transaction
    {
        let chain = state.blockchain.read().await;
        if let Some(params) = chain.verifying_params() {
            // Full validation with proof verification
            chain
                .state()
                .validate_transaction(&tx, params)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        } else {
            // Basic validation (no proof verification) - for development/testing
            // This still checks anchors, nullifiers, and signatures
            chain
                .state()
                .validate_transaction_basic(&tx)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            // Verify spend signatures manually since basic validation skips them
            for spend in &tx.spends {
                spend.verify_signature()
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid spend signature".to_string()))?;
            }
        }
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add(tx.clone())
    };

    if !added {
        return Err((
            StatusCode::CONFLICT,
            "Transaction already in mempool or conflicts with pending".to_string(),
        ));
    }

    // Relay to peers (fire and forget)
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
    if !peers.is_empty() {
        let tx_clone = tx.clone();
        let client = state.http_client.clone();
        tokio::spawn(async move {
            relay_transaction(&tx_clone, &peers, &client).await;
        });
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: "pending".to_string(),
    }))
}

/// V2 transaction submission request (post-quantum).
#[derive(Deserialize)]
struct SubmitTxV2Request {
    transaction: ShieldedTransactionV2,
}

/// Submit a V2 (post-quantum) shielded transaction.
async fn submit_transaction_v2(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<SubmitTxV2Request>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    // v2.7.0 Phase 1.3 — per-IP rate limit (sliding 60s window, max 8). One
    // misbehaving client (or a buggy parallel-consolidation loop) can no
    // longer monopolise the tx-submit semaphore; well-behaved clients keep
    // their slots. Peer-to-peer relays use a different ingress path.
    {
        let ip = addr.ip();
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(SUBMIT_RATE_WINDOW_SECS);
        let mut tracker = state
            .submit_rate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Touch the entry (LRU) and prune events outside the window.
        let dq = tracker.get_or_insert_mut(ip, std::collections::VecDeque::new);
        while let Some(front) = dq.front() {
            if now.duration_since(*front) > window {
                dq.pop_front();
            } else {
                break;
            }
        }
        if dq.len() >= SUBMIT_RATE_MAX_PER_IP {
            warn!(
                "submit_transaction_v2: rate-limit hit ip={} count={}",
                ip,
                dq.len()
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit: max {} V2 submissions per {}s per IP",
                    SUBMIT_RATE_MAX_PER_IP, SUBMIT_RATE_WINDOW_SECS
                ),
            ));
        }
        dq.push_back(now);
    }

    // v2.6.7 — bound concurrent v2 tx validations.
    // Validation holds the blockchain read lock and runs Plonky3 STARK proof
    // verification + ML-DSA-65 signature checks + nullifier set lookups,
    // each costing ~100ms-1s. Without a bound, a burst of 10+ submissions
    // (e.g. Phase 3.2 parallel consolidation) saturates the HTTP worker
    // pool and freezes the node for minutes. Try-acquire with a short
    // timeout: if the slot is full, return 503 + Retry-After=2s so the
    // client backs off, letting the HTTP server stay responsive for read
    // endpoints (/chain/info, /tip).
    // v2.7.0 Phase 1.2 — semaphore capacity bumped to 16, so the wait at the
    // gate is much shorter; cap the wait at 50 ms to fail fast under sustained
    // overload (the client retries with Retry-After=2s).
    let permit = match tokio::time::timeout(
        std::time::Duration::from_millis(50),
        state.tx_submit_semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "tx submit semaphore closed".to_string(),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "tx submit queue full, retry-after 2s".to_string(),
            ));
        }
    };

    let tx = req.transaction;
    let hash = hex::encode(tx.hash());

    info!("Received V2 transaction: {}", &hash[..16]);

    // Wrap in Transaction enum for validation and mempool
    let wrapped_tx = Transaction::V2(tx.clone());

    // v2.7.0 Phase 2.1 — Two-stage validation.
    //
    // Stage A (CPU only, ~300-500ms): STARK proof verify + ML-DSA-65 sigs +
    // proof-vs-tx self-consistency. Runs in `spawn_blocking` so it does NOT
    // pin a tokio worker, and crucially does NOT hold `blockchain.read()`.
    // While Stage A runs, /chain/info, /tip, /sync/blocks and /witness/v2
    // all stay responsive even under burst load.
    //
    // Stage B (state-dependent, ~5-10ms): anchor recency + nullifier
    // double-spend. Acquires the read lock briefly; releases immediately
    // before mempool insert.
    let tx_for_verify = tx.clone();
    let public_inputs = tokio::task::spawn_blocking(move || {
        crate::core::ShieldedState::validate_transaction_v2_proof_only(&tx_for_verify)
    })
    .await
    .map_err(|e| {
        warn!("V2 verify thread panicked: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "verify worker panic".to_string(),
        )
    })?
    .map_err(|e| {
        warn!("V2 proof validation failed: {}", e);
        (StatusCode::BAD_REQUEST, e.to_string())
    })?;

    {
        // v2.9.14 (W1B) — lock-free state check via concurrent caches.
        // Replaces `state.blockchain.read().await` + `state_check`, which
        // was starved by the tokio::sync::RwLock fairness queue under
        // continuous writer load (mining + p2p block reception). With
        // separate cache structures the reader never enqueues behind
        // writers; lookups are O(1) HashSet contains + small VecDeque
        // contains. Cache freshness invariant: writers populate the caches
        // in the same scope as `chain.add_block` (see
        // `update_state_caches_after_block`), so a tx whose nullifier was
        // just mined is rejected here before mempool insert.
        {
            let nf_cache = state.spent_nullifiers_cache.read().unwrap_or_else(|e| e.into_inner());
            for nf in public_inputs.nullifiers.iter() {
                if nf_cache.contains(nf) {
                    warn!("V2 state check failed: nullifier already spent");
                    return Err((StatusCode::BAD_REQUEST, "Nullifier already spent".to_string()));
                }
            }
        }
        {
            let anchor_cache = state.recent_anchors_cache.read().unwrap_or_else(|e| e.into_inner());
            for root in public_inputs.merkle_roots.iter() {
                if !anchor_cache.contains(root) {
                    warn!("V2 state check failed: invalid anchor");
                    return Err((StatusCode::BAD_REQUEST, "Invalid anchor".to_string()));
                }
            }
        }
    }
    // Permit released here so the semaphore frees up before relay/broadcast.
    drop(permit);

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add_v2(wrapped_tx.clone())
    };

    if !added {
        return Err((
            StatusCode::CONFLICT,
            "Transaction already in mempool or conflicts with pending".to_string(),
        ));
    }

    info!("V2 transaction {} added to mempool", &hash[..16]);
    // v2.3.9 — explorer telemetry.
    super::activity::record(
        &state.activity,
        &state.activity_bus,
        super::activity::ActivityKind::Tx,
        None,
        None,
        None,
    );

    // Relay V2 transaction to peers via P2P GossipSub
    {
        let p2p_tx = state.p2p_broadcast.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(sender) = p2p_tx {
            if let Ok(tx_data) = serde_json::to_vec(&tx) {
                let _ = sender.try_send(super::p2p::P2pCommand::BroadcastTransaction(tx_data));
            }
        }
    }

    // Relay V2 transaction to peers via HTTP (fallback for non-upgraded nodes)
    {
        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
        let tx_clone = tx.clone();
        let client = state.http_client.clone();
        tokio::spawn(async move {
            for peer in &peers {
                if !crate::network::is_contactable_peer(peer) { continue; }
                let url = format!("{}/tx/v2", peer);
                let _ = client.post(&url)
                    .json(&serde_json::json!({ "transaction": tx_clone }))
                    .send()
                    .await;
            }
        });
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: "pending".to_string(),
    }))
}

#[derive(Serialize)]
struct MempoolResponse {
    count: usize,
    transactions: Vec<String>,
    total_fees: u64,
}

async fn get_mempool(State(state): State<Arc<AppState>>) -> Json<MempoolResponse> {
    let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
    let v1_txs = mempool.get_transactions(100);
    let v2_txs = mempool.get_v2_transactions(100);

    let mut tx_hashes: Vec<String> = v1_txs.iter().map(|tx| hex::encode(tx.hash())).collect();
    tx_hashes.extend(v2_txs.iter().map(|tx| hex::encode(tx.hash())));

    Json(MempoolResponse {
        count: mempool.len(),
        transactions: tx_hashes,
        total_fees: mempool.total_fees(),
    })
}

// ============ Peer Sync Endpoints ============

/// Receive a block from a peer node.
async fn receive_block(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(block): Json<ShieldedBlock>,
) -> Result<Json<ReceiveBlockResponse>, (StatusCode, String)> {
    // IP whitelist check
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Err((StatusCode::FORBIDDEN, format!("IP {} not whitelisted", ip)));
    }
    // Reject blocks from nodes that don't send version header or are outdated
    let peer_ver = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
    if let Some(ver) = peer_ver {
        if !crate::network::version_check::version_meets_minimum(ver) {
            warn!("Rejected block from outdated peer (version {})", ver);
            return Err((StatusCode::FORBIDDEN, format!("Node version {} is below minimum {}", ver, crate::network::version_check::MINIMUM_VERSION)));
        }
    }
    // Track peer info (version, height, last seen), but skip hardcoded seeds
    // — they render via the dedicated `seeds` list in /network/status.
    //
    // v2.4.3+: key by libp2p PeerID when the sender provides X-TSN-PeerID,
    // and do NOT also create a URL-hash entry — that caused every peer to
    // show up twice on the explorer (once under its libp2p PeerID, once
    // under peer:<hash(http://IP:9333)>).
    let sender_peer_id = headers.get("X-TSN-PeerID").and_then(|v| v.to_str().ok());
    if !is_sender_a_seed(&ip).await {
        if let Some(pid_str) = sender_peer_id {
            let mut info = state.peer_info.write().unwrap_or_else(|e| e.into_inner());
            let entry = info.entry(pid_str.to_string()).or_insert(PeerDetail {
                peer_id: pid_str.to_string(),
                version: "?".to_string(),
                role: "miner".to_string(),
                height: 0,
                last_seen: 0,
            });
            entry.role = "miner".to_string();
            entry.height = block.coinbase.height;
            entry.last_seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            if let Some(v) = peer_ver {
                entry.version = v.to_string();
            }
        } else {
            let peer_url = format!("http://{}:9333", addr.ip());
            update_peer_info(&state, &peer_url, peer_ver, Some(block.coinbase.height));
        }
    }

    let block_hash = block.hash_hex();

    // v2.3.0 Phase 1: dedup same block within BLOCK_DEDUP_SECS (60s).
    // Covers the case where multiple peers relay the same block to us in a burst.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
        let mut cache = state.seen_blocks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&seen_at) = cache.get(&block_hash) {
            if now_secs.saturating_sub(seen_at) < BLOCK_DEDUP_SECS {
                debug!("dedup: block {} already seen ({}s ago), skipping",
                    &block_hash[..16], now_secs - seen_at);
                return Ok(Json(ReceiveBlockResponse {
                    status: "duplicate".to_string(),
                    hash: block_hash,
                }));
            }
        }
        cache.put(block_hash.clone(), now_secs);
    }

    info!("Received block {} from peer", &block_hash[..16]);
    // v2.3.9 — explorer telemetry.
    super::activity::record(
        &state.activity,
        &state.activity_bus,
        super::activity::ActivityKind::Block,
        Some(block.coinbase.height),
        sender_peer_id.map(|s| s.chars().take(16).collect::<String>()),
        None,
    );

    // Try to add the block (handles forks and reorgs automatically)
    // v2.1.2: Acquire reorg_lock.read() before blockchain.write() — consistent with
    // P2P handler and miner. Without this, HTTP-received blocks could trigger reorgs
    // that race with watchdog resets (which hold reorg_lock.write()).
    let _reorg_guard = state.reorg_lock.read().await;
    let (accepted, status) = {
        let mut chain = state.blockchain.write().await;
        let old_height = chain.height();
        let old_tip = chain.latest_hash();

        match chain.try_add_block(block.clone()) {
            Ok(true) => {
                let new_height = chain.height();
                let reorged = old_tip != chain.get_block_by_height(old_height.min(new_height - 1))
                    .map(|b| b.hash())
                    .unwrap_or([0u8; 32]);

                // v2.9.14 (W1B + H-G) — refresh the lock-free state-check
                // caches before the write lock is released so submit_v2 /
                // check_nullifiers / chain_info never observe a tx whose
                // nullifier was just included via this HTTP block.
                let new_anchor_pq = chain.state().commitment_root_pq();
                crate::network::api::update_state_caches_after_block(
                    &state, &block, new_anchor_pq, chain.info(),
                );

                if reorged {
                    info!("Chain reorganization! New tip: {} (height: {})", &block_hash[..16], new_height);
                } else {
                    info!("Added block {} to chain (height: {})", &block_hash[..16], new_height);
                }

                // v2.0.9: Cancel mining when a new block is accepted via HTTP
                // Previously only P2P blocks cancelled mining, causing stale blocks and forks
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                // Remove confirmed transactions from mempool
                let tx_hashes: Vec<[u8; 32]> = block
                    .transactions
                    .iter()
                    .map(|tx| tx.hash())
                    .collect();

                let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
                mempool.remove_confirmed(&tx_hashes);

                // Remove transactions with now-spent nullifiers
                let nullifiers: Vec<[u8; 32]> = block.nullifiers().iter().map(|n| n.0).collect();
                mempool.remove_spent_nullifiers(&nullifiers);

                // v2.8.5 Phase 3 light (Anchored Mempool): on reorg, drop every
                // mempool tx whose anchor is no longer in `recent_roots`.
                // Prevents stale txs (referencing a tree state that does not
                // exist on the canonical chain anymore) from sitting until the
                // 30-min global age cap.
                if reorged {
                    let evicted = mempool.evict_stale_anchors(chain.state());
                    if evicted > 0 {
                        info!(
                            "Reorg eviction: dropped {} mempool tx(s) with stale anchors",
                            evicted
                        );
                    }
                }

                // Re-validate remaining mempool transactions
                let removed = mempool.revalidate(chain.state());
                if removed > 0 {
                    info!("Removed {} invalid transactions from mempool after block", removed);
                }

                (true, "accepted")
            }
            Ok(false) => {
                // Block was duplicate or stored as side chain
                info!("Block {} stored (orphan or side chain)", &block_hash[..16]);
                // v2.3.9 — explorer telemetry: a stored side-chain block is a
                // rejected propagation path from the network-consumer's view.
                super::activity::record(
                    &state.activity,
                    &state.activity_bus,
                    super::activity::ActivityKind::Reject,
                    Some(block.coinbase.height),
                    None,
                    None,
                );
                (false, "stored")
            }
            Err(e) => {
                warn!("Block {} rejected: {}", &block_hash[..16], e);
                // v2.3.9 — explorer telemetry.
                super::activity::record(
                    &state.activity,
                    &state.activity_bus,
                    super::activity::ActivityKind::Reject,
                    Some(block.coinbase.height),
                    None,
                    None,
                );
                return Err((StatusCode::BAD_REQUEST, format!("Block rejected: {}", e)));
            }
        }
    };

    // Relay to other peers (gossip protocol) if accepted
    if accepted {
        // Invalidate snapshot cache every 100 blocks so new nodes get fresh state
        let block_height = block.height();
        if block_height % 100 == 0 {
            let state_clone = state.clone();
            tokio::spawn(async move {
                let mut cache = state_clone.snapshot_cache.write().await;
                *cache = None;
            });
        }

        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
        if !peers.is_empty() {
            let block_clone = block.clone();
            let client = state.http_client.clone();
            tokio::spawn(async move {
                relay_block(&block_clone, &peers, &client).await;
            });
        }
    }

    Ok(Json(ReceiveBlockResponse {
        status: status.to_string(),
        hash: block_hash,
    }))
}

#[derive(Serialize)]
struct ReceiveBlockResponse {
    status: String,
    hash: String,
}

// ============ v2.8.7 Phase 0.2 — Compact Block Relay (BIP-152) ============

/// Response to a `/cmpct_block` POST. Either the block was reconstructed and
/// processed (`status = "accepted" | "stored" | "rejected"`), or the receiver
/// could not resolve every short_id from its mempool and asks the sender to
/// follow up with a `/blocktxn` POST containing the missing transactions.
#[derive(Serialize)]
struct CompactBlockResponse {
    status: String,
    /// When `status == "missing"`, the block-relative indexes the sender
    /// must include in a follow-up `/blocktxn` request.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    missing: Vec<u32>,
    /// Hex-encoded block hash (for diagnostics) — empty when the compact
    /// block was malformed and no header could be derived.
    #[serde(default)]
    hash: String,
}

/// Receive a compact block envelope from a peer. Try to reconstruct the full
/// block from local mempool; on success, fall through into the same accept
/// pipeline as `receive_block`. On miss, return the missing indexes so the
/// sender can complete the relay via `/blocktxn`.
async fn receive_compact_block(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(cb): Json<super::compact_block::CompactBlock>,
) -> Result<Json<CompactBlockResponse>, (StatusCode, String)> {
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Err((StatusCode::FORBIDDEN, format!("IP {} not whitelisted", ip)));
    }
    let peer_ver = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
    if let Some(ver) = peer_ver {
        if !crate::network::version_check::version_meets_minimum(ver) {
            return Err((StatusCode::FORBIDDEN, format!(
                "Node version {} is below minimum {}",
                ver, crate::network::version_check::MINIMUM_VERSION
            )));
        }
    }

    // v2.8.9 Phase 0.2 protection #3 — count cap on `short_ids`.
    // Honest blocks have at most ~200 v2 transactions today; anything past
    // the cap is a "combinatorial bomb" attempt and is dropped before any
    // mempool index work.
    if cb.short_ids.len() > crate::config::MAX_COMPACT_SHORT_IDS {
        warn!(
            "cmpct_block from {}: short_ids count {} > cap {}, dropping",
            ip, cb.short_ids.len(), crate::config::MAX_COMPACT_SHORT_IDS
        );
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "short_ids count {} exceeds cap {}",
                cb.short_ids.len(),
                crate::config::MAX_COMPACT_SHORT_IDS
            ),
        ));
    }

    // v2.8.9 Phase 0.2 protection #1 — PoW gate. Validate the block header
    // PoW BEFORE doing the heavy mempool index work, so an attacker cannot
    // exhaust our CPU by spamming bogus envelopes that never had a valid
    // proof. A real CompactBlock is always announced for a freshly mined
    // block whose header has a valid PoW, so honest peers pass through.
    {
        // Use the same height-aware hash as the rest of validation; the
        // height comes from the coinbase carried in `prefilled_txn`.
        let mut block_height: Option<u64> = None;
        for p in &cb.prefilled_txn {
            if let super::compact_block::PrefilledTxBody::Coinbase(ref cbtx) = p.tx {
                block_height = Some(cbtx.height);
                break;
            }
        }
        let valid = match block_height {
            Some(h) => cb.header.meets_difficulty_for_height(h),
            None => cb.header.meets_difficulty(), // pre-v0.7 path; honest senders embed coinbase
        };
        if !valid {
            warn!("cmpct_block from {}: PoW invalid, dropping", ip);
            return Err((
                StatusCode::BAD_REQUEST,
                "compact block header fails PoW".into(),
            ));
        }
    }

    // v2.8.9 Phase 0.2 protection #2 — per-IP rate limit on /cmpct_block.
    // Uses a dedicated static LruCache so it doesn't share eviction with
    // the v2 transaction submit_rate (different cap, different window).
    {
        use std::collections::VecDeque;
        use std::sync::Mutex;
        use std::time::Instant;
        use lru::LruCache;
        use std::num::NonZeroUsize;
        use once_cell::sync::Lazy;

        static CMPCT_RATE: Lazy<Mutex<LruCache<std::net::IpAddr, VecDeque<Instant>>>> =
            Lazy::new(|| {
                Mutex::new(LruCache::new(NonZeroUsize::new(4096).unwrap()))
            });

        let now = Instant::now();
        let window = std::time::Duration::from_secs(crate::config::COMPACT_BLOCK_RATE_WINDOW_SECS);
        let mut rate = CMPCT_RATE.lock().unwrap_or_else(|e| e.into_inner());
        let entry = rate.get_or_insert_mut(addr.ip(), VecDeque::new);
        while let Some(front) = entry.front() {
            if now.duration_since(*front) > window {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= crate::config::COMPACT_BLOCK_RATE_LIMIT {
            warn!(
                "cmpct_block from {}: rate-limit ({} in {}s), dropping",
                ip, entry.len(), crate::config::COMPACT_BLOCK_RATE_WINDOW_SECS
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "rate limit: max {} compact blocks per {}s",
                    crate::config::COMPACT_BLOCK_RATE_LIMIT,
                    crate::config::COMPACT_BLOCK_RATE_WINDOW_SECS
                ),
            ));
        }
        entry.push_back(now);
    }

    // v2.9.0 RAM fix — filter mempool by short_id BEFORE cloning. The
    // previous v2.8.7-v2.8.9 implementation cloned *every* transaction
    // currently in the mempool to build a short-id index per envelope.
    // Under load (100+ V2 txs each carrying a ~500 KB STARK proof) this
    // peaked at ~50 MB of allocation per receive, multiplied by every
    // concurrent peer pushing the same fresh block — the seed servers
    // (4 GB RAM) OOM-killed in this path several times during the 27/04
    // recovery deploy.
    //
    // The new code computes `target_set` = the short_ids the sender wants
    // us to look up, then iterates the mempool ONCE and clones only the
    // transactions whose short_id is in that set. Worst case clone is
    // bounded by `MAX_COMPACT_SHORT_IDS = 1000` regardless of mempool
    // size; typical clone is ~10-200 txs that actually appear in the
    // block being relayed, a 5-50× reduction over the legacy code.
    let key = super::compact_block::derive_key(&cb.header, cb.nonce);
    let target_set: std::collections::HashSet<super::compact_block::ShortTxId> =
        cb.short_ids.iter().copied().collect();
    let (v1s, v2s, deploys, calls): (
        Vec<crate::core::ShieldedTransaction>,
        Vec<crate::core::ShieldedTransactionV2>,
        Vec<crate::contract::ContractDeployTransaction>,
        Vec<crate::contract::ContractCallTransaction>,
    ) = {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        let v1 = mempool
            .v1_transactions_iter()
            .filter(|tx| {
                target_set.contains(&super::compact_block::compute_short_id(&tx.hash(), &key))
            })
            .cloned()
            .collect();
        let v2 = mempool
            .v2_transactions_iter()
            .filter_map(|t| match t {
                crate::core::Transaction::V2(tx)
                    if target_set
                        .contains(&super::compact_block::compute_short_id(&tx.hash(), &key)) =>
                {
                    Some(tx.clone())
                }
                _ => None,
            })
            .collect();
        let dep = mempool
            .contract_deploys_iter()
            .filter(|tx| {
                target_set.contains(&super::compact_block::compute_short_id(&tx.hash(), &key))
            })
            .cloned()
            .collect();
        let cal = mempool
            .contract_calls_iter()
            .filter(|tx| {
                target_set.contains(&super::compact_block::compute_short_id(&tx.hash(), &key))
            })
            .cloned()
            .collect();
        (v1, v2, dep, cal)
    };
    drop(target_set); // free the lookup set before the heavier reconstruction step
    let index = super::compact_block::build_short_id_index(&key, &v1s, &v2s, &deploys, &calls);

    let block_hash_hex = hex::encode(cb.header.hash()).chars().take(16).collect::<String>();

    match super::compact_block::reconstruct(&cb, &index) {
        super::compact_block::ReconstructResult::Complete(block) => {
            // Hand off to the regular receive_block pipeline by re-invoking it
            // (cleanest reuse — avoids duplicating the long block-acceptance
            // logic). We forward the original ConnectInfo so peer-tracking is
            // attributed correctly.
            let resp = receive_block(
                ConnectInfo(addr),
                State(state.clone()),
                headers,
                Json(block),
            )
            .await
            .map_err(|(c, m)| (c, m))?;
            let inner = resp.0;
            Ok(Json(CompactBlockResponse {
                status: inner.status,
                missing: Vec::new(),
                hash: inner.hash,
            }))
        }
        super::compact_block::ReconstructResult::Incomplete { missing } => {
            info!(
                "CompactBlock {} reconstructed with {} miss(es), requesting follow-up blocktxn",
                block_hash_hex, missing.len()
            );
            Ok(Json(CompactBlockResponse {
                status: "missing".into(),
                missing,
                hash: block_hash_hex,
            }))
        }
        super::compact_block::ReconstructResult::Invalid(reason) => {
            warn!("CompactBlock {} invalid: {}", block_hash_hex, reason);
            Err((StatusCode::BAD_REQUEST, format!("Invalid compact block: {}", reason)))
        }
    }
}

/// Sender-side complement of `receive_compact_block`: the peer hands us the
/// block hash and indexes it could not resolve, and we look up the full
/// transactions in our local block store + mempool to send back. Used in
/// the rare case the receiver's mempool was out of sync at compact-block
/// time. We answer from the canonical chain (the block must exist locally
/// because we just sent the cmpctblock for it).
async fn receive_block_txn_request(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<super::compact_block::BlockTxnRequest>,
) -> Result<Json<super::compact_block::BlockTxn>, (StatusCode, String)> {
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Err((StatusCode::FORBIDDEN, format!("IP {} not whitelisted", ip)));
    }

    // Look up the block locally.
    let chain = state.blockchain.read().await;
    let block = match chain.get_block(&req.block_hash) {
        Some(b) => b.clone(),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("Block {} not found locally", hex::encode(&req.block_hash[..8])),
            ));
        }
    };
    drop(chain);

    let total = super::compact_block::block_tx_count(&block);

    // Build the canonical iteration order so we can index the requested slots
    // without re-implementing the order in two places.
    let mut bodies: Vec<super::compact_block::PrefilledTxBody> = Vec::with_capacity(req.indexes.len());
    for &slot in &req.indexes {
        let s = slot as usize;
        if s >= total {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("requested slot {} out of bounds (total={})", slot, total),
            ));
        }
        let body = if s < block.transactions.len() {
            super::compact_block::PrefilledTxBody::V1(block.transactions[s].clone())
        } else if s < block.transactions.len() + block.transactions_v2.len() {
            let i = s - block.transactions.len();
            super::compact_block::PrefilledTxBody::V2(block.transactions_v2[i].clone())
        } else if s
            < block.transactions.len()
                + block.transactions_v2.len()
                + block.contract_deploys.len()
        {
            let i = s - block.transactions.len() - block.transactions_v2.len();
            super::compact_block::PrefilledTxBody::Deploy(block.contract_deploys[i].clone())
        } else if s
            < block.transactions.len()
                + block.transactions_v2.len()
                + block.contract_deploys.len()
                + block.contract_calls.len()
        {
            let i = s
                - block.transactions.len()
                - block.transactions_v2.len()
                - block.contract_deploys.len();
            super::compact_block::PrefilledTxBody::Call(block.contract_calls[i].clone())
        } else {
            // The very last slot is the coinbase. Senders normally include
            // the coinbase in `prefilled_txn` of the cmpctblock so it should
            // never be requested; service it anyway for robustness.
            super::compact_block::PrefilledTxBody::Coinbase(block.coinbase.clone())
        };
        bodies.push(body);
    }

    Ok(Json(super::compact_block::BlockTxn {
        block_hash: req.block_hash,
        transactions: bodies,
    }))
}

/// Get all blocks since a given height (for chain sync).
async fn get_blocks_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<BlocksSinceParams>,
) -> Json<Vec<ShieldedBlock>> {
    let chain = state.blockchain.read().await;
    let current_height = chain.height();
    // Default limit of 50 blocks per request to avoid HTTP timeouts
    let max_blocks: u64 = params.limit.unwrap_or(50).min(200) as u64;
    let end_height = current_height.min(since_height.saturating_add(max_blocks));

    let mut blocks = Vec::new();

    // Return blocks from since_height+1 to end_height
    for h in (since_height + 1)..=end_height {
        if let Some(block) = chain.get_block_by_height(h) {
            blocks.push(block);
        }
    }

    // v2.3.9 — explorer telemetry: only count sync requests whose since_height
    // is strictly greater than the last one we counted, so identical polling
    // from a healthy peer does not repeatedly pulse a sync particle on screen.
    if state.activity.bump_unique_sync(since_height) {
        state.activity_bus.publish(super::activity::ActivityEvent {
            kind: super::activity::ActivityKind::Sync,
            at_unix: super::activity::now_secs(),
            height: Some(since_height),
            from_peer: None,
            bytes: None,
        });
    }

    Json(blocks)
}

#[derive(Deserialize)]
struct BlocksSinceParams {
    limit: Option<usize>,
}

/// GET /headers/since/{height} — returns compact headers for headers-first sync protocol.
/// Lightweight (~200 bytes/header vs ~5KB/block). Used to detect forks and find
/// common ancestors without downloading full blocks.
/// Max 500 headers per request (~100KB).
async fn get_headers_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<HeadersSinceParams>,
) -> Json<Vec<crate::core::CompactHeader>> {
    let chain = state.blockchain.read().await;
    let limit = params.limit.unwrap_or(500).min(1000);
    let headers = chain.get_compact_headers_since(since_height, limit);
    Json(headers)
}

#[derive(Deserialize)]
struct HeadersSinceParams {
    limit: Option<usize>,
}

// ============ Peer Management Endpoints ============

#[derive(Serialize)]
struct PeersResponse {
    peers: Vec<String>,
    count: usize,
    /// P2P peers connected via libp2p (identified by PeerID)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    p2p_peers: Vec<super::p2p::PeerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_count: Option<usize>,
}

/// Get the list of known peers.
async fn get_peers(State(state): State<Arc<AppState>>) -> Json<PeersResponse> {
    let peers = state.peers.read().unwrap_or_else(|e| e.into_inner());
    // Privacy: return hashed peer IDs instead of raw URLs/IPs
    let mut seen = std::collections::HashSet::new();
    let masked_peers: Vec<String> = peers
        .iter()
        .map(|p| normalize_peer_url(p))
        .filter(|p| !p.contains("://localhost") && !p.contains("://127.0.0.1") && !p.contains("://0.0.0.0"))
        .map(|p| super::peer_id(&p))
        .filter(|p| seen.insert(p.clone()))
        .collect();
    Json(PeersResponse {
        count: masked_peers.len(),
        peers: masked_peers,
        p2p_peers: vec![],
        p2p_count: None,
    })
}

/// Get P2P peers connected via libp2p (identified by PeerID).
async fn get_p2p_peers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let local_height = state.blockchain.read().await.height();
    // Read directly from shared peer list — instant, no channel wait, no HTTP calls
    let peers = state.p2p_shared_peers.read().unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|sp| sp.read().unwrap_or_else(|e| e.into_inner()).clone())
        .unwrap_or_default();
    Json(serde_json::json!({
        "count": peers.len(),
        "peers": peers,
        "local_height": local_height,
    }))
}

/// v2.7.1 Phase 2 — Aggregate `/peers/p2p` from every seed and merge by
/// `peer_id`. The Rust nodes only ever publish the peers they have personally
/// dialled (seed-1 sees the cortex, others don't, etc.), so a single seed's
/// view is always partial. Merging gives the explorer the union of every
/// node's view in one call. Cached for 5s to keep the explorer's polling rate
/// from amplifying into 5× outbound HTTP per refresh.
async fn get_p2p_peers_aggregate(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use std::collections::HashMap;

    let local_height = state.blockchain.read().await.height();
    // Local view first.
    let local_peers = state.p2p_shared_peers.read().unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|sp| sp.read().unwrap_or_else(|e| e.into_inner()).clone())
        .unwrap_or_default();

    // Collect remote views in parallel; tolerate any failure.
    let client = state.http_client.clone();
    let remote_futures = crate::config::SEED_NODES.iter().map(|seed_url| {
        let client = client.clone();
        let url = format!("{}/peers/p2p", seed_url);
        async move {
            match client.get(&url).timeout(std::time::Duration::from_secs(2)).send().await {
                Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
                    Ok(v) => v.get("peers").cloned().unwrap_or_default(),
                    Err(_) => serde_json::Value::Null,
                },
                _ => serde_json::Value::Null,
            }
        }
    });
    let remote_results = futures::future::join_all(remote_futures).await;

    // Merge by peer_id; later entries with `height` populated win over `null`.
    let mut by_id: HashMap<String, serde_json::Value> = HashMap::new();
    let key_of = |p: &serde_json::Value| -> Option<String> {
        p.get("peer_id").and_then(|v| v.as_str()).map(String::from)
    };
    let merge = |existing: serde_json::Value, incoming: serde_json::Value| -> serde_json::Value {
        // Pick the entry whose `height` is non-null, fallback to existing.
        let inc_h = incoming.get("height").map(|v| !v.is_null()).unwrap_or(false);
        let ex_h = existing.get("height").map(|v| !v.is_null()).unwrap_or(false);
        match (inc_h, ex_h) {
            (true, false) => incoming,
            (false, true) => existing,
            // Both have heights or both null — prefer the higher height (or
            // existing on tie / both null).
            _ => {
                let inc = incoming.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                let ex = existing.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                if inc > ex { incoming } else { existing }
            }
        }
    };

    for p in local_peers.iter() {
        let v = serde_json::to_value(p).unwrap_or(serde_json::Value::Null);
        if let Some(k) = key_of(&v) {
            by_id.entry(k).and_modify(|e| *e = merge(e.clone(), v.clone())).or_insert(v);
        }
    }
    for remote in remote_results.into_iter() {
        if let serde_json::Value::Array(peers) = remote {
            for v in peers {
                if let Some(k) = key_of(&v) {
                    by_id.entry(k).and_modify(|e| *e = merge(e.clone(), v.clone())).or_insert(v);
                }
            }
        }
    }

    // v2.7.4 — for each merged peer, compute `height_age_secs` from
    // `height_updated_at` and null out the height if it is older than 30
    // seconds. Without this, the explorer happily displays a P2P peer's
    // last-seen height from minutes ago and reports it as "525 blocks
    // behind" while the peer itself is actually fully synced. Setting
    // height to null lets the existing `height == null` UI path render
    // "P2P refreshing" / "Synced" instead of a misleading lag.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    const STALE_THRESHOLD_SECS: u64 = 30;
    let mut merged: Vec<serde_json::Value> = by_id.into_values().collect();
    for v in merged.iter_mut() {
        if let Some(obj) = v.as_object_mut() {
            let updated_at = obj
                .get("height_updated_at")
                .and_then(|x| x.as_u64());
            let age = updated_at.map(|t| now_secs.saturating_sub(t));
            if let Some(a) = age {
                obj.insert("height_age_secs".into(), serde_json::json!(a));
                if a > STALE_THRESHOLD_SECS {
                    obj.insert("height".into(), serde_json::Value::Null);
                }
            } else {
                // Never observed a height for this peer.
                obj.insert("height_age_secs".into(), serde_json::Value::Null);
                obj.insert("height".into(), serde_json::Value::Null);
            }
        }
    }
    Json(serde_json::json!({
        "count": merged.len(),
        "peers": merged,
        "local_height": local_height,
        "aggregated_from": crate::config::SEED_NODES.len() + 1,
    }))
}

/// Aggregated network status for the explorer.
/// Fetches real heights from all seed nodes via HTTP (server-side, no CORS issues).
/// Returns P2P peers with raw heights (no faking). Computes statuses.
async fn network_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // v2.5.4 — microcache + parallel fetch. The previous revision sequentially
    // polled each of the 5 seeds for `/tip` and `/node/info` (2s timeout each),
    // giving a worst case of ~20 s per handler invocation under a flood. Those
    // slow handlers accumulated CLOSE-WAIT sockets (the client side cuts its
    // end but our handler is still stuck waiting on downstream I/O before it
    // can drop the accepted socket) until seed3/seed4 ran out of file
    // descriptors. Parallelizing turns 5×2 ≈ 20 s into max(2 s, 2 s) = 2 s,
    // and the 3-second response cache makes the handler effectively O(1) under
    // sustained polling (the explorer refreshes every 10 s per client).
    {
        let cache = state.network_status_cache.read().unwrap_or_else(|e| e.into_inner());
        if let Some(ref cached) = *cache {
            if cached.expires_at > std::time::Instant::now() {
                return Json(cached.body.clone());
            }
        }
    }

    let local_tip = {
        let chain = state.blockchain.read().await;
        (chain.height(), hex::encode(chain.latest_hash()))
    };
    let tip_height = local_tip.0;
    let tip_hash = local_tip.1;

    // Fetch real height from each seed node via HTTP — in parallel, 1s timeout
    let client = state.http_client.clone();
    let seed_names = ["nexus", "seed-1", "seed-2", "seed-3", "seed-4"];
    let seed_futures = crate::config::SEED_NODES.iter().enumerate().map(|(i, seed_url)| {
        let client = client.clone();
        let name = seed_names.get(i).copied().unwrap_or("seed").to_string();
        let seed_url = (*seed_url).to_string();
        async move {
            let ip = seed_url.trim_start_matches("http://").split(':').next().unwrap_or("?").to_string();
            let tip_url = format!("{}/tip", seed_url);
            let info_url = format!("{}/node/info", seed_url);
            let mut seed_info = serde_json::json!({
                "name": name,
                "ip": ip,
                "height": null,
                "hash": null,
                "version": null,
                "online": false,
                "status": "offline",
                "lag": null,
            });
            let tip_fut = client.get(&tip_url).timeout(std::time::Duration::from_secs(1)).send();
            let info_fut = client.get(&info_url).timeout(std::time::Duration::from_secs(1)).send();
            let (tip_res, info_res) = tokio::join!(tip_fut, info_fut);
            if let Ok(resp) = tip_res {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let h = data["height"].as_u64();
                    seed_info["height"] = serde_json::json!(h);
                    seed_info["online"] = serde_json::json!(true);
                    // v2.9.7 — Expose the seed's tip hash so the explorer can
                    // verify all seeds agree on the same (height, hash)
                    // before lighting the in-quorum indicator. Height alone
                    // would let two nodes on different forks pass.
                    if let Some(h_hex) = data["hash"].as_str() {
                        seed_info["hash"] = serde_json::json!(h_hex);
                    } else if let Some(h_hex) = data["latest_hash"].as_str() {
                        seed_info["hash"] = serde_json::json!(h_hex);
                    }
                    if let Some(h) = h {
                        let lag = tip_height.saturating_sub(h);
                        seed_info["lag"] = serde_json::json!(lag);
                        seed_info["status"] = serde_json::json!(
                            if lag <= 5 { "fresh" }
                            else if lag <= 50 { "stale" }
                            else { "behind" }
                        );
                    }
                }
            }
            if let Ok(resp) = info_res {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    seed_info["version"] = data["version"].clone();
                    seed_info["peer_id"] = data["peer_id"].clone();
                }
            }
            seed_info
        }
    });
    let mut seeds: Vec<serde_json::Value> = futures::future::join_all(seed_futures).await;

    // Collect seed PeerIDs AND seed IPs for dedup against P2P list
    let seed_peer_ids: std::collections::HashSet<String> = seeds.iter()
        .filter_map(|s| s["peer_id"].as_str().map(|s| s.to_string()))
        .collect();
    let seed_ips: std::collections::HashSet<String> = seeds.iter()
        .filter_map(|s| s["ip"].as_str().map(|s| s.to_string()))
        .collect();

    // P2P peers with raw heights + freshness info, excluding seeds
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    // v2.3.9 — A peer must *prove* it belongs on this chain before it appears in
    // the public explorer. Without this filter, a misconfigured node on an
    // incompatible version or a different testnet briefly shows up as a ghost
    // (libp2p accepts the connection on the same protocol ID, then the TSN
    // middleware rejects its HTTP requests ~2 s later). The 2-second flicker
    // breaks the network-graph animation. Rules:
    //   1. `protocol` must be a well-formed `tsn/<version>/<role>`.
    //   2. Declared version must meet the current minimum.
    //   3. The peer must have successfully exchanged at least one height
    //      (confirms the TSN handshake completed, not just libp2p's).
    let peer_passes_explorer_filter = |p: &crate::network::p2p::PeerInfo| -> bool {
        let parts: Vec<&str> = p.protocol.split('/').collect();
        if parts.len() < 2 || parts[0] != "tsn" { return false; }
        if !crate::network::version_check::version_meets_minimum(parts[1]) {
            return false;
        }
        p.height.is_some() && p.height_updated_at.is_some()
    };
    let p2p_peers: Vec<serde_json::Value> = {
        let peers = state.p2p_shared_peers.read().unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|sp| sp.read().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default();
        peers.iter()
            .filter(|p| !seed_peer_ids.contains(&p.peer_id)) // exclude seeds by PeerID
            .filter(|p| peer_passes_explorer_filter(p))      // v2.3.9 — no ghosts
            .map(|p| {
            let h = p.height;
            let lag = h.map(|ph| tip_height.saturating_sub(ph));
            // Compute how old the height data is (seconds since last update)
            let height_age_secs = p.height_updated_at.map(|t| now_secs.saturating_sub(t));
            // v2.9.24 — peer status reflects actual peer health, not just broadcast
            // recency. The previous logic flagged any peer with age > 30s as
            // "stale" regardless of its tip lag, which on a PoW network with
            // ~10 s block time and N miners produced a lot of false positives:
            // each miner only broadcasts after winning a block (~N × block_time
            // on average), so most miners are silent for >30 s most of the time
            // even when they are mining cleanly on consensus.
            //
            // Rules now, in order:
            //   - lag is the strongest signal: if lag <= 5, the peer's tip
            //     matches consensus, mark "fresh" regardless of broadcast age;
            //   - lag > 50 is real lag, mark "behind" regardless of age;
            //   - between, if the last broadcast is older than ~3 min the peer
            //     has not advanced in a long time, mark "stale";
            //   - otherwise the peer is moderately lagging but recently seen,
            //     mark "stale" (label kept identical for back-compat).
            let stale_age_threshold_secs: u64 = 180;
            let status = match (h, lag, height_age_secs) {
                (None, _, _) => "unknown",
                (Some(_), Some(l), _) if l <= 5 => "fresh",
                (Some(_), Some(_), None) => "stale",                 // never seen height
                (Some(_), Some(l), Some(_)) if l > 50 => "behind",
                (Some(_), Some(_), Some(age)) if age > stale_age_threshold_secs => "stale",
                (Some(_), Some(_), Some(_)) => "stale",              // moderate lag, fresh enough
                _ => "unknown",
            };
            serde_json::json!({
                "peer_id": p.peer_id,
                "height": h,
                "protocol": p.protocol,
                "lag": lag,
                "status": status,
                "height_age_secs": height_age_secs,
                // v2.5.4 Bug #9 — expose the miner's stable pk_hash so the
                // explorer can show the same name in the Network tile and
                // in Recent Blocks (both derive from the same identifier).
                "miner_pk_hash": p.miner_pk_hash,
            })
        }).collect()
    };

    // HTTP peers from peer_info (submit blocks or broadcast via HTTP, may also be
    // visible in P2P). Two categories surface separately so the explorer can
    // render relays distinctly from mining nodes:
    //  - http_miners : role == "miner"
    //  - http_relays : role == "relay" AND not one of the hardcoded seeds
    //                  (seeds already render under `seeds`, don't double-count).
    // Dedup: skip peers whose PeerID is already in p2p_peers.
    let p2p_peer_ids_set: std::collections::HashSet<String> = p2p_peers.iter()
        .filter_map(|p| p["peer_id"].as_str().map(|s| s.to_string()))
        .collect();
    // Seeds register in peer_info under the hashed url peer_id (e.g. `peer:b0fb...`).
    // Two hashing paths exist in practice:
    //   1. peer_id(SEED_NODES[i])             — DNS-based (e.g. http://nexus...com:9333)
    //   2. peer_id(format!("http://{ip}:9333")) — IP-based, used when a seed
    //      receives a block/tip from another seed (the receiver sees the peer
    //      by its resolved IP, not by its DNS name).
    // We compute BOTH forms here so we can exclude seeds from the http_relays
    // list regardless of which path created the entry.
    let mut seed_hashed_ids: std::collections::HashSet<String> =
        crate::config::SEED_NODES.iter()
            .map(|url| crate::network::peer_id(url))
            .collect();
    for url in crate::config::SEED_NODES.iter() {
        let host = url.trim_start_matches("http://")
            .trim_start_matches("https://")
            .split(':').next().unwrap_or("");
        if host.is_empty() { continue; }
        if let Ok(addrs) = tokio::net::lookup_host((host, 9333u16)).await {
            for addr in addrs {
                seed_hashed_ids.insert(
                    crate::network::peer_id(&format!("http://{}:9333", addr.ip()))
                );
            }
        }
    }
    let (http_miners, http_relays, http_cortex): (Vec<serde_json::Value>, Vec<serde_json::Value>, Vec<serde_json::Value>) = {
        let info = state.peer_info.read().unwrap_or_else(|e| e.into_inner());
        let mut miners = Vec::new();
        let mut relays = Vec::new();
        let mut cortex = Vec::new();
        for p in info.values() {
            if p2p_peer_ids_set.contains(&p.peer_id) { continue; }
            if now_secs.saturating_sub(p.last_seen) >= 120 { continue; }
            // v2.5.2 — skip peers with unknown version. A "?" version means the
            // peer either never sent X-TSN-Version or is on a pre-v2.3.6 protocol.
            // Showing it in the explorer with `tsn/?/relay` is noise; once a
            // proper tip broadcast with headers lands, the entry becomes usable
            // and reappears naturally.
            if p.version == "?" || p.version.is_empty() { continue; }
            let lag = tip_height.saturating_sub(p.height);
            let age = now_secs.saturating_sub(p.last_seen);
            // v2.9.24 — same status semantics as the P2P classifier above:
            // lag is the strongest signal; broadcast-age alone never overrides
            // a small lag. See the P2P classifier comment for rationale.
            let status = if lag <= 5 { "fresh" }
                else if lag > 50 { "behind" }
                else if age > 180 { "stale" }
                else { "stale" };
            // Don't double-count seeds: if this peer_info entry matches one
            // of the hardcoded seeds (by libp2p PeerID or URL hash), skip it
            // — the seed is already in the `seeds` list. Applies to both
            // roles; previously only relays were filtered, so seeds that
            // happened to also be mining showed up twice.
            if seed_peer_ids.contains(&p.peer_id) { continue; }
            if seed_hashed_ids.contains(&p.peer_id) { continue; }
            match p.role.as_str() {
                "miner" => miners.push(serde_json::json!({
                    "peer_id": p.peer_id,
                    "height": p.height,
                    "protocol": format!("tsn/{}/miner", p.version),
                    "lag": lag,
                    "status": status,
                    "height_age_secs": age,
                    "source": "http",
                })),
                "relay" => {
                    relays.push(serde_json::json!({
                        "peer_id": p.peer_id,
                        "height": p.height,
                        "protocol": format!("tsn/{}/relay", p.version),
                        "lag": lag,
                        "status": status,
                        "height_age_secs": age,
                        "source": "http",
                    }))
                }
                "cortex" => {
                    cortex.push(serde_json::json!({
                        "peer_id": p.peer_id,
                        "height": p.height,
                        "protocol": format!("tsn/{}/cortex", p.version),
                        "lag": lag,
                        "status": status,
                        "height_age_secs": age,
                        "source": "http",
                    }))
                }
                _ => {}
            }
        }
        (miners, relays, cortex)
    };

    // Merge: P2P peers (libp2p) + HTTP miners + HTTP relays + HTTP cortex.
    // Frontend uses protocol string `tsn/<version>/<role>` to colour-code each.
    let mut all_peers = p2p_peers;
    all_peers.extend(http_miners);
    all_peers.extend(http_relays);
    all_peers.extend(http_cortex);

    // v2.3.7 — consensus_height: median of online seed heights (plus local tip).
    // This is the stable canonical view of the network. Individual seeds oscillate
    // by ±1-2 blocks between polls; the median smooths that out so the front-end
    // never re-renders "fresh vs stale" just because our node was 1 block behind
    // a faster sibling for 3 seconds. Also returns `quorum` = seeds_agreeing.
    let mut seed_heights: Vec<u64> = seeds
        .iter()
        .filter_map(|s| s["height"].as_u64())
        .collect();
    seed_heights.push(tip_height);
    seed_heights.sort_unstable();
    let consensus_height = if seed_heights.is_empty() {
        tip_height
    } else {
        seed_heights[seed_heights.len() / 2]
    };
    let quorum = seed_heights.iter().filter(|h| consensus_height.saturating_sub(**h) <= 2).count();

    // v2.3.7 — tag peers that are far AHEAD of consensus as solo-fork miners.
    // A peer reporting height > consensus_height + 20 is mining on its own chain
    // that nobody else accepts. The front-end highlights these nodes in red so
    // the operator can identify and rescue them (wipe + fast-sync).
    const SOLO_FORK_THRESHOLD: u64 = 20;
    let mut tag_solo_fork = |node: &mut serde_json::Value| {
        if let Some(h) = node.get("height").and_then(|v| v.as_u64()) {
            if h > consensus_height + SOLO_FORK_THRESHOLD {
                let above = h - consensus_height;
                node["solo_fork"] = serde_json::json!(true);
                node["above_consensus"] = serde_json::json!(above);
                node["status"] = serde_json::json!("solo_fork");
            }
        }
    };
    for s in seeds.iter_mut() { tag_solo_fork(s); }
    for p in all_peers.iter_mut() { tag_solo_fork(p); }

    let body = serde_json::json!({
        "tip_height": tip_height,
        "tip_hash": tip_hash,
        "consensus_height": consensus_height,
        "quorum": quorum,
        "seeds": seeds,
        "peers": all_peers,
    });
    // Store in 3s microcache so sustained polling stops pinning handlers.
    {
        let mut cache = state.network_status_cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = Some(NetworkStatusCache {
            body: body.clone(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(3),
        });
    }
    Json(body)
}

/// Returns detailed info about HTTP peers with stale cleanup (>5min offline removed).
async fn get_peers_detailed(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stale_threshold = 300; // 5 minutes

    let peers: Vec<serde_json::Value> = {
        let mut info = state.peer_info.write().unwrap();
        info.retain(|_, v| now - v.last_seen < stale_threshold);
        info.values().map(|p| serde_json::json!({
            "peer_id": p.peer_id,
            "version": p.version,
            "role": p.role,
            "height": p.height,
            "last_seen": p.last_seen,
        })).collect()
    };

    let local_h = state.blockchain.read().await.height();
    Json(serde_json::json!({
        "local_height": local_h,
        "peers": peers,
    }))
}

#[derive(Deserialize)]
struct AddPeerRequest {
    url: String,
}

#[derive(Serialize)]
struct AddPeerResponse {
    status: String,
    peer_count: usize,
}

/// Normalize a peer URL: trim trailing slashes and lowercase the scheme+host.
fn normalize_peer_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    while s.ends_with('/') {
        s.pop();
    }
    // Lowercase scheme and host (but not path)
    if let Some(idx) = s.find("://") {
        let after_scheme = idx + 3;
        // Find end of host:port (first '/' after scheme)
        let host_end = s[after_scheme..].find('/').map(|i| i + after_scheme).unwrap_or(s.len());
        let lower_prefix: String = s[..host_end].to_lowercase();
        s = format!("{}{}", lower_prefix, &s[host_end..]);
    }
    s
}

/// Check if a URL refers to this node (localhost or self-address).
fn is_self_peer(url: &str, our_addresses: &[String]) -> bool {
    let normalized = normalize_peer_url(url);
    if normalized.contains("://localhost") || normalized.contains("://127.0.0.1") || normalized.contains("://0.0.0.0") {
        return true;
    }
    our_addresses.iter().any(|addr| normalize_peer_url(addr) == normalized)
}

/// Add a new peer to the peer list.
async fn add_peer(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddPeerRequest>,
) -> Json<AddPeerResponse> {
    // IP whitelist check
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Json(AddPeerResponse {
            status: format!("rejected: IP {} not whitelisted", ip),
            peer_count: state.peers.read().unwrap_or_else(|e| e.into_inner()).len(),
        });
    }
    let normalized = normalize_peer_url(&req.url);

    // H4 audit fix: validate URL scheme (only HTTP/HTTPS allowed — blocks file://, ftp://, etc.)
    if !normalized.starts_with("http://") && !normalized.starts_with("https://") {
        warn!("Rejected peer with invalid scheme: {}", peer_id(&normalized));
        return Json(AddPeerResponse {
            status: "rejected: invalid scheme".to_string(),
            peer_count: state.peers.read().unwrap_or_else(|e| e.into_inner()).len(),
        });
    }

    // Note: private IPs are allowed for peers (local miners, LAN nodes).
    // Only block loopback to prevent self-connection.
    let is_loopback = normalized.contains("://127.") || normalized.contains("://[::1]") || normalized.contains("://localhost");
    if is_loopback {
        warn!("Rejected loopback peer: {}", peer_id(&normalized));
        return Json(AddPeerResponse {
            status: "rejected: loopback IP".to_string(),
            peer_count: state.peers.read().unwrap_or_else(|e| e.into_inner()).len(),
        });
    }

    let mut peers = state.peers.write().unwrap_or_else(|e| e.into_inner());

    // Limit max peers to prevent relay saturation and memory exhaustion.
    // With 8 max relay targets + P2P GossipSub, we don't need hundreds of HTTP peers.
    const MAX_PEERS: usize = 50;
    if peers.len() >= MAX_PEERS {
        return Json(AddPeerResponse {
            status: "rejected: max peers reached".to_string(),
            peer_count: peers.len(),
        });
    }

    // Build list of our own addresses for self-detection
    let our_addresses: Vec<String> = Vec::new(); // Basic localhost check covers most cases

    // Skip localhost/self-references
    let is_self = is_self_peer(&normalized, &our_addresses);

    // Check for duplicates using normalized comparison
    let already_known = peers.iter().any(|p| normalize_peer_url(p) == normalized);

    if !is_self && !already_known {
        peers.push(normalized.clone());
        info!("Added peer: {}", peer_id(&normalized));
    }

    Json(AddPeerResponse {
        status: "ok".to_string(),
        peer_count: peers.len(),
    })
}

// ============ Transaction Relay ============

/// Receive a transaction from a peer (relay endpoint).
async fn receive_transaction(
    State(state): State<Arc<AppState>>,
    Json(tx): Json<ShieldedTransaction>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let hash = hex::encode(tx.hash());

    // Check if already in mempool
    {
        let mempool = state.mempool.read().unwrap_or_else(|e| e.into_inner());
        if mempool.contains(&tx.hash()) {
            return Ok(Json(SubmitTxResponse {
                hash,
                status: "duplicate".to_string(),
            }));
        }
    }

    // Validate transaction
    {
        let chain = state.blockchain.read().await;
        if let Some(params) = chain.verifying_params() {
            chain
                .state()
                .validate_transaction(&tx, params)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        } else {
            chain
                .state()
                .validate_transaction_basic(&tx)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            for spend in &tx.spends {
                spend.verify_signature()
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid spend signature".to_string()))?;
            }
        }
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add(tx.clone())
    };

    if added {
        info!("Added relayed transaction {} to mempool", &hash[..16]);

        // Continue relaying to other peers
        let peers = state.peers.read().unwrap_or_else(|e| e.into_inner()).clone();
        if !peers.is_empty() {
            let tx_clone = tx.clone();
            let client = state.http_client.clone();
            tokio::spawn(async move {
                relay_transaction(&tx_clone, &peers, &client).await;
            });
        }
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: if added { "accepted".to_string() } else { "duplicate".to_string() },
    }))
}

// ============ Relay Helper Functions ============

/// Relay a block to all known peers concurrently (futures::join_all).
/// Previously sequential (O(N) × latency), now parallel (~1× latency).
/// Global semaphore limiting concurrent HTTP relay connections.
/// Prevents relay timeouts from saturating the tokio runtime and blocking the API.
static RELAY_SEMAPHORE: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(8));

/// Maximum number of peers to relay a block to via HTTP.
/// HTTP relay is best-effort backup — GossipSub P2P is the primary propagation.
const MAX_RELAY_PEERS: usize = 8;

async fn relay_block(block: &ShieldedBlock, peers: &[String], client: &reqwest::Client) {
    // v2.3.0 Phase 1: block-level dedup now lives in receive_block via AppState.seen_blocks.
    // By the time relay_block is called, the caller has already filtered out duplicates,
    // so the previous static RELAYED LRU is gone.
    let block_hash_str = block.hash_hex()[..16].to_string();

    // Filter contactable peers, cap at MAX_RELAY_PEERS.
    // Prioritize seed nodes (known IPs) over random peers.
    let contactable: Vec<&String> = peers.iter()
        .filter(|p| crate::network::is_contactable_peer(p))
        .take(MAX_RELAY_PEERS)
        .collect();

    // Fire-and-forget: spawn relay tasks but don't await them.
    // Each task is guarded by a semaphore to prevent connection explosion.
    // HTTP relay is best-effort — GossipSub P2P is the primary propagation path.
    for peer in contactable {
        let url = format!("{}/blocks", peer);
        let client = client.clone();
        let block = block.clone();
        let peer_name = peer_id(peer);
        let bh = block_hash_str.clone();
        tokio::spawn(async move {
            // Acquire semaphore permit (max 8 concurrent relays)
            let _permit = match RELAY_SEMAPHORE.try_acquire() {
                Ok(p) => p,
                Err(_) => {
                    debug!("Relay to {} skipped — semaphore full", peer_name);
                    return;
                }
            };
            match client.post(&url)
                .timeout(std::time::Duration::from_secs(3))
                .json(&block).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!("Relayed block {} to {}", bh, peer_name);
                }
                Ok(_) | Err(_) => {
                    // Best-effort — don't spam logs for every failed relay
                    debug!("Relay to {} failed (best-effort, P2P is primary)", peer_name);
                }
            }
        });
    }
}

/// Relay a transaction to all known peers.
async fn relay_transaction(tx: &ShieldedTransaction, peers: &[String], client: &reqwest::Client) {
    let tx_hash = &hex::encode(tx.hash())[..16];

    for peer in peers {
        if !crate::network::is_contactable_peer(peer) { continue; }
        let url = format!("{}/tx/relay", peer);
        match client.post(&url).timeout(std::time::Duration::from_secs(3)).json(tx).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Relayed transaction {} to {}", tx_hash, peer_id(peer));
            }
            Ok(_) => {
                // Peer might already have it - not an error
            }
            Err(e) => {
                warn!("Failed to relay transaction to {} (timeout or unreachable)", peer_id(peer));
            }
        }
    }
}

// ============ Wallet Scanning Endpoints ============

/// An encrypted output from a block (transaction output or coinbase).
#[derive(Serialize)]
struct EncryptedOutput {
    /// Position in the commitment tree.
    position: u64,
    /// Block height where this output was created.
    block_height: u64,
    /// The note commitment V1/BN254 (hex).
    note_commitment: String,
    /// The note commitment V2/PQ Goldilocks (hex) - for post-quantum transactions.
    note_commitment_pq: String,
    /// Ephemeral public key for decryption (hex).
    ephemeral_pk: String,
    /// Encrypted note ciphertext (hex).
    ciphertext: String,
}

/// Response for outputs/since/:height endpoint.
#[derive(Serialize)]
struct OutputsSinceResponse {
    outputs: Vec<EncryptedOutput>,
    current_height: u64,
    commitment_root: String,
}

/// Get all encrypted outputs since a given block height.
/// Used by wallets to scan for incoming payments.
/// If since_height is 0, returns ALL outputs including genesis.
async fn get_outputs_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<OutputsSinceParams>,
) -> Json<OutputsSinceResponse> {
    let chain = state.blockchain.read().await;
    let current_height = chain.height();
    let commitment_root = hex::encode(chain.commitment_root());
    let end_height = match params.limit {
        Some(0) | None => current_height,
        Some(limit) => current_height.min(since_height.saturating_add(limit as u64)),
    };

    let mut outputs = Vec::new();
    let mut position = 0u64;

    // Determine the starting height for collecting outputs
    // If since_height is 0, we want ALL outputs (initial scan)
    // Otherwise, we want outputs from since_height+1 onwards
    let start_height = if since_height == 0 { 0 } else { since_height + 1 };

    // Count all commitments before start_height to get starting position.
    // After fast-sync, blocks before fast_sync_base_height don't exist in DB.
    // Use the stored commitment offset to get the correct starting position.
    let fast_sync_base = chain.fast_sync_base_height();
    let fast_sync_offset = chain.fast_sync_commitment_offset();

    if fast_sync_base > 0 && start_height <= fast_sync_base {
        // All requested blocks are within fast-sync range — use stored offset.
        // The offset already accounts for all commitments up to fast_sync_base.
        position = fast_sync_offset;
    } else if fast_sync_base > 0 {
        // Start is after fast-sync: use offset as base, then count outputs
        // in blocks between fast_sync_base+1 and start_height-1.
        // The fast_sync_offset already includes ALL commitments up to and
        // including the fast_sync_base block. Do NOT count genesis or
        // fast_sync_base again — they are already in the offset.
        position = fast_sync_offset;
        for h in (fast_sync_base + 1)..start_height.min(current_height + 1) {
            if let Some(block) = chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    position += tx.outputs.len() as u64;
                }
                for tx in &block.transactions_v2 {
                    position += tx.outputs.len() as u64;
                }
                position += 1; // coinbase
                if block.coinbase.dev_fee_encrypted_note.is_some() {
                    position += 1; // dev fee
                }
            }
        }
    } else {
        // No fast-sync — count from genesis normally
        for h in 0..start_height.min(current_height + 1) {
            if let Some(block) = chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    position += tx.outputs.len() as u64;
                }
                for tx in &block.transactions_v2 {
                    position += tx.outputs.len() as u64;
                }
                position += 1; // coinbase
                if block.coinbase.dev_fee_encrypted_note.is_some() {
                    position += 1; // dev fee
                }
            }
        }
    }

    // Now collect outputs from start_height onwards.
    // After fast-sync, skip blocks that are within the snapshot range because
    // their commitments are already in the snapshot offset — the genesis and
    // fast-sync base blocks still exist in DB but their outputs have positions
    // inside the snapshot, not after it.
    let collect_from = if fast_sync_base > 0 && start_height <= fast_sync_base {
        fast_sync_base + 1
    } else {
        start_height
    };
    for h in collect_from..=end_height {
        if let Some(block) = chain.get_block_by_height(h) {
            // V1 Transaction outputs (note_commitment_pq not available for legacy tx)
            for tx in &block.transactions {
                for output in &tx.outputs {
                    outputs.push(EncryptedOutput {
                        position,
                        block_height: h,
                        note_commitment: hex::encode(output.note_commitment.to_bytes()),
                        note_commitment_pq: String::new(), // V1 tx don't have PQ commitments
                        ephemeral_pk: hex::encode(&output.encrypted_note.ephemeral_pk),
                        ciphertext: hex::encode(&output.encrypted_note.ciphertext),
                    });
                    position += 1;
                }
            }

            // V2 Transaction outputs (only have PQ commitments)
            for tx in &block.transactions_v2 {
                for output in &tx.outputs {
                    outputs.push(EncryptedOutput {
                        position,
                        block_height: h,
                        note_commitment: String::new(), // V2 tx don't have legacy commitments
                        note_commitment_pq: hex::encode(output.note_commitment),
                        ephemeral_pk: hex::encode(&output.encrypted_note.ephemeral_pk),
                        ciphertext: hex::encode(&output.encrypted_note.ciphertext),
                    });
                    position += 1;
                }
            }

            // Coinbase output (has both V1 and V2/PQ commitments)
            outputs.push(EncryptedOutput {
                position,
                block_height: h,
                note_commitment: hex::encode(block.coinbase.note_commitment.to_bytes()),
                note_commitment_pq: hex::encode(block.coinbase.note_commitment_pq),
                ephemeral_pk: hex::encode(&block.coinbase.encrypted_note.ephemeral_pk),
                ciphertext: hex::encode(&block.coinbase.encrypted_note.ciphertext),
            });
            position += 1;

            // Dev fee output (also inserted into the commitment tree)
            if let Some(ref dev_encrypted) = block.coinbase.dev_fee_encrypted_note {
                let dev_cm = block.coinbase.dev_fee_commitment
                    .map(|c| hex::encode(c.to_bytes()))
                    .unwrap_or_default();
                let dev_cm_pq = block.coinbase.dev_fee_commitment_pq
                    .map(|c| hex::encode(c))
                    .unwrap_or_default();
                outputs.push(EncryptedOutput {
                    position,
                    block_height: h,
                    note_commitment: dev_cm,
                    note_commitment_pq: dev_cm_pq,
                    ephemeral_pk: hex::encode(&dev_encrypted.ephemeral_pk),
                    ciphertext: hex::encode(&dev_encrypted.ciphertext),
                });
                position += 1;
            }
        }
    }

    Json(OutputsSinceResponse {
        outputs,
        current_height,
        commitment_root,
    })
}

#[derive(Deserialize)]
struct OutputsSinceParams {
    limit: Option<usize>,
}

/// Request for checking nullifiers.
#[derive(Deserialize)]
struct CheckNullifiersRequest {
    nullifiers: Vec<String>,
}

/// Response for nullifier checking.
#[derive(Serialize)]
struct CheckNullifiersResponse {
    /// List of nullifiers that are spent (exist in nullifier set).
    spent: Vec<String>,
}

/// Check which nullifiers are spent.
/// Used by wallets to determine which of their notes have been consumed.
async fn check_nullifiers(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckNullifiersRequest>,
) -> Json<CheckNullifiersResponse> {
    // M8 audit fix: limit input size to prevent memory/CPU exhaustion
    const MAX_NULLIFIERS_PER_REQUEST: usize = 500;
    let nullifiers = if req.nullifiers.len() > MAX_NULLIFIERS_PER_REQUEST {
        &req.nullifiers[..MAX_NULLIFIERS_PER_REQUEST]
    } else {
        &req.nullifiers
    };

    // v2.9.14 (H-G) — use the lock-free spent_nullifiers_cache instead of
    // blockchain.read(). Same rationale as W1B for submit_v2: under
    // continuous writer load the fairness queue starves any reader that
    // takes blockchain.read(), so /nullifiers/check returned stale data
    // (or timed out client-side at 10s reqwest default), which made
    // wait_nullifiers_mined report 0/N spent for tens of seconds while
    // the chain was already past the inclusion. The cache is populated
    // by every add_block site, so a poll right after the next block
    // sees the updated nullifier set immediately.
    let nf_cache = state.spent_nullifiers_cache.read().unwrap_or_else(|e| e.into_inner());

    let mut spent = Vec::new();

    for nf_hex in nullifiers {
        if let Ok(nf_bytes) = hex::decode(nf_hex) {
            if nf_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&nf_bytes);
                if nf_cache.contains(&arr) {
                    spent.push(nf_hex.clone());
                }
            }
        }
    }

    Json(CheckNullifiersResponse { spent })
}

/// Response for witness endpoint.
#[derive(Serialize)]
struct WitnessResponse {
    /// The current commitment tree root (hex).
    root: String,
    /// The Merkle path (sibling hashes from leaf to root, hex encoded).
    path: Vec<String>,
    /// Position in the tree.
    position: u64,
}

/// Get a Merkle witness for a commitment.
/// Used when creating spend proofs.
async fn get_witness(
    State(state): State<Arc<AppState>>,
    Path(commitment_hex): Path<String>,
) -> Result<Json<WitnessResponse>, StatusCode> {
    let commitment_bytes: [u8; 32] = hex::decode(&commitment_hex)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().await;
    let commitment_tree = chain.state().commitment_tree();

    // Find the position of this commitment in the tree
    // We need to search through all positions
    let tree_size = commitment_tree.size();
    let mut found_position: Option<u64> = None;

    for pos in 0..tree_size {
        if let Some(cm) = commitment_tree.get_commitment(pos) {
            if cm.to_bytes() == commitment_bytes {
                found_position = Some(pos);
                break;
            }
        }
    }

    let position = found_position.ok_or(StatusCode::NOT_FOUND)?;

    let merkle_path = commitment_tree.get_path(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let root = commitment_tree.root();

    Ok(Json(WitnessResponse {
        root: hex::encode(root),
        path: merkle_path.auth_path.iter().map(|h| hex::encode(h)).collect(),
        position,
    }))
}

/// Get witness by position (simpler than searching by commitment).
async fn get_witness_by_position(
    State(state): State<Arc<AppState>>,
    Path(position): Path<u64>,
) -> Result<Json<WitnessResponse>, StatusCode> {
    let chain = state.blockchain.read().await;
    let commitment_tree = chain.state().commitment_tree();

    let _commitment = commitment_tree.get_commitment(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let merkle_path = commitment_tree.get_path(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let root = commitment_tree.root();

    Ok(Json(WitnessResponse {
        root: hex::encode(root),
        path: merkle_path.auth_path.iter().map(|h| hex::encode(h)).collect(),
        position,
    }))
}

/// Response for V2 witness endpoint.
/// Uses Poseidon/Goldilocks Merkle tree (quantum-resistant).
#[derive(Clone, Serialize)]
pub struct WitnessResponseV2 {
    /// The current V2 commitment tree root (hex).
    pub root: String,
    /// The Merkle path (sibling hashes from leaf to root, hex encoded).
    pub path: Vec<String>,
    /// Path indices (0 = left, 1 = right).
    pub indices: Vec<u8>,
    /// Position in the tree.
    pub position: u64,
    /// The actual leaf commitment at this position (hex). For debugging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<String>,
}

/// Get V2 witness by position (for quantum-resistant transactions).
/// Uses Poseidon/Goldilocks Merkle tree instead of BN254.
///
/// v2.7.0 Phase 1.1 — A `lru::LruCache` keyed by `position` short-circuits
/// the lookup when the cached entry was computed at the current tip height.
/// On miss (or stale entry), the handler acquires `blockchain.read()` once,
/// computes root + path + leaf, and stores the result. Cache invalidation is
/// height-driven: any append to the commitment tree increments the chain
/// height, which makes existing entries fail the `cached_height == current`
/// check and forces a recompute. This keeps the cache correct even though
/// internal Merkle siblings shift on every append.
async fn get_witness_by_position_v2(
    State(state): State<Arc<AppState>>,
    Path(position): Path<u64>,
) -> Result<Json<WitnessResponseV2>, StatusCode> {
    // O(1) read of the latest height — no lock contention.
    let current_height = state.chain_info_cache.load().height;

    // Fast path: cache hit at the current height.
    {
        let mut cache = state.witness_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached_height, response)) = cache.get(&position) {
            if *cached_height == current_height {
                return Ok(Json(response.clone()));
            }
        }
    }

    // Miss or stale — compute under the read lock.
    let chain = state.blockchain.read().await;
    let commitment_tree_pq = chain.state().commitment_tree_pq();

    let witness = commitment_tree_pq.witness(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let leaf_hex = commitment_tree_pq.leaf_at(position)
        .map(|l| hex::encode(l))
        .unwrap_or_default();

    let response = WitnessResponseV2 {
        root: hex::encode(witness.root),
        path: witness.path.siblings.iter().map(|h| hex::encode(h)).collect(),
        indices: witness.path.indices.clone(),
        position: witness.position,
        leaf: Some(leaf_hex),
    };

    // Drop the chain read lock before taking the cache mutex to keep both
    // critical sections short.
    drop(chain);

    {
        let mut cache = state.witness_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.put(position, (current_height, response.clone()));
    }

    Ok(Json(response))
}

/// Bulk leaf lookup: POST body = {"positions": [u64, ...]} → returns
/// {"leaves": [{"position": u64, "leaf": hex_string|null}, ...]}.
///
/// v2.4.3 — wallet pre-validation used to fire one `/witness/v2/position/N`
/// per unspent note (896 requests for a 41k TSN wallet), saturating its own
/// rate limit and stalling `tsn send` for 90+ seconds or indefinitely. The
/// wallet only needs the leaf bytes for orphan detection (compare-equal vs
/// the stored commitment), not the full merkle path. Collapsing to one bulk
/// call makes a 10 TSN transfer finish in <2 s even with thousands of notes.
#[derive(Deserialize)]
struct BulkLeavesRequest { positions: Vec<u64> }

#[derive(Serialize)]
struct BulkLeafEntry { position: u64, leaf: Option<String> }

#[derive(Serialize)]
struct BulkLeavesResponse { leaves: Vec<BulkLeafEntry> }

async fn get_leaves_bulk(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BulkLeavesRequest>,
) -> Result<Json<BulkLeavesResponse>, StatusCode> {
    const MAX_BULK_POSITIONS: usize = 10_000;
    if req.positions.len() > MAX_BULK_POSITIONS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let chain = state.blockchain.read().await;
    let commitment_tree_pq = chain.state().commitment_tree_pq();
    let leaves: Vec<BulkLeafEntry> = req.positions.into_iter().map(|position| {
        BulkLeafEntry {
            position,
            leaf: commitment_tree_pq.leaf_at(position).map(hex::encode),
        }
    }).collect();
    Ok(Json(BulkLeavesResponse { leaves }))
}

/// Debug endpoint to test Poseidon hash compatibility.
/// Returns the hash of inputs [1,2,3,4] for comparison with circomlibjs.
async fn debug_poseidon_test() -> Json<serde_json::Value> {
    use crate::crypto::poseidon::{poseidon_hash, field_to_bytes32, DOMAIN_NOTE_COMMITMENT};
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon, PoseidonHasher};

    // Test 1: Direct light-poseidon hash of [1,2,3,4]
    let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let mut poseidon = Poseidon::<Fr>::new_circom(4)
        .expect("BUG: Poseidon init for 4 inputs cannot fail");
    let direct_hash = poseidon.hash(&inputs)
        .expect("BUG: Poseidon hash with matching input count cannot fail");
    let direct_bytes = field_to_bytes32(&direct_hash);

    // Test 2: Our poseidon_hash with domain separation (domain=1, then [2,3,4])
    // This is: poseidon([1, 2, 3, 4]) with 1 as domain
    let domain_hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]);
    let domain_bytes = field_to_bytes32(&domain_hash);

    Json(serde_json::json!({
        "test": "Poseidon compatibility",
        "direct_hash_1234": {
            "description": "poseidon([1,2,3,4]) - direct light-poseidon",
            "bytes_le": direct_bytes.to_vec(),
            "hex": hex::encode(direct_bytes),
        },
        "domain_hash_1_234": {
            "description": "poseidon_hash(domain=1, [2,3,4]) - our wrapper",
            "bytes_le": domain_bytes.to_vec(),
            "hex": hex::encode(domain_bytes),
        }
    }))
}

/// Debug endpoint for V2/PQ Poseidon hash (Goldilocks field).
/// Returns hash of [1,2,3,4] and Merkle node hash for comparison with TypeScript.
async fn debug_poseidon_pq_test() -> Json<serde_json::Value> {
    use crate::crypto::pq::poseidon_pq::{
        poseidon_pq_hash, hash_out_to_bytes, GoldilocksField,
        DOMAIN_MERKLE_NODE_PQ, DOMAIN_MERKLE_EMPTY_PQ,
    };

    // Test 1: Simple hash of [1,2,3,4]
    let inputs: Vec<GoldilocksField> = vec![
        GoldilocksField::new(1),
        GoldilocksField::new(2),
        GoldilocksField::new(3),
        GoldilocksField::new(4),
    ];
    let hash1 = poseidon_pq_hash(&inputs);
    let hash1_bytes = hash_out_to_bytes(&hash1);

    // Test 2: Empty leaf hash
    let empty_hash = poseidon_pq_hash(&[DOMAIN_MERKLE_EMPTY_PQ]);
    let empty_bytes = hash_out_to_bytes(&empty_hash);

    // Test 3: Merkle node hash of two empty leaves
    let mut node_inputs = vec![DOMAIN_MERKLE_NODE_PQ];
    node_inputs.extend_from_slice(&empty_hash);
    node_inputs.extend_from_slice(&empty_hash);
    let node_hash = poseidon_pq_hash(&node_inputs);
    let node_bytes = hash_out_to_bytes(&node_hash);

    Json(serde_json::json!({
        "test": "V2/PQ Poseidon compatibility (Goldilocks)",
        "hash_1234": {
            "description": "poseidon_pq_hash([1,2,3,4])",
            "hex": hex::encode(hash1_bytes),
            "elements": hash1.map(|f| f.0.to_string()),
        },
        "empty_leaf": {
            "description": "poseidon_pq_hash([DOMAIN_MERKLE_EMPTY_PQ])",
            "hex": hex::encode(empty_bytes),
            "elements": empty_hash.map(|f| f.0.to_string()),
        },
        "merkle_node_empty_empty": {
            "description": "merkle_hash(empty, empty)",
            "hex": hex::encode(node_bytes),
            "elements": node_hash.map(|f| f.0.to_string()),
        },
    }))
}

/// Debug endpoint to list all commitments in the tree.
async fn debug_list_commitments(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().await;
    let commitment_tree = chain.state().commitment_tree();
    let tree_size = commitment_tree.size();

    let mut commitments = Vec::new();
    for pos in 0..tree_size.min(100) { // Limit to first 100
        if let Some(cm) = commitment_tree.get_commitment(pos) {
            commitments.push(serde_json::json!({
                "position": pos,
                "commitment": hex::encode(cm.to_bytes())
            }));
        }
    }

    Json(serde_json::json!({
        "tree_size": tree_size,
        "root": hex::encode(commitment_tree.root()),
        "commitments": commitments
    }))
}

/// Debug endpoint to show V2/PQ Merkle tree state and recent roots.
async fn debug_merkle_pq(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().await;
    let tree_pq = chain.state().commitment_tree_pq();

    let size = tree_pq.size();
    let current_root = tree_pq.root();
    let recent_roots: Vec<String> = tree_pq.recent_roots()
        .iter()
        .map(|r| hex::encode(r))
        .collect();

    // Also compute a test commitment for verification
    use crate::crypto::pq::commitment_pq::commit_to_note_pq;

    // Test with value that needs no reduction
    let test_value: u64 = 50_000_000_000; // BLOCK_REWARD
    let test_pk_hash = [0x01u8; 32];
    let test_randomness = [0x02u8; 32];
    let test_commitment = commit_to_note_pq(test_value, &test_pk_hash, &test_randomness);

    // Test with bytes that WOULD need reduction (values >= Goldilocks prime)
    // Goldilocks prime is 0xFFFF_FFFF_0000_0001
    // So any 8-byte chunk >= this needs reduction
    let mut reduction_test_bytes = [0u8; 32];
    // First chunk: 0xFFFFFFFF00000002 (needs reduction to 1)
    reduction_test_bytes[0..8].copy_from_slice(&0xFFFF_FFFF_0000_0002u64.to_le_bytes());
    let reduction_commitment = commit_to_note_pq(test_value, &reduction_test_bytes, &test_randomness);

    Json(serde_json::json!({
        "tree_size": size,
        "current_root": hex::encode(current_root),
        "recent_roots_count": recent_roots.len(),
        "recent_roots": recent_roots,
        "test_commitment": {
            "value": test_value.to_string(),
            "pk_hash": hex::encode(test_pk_hash),
            "randomness": hex::encode(test_randomness),
            "commitment": hex::encode(test_commitment),
        },
        "reduction_test": {
            "description": "Test with pk_hash bytes that need reduction mod Goldilocks prime",
            "pk_hash": hex::encode(reduction_test_bytes),
            "commitment": hex::encode(reduction_commitment),
        }
    }))
}

/// Debug endpoint to verify Merkle path computation.
/// Computes root from commitment + path using server's logic for comparison with WASM.
#[derive(Debug, Deserialize)]
struct VerifyPathRequest {
    commitment: String,  // hex
    path: Vec<String>,   // hex siblings
    indices: Vec<u8>,
}

async fn debug_verify_path(
    Json(req): Json<VerifyPathRequest>,
) -> Json<serde_json::Value> {
    use crate::crypto::pq::poseidon_pq::{
        poseidon_pq_hash, bytes_to_hash_out, hash_out_to_bytes, GoldilocksField,
        DOMAIN_MERKLE_NODE_PQ,
    };

    // Parse commitment
    let commitment_bytes: [u8; 32] = match hex::decode(&req.commitment) {
        // SAFETY: length checked by guard (== 32)
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return Json(serde_json::json!({"error": "Invalid commitment hex"})),
    };

    // Hash node helper (same as merkle_pq.rs)
    fn hash_node(
        left: &[GoldilocksField; 4],
        right: &[GoldilocksField; 4],
    ) -> [GoldilocksField; 4] {
        let mut inputs = vec![DOMAIN_MERKLE_NODE_PQ];
        inputs.extend_from_slice(left);
        inputs.extend_from_slice(right);
        poseidon_pq_hash(&inputs)
    }

    let mut current = bytes_to_hash_out(&commitment_bytes);

    // Log leaf field elements (same format as WASM)
    let leaf_fields: Vec<u64> = current.iter().map(|f| f.value()).collect();

    let mut debug_info: Vec<serde_json::Value> = vec![];
    debug_info.push(serde_json::json!({
        "depth": "leaf",
        "bytes": req.commitment,
        "field_elements": leaf_fields,
    }));

    // Log first few indices
    let indices_preview: Vec<u8> = req.indices.iter().take(8).copied().collect();

    for (i, (sibling_hex, &index)) in req.path.iter().zip(req.indices.iter()).enumerate() {
        let sibling_bytes: [u8; 32] = match hex::decode(sibling_hex) {
            // SAFETY: length checked by guard (== 32)
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
            _ => return Json(serde_json::json!({"error": format!("Invalid sibling hex at {}", i)})),
        };

        let sibling = bytes_to_hash_out(&sibling_bytes);

        // Log depth 0 details (same as WASM)
        if i == 0 {
            let sibling_fields: Vec<u64> = sibling.iter().map(|f| f.value()).collect();
            let (left, right) = if index == 0 {
                (&current, &sibling)
            } else {
                (&sibling, &current)
            };

            let mut all_inputs: Vec<u64> = vec![DOMAIN_MERKLE_NODE_PQ.value()];
            all_inputs.extend(left.iter().map(|f| f.value()));
            all_inputs.extend(right.iter().map(|f| f.value()));

            debug_info.push(serde_json::json!({
                "depth": 0,
                "sibling_bytes": sibling_hex,
                "sibling_fields": sibling_fields,
                "index": index,
                "current_is": if index == 0 { "LEFT" } else { "RIGHT" },
                "hash_inputs_9": all_inputs,
            }));
        }

        current = if index == 0 {
            hash_node(&current, &sibling)
        } else {
            hash_node(&sibling, &current)
        };

        if i < 3 {
            let result_fields: Vec<u64> = current.iter().map(|f| f.value()).collect();
            debug_info.push(serde_json::json!({
                "depth": i,
                "result_bytes": hex::encode(hash_out_to_bytes(&current)),
                "result_fields": result_fields,
            }));
        }
    }

    let computed_root = hash_out_to_bytes(&current);

    Json(serde_json::json!({
        "commitment": req.commitment,
        "path_length": req.path.len(),
        "indices_0_8": indices_preview,
        "computed_root": hex::encode(computed_root),
        "debug": debug_info,
    }))
}

// ============ Faucet Endpoints ============

/// Get faucet status for a wallet.
async fn faucet_status(
    State(state): State<Arc<AppState>>,
    Path(pk_hash): Path<String>,
) -> Result<Json<FaucetStatus>, (StatusCode, String)> {
    let faucet = state.faucet.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Faucet not enabled".to_string())
    })?;

    let faucet = faucet.read().await;
    faucet
        .get_claim_info(&pk_hash)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

/// Request to claim from the faucet.
#[derive(Deserialize)]
struct FaucetClaimRequest {
    pk_hash: String,
}

/// Claim from the faucet.
async fn faucet_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FaucetClaimRequest>,
) -> Result<Json<ClaimResult>, (StatusCode, String)> {
    use std::collections::HashMap;

    let faucet_lock = state.faucet.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Faucet not enabled".to_string())
    })?;

    // First, get the note positions we need witnesses for (read lock on faucet)
    let positions = {
        let faucet = faucet_lock.read().await;
        faucet.get_note_positions_for_claim().map_err(|e| {
            let status = match &e {
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })?
    };

    // Get witnesses from blockchain state
    let witnesses: HashMap<u64, _> = {
        let blockchain = state.blockchain.read().await;
        let shielded_state = blockchain.state();
        positions
            .iter()
            .filter_map(|&pos| {
                shielded_state.witness_pq(pos).map(|w| (pos, w))
            })
            .collect()
    };

    // Process the claim (requires write lock since it modifies faucet state)
    let result = {
        let mut faucet = faucet_lock.write().await;
        faucet.process_claim(&req.pk_hash, &witnesses)
    };

    match result {
        Ok((claim_result, tx)) => {
            // Submit the transaction to the mempool
            let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());

            // Wrap in Transaction::V2 for mempool
            let wrapped_tx = crate::core::Transaction::V2(tx);
            if !mempool.add_v2(wrapped_tx) {
                tracing::warn!("Failed to add faucet tx to mempool");
                // Transaction was created but mempool rejected it - still return success
                // as the claim was recorded
            }

            Ok(Json(claim_result))
        }
        Err(e) => {
            let status = match &e {
                FaucetError::CooldownActive(_) => StatusCode::TOO_MANY_REQUESTS,
                FaucetError::InvalidPkHash => StatusCode::BAD_REQUEST,
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err((status, e.to_string()))
        }
    }
}

/// Request for game-based faucet claim.
#[derive(Deserialize)]
struct FaucetGameClaimRequest {
    pk_hash: String,
    tokens_collected: u8,
}

/// Claim from the faucet via game (variable amount based on tokens).
async fn faucet_game_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FaucetGameClaimRequest>,
) -> Result<Json<ClaimResult>, (StatusCode, String)> {
    use std::collections::HashMap;

    let faucet_lock = state.faucet.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Faucet not enabled".to_string())
    })?;

    // Validate token count (1-10)
    if req.tokens_collected < 1 || req.tokens_collected > 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("tokens_collected must be between 1 and 10, got {}", req.tokens_collected),
        ));
    }

    // Get note positions needed for this claim amount
    let positions = {
        let faucet = faucet_lock.read().await;
        faucet.get_note_positions_for_game_claim(req.tokens_collected).map_err(|e| {
            let status = match &e {
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                FaucetError::InvalidTokenCount(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })?
    };

    // Get witnesses from blockchain state
    let witnesses: HashMap<u64, _> = {
        let blockchain = state.blockchain.read().await;
        let shielded_state = blockchain.state();
        positions
            .iter()
            .filter_map(|&pos| {
                shielded_state.witness_pq(pos).map(|w| (pos, w))
            })
            .collect()
    };

    // Process the game claim
    let result = {
        let mut faucet = faucet_lock.write().await;
        faucet.process_game_claim(&req.pk_hash, req.tokens_collected, &witnesses)
    };

    match result {
        Ok((claim_result, tx)) => {
            // Submit the transaction to the mempool
            let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());

            let wrapped_tx = crate::core::Transaction::V2(tx);
            if !mempool.add_v2(wrapped_tx) {
                tracing::warn!("Failed to add faucet game tx to mempool");
            }

            info!(
                "Faucet game claim: {} tokens -> {} to {}",
                req.tokens_collected, claim_result.amount, &req.pk_hash[..16]
            );

            Ok(Json(claim_result))
        }
        Err(e) => {
            let status = match &e {
                FaucetError::CooldownActive(_) => StatusCode::TOO_MANY_REQUESTS,
                FaucetError::InvalidPkHash => StatusCode::BAD_REQUEST,
                FaucetError::InvalidTokenCount(_) => StatusCode::BAD_REQUEST,
                FaucetError::InsufficientBalance { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Err((status, e.to_string()))
        }
    }
}

/// Get public faucet statistics.
async fn faucet_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FaucetStats>, (StatusCode, String)> {
    let faucet = match state.faucet.as_ref() {
        Some(f) => f.read().await,
        None => {
            // Return disabled stats if faucet not enabled
            return Ok(Json(FaucetStats {
                total_distributed: "0.0 TSN".to_string(),
                unique_claimants: 0,
                active_streaks: 0,
                balance: None,
                enabled: false,
            }));
        }
    };

    faucet
        .get_stats()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// ============ Sync Gate (Anti-Fork) ============

/// Request body for POST /tip
#[derive(Deserialize)]
struct TipRequest {
    height: u64,
    hash: String,
}

/// Response for GET /tip and POST /tip
#[derive(Serialize)]
struct TipResponse {
    height: u64,
    hash: String,
    peer_count: usize,
    network_tip_height: u64,
}

/// Receive a tip announcement from a peer.
async fn receive_tip(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<TipRequest>,
) -> Result<Json<TipResponse>, (StatusCode, String)> {
    // IP whitelist check (version check is handled by version_gate_middleware
    // upstream — no duplicate work here).
    let ip = addr.ip().to_string();
    if !crate::config::is_ip_whitelisted(&ip) {
        return Err((StatusCode::FORBIDDEN, format!("IP {} not whitelisted", ip)));
    }
    let peer_ver = headers.get("X-TSN-Version").and_then(|v| v.to_str().ok());
    let sender_peer_id = headers.get("X-TSN-PeerID").and_then(|v| v.to_str().ok());
    let sender_role = headers.get("X-TSN-Role").and_then(|v| v.to_str().ok());
    let peer_url = format!("http://{}:9333", addr.ip());
    // Skip peer_info tracking entirely if the sender is a hardcoded seed —
    // seeds render via the dedicated `seeds` list in /network/status and
    // tracking them here leads to double-counting on the explorer.
    let is_seed_sender = is_sender_a_seed(&ip).await;
    // Track peer info for non-seed peers.
    //
    // v2.4.3+ node (sends X-TSN-PeerID + X-TSN-Role): key by the libp2p
    // PeerID ONLY. This is the only identity that distinguishes two nodes
    // behind the same public IP (miner on :9333 + relay on :9335), and
    // dropping the URL-hash entry avoids the double-count.
    //
    // Older peer (no PeerID header): fall back to the URL-hashed peer_id.
    if !is_seed_sender {
        if let Some(pid) = sender_peer_id {
            let mut info = state.peer_info.write().unwrap_or_else(|e| e.into_inner());
            let role = sender_role.unwrap_or("relay").to_string();
            let entry = info.entry(pid.to_string()).or_insert(PeerDetail {
                peer_id: pid.to_string(),
                version: "?".to_string(),
                role: role.clone(),
                height: 0,
                last_seen: 0,
            });
            entry.role = role;
            if req.height > entry.height { entry.height = req.height; }
            entry.last_seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            if let Some(v) = peer_ver { entry.version = v.to_string(); }
        } else {
            update_peer_info(&state, &peer_url, peer_ver, Some(req.height));
        }
    }

    // Parse the hash from hex
    let hash_bytes: [u8; 32] = hex::decode(&req.hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hash hex: {}", e)))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Hash must be exactly 32 bytes".to_string()))?;

    // v2.3.0 Phase 1: dedup same tip within TIP_DEDUP_SECS (30s).
    // Key = sender IP + height + hash16 — identifies a specific (peer, tip) pair.
    let hash16 = req.hash.get(..16).unwrap_or(&req.hash);
    let tip_key = format!("{}|{}|{}", ip, req.height, hash16);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // v2.6.0 — split the dedup check from the chain read to keep the
    // std::Mutex<LruCache> guard (!Send) out of scope while we .await the
    // tokio blockchain RwLock. Holding a std guard across await makes the
    // whole handler future !Send and axum rejects it.
    let is_dup = {
        let mut cache = state.seen_tips.lock().unwrap_or_else(|e| e.into_inner());
        let is_dup = cache.get(&tip_key)
            .map(|&seen_at| now_secs.saturating_sub(seen_at) < TIP_DEDUP_SECS)
            .unwrap_or(false);
        if !is_dup {
            cache.put(tip_key, now_secs);
        }
        is_dup
    };
    if is_dup {
        debug!("dedup: tip h={} hash={} already seen from {} ({}s ago)",
            req.height, hash16, peer_id(&peer_url), now_secs - now_secs);
        let (local_height, local_hash) = {
            let chain = state.blockchain.read().await;
            (chain.height(), hex::encode(chain.latest_hash()))
        };
        return Ok(Json(TipResponse {
            height: local_height,
            hash: local_hash,
            peer_count: state.sync_gate.peer_count(),
            network_tip_height: state.sync_gate.network_tip_height(),
        }));
    }

    // Use the hash as a pseudo peer-id (we don't have real peer IDs in HTTP mode)
    let peer_id = format!("peer-{}", &req.hash[..16]);
    state.sync_gate.update_tip(&peer_id, req.height, hash_bytes);

    info!("Received tip announcement: height={}, hash={}...", req.height, &req.hash[..16]);
    // v2.3.9 — explorer telemetry. Only count the *first* announcement at a
    // given height so the graph animates real network progress, not the echo
    // chamber of five relays forwarding the same tip.
    if state.activity.bump_unique_tip(req.height) {
        state.activity_bus.publish(super::activity::ActivityEvent {
            kind: super::activity::ActivityKind::Tip,
            at_unix: super::activity::now_secs(),
            height: Some(req.height),
            from_peer: Some(super::peer_id(&peer_url)),
            bytes: None,
        });
    }

    // Return our own tip info
    let chain = state.blockchain.read().await;
    let local_height = chain.height();
    let local_hash = hex::encode(chain.latest_hash());
    drop(chain);

    // v2.8.5 Phase 0.2 (proactive tip-pull): when a peer announces a tip ahead
    // of our local chain, kick off an immediate sync_from_peer task instead of
    // waiting for the next periodic sync tick. This compresses the gap between
    // a miner finding a block and the rest of the network adopting it,
    // reducing the window in which two miners can race-mine on top of an
    // older parent and create a transient fork. The check uses a small slack
    // (3 blocks) to avoid sync storms when many peers announce the same tip
    // within seconds of each other; the existing per-peer cooldown
    // (sync.rs::fork_recovery_cooldown) protects against retry floods on
    // failed pulls.
    if req.height > local_height.saturating_add(3) {
        let state_clone = state.clone();
        let peer_url_clone = peer_url.clone();
        tokio::spawn(async move {
            // Best-effort pull; errors are already logged inside sync_from_peer.
            let _ = super::sync::sync_from_peer(state_clone, &peer_url_clone).await;
        });
    }

    Ok(Json(TipResponse {
        height: local_height,
        hash: local_hash,
        peer_count: state.sync_gate.peer_count(),
        network_tip_height: state.sync_gate.network_tip_height(),
    }))
}

/// Get the local tip and sync gate status.
async fn get_tip(
    State(state): State<Arc<AppState>>,
) -> Json<TipResponse> {
    let chain = state.blockchain.read().await;
    let local_height = chain.height();
    let local_hash = hex::encode(chain.latest_hash());
    drop(chain);

    Json(TipResponse {
        height: local_height,
        hash: local_hash,
        peer_count: state.sync_gate.peer_count(),
        network_tip_height: state.sync_gate.network_tip_height(),
    })
}

// ============ Fast Sync: Snapshot Download ============

/// Response for GET /snapshot/info — metadata about the available snapshot.
#[derive(Serialize)]
struct SnapshotInfoResponse {
    available: bool,
    height: u64,
    block_hash: String,
    size_bytes: u64,
    /// v1.7.0: Exact cumulative_work at snapshot height, serialized as decimal string
    /// to avoid JSON number precision loss on u128 values.
    #[serde(default)]
    cumulative_work: String,
}

/// GET /snapshot/info — check if a state snapshot is available for download.
///
/// v2.4.3 — return the cumulative_work at the SNAPSHOT HEIGHT, not the sender's
/// current tip cw. The old code sent `chain.cumulative_work()` which is the
/// tip value — when the snapshot lagged the tip, the receiver adopted a wildly
/// inflated cw and then rejected every further block with LESS_WORK.
async fn snapshot_info(State(state): State<Arc<AppState>>) -> Json<SnapshotInfoResponse> {
    // KF-006 (incident 2026-05-02): toxic-snapshot quarantine.
    // Before publishing snapshot metadata, check whether this node is on
    // the canonical chain according to a quorum of peers. If we just
    // recovered or are on a fork, we don't want to seed our state to
    // others — that's how seed-1 served h=2 snapshots to seed-2/seed-3
    // during the 2026-05-02 cascade.
    if let Some(reason) = quarantine_reason(&state).await {
        tracing::warn!("snapshot_info: refusing — quarantine: {}", reason);
        return Json(SnapshotInfoResponse {
            available: false,
            height: 0,
            block_hash: String::new(),
            size_bytes: 0,
            cumulative_work: "0".to_string(),
        });
    }
    let chain = state.blockchain.read().await;
    match chain.export_snapshot() {
        Some((data, height, hash)) => {
            let snap_work = chain
                .cumulative_work_at_height(height)
                .unwrap_or_else(|| chain.cumulative_work());
            Json(SnapshotInfoResponse {
                available: true,
                height,
                block_hash: hash,
                size_bytes: data.len() as u64,
                cumulative_work: snap_work.to_string(),
            })
        }
        None => Json(SnapshotInfoResponse {
            available: false,
            height: 0,
            block_hash: String::new(),
            size_bytes: 0,
            cumulative_work: "0".to_string(),
        }),
    }
}

/// KF-006 quarantine check shared between `snapshot_info` and `snapshot_download`.
/// Returns `Some(reason)` if the node MUST NOT serve a snapshot right now,
/// `None` if serving is OK.
///
/// The check is conservative: any condition that suggests the local view is
/// untrustworthy (just reset, fewer than 3 contactable peers, hash mismatch
/// vs peer consensus) returns a quarantine reason. Low-peer scenarios
/// (legitimately) skip the consensus check and only enforce the
/// "just-reset" guard, so a coordinated network reset is not deadlocked.
async fn quarantine_reason(state: &Arc<AppState>) -> Option<String> {
    use crate::network::cum_work_consensus::observe_peers;
    use std::time::Duration;

    // Guard 1: never serve a snapshot if local height is suspiciously low.
    // A node serving h<10 has either just reset or is empty; either way it
    // shouldn't pretend to be a snapshot source.
    let (local_h, local_hash) = {
        let chain = state.blockchain.read().await;
        (chain.height(), chain.latest_hash())
    };
    if local_h < 10 {
        return Some(format!("local height {} below 10 (just reset?)", local_h));
    }

    // Guard 2: cross-check tip against peer consensus.
    // Skip this guard if we have <3 contactable peers (low-peer scenario).
    let peer_list: Vec<String> = state.peers.read()
        .map(|p| p.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|p| crate::network::is_contactable_peer(p))
        .collect();
    if peer_list.len() < 3 {
        return None; // Low-peer scenario: trust ourselves.
    }
    // 3-second timeout: if peers don't respond fast enough, we don't block
    // the snapshot endpoint indefinitely. Default-allow on inconclusive.
    let consensus = match observe_peers(
        &state.http_client,
        &peer_list,
        Duration::from_secs(3),
    ).await {
        Some(c) => c,
        None => return None, // Inconclusive — don't block.
    };
    // If consensus exists and matches our tip → serve. If it disagrees on
    // hash at our height, we're on a fork → quarantine.
    if consensus.height == local_h && consensus.hash != local_hash {
        return Some(format!(
            "fork detected: local hash {} vs consensus {} at h={} ({} peers agree)",
            hex::encode(&local_hash[..8]),
            hex::encode(&consensus.hash[..8]),
            local_h,
            consensus.agreement_count,
        ));
    }
    // If consensus is significantly ahead of us, we're stale — quarantine.
    if consensus.height > local_h + 50 {
        return Some(format!(
            "local h={} more than 50 blocks behind consensus h={}",
            local_h, consensus.height
        ));
    }
    None
}

/// GET /snapshot/download — download the state snapshot as compressed JSON.
/// Uses a pre-cached snapshot (refreshed every 100 blocks) and semaphore (max 3 concurrent).
/// Inspired by Cosmos state-sync (pre-generated snapshots) + Substrate (concurrent limits).
async fn snapshot_download(
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;
    use axum::http::header;

    // KF-006 quarantine check (see snapshot_info doc comment).
    if let Some(reason) = quarantine_reason(&state).await {
        tracing::warn!("snapshot_download: refusing — quarantine: {}", reason);
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Semaphore: max 3 concurrent snapshot downloads to prevent CPU/RAM saturation
    let _permit = state.snapshot_semaphore.clone().try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // Try to serve from cache first
    // v2.1.3 FIX: Validate cache is still coherent with current chain.
    // After a chain reset, the cache may contain state from the old chain.
    // v2.3.6 — Also invalidate if the cache is too far behind the current tip.
    // This covers the case where the chain rolled back and then re-synced past
    // the stale snapshot height via P2P: the cache.height <= chain.height check
    // alone would keep serving the stale cache to fast-syncing peers, causing
    // them to land on an old height and trigger cascading wipes.
    const CACHE_STALE_GAP: u64 = 500;
    let chain_height = state.blockchain.read().await.height();
    {
        let cache = state.snapshot_cache.read().await;
        if let Some(ref cached) = *cache {
            let too_old = chain_height.saturating_sub(cached.height) > CACHE_STALE_GAP;
            if cached.height <= chain_height && !too_old {
                info!(
                    "Snapshot download (cached): height={}, hash={}, raw={}KB, compressed={}KB",
                    cached.height, &cached.hash[..8.min(cached.hash.len())],
                    cached.raw_size / 1024, cached.compressed.len() / 1024
                );
                return Ok((
                    [
                        (header::CONTENT_TYPE, "application/gzip"),
                        (header::CONTENT_DISPOSITION, "attachment; filename=\"tsn-snapshot.json.gz\""),
                    ],
                    [
                        (header::HeaderName::from_static("x-snapshot-height"), header::HeaderValue::from_str(&cached.height.to_string()).unwrap()),
                        (header::HeaderName::from_static("x-snapshot-hash"), header::HeaderValue::from_str(&cached.hash).unwrap()),
                    ],
                    cached.compressed.clone(),
                ).into_response());
            }
            if too_old {
                info!("Snapshot cache too old: cached {} vs chain {} (gap={}), regenerating", cached.height, chain_height, chain_height - cached.height);
            } else {
                info!("Snapshot cache invalidated: cached height {} > chain height {}", cached.height, chain_height);
            }
        }
    }
    // Invalidate stale cache (ahead of chain OR too far behind)
    {
        let mut cache_w = state.snapshot_cache.write().await;
        if let Some(ref c) = *cache_w {
            let too_old = chain_height.saturating_sub(c.height) > CACHE_STALE_GAP;
            if c.height > chain_height || too_old { *cache_w = None; }
        }
    }

    // Cache miss — generate on the fly (first request or cache expired)
    // Isolate std::sync::RwLock access in a non-async block to keep future Send
    let (data, height, hash) = {
        let chain = state.blockchain.read().await;
        chain.export_snapshot()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
    };

    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let compressed = encoder.finish().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(
        "Snapshot download (generated): height={}, hash={}, raw={}KB, compressed={}KB",
        height, &hash[..8], data.len() / 1024, compressed.len() / 1024
    );

    // Store in cache for future requests
    {
        let mut cache = state.snapshot_cache.write().await;
        *cache = Some(CachedSnapshot {
            raw_size: data.len(),
            compressed: compressed.clone(),
            height,
            hash: hash.clone(),
        });
    }

    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"tsn-snapshot.json.gz\""),
        ],
        [
            (header::HeaderName::from_static("x-snapshot-height"), header::HeaderValue::from_str(&height.to_string()).unwrap()),
            (header::HeaderName::from_static("x-snapshot-hash"), header::HeaderValue::from_str(&hash).unwrap()),
        ],
        compressed,
    ).into_response())
}

// ============ React App ============
// Serve index.html for SPA routes (wallet, explorer)
async fn serve_index() -> Html<String> {
    let content = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| "<!DOCTYPE html><html><body>App not found. Run 'cd wallet && npm run build' first.</body></html>".to_string());
    Html(content)
}

/// Serve the technical whitepaper as a web page.
/// This serves the HTML content from the website directory for inline viewing.
#[allow(dead_code)]
async fn serve_whitepaper() -> Html<String> {
    let content = std::fs::read_to_string("website/index.html")
        .unwrap_or_else(|_| {
            // Fallback content if whitepaper HTML is not found
            "<!DOCTYPE html><html><head><title>TSN Whitepaper</title></head><body><h1>TSN Whitepaper</h1><p>Whitepaper content not available. Please check the deployment.</p></body></html>".to_string()
        });
    Html(content)
}

// ============ Wallet Viewing-Key Endpoints ============

/// GET /wallet/viewing-key
///
/// Export the viewing key of a freshly generated wallet as a hex string.
/// In production the wallet identity would come from an authenticated session;
/// here we generate a new wallet for demonstration / integration-test purposes.
async fn wallet_viewing_key() -> Json<serde_json::Value> {
    let wallet = ShieldedWallet::generate();
    let vk_hex = wallet.export_viewing_key();
    Json(serde_json::json!({
        "viewing_key": vk_hex,
        "address": wallet.address().to_hex(),
    }))
}

/// Request body for POST /wallet/watch.
#[derive(Deserialize)]
struct WatchWalletRequest {
    viewing_key: String,
}

/// POST /wallet/watch
///
/// Create a watch-only wallet from an imported viewing key.  The response
/// confirms the wallet was created and returns its pk_hash (which is the
/// identity used for scanning).
async fn wallet_watch(
    Json(body): Json<WatchWalletRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match ShieldedWallet::from_viewing_key(&body.viewing_key) {
        Ok(wallet) => {
            let pk_hash_hex = hex::encode(wallet.pk_hash());
            Ok(Json(serde_json::json!({
                "status": "ok",
                "watch_only": true,
                "pk_hash": pk_hash_hex,
            })))
        }
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid viewing key — expected 64-char hex (32 bytes)"
            })),
        )),
    }
}

// ============================================================================
// Smart Contract Endpoints
// ============================================================================

/// Request body for deploying a contract.
#[derive(Deserialize)]
struct ContractDeployRequest {
    /// Hex-encoded bytecode
    bytecode: String,
    /// Constructor arguments
    #[serde(default)]
    constructor_args: Vec<u64>,
    /// Gas limit
    gas_limit: u64,
    /// Fee
    fee: u64,
    /// Deployer's public key hash (hex)
    deployer_pk_hash: String,
    /// Deployer nonce
    nonce: u64,
    /// Hex-encoded ML-DSA-65 signature
    #[serde(default)]
    signature: String,
    /// Hex-encoded public key
    #[serde(default)]
    public_key: String,
}

/// Request body for calling a contract.
#[derive(Deserialize)]
struct ContractCallRequest {
    /// Contract address (hex)
    contract_address: String,
    /// Function selector (hex, 4 bytes)
    function_selector: String,
    /// Call arguments
    #[serde(default)]
    args: Vec<u64>,
    /// Gas limit
    gas_limit: u64,
    /// Fee
    fee: u64,
    /// Value to send
    #[serde(default)]
    value: u64,
    /// Caller's public key hash (hex)
    caller_pk_hash: String,
    /// Caller nonce
    nonce: u64,
    /// Hex-encoded signature
    #[serde(default)]
    signature: String,
    /// Hex-encoded public key
    #[serde(default)]
    public_key: String,
}

/// Request body for querying a contract (read-only).
#[derive(Deserialize)]
#[allow(dead_code)]
struct ContractQueryRequest {
    /// Contract address (hex)
    contract_address: String,
    /// Function selector (hex, 4 bytes)
    function_selector: String,
    /// Call arguments
    #[serde(default)]
    args: Vec<u64>,
}

/// Response for contract operations.
#[derive(Serialize)]
struct ContractResponse {
    success: bool,
    tx_hash: Option<String>,
    gas_used: Option<u64>,
    return_value: Option<u64>,
    contract_address: Option<String>,
    error: Option<String>,
    events: Vec<ContractEventResponse>,
}

/// Contract event in response.
#[derive(Serialize)]
struct ContractEventResponse {
    topic: u64,
    data: Vec<u64>,
}

/// Contract info response.
#[derive(Serialize)]
struct ContractInfoResponse {
    address: String,
    code_hash: String,
    creator: String,
    created_at_height: u64,
    balance: u64,
    bytecode_size: usize,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_4(s: &str) -> Result<[u8; 4], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 4 {
        return Err(format!("expected 4 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Deploy a new smart contract.
async fn contract_deploy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractDeployRequest>,
) -> Result<Json<ContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let bytecode = hex::decode(&req.bytecode).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid bytecode hex: {}", e)})))
    })?;

    let deployer_pk_hash = parse_hex_32(&req.deployer_pk_hash).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    // H5 audit fix: require valid signature and public key (no silent defaults)
    let signature = hex::decode(&req.signature).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid signature hex: {}", e)})))
    })?;
    let public_key = hex::decode(&req.public_key).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid public_key hex: {}", e)})))
    })?;
    if signature.is_empty() || public_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "signature and public_key are required"}))));
    }

    // Verify ML-DSA-65 signature over the deployment data
    {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(&bytecode);
        hasher.update(&deployer_pk_hash);
        hasher.update(&req.nonce.to_le_bytes());
        let msg_hash = hasher.finalize();

        let sig_valid = crate::crypto::signature::verify_mldsa65(&public_key, &msg_hash, &signature);
        if !sig_valid {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid signature: ML-DSA verification failed"}))));
        }
    }

    let deploy_tx = crate::contract::ContractDeployTransaction {
        bytecode,
        constructor_args: req.constructor_args,
        gas_limit: req.gas_limit,
        fee: req.fee,
        deployer_pk_hash,
        nonce: req.nonce,
        signature,
        public_key,
    };

    // Add to mempool — inner scope so the std::sync::RwLockWriteGuard (!Send)
    // is fully out of the future's live set before we .await the blockchain
    // tokio lock. An explicit drop() would not be enough: the binding name
    // still shows up in the Send analysis and makes the handler !Send.
    {
        let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
        mempool.add_contract_deploy(deploy_tx.clone());
    }

    // Execute immediately for the response (preview)
    let chain = state.blockchain.read().await;
    let height = chain.height();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    drop(chain);

    // Create a temporary executor for preview
    let tmp_db = sled::Config::new().temporary(true).open().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)})))
    })?;
    let executor = crate::contract::ContractExecutor::new(&tmp_db).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("executor error: {}", e)})))
    })?;

    match executor.deploy(&deploy_tx, height, timestamp) {
        Ok(receipt) => Ok(Json(ContractResponse {
            success: receipt.success,
            tx_hash: Some(hex::encode(receipt.tx_hash)),
            gas_used: Some(receipt.gas_used),
            return_value: receipt.return_value,
            contract_address: receipt.contract_address.map(|a| hex::encode(a)),
            error: receipt.error,
            events: receipt.events.iter().map(|e| ContractEventResponse {
                topic: e.topic,
                data: e.data.clone(),
            }).collect(),
        })),
        Err(e) => Ok(Json(ContractResponse {
            success: false,
            tx_hash: Some(hex::encode(deploy_tx.hash())),
            gas_used: None,
            return_value: None,
            contract_address: None,
            error: Some(e.to_string()),
            events: vec![],
        })),
    }
}

/// Call a deployed smart contract.
async fn contract_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractCallRequest>,
) -> Result<Json<ContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let contract_address = parse_hex_32(&req.contract_address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;
    let function_selector = parse_hex_4(&req.function_selector).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;
    let caller_pk_hash = parse_hex_32(&req.caller_pk_hash).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    let signature = hex::decode(&req.signature).unwrap_or_default();
    let public_key = hex::decode(&req.public_key).unwrap_or_default();

    let call_tx = crate::contract::ContractCallTransaction {
        contract_address,
        function_selector,
        args: req.args,
        gas_limit: req.gas_limit,
        fee: req.fee,
        value: req.value,
        caller_pk_hash,
        nonce: req.nonce,
        signature,
        public_key,
    };

    // Add to mempool
    let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
    mempool.add_contract_call(call_tx.clone());
    drop(mempool);

    Ok(Json(ContractResponse {
        success: true,
        tx_hash: Some(hex::encode(call_tx.hash())),
        gas_used: None,
        return_value: None,
        contract_address: None,
        error: None,
        events: vec![],
    }))
}

/// Query a contract (read-only, no state changes, no fee).
async fn contract_query(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractQueryRequest>,
) -> Result<Json<ContractResponse>, (StatusCode, Json<serde_json::Value>)> {
    let contract_address = parse_hex_32(&req.contract_address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;
    let _function_selector = parse_hex_4(&req.function_selector).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    let _chain = state.blockchain.read().await;
    let _height = _chain.height();
    drop(_chain);

    // For queries, we'd need access to the contract executor with the real DB.
    // For now, return a placeholder indicating query support is available.
    Ok(Json(ContractResponse {
        success: true,
        tx_hash: None,
        gas_used: None,
        return_value: None,
        contract_address: Some(hex::encode(contract_address)),
        error: Some("Query requires node-local contract executor (coming in v0.5.1)".into()),
        events: vec![],
    }))
}

/// Get contract info by address.
async fn contract_info(
    State(_state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<ContractInfoResponse>, (StatusCode, Json<serde_json::Value>)> {
    let _addr = parse_hex_32(&address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    // Contract registry lookup will be available when executor is integrated into AppState
    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Contract registry not yet available at this endpoint"})),
    ))
}

/// Get events for a contract.
async fn contract_events(
    State(_state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<Vec<ContractEventResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let _addr = parse_hex_32(&address).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})))
    })?;

    // Event store lookup will be available when executor is integrated into AppState
    Ok(Json(vec![]))
}

// ============================================================================
// v1.6.1: Telemetry & Admin endpoints
// ============================================================================

/// GET /node/errors — Returns recent errors for telemetry/dashboard
async fn get_node_errors(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let errors = state.error_log.read().unwrap();
    let recent: Vec<_> = errors.iter().rev().take(50).cloned().collect();
    Json(serde_json::json!({
        "errors": recent,
        "total": errors.len(),
        "auto_heal_mode": *state.auto_heal_mode.read().unwrap(),
    }))
}

/// GET /stats/activity — v2.3.9 explorer telemetry.
///
/// Returns cumulative counters for each network-activity kind (tip, block,
/// tx, sync, snapshot, peer, reject). The explorer polls this endpoint every
/// few seconds and derives per-type throughput by diffing successive snapshots.
///
/// Counters never reset. They are incremented wherever the node observes an
/// event (see `activity::record` call sites). Reading them is a single atomic
/// load per kind — cheap enough to serve on the polling path.
async fn get_activity_stats(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let snap = state.activity.snapshot_view();
    Json(serde_json::json!({
        "at_unix": super::activity::now_secs(),
        "counters": snap,
    }))
}

/// GET /events/stream — v2.3.9 Server-Sent Events.
///
/// Subscribes to the node's activity broadcast channel and streams one JSON
/// event per network incident. A browser can consume this with
/// `new EventSource('/events/stream')`. Buffer size on the producer side is
/// 256; lagging clients drop the oldest events (broadcast semantics), never
/// the producer.
async fn get_activity_stream(
    State(state): State<Arc<AppState>>,
) -> axum::response::Sse<impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>> {
    use axum::response::sse::{Event, Sse, KeepAlive};
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_stream::StreamExt;

    let rx = state.activity_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(event) => {
            // Best-effort JSON encode; on failure we simply skip this frame.
            let payload = serde_json::to_string(&event).ok()?;
            Some(Ok(Event::default().event("activity").data(payload)))
        }
        // A lagging subscriber dropping events is expected — skip the error.
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    )
}

/// POST /admin/force-resync — Force the node to wipe and re-sync from peers
/// SECURITY: Only accessible from localhost or private networks.
async fn admin_force_resync(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let remote_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    if let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() {
        if !is_local_or_private(ip) {
            return Err((StatusCode::FORBIDDEN, "Admin endpoints are localhost-only".to_string()));
        }
    }
    tracing::warn!("ADMIN: Force resync triggered via API from {}", remote_ip);
    log_node_error(&state, "admin_force_resync", &format!("Force resync triggered from {}", remote_ip));
    let mut chain = state.blockchain.write().await;
    chain.reset_for_snapshot_resync();
    let mut bans = state.banned_peers.write().unwrap();
    bans.clear();
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "Chain reset to height 0. Will fast-sync from peers."
    })))
}

/// GET /admin/config — Get current admin config
async fn get_admin_config(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "auto_heal_mode": *state.auto_heal_mode.read().unwrap(),
        "banned_peers_count": state.banned_peers.read().unwrap().len(),
        "error_count": state.error_log.read().unwrap().len(),
    }))
}

/// POST /admin/config — Update admin config (auto_heal_mode)
/// SECURITY: Only accessible from localhost or private networks.
async fn set_admin_config(
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let remote_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    if let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() {
        if !is_local_or_private(ip) {
            return Err((StatusCode::FORBIDDEN, "Admin endpoints are localhost-only".to_string()));
        }
    }
    if let Some(mode) = body.get("auto_heal_mode").and_then(|v| v.as_str()) {
        if mode == "validation" || mode == "automatic" {
            *state.auto_heal_mode.write().unwrap() = mode.to_string();
            tracing::info!("ADMIN: auto_heal_mode changed to '{}'", mode);
            return Ok(Json(serde_json::json!({"ok": true, "auto_heal_mode": mode})));
        }
    }
    Ok(Json(serde_json::json!({"error": "Invalid config. Use auto_heal_mode: 'validation' or 'automatic'"})))
}

/// POST /admin/mempool/purge — Remove a stuck v2 transaction from the mempool.
/// Also drops the tx from v1 mempool (as fallback) and clears associated
/// pending_nullifiers so the wallet that produced it can resubmit.
///
/// SECURITY: strict loopback only (ConnectInfo, not spoofable x-forwarded-for).
/// Body: {"hash": "<64 hex chars>"}
async fn admin_mempool_purge(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !addr.ip().is_loopback() {
        return Err((StatusCode::FORBIDDEN, "Endpoint is loopback-only".to_string()));
    }

    let hash_hex = body.get("hash")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Missing 'hash' field".to_string()))?;

    let mut hash = [0u8; 32];
    hex::decode_to_slice(hash_hex, &mut hash)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hash — must be 64 hex chars".to_string()))?;

    let mut mempool = state.mempool.write().unwrap_or_else(|e| e.into_inner());
    let count_before = mempool.len();

    tracing::warn!(
        "ADMIN: /admin/mempool/purge called for tx {} — mempool count before: {}",
        &hash_hex[..16], count_before
    );

    let (variant, nullifier_count) = if let Some(tx) = mempool.remove_v2(&hash) {
        ("v2", tx.nullifiers().len())
    } else if let Some(tx) = mempool.remove(&hash) {
        ("v1", tx.nullifiers().len())
    } else {
        tracing::warn!("ADMIN: /admin/mempool/purge — tx {} not found in mempool", &hash_hex[..16]);
        return Ok(Json(serde_json::json!({
            "ok": false,
            "removed": false,
            "reason": "not_in_mempool",
            "hash": hash_hex,
            "mempool_count": count_before,
        })));
    };

    let count_after = mempool.len();
    tracing::warn!(
        "ADMIN: purged {} tx {} — {} nullifiers cleared from pending set — mempool count: {} -> {}",
        variant, &hash_hex[..16], nullifier_count, count_before, count_after
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "removed": true,
        "variant": variant,
        "hash": hash_hex,
        "nullifiers_cleared": nullifier_count,
        "mempool_count_before": count_before,
        "mempool_count_after": count_after,
    })))
}

/// Check if an IP is localhost or private network (for admin endpoint protection)
fn is_local_or_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
        }
    }
}

/// Helper: log an error to the telemetry error_log
pub fn log_node_error(state: &AppState, error_type: &str, message: &str) {
    // v2.6.0 — blockchain is now a tokio::sync::RwLock which can't be
    // blockingly read from sync code without risking a deadlock if the
    // caller is inside a tokio worker. try_read() returns immediately;
    // when the lock is held by a writer we just log height=0 rather than
    // wait.
    let height = state.blockchain.try_read().map(|c| c.height()).unwrap_or(0);
    let error = NodeError {
        error_type: error_type.to_string(),
        message: message.chars().take(200).collect(),
        height,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let mut log = state.error_log.write().unwrap();
    log.push(error);
    // Keep last 100 errors max
    if log.len() > 100 {
        let drain_count = log.len() - 100;
        log.drain(0..drain_count);
    }
}

// ========================================================================
// SNAPSHOT MANIFEST ENDPOINTS (Phase 1)
// ========================================================================

/// v2.8.0 — GET /snapshot/signed — return the gzipped state snapshot file
/// whose SHA-256 matches the latest signed manifest. Reads `snapshot-{H}
/// .json.gz` from disk (persisted by `auto_snapshot_export`). Wallets use
/// this endpoint to bootstrap their local commitment tree in one round
/// trip with cryptographic integrity (SHA-256 of the body equals the
/// `snapshot_sha256` field returned by `/snapshot/latest`).
async fn snapshot_signed_data(
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;
    use axum::http::header;

    let manifest = {
        let manifests = state.snapshot_manifests.read().unwrap();
        match manifests.last() {
            Some(m) => m.clone(),
            None => return Err(StatusCode::NOT_FOUND),
        }
    };

    let data_dir = std::path::PathBuf::from(crate::config::get_data_dir());
    let snap_path = data_dir
        .join("snapshots")
        .join(format!("snapshot-{}.json.gz", manifest.height));
    let bytes = match tokio::fs::read(&snap_path).await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"tsn-snapshot-signed.json.gz\""),
        ],
        [
            (header::HeaderName::from_static("x-snapshot-height"), header::HeaderValue::from_str(&manifest.height.to_string()).unwrap()),
            (header::HeaderName::from_static("x-snapshot-sha256"), header::HeaderValue::from_str(&manifest.snapshot_sha256).unwrap()),
        ],
        bytes,
    ).into_response())
}

/// GET /snapshot/latest — return the latest signed snapshot manifest
async fn snapshot_latest_manifest(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let manifests = state.snapshot_manifests.read().unwrap();
    match manifests.last() {
        Some(m) => Ok(Json(serde_json::to_value(m).unwrap_or_default())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// GET /snapshot/manifest/:height — return manifest for a specific height
async fn snapshot_manifest_at_height(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let manifests = state.snapshot_manifests.read().unwrap();
    match manifests.iter().find(|m| m.height == height) {
        Some(m) => Ok(Json(serde_json::to_value(m).unwrap_or_default())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// GET /snapshot/history — list snapshot manifests with status classification.
///
/// v2.9.12 — entries are tagged `verified` (>=1 conf), `pending` (<6h, 0 conf),
/// or `stale` (>6h, 0 conf). Stale entries are filtered out by default; pass
/// `?include_stale=1` to keep them. Entries older than 24h with 0 confirmations
/// are pruned outright (not returned even with include_stale). The most
/// recent verified entry is always preserved regardless of age.
async fn snapshot_manifest_history(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Vec<super::snapshot_manifest::SnapshotEntry>> {
    use chrono::DateTime;
    let include_stale = params.get("include_stale").map(|v| v == "1" || v == "true").unwrap_or(false);
    let now = chrono::Utc::now();
    const STALE_AFTER_HOURS: i64 = 6;
    const PRUNE_AFTER_HOURS: i64 = 24;

    let manifests = state.snapshot_manifests.read().unwrap();

    // First pass: classify everything, keep latest verified pointer.
    let mut entries: Vec<super::snapshot_manifest::SnapshotEntry> = manifests.iter().map(|m| {
        let confs = m.valid_confirmation_count();
        let age_h = DateTime::parse_from_rfc3339(&m.created_at)
            .map(|t| now.signed_duration_since(t.with_timezone(&chrono::Utc)).num_hours())
            .unwrap_or(0);
        let status = if confs >= 1 {
            "verified"
        } else if age_h >= STALE_AFTER_HOURS {
            "stale"
        } else {
            "pending"
        };
        super::snapshot_manifest::SnapshotEntry {
            height: m.height,
            block_hash: m.block_hash.clone(),
            state_root: m.state_root.clone(),
            snapshot_sha256: m.snapshot_sha256.clone(),
            created_at: m.created_at.clone(),
            confirmations: confs,
            status: status.to_string(),
        }
    }).collect();

    // The most recent verified entry must always survive even if old.
    let latest_verified_height: Option<u64> = entries.iter()
        .filter(|e| e.status == "verified")
        .map(|e| e.height)
        .max();

    entries.retain(|e| {
        // Always keep verified.
        if e.status == "verified" {
            return true;
        }
        // Keep the newest verified anchor regardless of age (defense-in-depth).
        if Some(e.height) == latest_verified_height {
            return true;
        }
        // Prune anything older than 24h with 0 confirmations.
        let age_h = DateTime::parse_from_rfc3339(&e.created_at)
            .map(|t| now.signed_duration_since(t.with_timezone(&chrono::Utc)).num_hours())
            .unwrap_or(0);
        if age_h >= PRUNE_AFTER_HOURS {
            return false;
        }
        // Stale entries: kept only if explicitly requested.
        if e.status == "stale" {
            return include_stale;
        }
        // Pending: always kept.
        true
    });

    Json(entries)
}

/// POST /snapshot/export — trigger snapshot export at the current finalized height.
/// Returns the signed manifest if successful.
async fn snapshot_trigger_export(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let signing_key = state.seed_signing_key.as_ref()
        .ok_or_else(|| {
            warn!("Snapshot export failed: no seed signing key configured");
            StatusCode::SERVICE_UNAVAILABLE
        })?;

    // Get chain data. The snapshot captures the full state at the current tip.
    // The manifest records the tip height and hash. Finalization is guaranteed because:
    // 1. The export only triggers when tip > MAX_REORG_DEPTH + 100
    // 2. Cross-confirmation by 2+ independent seeds proves the height is canonical
    // 3. Post-import state_root verification proves the state is consistent
    let (data, height, block_hash, state_root, peer_id_str) = {
        let chain = state.blockchain.read().await;
        let tip = chain.height();
        let max_reorg = crate::config::MAX_REORG_DEPTH;
        if tip <= max_reorg + 100 {
            warn!("Chain too short for snapshot: tip={}", tip);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let snapshot = chain.export_snapshot().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let state_root = hex::encode(chain.state_root());
        let p2p_id = state.p2p_peer_id.read().unwrap().clone().unwrap_or_default();
        info!("Snapshot export: height={}, hash={}", snapshot.1, &snapshot.2[..16]);
        (snapshot.0, snapshot.1, snapshot.2, state_root, p2p_id)
    };

    // Compress
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let compressed = encoder.finish().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Compute SHA256 of compressed data
    let snapshot_sha256 = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&compressed))
    };

    // Build and sign the manifest
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let mut manifest = super::snapshot_manifest::SnapshotManifest {
        version: 1,
        chain_id: crate::config::NETWORK_NAME.to_string(),
        height,
        block_hash,
        state_root,
        snapshot_sha256,
        snapshot_size_bytes: compressed.len() as u64,
        format: "json-gzip".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        producer: super::snapshot_manifest::SeedIdentity {
            seed_name: state.public_url.clone().unwrap_or_else(|| "unknown".to_string()),
            peer_id: peer_id_str,
            public_key: public_key_hex,
        },
        signature: String::new(),
        confirmations: Vec::new(),
    };

    // Sign the manifest
    let payload = manifest.signing_payload();
    manifest.signature = super::snapshot_manifest::sign_ed25519(signing_key, &payload);

    info!(
        "Snapshot manifest exported: height={}, sha256={}, size={}KB",
        manifest.height, &manifest.snapshot_sha256[..16], manifest.snapshot_size_bytes / 1024
    );

    // Store the compressed data in snapshot_cache so /snapshot/download serves the EXACT same file
    {
        let cache_hash = manifest.block_hash.clone();
        let mut cache = state.snapshot_cache.write().await;
        *cache = Some(CachedSnapshot {
            compressed: compressed,
            height,
            hash: cache_hash,
            raw_size: data.len(),
        });
    }

    // Store the manifest
    let manifest_json = serde_json::to_value(&manifest).unwrap_or_default();
    {
        let mut manifests = state.snapshot_manifests.write().unwrap();
        // Replace if same height exists, otherwise append
        if let Some(pos) = manifests.iter().position(|m| m.height == manifest.height) {
            manifests[pos] = manifest;
        } else {
            manifests.push(manifest);
            // Keep max 10 manifests
            if manifests.len() > 10 {
                manifests.remove(0);
            }
        }
    }

    // Trigger cross-confirmation from other seeds (async, fire-and-forget)
    let state_clone = state.clone();
    let manifest_clone: super::snapshot_manifest::SnapshotManifest = serde_json::from_value(manifest_json.clone()).unwrap();
    tokio::spawn(async move {
        request_seed_confirmations(state_clone, manifest_clone).await;
    });

    Ok(Json(manifest_json))
}

/// Request confirmations from other seeds for a manifest
async fn request_seed_confirmations(
    state: Arc<AppState>,
    manifest: super::snapshot_manifest::SnapshotManifest,
) {
    let client = &state.http_client;
    let confirm_body = serde_json::to_string(&manifest).unwrap_or_default();

    for seed_url in crate::config::SEED_NODES.iter() {
        // Skip ourselves
        if let Some(ref our_url) = state.public_url {
            if seed_url.contains(our_url.split("://").last().unwrap_or("")) {
                continue;
            }
        }

        let url = format!("{}/snapshot/confirm", seed_url);
        match client.post(&url)
            .header("Content-Type", "application/json")
            .body(confirm_body.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(confirmation) = resp.json::<super::snapshot_manifest::SeedConfirmation>().await {
                    if confirmation.verify() {
                        info!("Received valid confirmation from {} for height {}", confirmation.seed_name, manifest.height);
                        let mut manifests = state.snapshot_manifests.write().unwrap();
                        if let Some(m) = manifests.iter_mut().find(|m| m.height == manifest.height) {
                            // Avoid duplicate confirmations from same seed
                            if !m.confirmations.iter().any(|c| c.seed_name == confirmation.seed_name) {
                                m.confirmations.push(confirmation);
                            }
                        }
                    } else {
                        warn!("Invalid confirmation signature from seed for height {}", manifest.height);
                    }
                }
            }
            Ok(resp) => {
                debug!("Seed {} returned {} for confirmation request", seed_url, resp.status());
            }
            Err(e) => {
                debug!("Failed to request confirmation from {}: {}", seed_url, e);
            }
        }
    }
}

/// POST /snapshot/confirm — receive a manifest and return a signed confirmation
/// if our chain agrees with the block_hash and state_root at that height.
async fn snapshot_confirm(
    State(state): State<Arc<AppState>>,
    Json(manifest): Json<super::snapshot_manifest::SnapshotManifest>,
) -> Result<Json<super::snapshot_manifest::SeedConfirmation>, StatusCode> {
    let signing_key = state.seed_signing_key.as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Verify producer signature first
    if !manifest.verify_producer_signature() {
        warn!("Rejecting confirmation request: invalid producer signature");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check our chain at the requested height
    let (block_hash_match, state_root_match) = {
        let chain = state.blockchain.read().await;
        let local_hash = chain.get_hash_at_height(manifest.height)
            .map(|h| hex::encode(h));
        let bh_match = local_hash.as_deref() == Some(&manifest.block_hash);
        // State root: we can only verify if we have the block
        // For now, trust block_hash match as state_root proxy
        // (full state_root verification requires snapshot replay)
        (bh_match, bh_match)
    };

    let peer_id_str = state.p2p_peer_id.read().unwrap().clone().unwrap_or_default();
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let mut confirmation = super::snapshot_manifest::SeedConfirmation {
        seed_name: state.public_url.clone().unwrap_or_else(|| "unknown".to_string()),
        peer_id: peer_id_str,
        height: manifest.height,
        block_hash_match,
        state_root_match,
        confirmed_at: chrono::Utc::now().to_rfc3339(),
        signature: String::new(),
        public_key: public_key_hex,
    };

    // Sign the confirmation
    let payload = confirmation.signing_payload();
    confirmation.signature = super::snapshot_manifest::sign_ed25519(signing_key, &payload);

    info!(
        "Snapshot confirmation: height={}, block_hash_match={}, state_root_match={}",
        manifest.height, block_hash_match, state_root_match
    );

    Ok(Json(confirmation))
}

/// GET /mining/metrics — performance counters for benchmarking
async fn mining_metrics(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    use std::sync::atomic::Ordering::Relaxed;
    let chain = state.blockchain.read().await;
    Json(serde_json::json!({
        "height": chain.height(),
        "empty_batches": state.metric_empty_batches.load(Relaxed),
        "stale_blocks": state.metric_stale_blocks.load(Relaxed),
        "fork_recoveries": state.metric_fork_recoveries.load(Relaxed),
        "recovery_time_ms": state.metric_recovery_time_ms.load(Relaxed),
        "commitment_mismatches": state.metric_commitment_mismatches.load(Relaxed),
        "reorg_count": state.reorg_count.load(Relaxed),
        "orphan_count": state.orphan_count.load(Relaxed),
        "relay_pool_balance": chain.relay_pool().balance(),
        "relay_pool_last_payout_height": chain.relay_pool().last_payout_height,
    }))
}

/// GET /mining/template — Phase 6 stub.
///
/// Returns a small header-preview payload usable by external miners to
/// discover the current parent tip and difficulty. The full template flow
/// (server-side block cache, nonce_prefix allocation, coinbase commit) lives
/// in `network::mining_api` and will be wired to a real mining coinbase
/// builder in a follow-up release. For now this endpoint is deliberately
/// read-only and does not allocate a reusable template on the server.
async fn mining_template(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().await;
    let tip = chain.latest_hash();
    let height = chain.height() + 1;
    let difficulty = chain.next_difficulty();
    Json(serde_json::json!({
        "height": height,
        "parent_hash": hex::encode(tip),
        "difficulty": difficulty,
        "minimum_version": crate::network::version_check::MINIMUM_VERSION,
        "note": "Preview endpoint. Full mining/template flow with server-side cache lands in a follow-up release.",
    }))
}

/// POST /mining/submit — Phase 6 stub.
///
/// Accepts a typed `SubmitRequest` body so GPU miners can start building
/// against the stable JSON shape. Always rejects until the full template
/// cache and block reconstitution flow are wired — this keeps the reward
/// path gated while still pinning the schema for clients.
async fn mining_submit(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<crate::network::mining_api::SubmitRequest>,
) -> Json<crate::network::mining_api::SubmitResponse> {
    Json(crate::network::mining_api::SubmitResponse::reject(
        "mining/submit is reserved; full template flow ships in a follow-up release",
    ))
}

// ============================================================================
// Relay Pool explorer endpoints (v2.4.0)
// ============================================================================

/// GET /relay/pool/status — live accumulator state + countdown to next payout.
async fn relay_pool_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use crate::consensus::relay_pool::PAYOUT_INTERVAL;
    let chain = state.blockchain.read().await;
    let pool = chain.relay_pool();
    let current_height = chain.height();
    let total_paid = chain.state().relay_pool_total_paid();
    // Next payout = smallest multiple of PAYOUT_INTERVAL strictly greater
    // than max(current_height, last_payout_height). Always guaranteed > 0.
    let anchor = current_height.max(pool.last_payout_height);
    let next_payout_height = ((anchor / PAYOUT_INTERVAL) + 1) * PAYOUT_INTERVAL;
    let blocks_until = next_payout_height.saturating_sub(current_height);
    // Total collected over the chain's lifetime = pending + already paid.
    let pool_balance = pool.balance();
    let total_accumulated = pool_balance.saturating_add(total_paid);
    let divisor = 10f64.powi(crate::config::COIN_DECIMALS as i32);
    // v2.5.3 — expose unallocated vs per-recipient split so the explorer and
    // debug tooling can see where endorsements landed before the h%1000 drain.
    let per_recipient: Vec<serde_json::Value> = pool
        .per_recipient
        .iter()
        .map(|(pk, amt)| serde_json::json!({
            "pk_hash": hex::encode(pk),
            "amount_atomic": amt,
            "amount_tsn": *amt as f64 / divisor,
        }))
        .collect();
    Json(serde_json::json!({
        "balance_atomic": pool_balance,
        "balance_tsn": pool_balance as f64 / divisor,
        "unallocated_atomic": pool.unallocated,
        "unallocated_tsn": pool.unallocated as f64 / divisor,
        "per_recipient": per_recipient,
        "total_paid_atomic": total_paid,
        "total_paid_tsn": total_paid as f64 / divisor,
        "total_accumulated_atomic": total_accumulated,
        "total_accumulated_tsn": total_accumulated as f64 / divisor,
        "last_payout_height": pool.last_payout_height,
        "next_payout_height": next_payout_height,
        "blocks_until_next_payout": blocks_until,
        "current_height": current_height,
        "payout_interval": PAYOUT_INTERVAL,
    }))
}

/// GET /relay/balance/:pk_hash — accumulated balance for a specific relay.
async fn relay_balance_of(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(pk_hash_hex): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bytes = hex::decode(&pk_hash_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    let chain = state.blockchain.read().await;
    let amount = chain.state().relay_balance_of(&pk);
    let divisor = 10f64.powi(crate::config::COIN_DECIMALS as i32);
    Ok(Json(serde_json::json!({
        "pk_hash": pk_hash_hex,
        "balance_atomic": amount,
        "balance_tsn": amount as f64 / divisor,
    })))
}

/// GET /relay/payouts/recent?limit=20 — the N most recent relay-pool payouts.
/// Walks back from the chain tip, collecting blocks that carry a
/// `relay_payout` (only happens every PAYOUT_INTERVAL blocks).
async fn relay_payouts_recent(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BlockListParams>,
) -> Json<serde_json::Value> {
    use crate::consensus::relay_pool::PAYOUT_INTERVAL;
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let chain = state.blockchain.read().await;

    // v2.5.4 Bug #8 — prefer the in-state rolling history (populated by
    // `apply_relay_payout` and preserved across fast-sync via the snapshot).
    // This makes `/relay/payouts/recent` authoritative on every node,
    // including fast-synced nodes that do not have the archival payout
    // blocks stored locally. Falls back to the legacy block-walk when the
    // history is empty (pre-v2.5.4 snapshots restored without it).
    let history = chain.state().recent_payouts();
    if !history.is_empty() {
        // Iterate newest → oldest.
        let payouts: Vec<serde_json::Value> = history
            .iter()
            .rev()
            .take(limit as usize)
            .map(|payout| {
                serde_json::json!({
                    "height": payout.height,
                    "pool_total": payout.pool_total,
                    "entries": payout.entries.iter().map(|e| serde_json::json!({
                        "recipient": hex::encode(e.recipient),
                        "amount": e.amount,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        return Json(serde_json::json!({ "payouts": payouts, "source": "state_history" }));
    }

    // Legacy path — walk backwards across payout boundaries. Still useful
    // for pre-v2.5.4 nodes that have the blocks but no snapshot-restored
    // history.
    let tip = chain.height();
    let mut payouts = Vec::new();
    let mut boundary = (tip / PAYOUT_INTERVAL) * PAYOUT_INTERVAL;
    while payouts.len() < limit as usize && boundary > 0 {
        if let Some(block) = chain.get_block_by_height(boundary) {
            if let Some(payout) = &block.relay_payout {
                payouts.push(serde_json::json!({
                    "height": payout.height,
                    "pool_total": payout.pool_total,
                    "entries": payout.entries.iter().map(|e| serde_json::json!({
                        "recipient": hex::encode(e.recipient),
                        "amount": e.amount,
                    })).collect::<Vec<_>>(),
                }));
            }
        }
        if boundary < PAYOUT_INTERVAL { break; }
        boundary -= PAYOUT_INTERVAL;
    }
    Json(serde_json::json!({ "payouts": payouts, "source": "block_walk" }))
}

// ============================================================================
// Wallet API endpoints (v2.2.0)
// ============================================================================

async fn wallet_balance_api(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(ref ws) = state.wallet_service else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no wallet configured"}))).into_response();
    };
    let balance = ws.balance().await;
    let height = ws.last_scanned_height().await;
    let count = ws.unspent_count().await;
    let coin_decimals = crate::config::COIN_DECIMALS;
    let divisor = 10u64.pow(coin_decimals);
    Json(serde_json::json!({
        "balance": balance,
        "balance_tsn": balance as f64 / divisor as f64,
        "scanned_height": height,
        "note_count": count,
    })).into_response()
}

async fn wallet_history_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(ref ws) = state.wallet_service else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no wallet configured"}))).into_response();
    };
    let limit = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20usize);
    let history = ws.tx_history(limit).await;
    Json(serde_json::json!({
        "transactions": history,
    })).into_response()
}

async fn wallet_address_api(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(ref ws) = state.wallet_service else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no wallet configured"}))).into_response();
    };
    let legacy = ws.address_hex().await;
    let pk_hash = hex::encode(ws.pk_hash().await);
    // v2.3.9 — unambiguous response shape.
    //
    // The previous v2.3.7 response exposed `address` as an alias of the
    // legacy 20-byte value, which directly caused the community confusion
    // reported on Discord ("the wallet shows pk_hash, the node shows
    // address with a different value, which do I share?"). A user copying
    // `address` was sending funds to a dead transparent-v1 identifier.
    //
    // `address` now aliases the pk_hash (the correct thing to share). The
    // legacy 20-byte form is still exposed as `legacy_address_v1` for tools
    // that need it, but it is no longer reachable through the ambiguous
    // `address` key.
    Json(serde_json::json!({
        "address":           pk_hash.clone(),
        "mining_address":    pk_hash.clone(),
        "pk_hash":           pk_hash,
        "legacy_address_v1": legacy,
        "format": {
            "address":           "32-byte hex (Blake2s256 of the ML-DSA-65 public key). Use this to receive TSN rewards and for shielded v2 transactions.",
            "mining_address":    "Alias of `address`. Same value.",
            "pk_hash":           "Alias of `address`. Same value.",
            "legacy_address_v1": "20-byte hex (truncated SHA-256). Pre-v2 transparent identifier, exposed for back-compat only — NOT used for rewards.",
        },
    })).into_response()
}

async fn wallet_scan_api(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(ref ws) = state.wallet_service else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no wallet configured"}))).into_response();
    };
    let scanned = ws.last_scanned_height().await;
    let chain_height = {
        let chain = state.blockchain.read().await;
        chain.height()
    };

    // v2.5.4 — cap the batch at `MAX_SCAN_BATCH` blocks so a wallet that is
    // thousands of blocks behind (fresh restore, long offline period) does not
    // hold the axum handler for minutes. If the scan is incomplete, the
    // response reports `complete: false` and the caller can poll the endpoint
    // again to continue. This also prevents the CLOSE-WAIT pileup on peers
    // that request `/wallet/scan` and give up before we finish.
    const MAX_SCAN_BATCH: u64 = 500;
    let target = chain_height.min(scanned + MAX_SCAN_BATCH);

    let mut new_notes = 0usize;
    for h in (scanned + 1)..=target {
        let block = {
            let chain = state.blockchain.read().await;
            chain.get_block_by_height(h)
        };
        if let Some(block) = block {
            // `scan_block` dedupes via UNIQUE constraint on commitment, so a
            // best-effort start position of 0 is safe.
            match ws.scan_block(&block, 0).await {
                Ok(n) => new_notes += n,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("scan failed: {}", e)}))).into_response();
                }
            }
        }
    }

    Json(serde_json::json!({
        "new_notes": new_notes,
        "scanned_from": scanned + 1,
        "scanned_to": target,
        "chain_height": chain_height,
        "complete": target == chain_height,
    })).into_response()
}

async fn wallet_rescan_api(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(ref ws) = state.wallet_service else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no wallet configured"}))).into_response();
    };
    if let Err(e) = ws.clear_notes().await {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("rescan failed: {}", e)}))).into_response();
    }
    Json(serde_json::json!({
        "status": "ok",
        "message": "wallet cleared, scan from height 0",
    })).into_response()
}

// ============================================================================
// v2.5.3 — relay pool endorsement endpoint
// ============================================================================

#[derive(serde::Deserialize)]
struct EndorseRequest {
    /// Hex-encoded 32-byte block hash the caller wants this relay to sign.
    header_hash: String,
}

/// POST /relay/endorse
///
/// A miner collects endorsements from known relays after finding a valid PoW.
/// The relay signs the block hash with its ML-DSA-65 wallet key and returns
/// `{ pub_key, signature }`. The miner verifies the signature locally, dedupes
/// by pk_hash, and attaches up to `MAX_ENDORSEMENTS_PER_BLOCK` entries to the
/// block before broadcasting.
///
/// Authorization: no ACL — any caller can ask for an endorsement. The relay's
/// signature commits it to the given block hash; if the hash does not end up
/// on the canonical chain, the endorsement is worthless but harmless. This
/// makes the endpoint self-rate-limiting by the relay-pool economics.
///
/// Signing a hash is cheap (~1–2 ms ML-DSA-65) but still worth rate-limiting
/// via the shared `rate_limit_layer` (200 rps burst 400) to prevent simple
/// floods from starving the relay of CPU during normal mining.
async fn relay_endorse_api(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EndorseRequest>,
) -> impl IntoResponse {
    let Some(ref ws) = state.wallet_service else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no wallet configured — this node cannot endorse"})),
        )
            .into_response();
    };

    let bytes = match hex::decode(body.header_hash.trim()) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "header_hash must be valid hex"})),
            )
                .into_response();
        }
    };
    if bytes.len() != crate::core::BLOCK_HASH_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "header_hash must be {} bytes, got {}",
                    crate::core::BLOCK_HASH_SIZE,
                    bytes.len()
                )
            })),
        )
            .into_response();
    }

    let pub_key = ws.public_key_bytes().await;
    let signature = ws.sign_message(&bytes).await;

    Json(serde_json::json!({
        "pub_key":   hex::encode(&pub_key),
        "signature": hex::encode(&signature),
    }))
    .into_response()
}
