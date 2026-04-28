//! v2.9.9 — Background backfill of historical blocks missing from the local
//! DB after a fast-sync / `/admin/force-resync`.
//!
//! On a freshly fast-synced node `height_index` is filled with `[0u8;32]`
//! placeholders for heights `0..fast_sync_base`, and `block_heights` /
//! `blocks` in sled hold no entry for those heights. The user-facing
//! consequences are concrete:
//!   - `GET /block/height/{N}` returns 404 for any historical N
//!   - The explorer's Dashboard / Blocks / Charts panels render empty
//!     because `/blocks/list` and `/blocks/since` walk those same DB
//!     entries and find nothing
//!   - The trusted-quorum checkpoint vote can never accept a candidate
//!     below `fast_sync_base + INTERVAL`, so checkpoint history stays
//!     empty too
//!
//! This loop runs once at boot and afterwards every
//! `BACKFILL_INTERVAL_SECS`. It walks the height range
//! `[start..tip - SAFETY_DEPTH]` in batches of `BATCH` blocks, asks a
//! healthy peer for any block whose height is currently missing from
//! `block_heights`, and persists the response with `db.save_block`. The
//! in-memory `height_index` is not mutated — that would require taking
//! `blockchain.write()` for every batch and would interleave badly with
//! the live sync loop. The HTTP handler `get_block_by_height` already
//! falls back to `db.load_block_by_height` after an LRU miss, so the UI
//! sees the new blocks the moment they land in sled.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::network::AppState;

/// How long to wait between backfill sweeps once we've caught up.
const BACKFILL_INTERVAL_SECS: u64 = 60;

/// Blocks per `/blocks/since` request. The endpoint caps at 200 server-side.
const BATCH: u64 = 100;

/// Don't backfill within this many blocks of the current tip — those
/// blocks are still being applied by the live sync loop and shouldn't be
/// touched by the backfill writer.
const SAFETY_DEPTH: u64 = 10;

/// HTTP timeout per `/blocks/since` call. A batch is small enough (~100
/// blocks * <100 KB each = ~10 MB) that 30 s is comfortable.
const FETCH_TIMEOUT_SECS: u64 = 30;

/// Spawn the backfill loop. Returns the JoinHandle which the caller may
/// drop; on shutdown the task ends with the runtime.
pub fn spawn(state: Arc<AppState>, peer_pool: Vec<String>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { run_loop(state, peer_pool).await })
}

async fn run_loop(state: Arc<AppState>, peer_pool: Vec<String>) {
    // Don't share the global HTTP client — backfill is a slow, low-priority
    // job and we don't want it to compete with sync for connection slots.
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("backfill: failed to build HTTP client: {} — disabled", e);
            return;
        }
    };

    info!(
        "backfill: started (batch={} blocks, safety_depth={}, interval={}s, peers={})",
        BATCH, SAFETY_DEPTH, BACKFILL_INTERVAL_SECS, peer_pool.len()
    );

    // Initial settle so we don't race the chain loader during the first 5 s.
    sleep(Duration::from_secs(15)).await;

    loop {
        let inserted = match tick(&state, &client, &peer_pool).await {
            Ok(n) => n,
            Err(e) => {
                debug!("backfill: tick error: {}", e);
                0
            }
        };
        if inserted > 0 {
            info!("backfill: inserted {} historical blocks this sweep", inserted);
            // Rapid second sweep when we're actively making progress.
            sleep(Duration::from_secs(5)).await;
        } else {
            sleep(Duration::from_secs(BACKFILL_INTERVAL_SECS)).await;
        }
    }
}

/// One sweep. Returns the number of blocks inserted into sled.
async fn tick(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_pool: &[String],
) -> Result<usize, String> {
    // Snapshot the chain bounds under the read lock, then drop it.
    let (tip, db_arc) = {
        let chain = state.blockchain.read().await;
        let tip = chain.height();
        let db_arc = chain
            .db_arc()
            .ok_or_else(|| "backfill: no DB available".to_string())?;
        (tip, db_arc)
    };

    let upper = tip.saturating_sub(SAFETY_DEPTH);
    if upper < 1 {
        return Ok(0);
    }

    // Find the first missing height in [1..=upper]. We scan in BATCH-sized
    // windows so we can skip past long contiguous ranges quickly.
    let first_missing = match find_first_missing(&db_arc, 1, upper) {
        Some(h) => h,
        None => return Ok(0), // already complete up to the safety depth
    };

    let from = first_missing.saturating_sub(1); // /blocks/since returns since+1..
    let to = (first_missing + BATCH).min(upper);

    // Rotate through the peer pool to avoid hammering a single seed.
    let mut inserted_total = 0usize;
    for peer in peer_pool.iter() {
        let url = format!("{}/blocks/since/{}?limit={}", peer.trim_end_matches('/'), from, BATCH);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("backfill: peer {} send error: {}", peer, e);
                continue;
            }
        };
        if !resp.status().is_success() {
            debug!("backfill: peer {} returned {}", peer, resp.status());
            continue;
        }
        let blocks: Vec<crate::core::ShieldedBlock> = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                debug!("backfill: peer {} parse error: {}", peer, e);
                continue;
            }
        };
        if blocks.is_empty() {
            // This peer also has the gap — try the next one.
            continue;
        }
        for block in blocks {
            let h = block.coinbase.height;
            if h == 0 || h > to {
                continue;
            }
            // Skip if it's already in sled (a peer may have served us an
            // overlapping window).
            if db_arc.get_block_hash_by_height(h).ok().flatten().is_some() {
                continue;
            }
            if let Err(e) = db_arc.save_block(&block, h) {
                debug!("backfill: save_block(h={}) failed: {}", h, e);
                continue;
            }
            inserted_total += 1;
        }
        if inserted_total > 0 {
            // Persist sled changes for this batch before the next loop.
            let _ = db_arc.flush();
            return Ok(inserted_total);
        }
    }

    Ok(inserted_total)
}

/// Walk `[from..=to]` in `block_heights` and return the first height that is
/// missing, or None if every height in the range is present. Uses
/// `get_block_hash_by_height` so we never deserialize the full block — just
/// a 32-byte hash lookup per height.
fn find_first_missing(
    db: &crate::storage::Database,
    from: u64,
    to: u64,
) -> Option<u64> {
    // Cheap fast path: if `from` itself is missing, return it.
    if db.get_block_hash_by_height(from).ok().flatten().is_none() {
        return Some(from);
    }
    // Otherwise jump through the range in BATCH steps and return the first
    // step that lands on a missing height. Linear search inside the missing
    // batch is then performed by `tick` via the /blocks/since response.
    let mut h = from;
    while h <= to {
        if db.get_block_hash_by_height(h).ok().flatten().is_none() {
            return Some(h);
        }
        h = h.saturating_add(BATCH);
    }
    None
}
