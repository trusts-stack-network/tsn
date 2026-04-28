//! v2.8.9 — Trusted-quorum checkpoint voting.
//!
//! Replaces the v2.8.x bug where every node self-checkpointed at every
//! `height % CHECKPOINT_INTERVAL == 0`. Two nodes with divergent recent
//! blocks both stamped a "permanent" checkpoint at the same height with
//! different hashes; from that moment they could never reconcile, because
//! rollbacks below `last_checkpoint_height` are forbidden by design.
//!
//! Now a checkpoint at height N is created only when at least
//! `CHECKPOINT_QUORUM` of `TRUSTED_CHECKPOINT_VOTERS` (the TSN team's own
//! 4 seeds + nexus) report the same hash at height N as the local node
//! has. If quorum is missed (voters down, voters lagging, voters disagree),
//! the candidate height is skipped and re-evaluated on the next tick.
//!
//! Crucially this is a *background* task, not a hook inside block-insert:
//! a slow voter can never stall block validation, and the network keeps
//! advancing whether or not checkpoints are converging.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::config::{
    CHECKPOINT_INTERVAL, CHECKPOINT_QUORUM, CHECKPOINT_VOTE_TICK_SECS,
    CHECKPOINT_VOTE_TIMEOUT_SECS, TRUSTED_CHECKPOINT_VOTERS,
};
use crate::network::AppState;

/// Minimal `/block/height/{N}` response used here. The endpoint exposes
/// the full block; we only need the hash, so deserialize selectively.
#[derive(Deserialize)]
struct BlockHashResponse {
    /// Same field name used by the existing `block_to_json` helper in api.rs.
    hash: String,
}

/// Spawn the background checkpoint voter. Runs forever. The caller drops
/// the join handle if it does not need it; on shutdown the task ends with
/// the runtime.
pub fn spawn(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { run_loop(state).await })
}

async fn run_loop(state: Arc<AppState>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(CHECKPOINT_VOTE_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("checkpoint_vote: failed to build HTTP client: {} — voter disabled", e);
            return;
        }
    };

    info!(
        "checkpoint_vote: started (interval={} blocks, quorum={}/{}, tick={}s, timeout={}s)",
        CHECKPOINT_INTERVAL,
        CHECKPOINT_QUORUM,
        TRUSTED_CHECKPOINT_VOTERS.len(),
        CHECKPOINT_VOTE_TICK_SECS,
        CHECKPOINT_VOTE_TIMEOUT_SECS,
    );

    loop {
        if let Err(e) = tick(&state, &client).await {
            debug!("checkpoint_vote: tick error: {}", e);
        }
        sleep(Duration::from_secs(CHECKPOINT_VOTE_TICK_SECS)).await;
    }
}

/// One round of vote evaluation. Returns Err on transient internal errors
/// (recorded but not fatal); the loop catches and retries next tick.
async fn tick(state: &Arc<AppState>, client: &reqwest::Client) -> Result<(), String> {
    // Snapshot the candidate height + our local hash under the read lock,
    // then drop the lock before doing HTTP.
    //
    // v2.9.3 — On a fast-synced node, `local_hash_at(next_target)` returns a
    // placeholder [0u8;32] for any height below `fast_sync_base_height`. The
    // previous version early-returned on the first placeholder it hit, so the
    // checkpoint-vote loop never produced a snapshot. We now scan upward in
    // CHECKPOINT_INTERVAL steps from `last_cp+INTERVAL` to the highest
    // candidate that is still `MAX_REORG_DEPTH` blocks below the tip,
    // accepting the first non-placeholder hash we find. This lets a
    // fast-synced node start voting from the first real block in its
    // height_index without operator intervention.
    // v2.9.5 — Fast-sync fallback window. After a snapshot import all blocks
    // below `fast_sync_base_height` are placeholders [0u8;32], and on a
    // fresh fast-synced fleet the only non-placeholder candidate slots are
    // very close to (or above) the snapshot height — typically above
    // `tip - MAX_REORG_DEPTH`. The strict v2.9.3 window then yields no
    // candidate and the quorum cannot be evaluated until the chain has
    // moved another `MAX_REORG_DEPTH` blocks past the snapshot.
    //
    // We now do two passes:
    //   1. Strict: window = [last_cp+1 .. tip - MAX_REORG_DEPTH], full
    //      reorg-safety. This is the path taken in steady state.
    //   2. Shallow fallback: if no candidate is found, retry with the
    //      window stretched to [last_cp+1 .. tip - SHALLOW_DEPTH]. Used
    //      only during the post-fast-sync transition; a candidate
    //      checkpoint is more useful even with a tighter reorg buffer
    //      than no checkpoint at all.
    const SHALLOW_DEPTH: u64 = 10;
    let scan_for_candidate =
        |chain: &crate::core::ShieldedBlockchain,
         first_target: u64,
         max_candidate: u64|
         -> Option<(u64, [u8; 32])> {
            if first_target > max_candidate {
                return None;
            }
            let mut h = first_target;
            while h <= max_candidate {
                if let Some(hash) = chain.local_hash_at(h) {
                    if hash != [0u8; 32] {
                        return Some((h, hash));
                    }
                }
                h = h.saturating_add(CHECKPOINT_INTERVAL);
            }
            None
        };

    let (candidate_height, our_hash, last_cp_observed) = {
        let chain = state.blockchain.read().await;
        let tip = chain.height();
        let last_cp = chain.last_checkpoint_height();
        let fsb = chain.fast_sync_base_height();
        // v2.9.6 — Anchor the candidate scan above the fast-sync base.
        // After /admin/force-resync the height_index is filled with
        // [0u8;32] placeholders for h < fast_sync_base. The previous
        // first_target = (last_cp/INTERVAL+1)*INTERVAL was 100, way below
        // fast_sync_base (typically tip-N), so the scan walked thousands
        // of placeholder slots and never reached a real one within the
        // shallow window either. We now start the scan at the highest of
        // {last_cp+INTERVAL, fast_sync_base+INTERVAL}, which is the first
        // slot that can actually have a real hash on a freshly fast-synced
        // node.
        let lcp_first = ((last_cp / CHECKPOINT_INTERVAL) + 1) * CHECKPOINT_INTERVAL;
        let fsb_first = ((fsb / CHECKPOINT_INTERVAL) + 1) * CHECKPOINT_INTERVAL;
        let first_target = lcp_first.max(fsb_first);
        let max_strict = tip.saturating_sub(crate::config::MAX_REORG_DEPTH);
        let max_shallow = tip.saturating_sub(SHALLOW_DEPTH);

        // Pass 1: strict reorg-safe window.
        let mut chosen = scan_for_candidate(&chain, first_target, max_strict);

        // Pass 2: shallow fallback for the post-fast-sync transition.
        if chosen.is_none() && max_shallow > max_strict {
            chosen = scan_for_candidate(&chain, first_target, max_shallow);
            if let Some((h, _)) = chosen {
                debug!(
                    "checkpoint_vote: candidate h={} chosen from shallow window (post-fast-sync transition)",
                    h
                );
            }
        }

        match chosen {
            Some((c_h, c_hash)) => (c_h, c_hash, last_cp),
            None => {
                // Tip not yet far enough above the next checkpoint slot OR
                // every candidate slot in both windows is a placeholder.
                // Publish "no-candidate" so the UI can show "waiting".
                publish_status(state, 0, 0, 0, 0, last_cp).await;
                return Ok(());
            }
        }
    };

    let our_hash_hex = hex::encode(our_hash);
    debug!(
        "checkpoint_vote: candidate h={} local_hash={}…",
        candidate_height,
        &our_hash_hex[..16]
    );

    // Poll all trusted voters in parallel.
    let polls: Vec<_> = TRUSTED_CHECKPOINT_VOTERS
        .iter()
        .map(|url| fetch_voter_hash(client, url, candidate_height))
        .collect();
    let results = futures::future::join_all(polls).await;

    // Tally agreement. We count the local node's own opinion as 1 vote
    // (the "self-vote"): if the network is partitioned and we are one of
    // the trusted voters, our HTTP call to ourselves will already return
    // our own hash, so we do NOT also self-add — counting via fetch
    // covers the self case naturally. The peer poll is symmetric: each
    // voter independently runs this same loop.
    let mut agree = 0usize;
    let mut disagree = 0usize;
    let mut unreachable = 0usize;

    for (voter, res) in TRUSTED_CHECKPOINT_VOTERS.iter().zip(results.iter()) {
        match res {
            Ok(Some(h)) if *h == our_hash_hex => {
                agree += 1;
                debug!("checkpoint_vote: {} agrees", voter);
            }
            Ok(Some(other)) => {
                disagree += 1;
                debug!(
                    "checkpoint_vote: {} disagrees: {}… vs ours {}…",
                    voter,
                    &other[..16.min(other.len())],
                    &our_hash_hex[..16]
                );
            }
            Ok(None) => {
                // Voter doesn't have the block at this height yet — count
                // as unreachable (they may catch up later; we'll re-vote).
                unreachable += 1;
            }
            Err(e) => {
                unreachable += 1;
                debug!("checkpoint_vote: {} unreachable: {}", voter, e);
            }
        }
    }

    if agree >= CHECKPOINT_QUORUM {
        // Acquire the write lock and finalize.
        let mut chain = state.blockchain.write().await;
        match chain.set_checkpoint_via_quorum(candidate_height, our_hash) {
            Ok(()) => {
                info!(
                    "checkpoint_vote: FINALIZED h={} hash={}… ({} agree / {} disagree / {} unreachable)",
                    candidate_height,
                    &our_hash_hex[..16],
                    agree, disagree, unreachable
                );
                // v2.9.7 — push to the bounded checkpoint history exposed by
                // GET /chain/checkpoints (Explorer's Checkpoints tab).
                push_checkpoint_record(
                    state,
                    candidate_height,
                    &our_hash_hex,
                    agree,
                    TRUSTED_CHECKPOINT_VOTERS.len(),
                );
            }
            Err(e) => {
                // Local chain moved between the vote and the lock — reorg
                // happened, drop the result and let the next tick re-vote
                // on the new head's hash at this height (or on the next
                // candidate height if the local hash also changed).
                warn!(
                    "checkpoint_vote: skip finalize at h={} ({} agree): {}",
                    candidate_height, agree, e
                );
            }
        }
    } else {
        warn!(
            "checkpoint_vote: quorum NOT reached at h={} ({} agree / {} disagree / {} unreachable, need {})",
            candidate_height, agree, disagree, unreachable, CHECKPOINT_QUORUM
        );
        // Do not finalize. The next tick will retry, either with the same
        // hash (peers catching up) or a new hash (we reorged in between).
    }

    // v2.9.2 — Publish the result of this tick. We re-read
    // `last_checkpoint_height` after the (possible) finalize so the UI sees
    // the freshly committed value when `is_quorum=true`.
    let last_finalized_height = state.blockchain.read().await.last_checkpoint_height();
    publish_status(
        state,
        candidate_height,
        agree,
        disagree,
        unreachable,
        last_finalized_height,
    )
    .await;
    let _ = last_cp_observed; // captured for parity with publish_status callers

    Ok(())
}

/// v2.9.7 — Append a finalized checkpoint to the bounded history shown by
/// the explorer's Checkpoints tab. Newest first; keeps at most
/// `CHECKPOINT_HISTORY_CAP` entries.
fn push_checkpoint_record(
    state: &Arc<AppState>,
    height: u64,
    hash_hex: &str,
    agree: usize,
    total: usize,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let record = crate::network::api::CheckpointRecord {
        height,
        hash: hash_hex.to_string(),
        agree,
        total,
        finalized_at_unix_ms: now_ms,
    };
    let current = state.checkpoint_history.load();
    // Avoid pushing the same height twice (set_checkpoint_via_quorum is
    // idempotent within one tick but the loop could re-elect the same
    // height after a reorg; keep the freshest record).
    let mut next: Vec<crate::network::api::CheckpointRecord> = current
        .iter()
        .filter(|r| r.height != height)
        .cloned()
        .collect();
    next.insert(0, record);
    if next.len() > crate::network::api::CHECKPOINT_HISTORY_CAP {
        next.truncate(crate::network::api::CHECKPOINT_HISTORY_CAP);
    }
    state.checkpoint_history.store(std::sync::Arc::new(next));
}

/// v2.9.3 — Publish the current tick's result to the lock-free
/// `quorum_status` snapshot read by `GET /chain/quorum_status`. Always
/// stamps `last_check_unix_ms = now`, so the UI can flag a dead loop.
async fn publish_status(
    state: &Arc<AppState>,
    candidate_height: u64,
    agree: usize,
    disagree: usize,
    unreachable: usize,
    last_finalized_height: u64,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    state
        .quorum_status
        .store(std::sync::Arc::new(crate::network::api::QuorumStatus {
            candidate_height,
            agree,
            disagree,
            unreachable,
            total: TRUSTED_CHECKPOINT_VOTERS.len(),
            quorum_required: CHECKPOINT_QUORUM,
            is_quorum: agree >= CHECKPOINT_QUORUM,
            last_finalized_height,
            last_check_unix_ms: now_ms,
        }));
}

/// Ask one trusted voter for the hash at `height`. Returns:
///  * `Ok(Some(hash_hex))` if the voter has the block and returned a hash
///  * `Ok(None)` if the voter answered 404 (no block at that height yet)
///  * `Err(_)` for any transport/parse failure (treated as unreachable)
async fn fetch_voter_hash(
    client: &reqwest::Client,
    base_url: &str,
    height: u64,
) -> Result<Option<String>, String> {
    let url = format!("{}/block/height/{}", base_url.trim_end_matches('/'), height);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("send: {}", e))?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: BlockHashResponse = resp
        .json()
        .await
        .map_err(|e| format!("parse: {}", e))?;
    Ok(Some(body.hash.to_lowercase()))
}
