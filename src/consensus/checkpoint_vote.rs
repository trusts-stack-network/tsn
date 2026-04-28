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
    let (candidate_height, our_hash) = {
        let chain = state.blockchain.read().await;
        let tip = chain.height();
        let last_cp = chain.last_checkpoint_height();
        let next_target = ((last_cp / CHECKPOINT_INTERVAL) + 1) * CHECKPOINT_INTERVAL;

        // Require the tip to be enough above the candidate that all voters
        // have realistically had time to receive and store it. The
        // `MAX_REORG_DEPTH` window is the natural confirmation depth that
        // makes a height "stable enough to vote on".
        if tip < next_target.saturating_add(crate::config::MAX_REORG_DEPTH) {
            return Ok(());
        }

        match chain.local_hash_at(next_target) {
            Some(h) if h != [0u8; 32] => (next_target, h),
            _ => return Ok(()), // height not in our index yet, or placeholder
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

    // v2.9.2 — Publish the result of this tick to the lock-free
    // `quorum_status` snapshot read by `GET /chain/quorum_status`.
    // We re-read `last_checkpoint_height` after the (possible) finalize so
    // the UI sees the freshly committed value when `is_quorum=true`.
    let last_finalized_height = state.blockchain.read().await.last_checkpoint_height();
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

    Ok(())
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
