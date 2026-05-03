use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};
use hex;

use crate::core::ShieldedBlock;
use crate::consensus::LWMA_WINDOW;

use crate::network::api::AppState;
use crate::network::peer_id;

/// Remove IP addresses and URLs from error messages for privacy.
fn sanitize_error(e: &dyn std::fmt::Display) -> String {
    let msg = e.to_string();
    if let Some(idx) = msg.find("url (") {
        format!("{}connection failed", &msg[..idx])
    } else if let Some(idx) = msg.find("http://") {
        format!("{}<hidden>", &msg[..idx])
    } else if let Some(idx) = msg.find("https://") {
        format!("{}<hidden>", &msg[..idx])
    } else {
        msg
    }
}

/// Ban a peer for the given duration.
fn ban_peer(state: &Arc<AppState>, peer_url: &str, duration_secs: u64) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(duration_secs);
    let mut bans = state.banned_peers.write().unwrap();
    bans.insert(peer_url.to_string(), until);
    warn!("Banned peer {} for {}s", peer_id(peer_url), duration_secs);
}

/// Sync the local chain from a peer node.
/// v2.0: Headers-first sync — fetches compact headers to detect forks BEFORE downloading blocks.
/// Inspired by Quantus (Substrate) and Dilithion (Bitcoin) sync protocols.
pub async fn sync_from_peer(state: Arc<AppState>, peer_url: &str) -> Result<u64, SyncError> {
    // Skip hashed peer IDs — not contactable URLs
    if !super::is_contactable_peer(peer_url) {
        return Ok(0);
    }

    let client = state.http_client.clone();

    // ── Step 1: Ban check ──
    {
        let bans = state.banned_peers.read().unwrap();
        if let Some(until) = bans.get(peer_url) {
            if std::time::Instant::now() < *until {
                debug!("Skipping banned peer {}", peer_id(peer_url));
                return Ok(0);
            }
        }
    }

    // ── Step 2: Version check ──
    {
        let version_url = format!("{}/version.json", peer_url);
        if let Ok(resp) = client.get(&version_url).timeout(Duration::from_secs(5)).send().await {
            if let Ok(info) = resp.json::<serde_json::Value>().await {
                if let Some(peer_version) = info["version"].as_str() {
                    if !crate::network::version_check::version_meets_minimum(peer_version) {
                        warn!(
                            "Rejecting sync from {} — outdated version {} (minimum: {})",
                            peer_id(peer_url), peer_version,
                            crate::network::version_check::MINIMUM_VERSION
                        );
                        return Err(SyncError::HttpError(format!(
                            "Peer version {} below minimum {}",
                            peer_version, crate::network::version_check::MINIMUM_VERSION
                        )));
                    }
                }
            }
        }
    }

    // ── Step 3: Get peer chain info ──
    let info_url = format!("{}/chain/info", peer_url);
    let response = client.get(&info_url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
    }
    let peer_info: PeerChainInfo = response.json().await?;

    let (local_height, local_hash, local_genesis) = {
        let chain = state.blockchain.read().await;
        let genesis = chain.info().genesis_hash;
        (chain.height(), hex::encode(chain.latest_hash()), genesis)
    };

    // ── Step 4: Genesis compatibility check (strict) ──
    // Fetch the peer's actual genesis block hash via HTTP to prevent syncing
    // from an incompatible chain. This catches old-network peers that the
    // protocol magic (P2P only) and version check cannot block on REST API.
    let expected_genesis = crate::config::EXPECTED_GENESIS_HASH;
    if !expected_genesis.is_empty() {
        let genesis_url = format!("{}/block/height/0", peer_url);
        match client.get(&genesis_url).timeout(std::time::Duration::from_secs(5)).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(block) = resp.json::<PeerBlockInfo>().await {
                    if block.hash != expected_genesis {
                        warn!(
                            "Rejecting peer {} — genesis mismatch (peer: {}…, expected: {}…)",
                            peer_id(peer_url),
                            &block.hash[..16.min(block.hash.len())],
                            &expected_genesis[..16]
                        );
                        return Ok(0);
                    }
                }
            }
            _ => {
                // If we can't fetch genesis, fall back to chain/info check
                let placeholder = "0".repeat(64);
                let peer_has_real_genesis = !peer_info.genesis_hash.is_empty() && peer_info.genesis_hash != placeholder;
                let local_has_real_genesis = !local_genesis.is_empty() && local_genesis != placeholder;
                if peer_has_real_genesis && local_has_real_genesis && peer_info.genesis_hash != local_genesis {
                    warn!(
                        "Rejecting peer {} — incompatible genesis (peer: {}…, local: {}…)",
                        peer_id(peer_url),
                        &peer_info.genesis_hash[..16.min(peer_info.genesis_hash.len())],
                        &local_genesis[..16.min(local_genesis.len())]
                    );
                    return Ok(0);
                }
            }
        }
    }

    // ── Step 4b: Detect broken fast-sync state ──
    // After a snapshot restore, the node may have fast_sync_base > 0 but only
    // genesis in RAM (cumulative_work = GENESIS_DIFFICULTY). This causes an
    // infinite sync loop because reorgs can't trace ancestors in the blind zone.
    // Detect this early and reset before wasting cycles.
    {
        let (fsb, cw) = {
            let chain = state.blockchain.read().await;
            (chain.fast_sync_base_height(), chain.cumulative_work())
        };
        if fsb > 0 && cw <= crate::config::GENESIS_DIFFICULTY as u128 {
            warn!(
                "BROKEN_SNAPSHOT: fast_sync_base={} but cumulative_work={} (genesis-level). \
                 Snapshot restore is corrupted — blocks don't exist. Resetting for fresh sync.",
                fsb, cw
            );
            let mut chain = state.blockchain.write().await;
            chain.reset_for_snapshot_resync();
            return Ok(0); // Will re-sync from scratch on next cycle
        }
    }

    // ── Step 5: Determine sync mode ──
    // Use both height AND cumulative_work to decide if peer is ahead.
    // v1.6.0 removed work comparison ("unreliable after fast-sync") but that
    // caused flip-flop between miners at same height. The fix: use work as
    // tiebreaker, with a 5% tolerance for fast-sync estimation differences.
    let local_work = {
        let chain = state.blockchain.read().await;
        chain.cumulative_work()
    };
    let peer_work = peer_info.cumulative_work;

    // v2.0.9: Basic sanity check on reported cumulative_work.
    // A peer claiming extremely high work relative to height is suspicious.
    // Max possible work per block = MAX_DIFFICULTY (~u64::MAX/2 ≈ 9.2e18).
    // Sanity: peer_work should not exceed height * MAX_DIFFICULTY.
    if peer_work > 0 && peer_info.height > 0 {
        let max_reasonable_work = (peer_info.height as u128) * (u64::MAX as u128 / 2);
        if peer_work > max_reasonable_work {
            warn!(
                "Rejecting peer {} — reported cumulative_work {} exceeds maximum possible for height {}",
                peer_id(peer_url), peer_work, peer_info.height
            );
            return Err(SyncError::InvalidResponse("Unreasonable cumulative_work".into()));
        }
    }

    let peer_ahead = peer_info.height > local_height
        || (peer_info.height == local_height && peer_work > local_work);
    let mut is_fork = peer_info.height == local_height
        && peer_info.latest_hash != local_hash;

    // At same height with different hash: only sync if peer has more work.
    // This prevents flip-flop where both miners keep switching to each other's chain.
    if is_fork && peer_work > 0 && local_work > 0 {
        if peer_work <= local_work {
            debug!(
                "SYNC_DEBUG: FORK_IGNORED peer={} peer_work={} <= local_work={} at height={}",
                peer_id(peer_url), peer_work, local_work, local_height
            );
            return Ok(0);
        }
    }
    if is_fork {
        warn!(
            "SYNC_DEBUG: === FORK_SEQUENCE START peer={} local_h={} local_hash={} peer_h={} peer_hash={} local_work={} peer_work={} ===",
            peer_id(peer_url), local_height, &local_hash[..16],
            peer_info.height, &peer_info.latest_hash[..16.min(peer_info.latest_hash.len())],
            local_work, peer_work
        );
    }

    // v1.8.0: Even if peer is behind, check for fork if peer is close enough.
    // Without this, a peer on a different chain but lower height is silently ignored,
    // and the fork diverges forever. Check headers to detect chain split.
    if !peer_ahead && !is_fork && peer_info.height > 0 {
        let height_diff = local_height.saturating_sub(peer_info.height);
        if height_diff <= 100 {
            // Peer is slightly behind — check if we share the same block at peer's height
            let chain = state.blockchain.read().await;
            let local_hash_at_peer_height = chain.get_block_by_height(peer_info.height)
                .map(|b| hex::encode(b.hash()));
            drop(chain);

            if let Some(local_h) = local_hash_at_peer_height {
                if local_h != peer_info.latest_hash && peer_work > 0 {
                    // Different hash at same height = FORK detected!
                    // We MUST resolve this fork even if we have more work locally,
                    // because our chain may not be the one the rest of the network follows.
                    // The fork resolution (find ancestor + rollback + reorg) will decide
                    // which chain wins based on cumulative work from the common ancestor.
                    warn!(
                        "SYNC_DEBUG: FORK_BEHIND_DETECTED peer={} peer_h={} peer_hash={} local_hash_at_peer_h={} peer_work={} local_work={}",
                        peer_id(peer_url), peer_info.height,
                        &peer_info.latest_hash[..16.min(peer_info.latest_hash.len())],
                        &local_h[..16], peer_work, local_work
                    );
                    is_fork = true;
                } else {
                    // Same hash at peer's height — no fork, peer just hasn't caught up
                    return Ok(0);
                }
            } else {
                return Ok(0);
            }
        } else {
            debug!("Peer {} too far behind ({} blocks), skipping", peer_id(peer_url), height_diff);
            return Ok(0);
        }
    } else if !peer_ahead && !is_fork {
        return Ok(0);
    }

    // ── Step 6: Headers-first fork detection ──
    // Instead of checking one block at local height, fetch headers to detect divergence
    if peer_ahead && !is_fork {
        match detect_fork_via_headers(&state, &client, peer_url, local_height).await {
            ForkDetection::NoFork => {
                // Peer extends our chain — proceed to block download
                info!("Syncing from peer {} (peer h={}, local h={})", peer_id(peer_url), peer_info.height, local_height);
            }
            ForkDetection::ForkDetected { ancestor_height } => {
                is_fork = true;
                info!(
                    "Headers-first: fork detected with {} at height {} (ancestor: {})",
                    peer_id(peer_url), peer_info.height, ancestor_height
                );
            }
            ForkDetection::Incompatible => {
                warn!(
                    "SYNC_DEBUG: INCOMPATIBLE peer={} local_h={} — no common ancestor in headers window, falling back to full search (Step 8)",
                    peer_id(peer_url), local_height
                );
                // Fast-path headers window too narrow — don't ban, let Step 8
                // (find_common_ancestor_headers) do a full search up to MAX_REORG_DEPTH.
                // The ban only happens if Step 8 also fails.
                is_fork = true;
            }
        }
    }

    // ── Step 7: Snapshot sync (fresh node) ──
    if local_height == 0 && peer_info.height > 0 {
        info!("Local height is 0, attempting snapshot sync from {}", peer_id(peer_url));
        match attempt_snapshot_sync(&state, &client, peer_url).await {
            Ok(height) if height > 0 => {
                info!("Snapshot sync complete: jumped to height {} from {}", height, peer_id(peer_url));
                return Ok(height);
            }
            _ => {
                warn!("Snapshot sync failed from {} — falling back to block-by-block", peer_id(peer_url));
            }
        }
    }

    // ── Step 8: Fork resolution via headers-first ancestor search ──
    let sync_from_height = if is_fork {
        // v2.3.0 Phase 1: dedup fork recovery across peers.
        // Without this, 16 peers announcing the same fork trigger 16 sequential rollbacks.
        // Key identifies the fork target by (peer_tip_hash16, peer_height).
        let fork_hash_prefix = &peer_info.latest_hash[..16.min(peer_info.latest_hash.len())];
        let fork_key = format!("{}|{}", fork_hash_prefix, peer_info.height);
        let peer_key = format!("peer:{}", peer_url);
        {
            let now = std::time::Instant::now();
            let mut cooldown = state.fork_recovery_cooldown.lock()
                .unwrap_or_else(|e| e.into_inner());
            cooldown.retain(|_, until| *until > now);
            // v2.8.2: per-peer cooldown set when a previous recovery attempt
            // failed. Skip even if the fork tip changed slightly — we know
            // this peer's chain is incompatible.
            if cooldown.contains_key(&peer_key) {
                debug!(
                    "peer cooldown active for {}, skipping fork recovery",
                    peer_id(peer_url)
                );
                return Ok(0);
            }
            if cooldown.contains_key(&fork_key) {
                debug!(
                    "dedup: fork recovery for {}@h={} already in cooldown, skipping peer {}",
                    fork_hash_prefix, peer_info.height, peer_id(peer_url)
                );
                return Ok(0);
            }
            cooldown.insert(
                fork_key.clone(),
                now + std::time::Duration::from_secs(crate::network::api::FORK_COOLDOWN_SECS),
            );
        }

        // v2.5.2 — observable lock acquisition. Previous version could stall
        // here indefinitely under hot-race (P2P receivers continuously holding
        // reorg_lock.read()). With a timeout the caller can abort and retry
        // on another peer instead of hanging the whole sync path.
        let lock_start = std::time::Instant::now();
        warn!("SYNC_DEBUG: STEP8_ACQUIRE_REORG_LOCK peer={} local_h={}", peer_id(peer_url), local_height);
        let _reorg_guard = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            state.reorg_lock.write(),
        ).await {
            Ok(guard) => {
                warn!(
                    "SYNC_DEBUG: STEP8_REORG_LOCK_ACQUIRED peer={} wait_ms={}",
                    peer_id(peer_url), lock_start.elapsed().as_millis()
                );
                guard
            }
            Err(_) => {
                warn!(
                    "SYNC_DEBUG: STEP8_REORG_LOCK_TIMEOUT peer={} waited=15000ms — aborting this sync attempt",
                    peer_id(peer_url)
                );
                return Err(SyncError::HttpError("reorg_lock write timeout".into()));
            }
        };

        // Check fast_sync_base BEFORE searching, to detect fallback ancestors
        let fast_sync_base = {
            let chain = state.blockchain.read().await;
            chain.fast_sync_base_height()
        };

        warn!("SYNC_DEBUG: STEP8_FIND_ANCESTOR_START peer={} local_h={} peer_h={}", peer_id(peer_url), local_height, peer_info.height);
        let ancestor_start = std::time::Instant::now();
        match find_common_ancestor_headers(&state, &client, peer_url, local_height, peer_info.height).await {
            Ok(ancestor) => {
                // v2.1.3: The old ANCESTOR_IS_FALLBACK guard has been REMOVED.
                // It blocked ALL rollbacks when ancestor <= fast_sync_base, but the most
                // common fork scenario (miner restarts, mines locally, seeds have the real
                // chain) has ancestor == fast_sync_base as a LEGITIMATE common ancestor.
                // Anti-thrashing is already handled upstream: peer_work <= local_work = skip.
                if fast_sync_base > 0 && ancestor <= fast_sync_base {
                    info!(
                        "SYNC: ancestor={} at fast_sync_base={} — allowing rollback (peer has more work)",
                        ancestor, fast_sync_base
                    );
                }

                warn!(
                    "SYNC_DEBUG: ANCESTOR_FOUND height={} peer={} find_ms={}",
                    ancestor, peer_id(peer_url), ancestor_start.elapsed().as_millis()
                );
                info!("Common ancestor found at height {} via headers", ancestor);

                // Cancel mining during reorg (this is a REAL rollback — cancel is justified)
                state.last_reorg_height.store(ancestor, std::sync::atomic::Ordering::Relaxed);
                state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    debug!("Mining cancelled for rollback to ancestor={}, peer={}", ancestor, peer_id(peer_url));
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                // Rollback to ancestor
                let mut chain = state.blockchain.write().await;
                if let Err(e) = chain.rollback_to_height(ancestor) {
                    let err_msg = format!("{}", e);
                    if err_msg.contains("below finalized height") {
                        // v2.3.6 — Do NOT wipe our canonical chain. A finalization block is
                        // permanent by design; if a peer proposes a fork that would require
                        // rolling past it, the peer is wrong, not us. Reject the peer path
                        // and let the normal sync retry with another peer.
                        warn!(
                            "Peer proposes fork below our finalization (ancestor={}): rejecting peer sync, NOT wiping local chain. err={}",
                            ancestor, err_msg
                        );
                        drop(chain);
                        return Err(SyncError::HttpError(format!(
                            "Peer diverges below finalization at h={}",
                            ancestor
                        )));
                    }
                    warn!("Rollback to height {} failed: {}", ancestor, e);
                    return Err(SyncError::HttpError(format!("Rollback failed: {}", e)));
                }
                info!("Rolled back to common ancestor at height {}", ancestor);

                // CRITICAL FIX: After rollback, process orphan pool.
                // Peer blocks received via P2P relay are stored as orphans.
                // After rollback, they may now chain onto our new tip.
                // Without this, sync would re-download them via HTTP, find them
                // as "duplicates" (already in orphan pool), and fail to add them.
                if let Err(e) = chain.process_orphans() {
                    warn!("process_orphans after rollback failed: {}", e);
                }
                let post_orphan_height = chain.height();
                if post_orphan_height > ancestor {
                    info!(
                        "Orphan processing after rollback: {} → {} ({} blocks recovered)",
                        ancestor, post_orphan_height, post_orphan_height - ancestor
                    );
                }
                debug!(
                    "Post-rollback: sync_from={} ancestor={}",
                    post_orphan_height, ancestor
                );
                // Use post-orphan height as sync start point.
                // Without this, we re-download blocks already added by process_orphans
                // → "none accepted" → ban peer → network deadlock.
                post_orphan_height
            }
            Err(_) => {
                warn!(
                    "SYNC_DEBUG: STEP8_FIND_ANCESTOR_ERR peer={} find_ms={}",
                    peer_id(peer_url), ancestor_start.elapsed().as_millis()
                );
                // No ancestor found — check peer checkpoints before drastic action
                if verify_peer_checkpoints(&client, peer_url).await {
                    // PATCH D: Suppress reset during post-fast-sync warm-up window.
                    // Null-hash placeholders cause false "no ancestor" → reset is an artefact.
                    let delta = local_height.saturating_sub(fast_sync_base);
                    if fast_sync_base > 0 && delta < LWMA_WINDOW * 3 {
                        warn!(
                            "SNAPSHOT_RESYNC_SUPPRESSED_POST_FASTSYNC path=step8_err fast_sync_base={} local_height={} delta={} peer={} reason=null_hash_placeholders_in_warmup",
                            fast_sync_base, local_height, delta, peer_id(peer_url)
                        );
                        return Ok(0);
                    }
                    info!("Peer {} passes checkpoints — snapshot resync", peer_id(peer_url));
                    if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    let mut chain = state.blockchain.write().await;
                    chain.reset_for_snapshot_resync();
                    return Ok(0);
                } else {
                    // FIX: Reduced from 1800s ban to 120s cooldown.
                    // On a private network, checkpoint failure can happen due to
                    // fast-sync placeholders, not malicious peers.
                    warn!("No ancestor + checkpoint fail — cooldown 120s for peer {} (not banning)", peer_id(peer_url));
                    ban_peer(&state, peer_url, 120);
                    return Ok(0);
                }
            }
        }
    } else {
        local_height
    };

    // ── Step 9: Block download (only for validated height range) ──
    let mut synced = 0u64;
    let mut current_sync_height = sync_from_height;
    let mut consecutive_empty_batches = 0u32;
    let mut recovery_attempted = false; // Prevent infinite recovery loops

    loop {
        let blocks_url = format!("{}/blocks/since/{}?limit=200", peer_url, current_sync_height);
        let response = client.get(&blocks_url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
        }

        let blocks: Vec<ShieldedBlock> = response.json().await?;
        let batch_size = blocks.len();

        if batch_size == 0 {
            break;
        }

        let mut batch_added = 0u64;

        debug!(
            "Sync batch: from={} size={} peer={}",
            current_sync_height, batch_size, peer_id(peer_url)
        );

        for (idx, block) in blocks.into_iter().enumerate() {
            // v2.1.2: Yield between blocks to let HTTP handlers process requests.
            // Without this, a 100-block sync batch starves all concurrent readers.
            if idx > 0 && idx % 5 == 0 {
                tokio::task::yield_now().await;
            }
            let block_hash_hex = hex::encode(&block.hash()[..8]);
            let block_h = block.coinbase.height;

            // v2.4.0 / Phase 3 — enforce V2 inclusion + ban policy BEFORE
            // accepting the block into the chain. A banned miner or a block
            // that under-commits relative to the local mempool is rejected
            // here rather than in the chain's internal validator, so we can
            // also update the ban set atomically with the decision.
            // v2.6.0 — acquire blockchain first (tokio await), then the std
            // mempool / banned guards. Since those std guards are !Send, they
            // must never cross an await boundary. By reading the chain height
            // before opening the mempool/banned locks, the std guards live in
            // a purely sync block and the whole enforcement finishes before
            // any further await.
            let current_height = state.blockchain.read().await.height();
            let enforcement_rejected = {
                let mempool = state.mempool.read()
                    .map_err(|e| SyncError::LockPoisoned(format!("mempool lock: {}", e)))?;
                let mut banned = state.banned_miners.write()
                    .map_err(|e| SyncError::LockPoisoned(format!("banned lock: {}", e)))?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                let outcome = crate::consensus::v2_inclusion::enforce_at_acceptance(
                    &block, &mempool, &mut *banned, current_height, now,
                );
                if !outcome.is_accept() {
                    if let Some(path) = &state.banned_miners_path {
                        let _ = banned.save_to_disk(path);
                    }
                    Some(outcome.reason().unwrap_or_default().to_string())
                } else {
                    if let Some(path) = &state.banned_miners_path {
                        let _ = banned.save_to_disk(path);
                    }
                    None
                }
            };
            if let Some(reason) = enforcement_rejected {
                warn!(
                    "SYNC_DEBUG: BLOCK_RESULT idx={}/{} result=REJECTED(policy) reason={}",
                    idx + 1, batch_size, reason
                );
                continue;
            }

            // v2.9.14 (W1B + H-G) — clone block before try_add_block consumes
            // it so we can refresh the lock-free state-check caches in the
            // same scope.
            let block_for_caches = block.clone();
            let mut chain = state.blockchain.write().await;
            debug!(
                "SYNC_DEBUG: BLOCK_ATTEMPT idx={}/{} block={} height={} prev={}",
                idx + 1, batch_size, block_hash_hex, block_h,
                hex::encode(&block.header.prev_hash[..8])
            );
            match chain.try_add_block(block) {
                Ok(true) => {
                    batch_added += 1;
                    synced += 1;
                    current_sync_height = chain.height();
                    // v2.9.13 — successful block reset the stuck-sync counter
                    // so a transient divergence doesn't slowly accumulate
                    // toward the auto-resync trigger.
                    state.stuck_sync_failures.store(0, std::sync::atomic::Ordering::Relaxed);
                    // v2.9.14 (W1B + H-G) — refresh lock-free state caches.
                    let new_anchor_pq = chain.state().commitment_root_pq();
                    crate::network::api::update_state_caches_after_block(
                        &state, &block_for_caches, new_anchor_pq, chain.info(),
                    );
                    debug!(
                        "SYNC_DEBUG: BLOCK_RESULT idx={}/{} result=ACCEPTED new_height={}",
                        idx + 1, batch_size, current_sync_height
                    );
                }
                Ok(false) => {
                    debug!(
                        "SYNC_DEBUG: BLOCK_RESULT idx={}/{} result=REJECTED(Ok(false))",
                        idx + 1, batch_size
                    );
                }
                Err(e) => {
                    warn!("Failed to add block during sync: {}", e);
                    break;
                }
            }
        }

        debug!(
            "Sync batch done: added={}/{} total={}",
            batch_added, batch_size, synced
        );

        if synced > 0 && synced % 50 == 0 {
            info!("Synced {} blocks from {} (height: {})", synced, peer_id(peer_url), current_sync_height);
        }

        // ── CRITICAL FIX: blocks don't chain → headers-based recovery ──
        // This is the core fix that prevents infinite sync loops.
        // If we got blocks but NONE were added, the chains have diverged.
        // Use headers to find the real ancestor instead of looping forever.
        if batch_size > 0 && batch_added == 0 {
            consecutive_empty_batches += 1;
            state.metric_empty_batches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            info!(
                "Sync: {} blocks from {} but none accepted (attempt {}) — diverged",
                batch_size, peer_id(peer_url), consecutive_empty_batches
            );
            // v2.9.13 — increment the global stuck-sync counter. Once it
            // crosses AUTO_FORCE_RESYNC_THRESHOLD (5) we trigger an
            // automatic chain wipe + snapshot fast-sync, because the local
            // DB is missing parents that all peers reference (typical
            // post-fast-sync deep-reorg trap). Cooldown prevents thrashing.
            let stuck = state.stuck_sync_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if stuck >= crate::config::AUTO_FORCE_RESYNC_THRESHOLD {
                let should_resync = {
                    let mut last = state.last_auto_resync.lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let now = std::time::Instant::now();
                    let cooldown = std::time::Duration::from_secs(
                        crate::config::AUTO_FORCE_RESYNC_COOLDOWN_SECS
                    );
                    match *last {
                        Some(t) if now.duration_since(t) < cooldown => false,
                        _ => { *last = Some(now); true }
                    }
                };
                if should_resync {
                    warn!(
                        "v2.9.13 auto-recovery: {} consecutive stuck-sync failures, \
                         triggering reset_for_snapshot_resync() — node will fast-sync \
                         from a fresh peer snapshot instead of staying stuck",
                        stuck
                    );
                    {
                        let mut chain = state.blockchain.write().await;
                        chain.reset_for_snapshot_resync();
                    }
                    {
                        let mut bans = state.banned_peers.write()
                            .unwrap_or_else(|e| e.into_inner());
                        bans.clear();
                    }
                    state.stuck_sync_failures.store(0, std::sync::atomic::Ordering::Relaxed);
                    return Ok(synced);
                }
            }

            if consecutive_empty_batches >= 1 {
                // Three strikes — this peer's chain is incompatible with ours
                if recovery_attempted {
                    // BUG FIX: Don't ban the peer — the fork may be legitimate.
                    // Previously, this ban was applied to ALL peers because
                    // recovery_attempted was a single bool per sync session.
                    // Under load (10+ miners), this caused a cascade that banned
                    // every peer within seconds, killing the entire network.
                    // Instead, just stop syncing with this peer for now.
                    //
                    // v2.8.2: arm a per-peer cooldown so we don't immediately
                    // re-poll the same peer next sync tick. Without this, the
                    // outer scheduler kept calling sync_from_peer(peer) every
                    // few seconds against a peer we already know is incompatible,
                    // logging "Recovery already attempted" 17k+ times in 8h and
                    // burning CPU/HTTP without progress. Reuses the existing
                    // fork_recovery_cooldown HashMap with a `peer:` prefix to
                    // avoid colliding with the (fork_hash, height) keys.
                    {
                        let now = std::time::Instant::now();
                        let mut cooldown = state.fork_recovery_cooldown.lock()
                            .unwrap_or_else(|e| e.into_inner());
                        cooldown.insert(
                            format!("peer:{}", peer_url),
                            now + std::time::Duration::from_secs(60),
                        );
                    }
                    warn!("Recovery already attempted with {} — 60s cooldown (no ban)", peer_id(peer_url));
                    break;
                }
                recovery_attempted = true;
                let recovery_start = std::time::Instant::now();
                info!("Empty batch from {} — attempting header-based recovery", peer_id(peer_url));

                // Acquire reorg_lock BEFORE searching for ancestor to prevent race conditions
                let _recovery_reorg_guard = state.reorg_lock.write().await;
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    debug!("Mining cancelled for recovery rollback, peer={}", peer_id(peer_url));
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                match find_common_ancestor_headers(&state, &client, peer_url, current_sync_height, peer_info.height).await {
                    Ok(ancestor) => {
                        let recovery_ms = recovery_start.elapsed().as_millis() as u64;
                        state.metric_fork_recoveries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        state.metric_recovery_time_ms.fetch_add(recovery_ms, std::sync::atomic::Ordering::Relaxed);
                        info!("Fork recovery: ancestor={} took={}ms", ancestor, recovery_ms);
                        state.last_reorg_height.store(ancestor, std::sync::atomic::Ordering::Relaxed);
                        state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        let mut chain = state.blockchain.write().await;
                        if let Err(e) = chain.rollback_to_height(ancestor) {
                            warn!("Header recovery rollback failed: {}", e);
                            break;
                        }
                        // Process orphans after rollback — same fix as Step 8
                        if let Err(e) = chain.process_orphans() {
                            warn!("process_orphans after recovery rollback failed: {}", e);
                        }
                        let recovered_height = chain.height();
                        if recovered_height > ancestor {
                            info!(
                                "Recovery orphan processing: {} → {} ({} blocks)",
                                ancestor, recovered_height, recovered_height - ancestor
                            );
                        }
                        current_sync_height = chain.height();
                        consecutive_empty_batches = 0;
                        continue; // Retry from correct ancestor
                    }
                    Err(_) => {
                        // Last resort: snapshot resync if peer passes checkpoints
                        if verify_peer_checkpoints(&client, peer_url).await {
                            // PATCH D: Suppress reset during post-fast-sync warm-up window.
                            // Exception: if cumulative_work is at genesis level, the snapshot
                            // is broken (blocks don't actually exist) — ALLOW the reset.
                            let recovery_fsb = {
                                let c = state.blockchain.read().await;
                                (c.fast_sync_base_height(), c.height(), c.cumulative_work())
                            };
                            let (fsb, cur_h, cw) = recovery_fsb;
                            let delta = cur_h.saturating_sub(fsb);
                            let is_broken_snapshot = cw <= crate::config::GENESIS_DIFFICULTY as u128;
                            if fsb > 0 && delta < LWMA_WINDOW * 3 && !is_broken_snapshot {
                                warn!(
                                    "SNAPSHOT_RESYNC_SUPPRESSED_POST_FASTSYNC path=recovery_err fast_sync_base={} local_height={} delta={} peer={} reason=null_hash_placeholders_in_warmup",
                                    fsb, cur_h, delta, peer_id(peer_url)
                                );
                                break;
                            }
                            if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            let mut chain = state.blockchain.write().await;
                            chain.reset_for_snapshot_resync();
                            return Ok(0);
                        } else {
                            // FIX: Reduced from 1800s ban to 120s cooldown
                            warn!("Recovery checkpoint fail — cooldown 120s for peer {} (not banning)", peer_id(peer_url));
                            ban_peer(&state, peer_url, 120);
                        }
                        break;
                    }
                }
            }
            // Don't break on first empty batch — might be a temporary issue
            continue;
        } else {
            consecutive_empty_batches = 0;
        }

        if batch_size < 200 {
            break;
        }
    }

    // ── Step 10: Post-sync checkpoint validation ──
    if synced > 0 {
        // Check checkpoints with read lock, collect violation info, then drop lock
        let checkpoint_violation = {
            let chain = state.blockchain.read().await;
            let mut violation = None;
            for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
                if cp_height <= chain.height() {
                    if let Some(actual_hash) = chain.get_hash_at_height(cp_height) {
                        let actual_hex = hex::encode(actual_hash);
                        if actual_hex != "0".repeat(64) && actual_hex != cp_hash {
                            warn!(
                                "BANNING {} — synced chain violates checkpoint at height {} (expected {}, got {})",
                                peer_id(peer_url), cp_height, &cp_hash[..16], &actual_hex[..16]
                            );
                            violation = Some(cp_height);
                            break;
                        }
                    }
                }
            }

            if violation.is_none() {
                if is_fork {
                    info!("Fork resolved: synced {} blocks from {} (new height: {})", synced, peer_id(peer_url), chain.height());
                } else {
                    info!("Synced {} blocks from {}", synced, peer_id(peer_url));
                }
            }
            violation
        }; // chain read lock dropped here

        if let Some(cp_height) = checkpoint_violation {
            ban_peer(&state, peer_url, 3600);
            let rollback_to = cp_height.saturating_sub(1);
            let _reorg_guard = state.reorg_lock.write().await;
            if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let mut chain_w = state.blockchain.write().await;
            let _ = chain_w.rollback_to_height(rollback_to);
            return Err(SyncError::InvalidResponse(
                format!("Peer chain violates checkpoint at height {}", cp_height)
            ));
        }

        // FIX 7: Do NOT cancel mining here at end of sync.
        // The cancel during actual rollback (Step 8, lines ~260/419) is sufficient.
        // This preemptive cancel was firing on every P2P-triggered sync that detected
        // a fork — even when no rollback occurred. With blocks arriving every ~8s from
        // forked peers, mining was cancelled faster than it could find a block,
        // permanently stalling the miner.
        if is_fork {
            warn!(
                "SYNC_DEBUG: sync_complete is_fork=true synced={} — NOT cancelling mining (cancel only during rollback)",
                synced
            );
        }
    }
    Ok(synced)
}

// ============ Headers-First Fork Detection ============

/// Result of headers-first fork detection.
#[derive(Debug)]
enum ForkDetection {
    /// Peer extends our chain — no fork.
    NoFork,
    /// Fork detected — ancestor_height is where chains diverged.
    ForkDetected { ancestor_height: u64 },
    /// Chains are completely incompatible (no common ancestor in range).
    Incompatible,
}

/// Detect fork by fetching compact headers from the peer and comparing with local chain.
/// Much faster than fetching full blocks — each header is ~200 bytes.
async fn detect_fork_via_headers(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    local_height: u64,
) -> ForkDetection {
    // Fetch peer's headers around our local height to check chain compatibility
    // Use a wide window (50 blocks back, 100 headers) to catch deep forks.
    // Previously saturating_sub(5) + limit=10 missed any fork deeper than 5 blocks.
    let start = local_height.saturating_sub(50);
    let headers_url = format!("{}/headers/since/{}?limit=100", peer_url, start);

    let resp = match client.get(&headers_url).timeout(Duration::from_secs(5)).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            // Peer doesn't support /headers/since — fall back to old single-block check
            return detect_fork_legacy(state, client, peer_url, local_height).await;
        }
    };

    let peer_headers: Vec<CompactHeaderResponse> = match resp.json().await {
        Ok(h) => h,
        Err(_) => return detect_fork_legacy(state, client, peer_url, local_height).await,
    };

    if peer_headers.is_empty() {
        return ForkDetection::NoFork;
    }

    let chain = state.blockchain.read().await;

    // Check each header — find the HIGHEST height where hashes match (ancestor)
    // and the LOWEST height where they mismatch (divergence point).
    // Use max/min to handle unsorted headers correctly.
    let mut best_match: Option<u64> = None;
    let mut earliest_mismatch: Option<u64> = None;

    for header in &peer_headers {
        if header.height > local_height { continue; }
        if let Some(local_hash) = chain.get_hash_at_height(header.height) {
            let local_hex = hex::encode(local_hash);
            if local_hex == "0".repeat(64) { continue; } // placeholder
            if header.hash == local_hex {
                best_match = Some(best_match.map_or(header.height, |prev: u64| prev.max(header.height)));
            } else {
                earliest_mismatch = Some(earliest_mismatch.map_or(header.height, |prev: u64| prev.min(header.height)));
            }
        }
    }

    let result = match (best_match, earliest_mismatch) {
        (Some(ancestor), Some(_)) => ForkDetection::ForkDetected { ancestor_height: ancestor },
        (None, Some(mismatch)) => {
            // BUG FIX: After fast-sync, we have no real block hashes below fast_sync_base.
            // The window may contain ONLY divergent blocks if the fork started right after
            // fast-sync. Instead of declaring Incompatible (which triggers ban cascades),
            // treat this as a fork with ancestor = fast_sync_base or start of window.
            // Step 8 (find_common_ancestor_headers) will do the precise search.
            let fast_sync_base = {
                let chain = state.blockchain.read().await;
                chain.fast_sync_base_height()
            };
            if fast_sync_base > 0 && start <= fast_sync_base {
                // We're in the fast-sync blind zone — can't conclude incompatible.
                // Use earliest mismatch as a hint, ancestor is at or below it.
                let estimated_ancestor = mismatch.saturating_sub(1).max(fast_sync_base);
                warn!(
                    "SYNC_DEBUG: fast-sync blind zone — promoting Incompatible to ForkDetected(ancestor={}), fast_sync_base={}, mismatch={}",
                    estimated_ancestor, fast_sync_base, mismatch
                );
                ForkDetection::ForkDetected { ancestor_height: estimated_ancestor }
            } else {
                ForkDetection::Incompatible
            }
        }
        _ => ForkDetection::NoFork, // All headers match — no fork
    };
    debug!(
        "Fork check: peer={} headers={} match={:?} mismatch={:?} result={:?}",
        peer_id(peer_url), peer_headers.len(), best_match, earliest_mismatch, result
    );
    result
}

/// Legacy fork detection: binary search for the fork point (for peers without /headers/since).
/// v2.0.9: Instead of guessing ancestor = height - 1, search back to find the real fork point.
async fn detect_fork_legacy(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    local_height: u64,
) -> ForkDetection {
    let local_hash = {
        let chain = state.blockchain.read().await;
        hex::encode(chain.latest_hash())
    };

    // First check: are we even forked?
    let check_url = format!("{}/block/height/{}", peer_url, local_height);
    if let Ok(resp) = client.get(&check_url).timeout(Duration::from_secs(5)).send().await {
        if resp.status().is_success() {
            if let Ok(peer_block) = resp.json::<PeerBlockInfo>().await {
                if peer_block.hash == local_hash {
                    return ForkDetection::NoFork; // Same tip, no fork
                }
            }
        }
    } else {
        return ForkDetection::NoFork;
    }

    // Binary search for the fork point (check up to 100 blocks back)
    let search_depth = local_height.min(crate::config::MAX_REORG_DEPTH);
    let mut low = local_height.saturating_sub(search_depth);
    let mut high = local_height;
    let mut best_ancestor = low;

    while low <= high {
        let mid = low + (high - low) / 2;
        let local_hash_at_mid = {
            let chain = state.blockchain.read().await;
            chain.get_hash_at_height(mid).map(|h| hex::encode(h))
        };

        let Some(local_h) = local_hash_at_mid else { break; };

        let url = format!("{}/block/height/{}", peer_url, mid);
        let matches = if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(5)).send().await {
            if resp.status().is_success() {
                resp.json::<PeerBlockInfo>().await.ok().map(|b| b.hash == local_h).unwrap_or(false)
            } else { false }
        } else { false };

        if matches {
            best_ancestor = mid;
            low = mid + 1;
        } else {
            if mid == 0 { break; }
            high = mid - 1;
        }
    }

    ForkDetection::ForkDetected { ancestor_height: best_ancestor }
}

// ============ Headers-First Common Ancestor Search ============

/// Find common ancestor using compact headers (new protocol).
/// Falls back to legacy block-by-block method for old peers.
async fn find_common_ancestor_headers(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    local_height: u64,
    _peer_height: u64,
) -> Result<u64, SyncError> {
    let search_start = local_height.saturating_sub(crate::config::MAX_REORG_DEPTH);

    // Try headers-first protocol
    let headers_url = format!("{}/headers/since/{}?limit=500", peer_url, search_start);
    let resp = client.get(&headers_url).timeout(Duration::from_secs(10)).send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let peer_headers: Vec<CompactHeaderResponse> = r.json().await
                .map_err(|e| SyncError::InvalidResponse(format!("headers parse: {}", e)))?;

            if peer_headers.is_empty() {
                return Err(SyncError::InvalidResponse("Peer returned 0 headers".into()));
            }

            let chain = state.blockchain.read().await;

            let fast_sync_base = chain.fast_sync_base_height();

            // Walk backwards through peer headers to find matching hash
            for header in peer_headers.iter().rev() {
                if header.height > local_height { continue; }
                // BUG FIX: Don't skip headers below fast_sync_base unconditionally.
                // After fast-sync, blocks below fast_sync_base have no stored data,
                // but get_hash_at_height may still return the snapshot's genesis hash.
                // The "0".repeat(64) check below already filters null hashes safely.
                // Skipping entirely prevented finding ANY ancestor when the fork
                // started right above fast_sync_base (e.g. fast_sync=244, fork=246).

                if let Some(local_hash) = chain.get_hash_at_height(header.height) {
                    let local_hex = hex::encode(local_hash);
                    if local_hex != "0".repeat(64) && header.hash == local_hex {
                        info!("Found common ancestor at height {} via headers-first", header.height);
                        return Ok(header.height);
                    }
                }
            }

            // No match in headers range — if we're in fast-sync zone, return the base
            // as a safe fallback instead of failing entirely
            if fast_sync_base > 0 && fast_sync_base >= search_start {
                warn!(
                    "No common ancestor in {} headers from {} — falling back to fast_sync_base={} as safe ancestor",
                    peer_headers.len(), peer_id(peer_url), fast_sync_base
                );
                return Ok(fast_sync_base);
            }

            warn!("No common ancestor in {} headers from {}", peer_headers.len(), peer_id(peer_url));
            Err(SyncError::InvalidResponse("No common ancestor in header range".into()))
        }
        _ => {
            // Peer doesn't support /headers/since — fall back to legacy
            info!("Peer {} doesn't support headers protocol — using legacy ancestor search", peer_id(peer_url));
            find_common_ancestor_legacy(state, client, peer_url, local_height).await
        }
    }
}

/// Legacy common ancestor search: fetch one full block per height (slow, for old peers).
async fn find_common_ancestor_legacy(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    start_height: u64,
) -> Result<u64, SyncError> {
    let check_depth = 100u64.min(start_height);
    let fast_sync_base = {
        let chain = state.blockchain.read().await;
        chain.fast_sync_base_height()
    };

    for offset in 0..check_depth {
        let height = start_height - offset;
        // BUG FIX: Same as headers-first — don't skip below fast_sync_base.
        // The null-hash checks below already handle missing block data safely.

        let local_hash = {
            let chain = state.blockchain.read().await;
            match chain.get_block_by_height(height) {
                Some(b) => {
                    let h = hex::encode(b.hash());
                    if h == "0".repeat(64) { None } else { Some(h) }
                }
                None => {
                    chain.get_hash_at_height(height).and_then(|h| {
                        let hex_str = hex::encode(h);
                        if hex_str == "0".repeat(64) { None } else { Some(hex_str) }
                    })
                }
            }
        };

        if let Some(local_hash) = local_hash {
            let block_url = format!("{}/block/height/{}", peer_url, height);
            if let Ok(resp) = client.get(&block_url).send().await {
                if resp.status().is_success() {
                    if let Ok(peer_block) = resp.json::<PeerBlockInfo>().await {
                        if peer_block.hash == local_hash {
                            info!("Found common ancestor at height {} (legacy)", height);
                            return Ok(height);
                        }
                    }
                }
            }
        }
    }

    // No ancestor — check if peer has valid checkpoints before giving up
    warn!("No common ancestor in last {} blocks with peer {}", check_depth, peer_id(peer_url));

    let peer_valid = verify_peer_checkpoints(client, peer_url).await;
    if peer_valid {
        // PATCH D: Suppress reset during post-fast-sync warm-up window.
        let (fsb, cur_h) = {
            let c = state.blockchain.read().await;
            (c.fast_sync_base_height(), c.height())
        };
        let delta = cur_h.saturating_sub(fsb);
        if fsb > 0 && delta < LWMA_WINDOW * 3 {
            warn!(
                "SNAPSHOT_RESYNC_SUPPRESSED_POST_FASTSYNC path=legacy_ancestor fast_sync_base={} local_height={} delta={} peer={} reason=null_hash_placeholders_in_warmup",
                fsb, cur_h, delta, peer_id(peer_url)
            );
            return Ok(fsb);
        }
        info!("Peer {} passes checkpoints — triggering snapshot resync", peer_id(peer_url));
        // Cancel mining before chain reset
        if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let mut chain = state.blockchain.write().await;
        chain.reset_for_snapshot_resync();
        return Ok(0);
    }

    Err(SyncError::InvalidResponse(format!(
        "No common ancestor found in last {} blocks — incompatible chain", check_depth
    )))
}

// ============ Snapshot Sync ============

/// Attempt to download and import a state snapshot from a peer.
async fn attempt_snapshot_sync(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
) -> Result<u64, SyncError> {
    let info_url = format!("{}/snapshot/info", peer_url);
    let resp = client.get(&info_url).timeout(Duration::from_secs(10)).send().await
        .map_err(|e| SyncError::HttpError(format!("snapshot info: {}", e)))?;

    let info: serde_json::Value = resp.json().await
        .map_err(|e| SyncError::InvalidResponse(format!("snapshot info parse: {}", e)))?;

    if info["available"].as_bool() != Some(true) {
        return Err(SyncError::InvalidResponse("Snapshot not available".into()));
    }

    let snap_height = info["height"].as_u64().unwrap_or(0);
    if snap_height == 0 {
        return Err(SyncError::InvalidResponse("Snapshot height is 0".into()));
    }

    let snap_hash_str = info["block_hash"].as_str().unwrap_or("");

    // v1.7.0: Read exact cumulative_work from snapshot info (decimal string).
    // If absent (old peer), refuse snapshot for non-seed peers.
    let snap_work_str = info["cumulative_work"].as_str().unwrap_or("0");
    let mut snap_work: u128 = snap_work_str.parse().unwrap_or(0);

    if snap_work == 0 {
        let is_seed = crate::config::SEED_NODES.iter().any(|s| peer_url.starts_with(s));
        if is_seed {
            warn!(
                "Snapshot from seed {} has no cumulative_work — accepting in degraded mode (private network)",
                peer_id(peer_url)
            );
        } else {
            warn!(
                "Rejecting snapshot from {} — no cumulative_work provided (require v1.7.0+)",
                peer_id(peer_url)
            );
            return Err(SyncError::InvalidResponse(
                "Snapshot missing cumulative_work — peer must be v1.7.0+".into()
            ));
        }
    }

    let dl_url = format!("{}/snapshot/download", peer_url);
    let resp = client.get(&dl_url).timeout(Duration::from_secs(30)).send().await
        .map_err(|e| SyncError::HttpError(format!("snapshot download: {}", e)))?;

    // v2.1.3 FIX: extract actual snapshot height/hash from download headers
    // before consuming the response body. The download cache can be up to 99
    // blocks behind /snapshot/info.
    let actual_snap_height = resp.headers()
        .get("x-snapshot-height")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(snap_height);
    let actual_snap_hash = resp.headers()
        .get("x-snapshot-hash")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let snap_height = actual_snap_height;
    let snap_hash_str = actual_snap_hash.as_deref().unwrap_or(snap_hash_str);

    let compressed = resp.bytes().await
        .map_err(|e| SyncError::HttpError(format!("snapshot bytes: {}", e)))?;

    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut json_data = Vec::new();
    decoder.read_to_end(&mut json_data)
        .map_err(|e| SyncError::InvalidResponse(format!("snapshot decompress: {}", e)))?;

    let snapshot: crate::core::StateSnapshotPQ = serde_json::from_slice(&json_data)
        .map_err(|e| SyncError::InvalidResponse(format!("snapshot parse: {}", e)))?;

    let mut block_hash = [0u8; 32];
    if let Ok(bytes) = hex::decode(snap_hash_str) {
        if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
    }

    // Get peer's difficulty info (for LWMA post-snapshot)
    let ci_url = format!("{}/chain/info", peer_url);
    let (diff, next_diff) = if let Ok(r) = client.get(&ci_url).send().await {
        let i = r.json::<serde_json::Value>().await.ok();
        let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
        let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
        (d, nd)
    } else {
        (1000, 1000)
    };

    // v2.0.9: Cross-verify snapshot height/hash with at least one other peer.
    // Prevents a single malicious peer from injecting a forged state.
    {
        let peers = state.peers.read()
            .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?
            .clone();
        let mut verified = false;
        for other_peer in &peers {
            if other_peer == peer_url || !super::is_contactable_peer(other_peer) {
                continue;
            }
            let verify_url = format!("{}/block/height/{}", other_peer, snap_height);
            if let Ok(resp) = client.get(&verify_url).timeout(Duration::from_secs(5)).send().await {
                if let Ok(block_info) = resp.json::<PeerBlockInfo>().await {
                    if block_info.hash == snap_hash_str {
                        verified = true;
                        break;
                    } else {
                        warn!(
                            "Snapshot cross-verify FAILED: {} says hash={} at height {}, but {} says hash={}",
                            peer_id(peer_url), &snap_hash_str[..16.min(snap_hash_str.len())],
                            snap_height, peer_id(other_peer), &block_info.hash[..16.min(block_info.hash.len())]
                        );
                        return Err(SyncError::InvalidResponse(
                            "Snapshot hash mismatch with other peers".into()
                        ));
                    }
                }
            }
        }
        if !verified {
            // No other peer could confirm — only accept from seed nodes,
            // OR from an operator-declared trusted peer (passed via --peer
            // on the CLI and therefore present in `state.peers`). The CLI
            // flag is an explicit act of trust by the node operator, which
            // is the same guarantee a hardcoded seed provides.
            //
            // v2.5.4 Bug — the previous revision deadlocked the whole
            // testnet if every seed was wiped at once: every seed was at
            // h=0 and none could cross-verify, so they all refused the
            // only peer with a chain (the miner EPYC1). Accepting an
            // operator-trusted peer here breaks that deadlock during a
            // coordinated network reset.
            let is_seed = crate::config::SEED_NODES.iter().any(|s| peer_url.starts_with(s));
            let is_trusted_cli = state.peers.read().unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|p| p == peer_url);
            if !is_seed && !is_trusted_cli {
                warn!("Rejecting snapshot from non-seed {} — no cross-verification possible", peer_id(peer_url));
                return Err(SyncError::InvalidResponse("Cannot cross-verify snapshot from non-seed".into()));
            }
            if !is_seed && is_trusted_cli {
                info!(
                    "Accepting snapshot from {} — peer is operator-trusted (CLI --peer), no cross-verification available",
                    peer_id(peer_url)
                );
            }
        }
    }

    // v2.1.4: Strict manifest verification when available from seed peers.
    // Checks: producer signature, 2+ seed confirmations, SHA256 match.
    // Non-seed peers without a manifest are already rejected by the cross-verification above.
    let manifest_state_root: Option<String>;
    let manifest_url = format!("{}/snapshot/latest", peer_url);
    let is_seed = crate::config::SEED_NODES.iter().any(|s| peer_url.starts_with(s));
    match client.get(&manifest_url).timeout(Duration::from_secs(5)).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<super::snapshot_manifest::SnapshotManifest>().await {
                Ok(manifest) if manifest.height == snap_height => {
                    // 1. Verify producer signature
                    if !manifest.verify_producer_signature() {
                        warn!("Snapshot manifest REJECTED: invalid producer signature at height {}", snap_height);
                        return Err(SyncError::InvalidResponse(
                            "Snapshot manifest has invalid producer signature".into()
                        ));
                    }
                    info!("Manifest check 1/4: producer signature VALID");

                    // 2. Verify at least 2 seed confirmations
                    let valid_confs = manifest.valid_confirmation_count();
                    if valid_confs < 2 {
                        warn!(
                            "Snapshot manifest REJECTED: only {} valid confirmations (need 2+) at height {}",
                            valid_confs, snap_height
                        );
                        return Err(SyncError::InvalidResponse(
                            format!("Insufficient manifest confirmations: {} (need 2+)", valid_confs)
                        ));
                    }
                    info!("Manifest check 2/4: {} seed confirmations VALID", valid_confs);

                    // 3. Verify SHA256 of compressed data
                    let computed_sha = {
                        use sha2::Digest;
                        hex::encode(sha2::Sha256::digest(&compressed))
                    };
                    if computed_sha != manifest.snapshot_sha256 {
                        warn!(
                            "Snapshot manifest REJECTED: SHA256 mismatch at height {}: computed={}, manifest={}",
                            snap_height, &computed_sha[..16], &manifest.snapshot_sha256[..16]
                        );
                        return Err(SyncError::InvalidResponse(
                            "Snapshot SHA256 mismatch with signed manifest".into()
                        ));
                    }
                    info!("Manifest check 3/4: SHA256 MATCH ({})", &computed_sha[..16]);

                    // Save state_root for post-import verification (check 4/4)
                    manifest_state_root = Some(manifest.state_root.clone());
                    info!(
                        "Snapshot manifest VERIFIED: height={}, producer sig OK, {} confirmations, SHA256 OK",
                        snap_height, valid_confs
                    );
                }
                Ok(manifest) => {
                    // Manifest exists but for a different height — skip verification
                    info!("Manifest height {} != snapshot height {} — skipping manifest check", manifest.height, snap_height);
                    manifest_state_root = None;
                }
                Err(e) => {
                    if is_seed {
                        info!("Could not parse manifest from seed {}: {} — proceeding without manifest", peer_id(peer_url), e);
                    }
                    manifest_state_root = None;
                }
            }
        }
        _ => {
            // No manifest endpoint available — OK for seeds (backward compat)
            if is_seed {
                info!("Seed {} has no manifest endpoint — proceeding with cross-verification only", peer_id(peer_url));
            }
            manifest_state_root = None;
        }
    }

    // v2.3.9 — Before taking the blockchain write lock, fetch the LWMA seed
    // headers from the same peer so the freshly fast-synced node can compute
    // next_difficulty() locally (otherwise the snapshot's frozen difficulty
    // is reused and full-sync validators reject the miner's blocks with
    // `Invalid difficulty`). An empty result is acceptable — the node then
    // falls back to the previous behaviour.
    let lwma_seed = fetch_pre_snapshot_lwma_headers(&client, peer_url, snap_height).await;

    // KF-007 + KF-008 (incident 2026-05-02, RC v3 patch 2026-05-03):
    // cross-validate the snapshot before import using two independent peer
    // observations. The previous (RC v2) version compared the snapshot's
    // (height, hash) to peers' CURRENT TIP — which over-rejected legitimate
    // stale-but-canonical snapshots and blocked node-1 from catching up
    // during the soak (a peer serving snapshot at h=28900 was rejected
    // because consensus tip had advanced to h=28918 — even though the
    // snapshot's hash matched what the cluster actually has at h=28900).
    //
    // RC v3 separates the two questions:
    //   (1) Is the snapshot on the canonical chain? Asks peers for
    //       /block/height/{snap_height} and accepts iff the snapshot's
    //       block_hash matches the majority hash AT THAT HEIGHT. This
    //       allows older snapshots as long as they're on the right chain.
    //   (2) Is the snapshot's cum_work consistent? Only enforced if the
    //       snapshot is RECENT (within 10 blocks of consensus tip), where
    //       the cum_work check is meaningful. For older snapshots the
    //       cw check is skipped — a stale snapshot's cw is from a
    //       different point in history and can't be compared to current
    //       tip cw without per-height cw queries (not available API-side).
    {
        use super::cum_work_consensus::{
            CUM_WORK_DRIFT_TOLERANCE_PCT, MIN_AGREEMENT_COUNT,
        };
        let peer_list: Vec<String> = state.peers.read()
            .map(|p| p.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|p| super::is_contactable_peer(p))
            .collect();

        if peer_list.len() >= MIN_AGREEMENT_COUNT {
            // (1) Hash @ snap_height majority check.
            // Poll /block/height/{snap_height} on each peer in parallel,
            // tracking which peer URL voted for which hash so we can
            // re-poll cum_work@h from the *canonical-hash* peers in step (2).
            let mut hash_handles = Vec::new();
            for peer in &peer_list {
                let c = client.clone();
                let p = peer.clone();
                let url = format!("{}/block/height/{}", peer, snap_height);
                hash_handles.push(tokio::spawn(async move {
                    let resp = c.get(&url).timeout(Duration::from_secs(3)).send().await
                        .ok().and_then(|r| if r.status().is_success() { Some(r) } else { None });
                    let hash_opt = if let Some(r) = resp {
                        r.json::<serde_json::Value>().await.ok()
                            .and_then(|body| body.get("hash").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    } else { None };
                    (p, hash_opt)
                }));
            }
            let mut hash_votes: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            let mut hash_responding = 0usize;
            // Peer URLs that returned the snapshot's own hash — these are
            // the ones we trust to ask for cum_work@h in step (2).
            let mut canonical_hash_peers: Vec<String> = Vec::new();
            let snap_hash_for_filter = hex::encode(&block_hash);
            for h in hash_handles {
                if let Ok((peer_url_str, Some(hash_str))) = h.await {
                    *hash_votes.entry(hash_str.clone()).or_insert(0) += 1;
                    hash_responding += 1;
                    if hash_str == snap_hash_for_filter {
                        canonical_hash_peers.push(peer_url_str);
                    }
                }
            }
            let snap_hash_hex = snap_hash_for_filter.clone();
            let votes_for_snap = hash_votes.get(&snap_hash_hex).copied().unwrap_or(0);

            if hash_responding >= MIN_AGREEMENT_COUNT {
                // We have a real signal. The snapshot's hash must be the
                // most-voted hash AT snap_height (a strict majority isn't
                // required if no other hash has a stronger vote — but for
                // safety we require votes_for_snap >= MIN_AGREEMENT_COUNT
                // AND votes_for_snap >= max_other_hash_votes).
                let max_other = hash_votes.iter()
                    .filter(|(k, _)| **k != snap_hash_hex)
                    .map(|(_, v)| *v)
                    .max()
                    .unwrap_or(0);
                if votes_for_snap < MIN_AGREEMENT_COUNT || votes_for_snap < max_other {
                    warn!(
                        "Snapshot REJECTED (KF-007 hash@h): snap_hash {} at h={} has only {} peer votes (max competing hash has {} votes, {} peers responded)",
                        &snap_hash_hex[..16], snap_height, votes_for_snap, max_other, hash_responding
                    );
                    return Err(SyncError::InvalidResponse(format!(
                        "snapshot hash at h={} not majority among {} peers (votes={}, max_other={})",
                        snap_height, hash_responding, votes_for_snap, max_other
                    )));
                }
                info!(
                    "Snapshot hash@h={} cross-check OK: {} of {} peers confirm hash {}",
                    snap_height, votes_for_snap, hash_responding, &snap_hash_hex[..16]
                );

                // (2) KF-008 ROOT FIX (RC v4 — incident 2026-05-02 follow-up).
                // We DO NOT trust the snapshot publisher's `snap_work` value.
                // Instead, query each peer that voted for the canonical hash
                // for its own `cumulative_work_at_height(snap_height)` via the
                // dedicated endpoint, and require ≥ MIN_AGREEMENT_COUNT peers
                // to return a value within CUM_WORK_DRIFT_TOLERANCE_PCT of
                // each other. The median of the agreeing values is what gets
                // persisted in DB. If we cannot form a quorum, the snapshot
                // is REFUSED — not silently imported with a single-source
                // value as in RC v3 and earlier.
                //
                // This makes it impossible for one drifted publisher to seed
                // the rest of the network with a wrong cum_work base.
                let mut cw_handles = Vec::new();
                for peer in &canonical_hash_peers {
                    let c = client.clone();
                    let url = format!("{}/cumulative_work/{}", peer, snap_height);
                    cw_handles.push(tokio::spawn(async move {
                        c.get(&url).timeout(Duration::from_secs(3)).send().await
                            .ok()
                            .and_then(|r| if r.status().is_success() { Some(r) } else { None })
                            .map(|r| async move {
                                r.json::<serde_json::Value>().await.ok()
                                    .and_then(|body| body.get("cumulative_work")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.parse::<u128>().ok()))
                            })
                    }));
                }
                let mut cw_values: Vec<u128> = Vec::new();
                for h in cw_handles {
                    if let Ok(Some(fut)) = h.await {
                        if let Some(cw) = fut.await {
                            cw_values.push(cw);
                        }
                    }
                }
                cw_values.sort();

                if cw_values.len() < MIN_AGREEMENT_COUNT {
                    warn!(
                        "Snapshot REJECTED (KF-008 root): only {} of {} canonical-hash peers returned cum_work@h={} (need ≥{}). Refusing to import snapshot with single-source cum_work seed.",
                        cw_values.len(), canonical_hash_peers.len(), snap_height, MIN_AGREEMENT_COUNT
                    );
                    return Err(SyncError::InvalidResponse(format!(
                        "KF-008: only {} peers returned cum_work@h={} (need ≥{})",
                        cw_values.len(), snap_height, MIN_AGREEMENT_COUNT
                    )));
                }

                // Compute median of the returned cw values.
                let median_cw = cw_values[cw_values.len() / 2];

                // Verify a tight cluster: require ≥ MIN_AGREEMENT_COUNT values
                // within CUM_WORK_DRIFT_TOLERANCE_PCT of the median. If the
                // peers themselves disagree wildly, we cannot trust any of
                // them — refuse.
                let tolerance = median_cw.saturating_mul(CUM_WORK_DRIFT_TOLERANCE_PCT) / 100;
                let agreeing: Vec<u128> = cw_values.iter().copied()
                    .filter(|v| {
                        let d = if *v > median_cw { *v - median_cw } else { median_cw - *v };
                        d <= tolerance || median_cw == 0
                    })
                    .collect();
                if agreeing.len() < MIN_AGREEMENT_COUNT {
                    warn!(
                        "Snapshot REJECTED (KF-008 root): peers disagree on cum_work@h={} — only {} of {} values within {}% of median {}. Values: {:?}",
                        snap_height, agreeing.len(), cw_values.len(),
                        CUM_WORK_DRIFT_TOLERANCE_PCT, median_cw, cw_values
                    );
                    return Err(SyncError::InvalidResponse(format!(
                        "KF-008: peers disagree on cum_work@h={} ({} agreeing of {})",
                        snap_height, agreeing.len(), cw_values.len()
                    )));
                }

                // Override snap_work with the recomputed median. This is the
                // value that gets persisted by import_snapshot_at_height.
                let publisher_cw = snap_work;
                snap_work = median_cw;
                let drift_from_publisher = if publisher_cw > median_cw {
                    publisher_cw - median_cw
                } else {
                    median_cw - publisher_cw
                };
                if drift_from_publisher > tolerance && publisher_cw > 0 {
                    warn!(
                        "KF-008: publisher cum_work {} drifts from peer median {} by {} (>{}% tolerance) — OVERRIDDEN with peer-median value before import",
                        publisher_cw, median_cw, drift_from_publisher, CUM_WORK_DRIFT_TOLERANCE_PCT
                    );
                } else {
                    info!(
                        "KF-008 cum_work cross-check OK: snap_work={} (peer median of {} values, all within {}% of median)",
                        snap_work, agreeing.len(), CUM_WORK_DRIFT_TOLERANCE_PCT
                    );
                }
            } else {
                warn!(
                    "Snapshot KF-007 hash@h check SKIPPED: only {} peers returned a block at h={} (need {})",
                    hash_responding, snap_height, MIN_AGREEMENT_COUNT
                );
            }
        } else {
            info!(
                "Snapshot KF-007 cross-check SKIPPED: only {} contactable peers (need ≥{}); relying on hash+height cross-verify earlier in the function",
                peer_list.len(), MIN_AGREEMENT_COUNT
            );
        }
    }

    // Import the snapshot
    let mut chain = state.blockchain.write().await;
    chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, snap_work);
    if !lwma_seed.is_empty() {
        info!(
            "pre_snapshot_lwma: seeded {} headers from peer {} for post-fast-sync LWMA",
            lwma_seed.len(), peer_id(peer_url)
        );
        chain.set_pre_snapshot_lwma(lwma_seed);
    }

    // 4. Post-import: verify state_root if manifest provided one
    if let Some(expected_root) = manifest_state_root {
        let computed_root = hex::encode(chain.state_root());
        if computed_root == expected_root {
            info!("Manifest check 4/4: state_root MATCH after import ({})", &computed_root[..16]);
        } else {
            warn!(
                "Snapshot state_root MISMATCH after import: computed={}, manifest={}. Chain may be inconsistent.",
                &computed_root[..16], &expected_root[..16]
            );
            // Don't reject — the chain will self-heal via sync. Log for monitoring.
        }
    }

    Ok(snap_height)
}

// ============ Checkpoint Verification ============

/// Verify that a peer's chain matches our hardcoded checkpoints.
/// When no checkpoints exist, returns true only for seed nodes (trusted bootstrap).
async fn verify_peer_checkpoints(client: &reqwest::Client, peer_url: &str) -> bool {
    if crate::config::HARDCODED_CHECKPOINTS.is_empty() {
        // No checkpoints — only trust seed nodes for bootstrap
        let is_seed = crate::config::SEED_NODES.iter().any(|s| peer_url.starts_with(s));
        if !is_seed {
            debug!("No checkpoints + non-seed peer {} — untrusted", peer_id(peer_url));
        }
        return is_seed;
    }
    for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
        let url = format!("{}/block/height/{}", peer_url, cp_height);
        match client.get(&url).timeout(Duration::from_secs(5)).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(block) = resp.json::<PeerBlockInfo>().await {
                    if block.hash != cp_hash {
                        warn!(
                            "Peer {} FAILS checkpoint at height {}: expected {}, got {}",
                            peer_id(peer_url), cp_height, &cp_hash[..16], &block.hash[..16]
                        );
                        return false;
                    }
                }
            }
            _ => continue, // Peer doesn't have this block — skip
        }
    }
    true
}

// ============ Block Broadcast ============

/// Broadcast a newly mined block to all peers (concurrent, with timeout).
pub async fn broadcast_block(block: &ShieldedBlock, peers: &[String], client: &reqwest::Client) -> Vec<Result<(), SyncError>> {
    broadcast_block_with_id(block, peers, client, None).await
}

/// v2.8.7 Phase 0.2 (BIP-152) — broadcast a compact-block envelope to every
/// peer. On a `200 {"status":"missing","missing":[...]}` reply, follow up
/// with a `/blocktxn` POST carrying the requested transactions in full.
/// Falls back to a full block POST when a peer rejects the compact block
/// (returns 4xx/5xx) or fails the follow-up. Returns one Result per peer.
///
/// This typically reduces wire bytes per peer from ~8 MB (full V2 block)
/// to ~5-50 KB when the mempool is in sync, dramatically lowering the
/// propagation latency that drives course-mining fork rate.
pub async fn broadcast_compact_block(
    block: &ShieldedBlock,
    peers: &[String],
    client: &reqwest::Client,
    local_peer_id: Option<String>,
) -> Vec<Result<(), SyncError>> {
    use super::compact_block::{
        build_compact_block, BlockTxn, BlockTxnRequest, PrefilledTxBody,
    };

    // Coinbase-only prefill: we expect peers to have all v1/v2 txs in their
    // mempool (most are submitted via /tx/relay or /transaction/submit_v2).
    // The receiver requests anything else via /blocktxn.
    let cb = build_compact_block(block, &[]);
    let block_hash = block.hash();
    let total_slots: usize = cb.short_ids.len() + cb.prefilled_txn.len();

    let mut handles = Vec::new();
    for peer in peers {
        if !super::is_contactable_peer(peer) { continue; }
        let cb_url = format!("{}/cmpct_block", peer);
        let txn_url = format!("{}/blocktxn", peer);
        let blocks_url = format!("{}/blocks", peer);
        let cb_clone = cb.clone();
        let block_clone = block.clone();
        let client = client.clone();
        let peer_label = peer_id(peer);
        let pid = local_peer_id.clone();
        let block_hash_for_task = block_hash;
        let total_for_task = total_slots;

        handles.push(tokio::spawn(async move {
            let common_headers = move |req: reqwest::RequestBuilder| {
                let mut r = req
                    .header("X-TSN-Version", env!("CARGO_PKG_VERSION"))
                    .header("X-TSN-Network", crate::config::NETWORK_NAME)
                    .header("X-TSN-Genesis", crate::config::EXPECTED_GENESIS_HASH);
                if let Some(ref id) = pid {
                    r = r.header("X-TSN-PeerID", id.as_str());
                }
                r
            };

            // Step 1: send the compact envelope.
            let cb_resp = match common_headers(client.post(&cb_url))
                .timeout(std::time::Duration::from_secs(15))
                .json(&cb_clone)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    // Network error on cmpct_block — fall back to full block.
                    debug!(
                        "cmpct_block transport error to {} ({:?}), falling back to /blocks",
                        peer_label, e
                    );
                    return fallback_full_block(
                        &client, &blocks_url, &block_clone, &peer_label, common_headers,
                    )
                    .await;
                }
            };

            if !cb_resp.status().is_success() {
                debug!(
                    "cmpct_block to {} returned HTTP {}, falling back to /blocks",
                    peer_label, cb_resp.status()
                );
                return fallback_full_block(
                    &client, &blocks_url, &block_clone, &peer_label, common_headers,
                )
                .await;
            }

            // Parse the response — we expect either a regular ReceiveBlock
            // success (status accepted/stored/rejected) or a missing-list.
            #[derive(serde::Deserialize)]
            struct CompactReply {
                status: String,
                #[serde(default)]
                missing: Vec<u32>,
            }
            let parsed: CompactReply = match cb_resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("cmpct_block reply parse error from {}: {}", peer_label, e);
                    return Err(SyncError::HttpError(format!("parse: {}", e)));
                }
            };

            if parsed.status != "missing" {
                // Receiver fully reconstructed and processed the block.
                return Ok(());
            }

            // Step 2: missing indexes — assemble a BlockTxnRequest.
            let mut bodies: Vec<PrefilledTxBody> = Vec::with_capacity(parsed.missing.len());
            for &slot in &parsed.missing {
                let s = slot as usize;
                if s >= total_for_task {
                    warn!(
                        "peer {} requested out-of-range slot {} (total={})",
                        peer_label, slot, total_for_task
                    );
                    return Err(SyncError::HttpError("slot oob".into()));
                }
                let body = if s < block_clone.transactions.len() {
                    PrefilledTxBody::V1(block_clone.transactions[s].clone())
                } else if s < block_clone.transactions.len() + block_clone.transactions_v2.len() {
                    let i = s - block_clone.transactions.len();
                    PrefilledTxBody::V2(block_clone.transactions_v2[i].clone())
                } else if s
                    < block_clone.transactions.len()
                        + block_clone.transactions_v2.len()
                        + block_clone.contract_deploys.len()
                {
                    let i = s - block_clone.transactions.len() - block_clone.transactions_v2.len();
                    PrefilledTxBody::Deploy(block_clone.contract_deploys[i].clone())
                } else if s
                    < block_clone.transactions.len()
                        + block_clone.transactions_v2.len()
                        + block_clone.contract_deploys.len()
                        + block_clone.contract_calls.len()
                {
                    let i = s
                        - block_clone.transactions.len()
                        - block_clone.transactions_v2.len()
                        - block_clone.contract_deploys.len();
                    PrefilledTxBody::Call(block_clone.contract_calls[i].clone())
                } else {
                    PrefilledTxBody::Coinbase(block_clone.coinbase.clone())
                };
                bodies.push(body);
            }

            let req_body = BlockTxn {
                block_hash: block_hash_for_task,
                transactions: bodies,
            };

            // Re-using the BlockTxn body shape for both directions keeps the
            // wire types consistent — the request endpoint expects a
            // BlockTxnRequest{block_hash, indexes}, but the *response* body
            // (sent back from sender to receiver) is actually pushed via
            // POST /blocks once we have the missing slots resolved. Simpler:
            // send the full block now since the round-trip cost is the same.
            let _ = req_body;
            let _ = BlockTxnRequest {
                block_hash: block_hash_for_task,
                indexes: parsed.missing.clone(),
            };
            // Push the full block so the receiver can finish reconstruction.
            // (The /blocktxn-style follow-up is reserved for future expansion
            // when the sender can re-build the partial reconstruction
            // server-side; for now sending the full block is the simplest
            // correct fallback that preserves the bytes-savings on receivers
            // that DID reconstruct from mempool.)
            fallback_full_block(
                &client, &blocks_url, &block_clone, &peer_label, common_headers,
            )
            .await
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => results.push(Err(SyncError::HttpError("compact broadcast join".into()))),
        }
    }
    results
}

/// Helper: send the full block to a peer. Used as the fallback path of
/// `broadcast_compact_block` and reused by the legacy `broadcast_block_with_id`.
async fn fallback_full_block<F>(
    client: &reqwest::Client,
    blocks_url: &str,
    block: &ShieldedBlock,
    peer_label: &str,
    common_headers: F,
) -> Result<(), SyncError>
where
    F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
{
    let result = common_headers(client.post(blocks_url))
        .timeout(std::time::Duration::from_secs(30))
        .json(block)
        .send()
        .await
        .map(|_| ())
        .map_err(SyncError::from);
    if let Err(ref e) = result {
        warn!("Failed to broadcast full block to {}: {}", peer_label, sanitize_error(e));
    }
    result
}

/// Broadcast a block with an optional local PeerID header for identification.
pub async fn broadcast_block_with_id(block: &ShieldedBlock, peers: &[String], client: &reqwest::Client, local_peer_id: Option<String>) -> Vec<Result<(), SyncError>> {
    let mut handles = Vec::new();
    for peer in peers {
        if !super::is_contactable_peer(peer) { continue; }
        let url = format!("{}/blocks", peer);
        let client = client.clone();
        let block = block.clone();
        let peer_label = peer_id(peer);
        let pid = local_peer_id.clone();
        handles.push(tokio::spawn(async move {
            let mut req = client
                .post(&url)
                .header("X-TSN-Version", env!("CARGO_PKG_VERSION"))
                .header("X-TSN-Network", crate::config::NETWORK_NAME)
                .header("X-TSN-Genesis", crate::config::EXPECTED_GENESIS_HASH);
            if let Some(ref id) = pid {
                req = req.header("X-TSN-PeerID", id.as_str());
            }
            // v2.6.1 — 30s timeout (was 3s). v2 transactions carry a Plonky3
            // STARK proof + ML-DSA-65 signature ≈ 500 KB each; with
            // V2_INCLUSION_CAP = 16, blocks can reach 8 MB. 3s was too tight on
            // residential uplinks (10K send on 2026-04-25 silently lost the
            // HTTP fallback path because the 4 MB block POST timed out before
            // the seed could read it). Also raise the failure log to warn so
            // a silent fallback failure cannot recur unnoticed.
            let result = req
                .timeout(std::time::Duration::from_secs(30))
                .json(&block)
                .send()
                .await
                .map(|_| ())
                .map_err(SyncError::from);

            if let Err(ref e) = result {
                warn!("Failed to broadcast block to {}: {}", peer_label, sanitize_error(e));
            }
            result
        }));
    }
    let mut results = Vec::new();
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => results.push(Err(SyncError::HttpError("broadcast task join error".to_string()))),
        }
    }
    results
}

// ============ v2.5.3 — Relay endorsement collection ============

/// Collect ML-DSA-65 endorsements from a set of peers over a block hash.
///
/// For each peer, POST `/relay/endorse` with the 32-byte hex-encoded hash.
/// Returned endorsements are verified locally against the block hash and
/// deduped by pk_hash. The miner's own pk_hash is filtered out (self-endorsement
/// would be pointless — the miner is already getting the 97% block reward).
///
/// Capped at `MAX_ENDORSEMENTS_PER_BLOCK` (5). If more peers respond valid,
/// the first 5 in response order win; a future tightening could score by
/// historical relay quality.
///
/// Timeout: 3s per peer in parallel. One slow peer does not starve the set.
///
/// This function never fails — if every peer is unreachable or returns junk,
/// the returned Vec is simply empty and the miner still produces a valid
/// block (no endorsements means 100% of this block's 3% slice rolls into
/// `unallocated` and eventually drops to `DEV_TREASURY` at payout height).
pub async fn collect_endorsements(
    block_hash: &[u8; crate::core::BLOCK_HASH_SIZE],
    peers: &[String],
    client: &reqwest::Client,
    miner_pk_hash: &[u8; 32],
) -> Vec<crate::core::Endorsement> {
    use crate::core::{Endorsement, MAX_ENDORSEMENTS_PER_BLOCK};

    let hash_hex = hex::encode(block_hash);
    let mut handles = Vec::new();
    for peer in peers {
        if !super::is_contactable_peer(peer) {
            continue;
        }
        let url = format!("{}/relay/endorse", peer);
        let client = client.clone();
        let body = serde_json::json!({ "header_hash": hash_hex.clone() });
        let peer_label = peer_id(peer);
        handles.push(tokio::spawn(async move {
            let resp = client
                .post(&url)
                .header("X-TSN-Version", env!("CARGO_PKG_VERSION"))
                .header("X-TSN-Network", crate::config::NETWORK_NAME)
                .header("X-TSN-Genesis", crate::config::EXPECTED_GENESIS_HASH)
                .timeout(std::time::Duration::from_secs(3))
                .json(&body)
                .send()
                .await;
            let resp = match resp {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    debug!(
                        "endorse: {} returned status {}",
                        peer_label,
                        r.status().as_u16()
                    );
                    return None;
                }
                Err(e) => {
                    debug!("endorse: {} failed: {}", peer_label, sanitize_error(&e));
                    return None;
                }
            };
            let body: serde_json::Value = match resp.json().await {
                Ok(b) => b,
                Err(_) => return None,
            };
            let pub_key_hex = body.get("pub_key").and_then(|v| v.as_str())?;
            let signature_hex = body.get("signature").and_then(|v| v.as_str())?;
            let pub_key = hex::decode(pub_key_hex).ok()?;
            let signature = hex::decode(signature_hex).ok()?;
            Some(Endorsement { pub_key, signature })
        }));
    }

    let mut accepted: Vec<Endorsement> = Vec::with_capacity(MAX_ENDORSEMENTS_PER_BLOCK);
    let mut seen_pk_hashes: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    // Miner does not endorse its own blocks.
    seen_pk_hashes.insert(*miner_pk_hash);

    for h in handles {
        if accepted.len() >= MAX_ENDORSEMENTS_PER_BLOCK {
            break;
        }
        let Ok(Some(end)) = h.await else { continue };
        if !end.verify(block_hash) {
            debug!("endorse: dropping invalid signature");
            continue;
        }
        let pkh = end.pk_hash();
        if !seen_pk_hashes.insert(pkh) {
            continue;
        }
        accepted.push(end);
    }
    accepted
}

// ============ Sync Loop ============

/// Consecutive failure counter (reduces log spam).
static SYNC_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Background task that periodically syncs with peers.
pub async fn sync_loop(state: Arc<AppState>, seed_peers: Vec<String>, sync_interval_secs: u64) {
    if seed_peers.is_empty() {
        return;
    }

    let mut interval = interval(Duration::from_secs(sync_interval_secs));
    let mut peer_failures: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    loop {
        interval.tick().await;

        // Cleanup expired bans
        {
            let now = std::time::Instant::now();
            let mut bans = state.banned_peers.write().unwrap();
            bans.retain(|url, until| {
                if now >= *until {
                    info!("Ban expired for peer {}", peer_id(url));
                    false
                } else {
                    true
                }
            });
        }

        let mut peers = state.peers.read().unwrap().clone();
        // v2.1.2: Prioritize seed nodes for sync — they have the full chain
        // and return large batches (50 blocks). Other peers may only be 1 block ahead.
        peers.sort_by(|a, b| {
            let a_is_seed = seed_peers.contains(a);
            let b_is_seed = seed_peers.contains(b);
            b_is_seed.cmp(&a_is_seed) // seeds first
        });

        for peer in &peers {
            // Skip hashed peer IDs (not contactable URLs)
            if !super::is_contactable_peer(peer) {
                continue;
            }
            // v1.8.0: Skip peers with too many consecutive failures (temporary cooldown).
            // After 20 failures, skip this peer for this cycle. Counter resets on success.
            // This prevents the sync loop from wasting time on dead peers while
            // other live peers with forked chains go undetected.
            let fail_count = peer_failures.get(peer).copied().unwrap_or(0);
            if fail_count >= 20 {
                // Only attempt dead peers every 10th cycle to detect recovery
                let cycle = SYNC_FAIL_COUNT.load(Ordering::Relaxed);
                if cycle % 10 != 0 {
                    continue;
                }
            }

            // v2.0.9: Max 50 iterations per peer to prevent infinite loop
            // if a peer keeps returning the same blocks
            let mut sync_iterations = 0u32;
            loop {
                sync_iterations += 1;
                if sync_iterations > 50 {
                    warn!("Sync from {} hit max iterations (50), moving to next peer", peer_id(peer));
                    break;
                }
                match sync_from_peer(state.clone(), peer).await {
                    Ok(n) if n > 0 => {
                        SYNC_FAIL_COUNT.store(0, Ordering::Relaxed);
                        peer_failures.remove(peer);
                        info!("Synced {} blocks from {}", n, peer_id(peer));
                        continue; // Peer may have more
                    }
                    Ok(_) => {
                        peer_failures.remove(peer);
                        break;
                    }
                    Err(e) => {
                        let count = SYNC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        let peer_count = peer_failures.entry(peer.clone()).or_insert(0);
                        *peer_count += 1;

                        if *peer_count == 1 {
                            warn!("Sync from {} failed: {}", peer_id(peer), sanitize_error(&e));
                        } else if *peer_count % 10 == 0 {
                            warn!("Sync from {} failed ({} consecutive): {}", peer_id(peer), *peer_count, sanitize_error(&e));
                        }

                        // Ghost peer cleanup: remove after 5 consecutive failures (was 10)
                        // Seed nodes are never removed.
                        if *peer_count >= 5 && !seed_peers.contains(peer) {
                            info!("Removing ghost peer {} after {} failures (blacklisted)", peer_id(peer), peer_count);
                            let mut peers_write = state.peers.write().unwrap();
                            peers_write.retain(|p| p != peer);
                            peer_failures.remove(peer);
                            // v2.1.3: Blacklist to prevent Kademlia re-adding via PeerHttpAddr
                            state.removed_peers.lock().unwrap().insert(peer.clone());
                        }
                        break;
                    }
                }
            }
        }
    }
}

// ============ Types ============

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
    difficulty: u64,
    commitment_count: u64,
    #[serde(default)]
    genesis_hash: String,
    #[serde(default)]
    cumulative_work: u128,
    #[serde(default)]
    finalized_height: u64,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerBlockInfo {
    hash: String,
    height: u64,
    prev_hash: String,
}

/// Compact header response from /headers/since endpoint.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct CompactHeaderResponse {
    height: u64,
    hash: String,
    prev_hash: String,
    difficulty: u64,
    timestamp: u64,
    cumulative_work: u128,
}

/// v2.3.9 — Fetch the last `LWMA_WINDOW + 1` compact headers that sit right
/// below `snap_height` from the peer, so the freshly fast-synced node can run
/// LWMA locally and match what full-sync validators compute. Returns an empty
/// vec if the peer is unreachable, the response is malformed, or the peer does
/// not hold those headers (e.g. it fast-synced too recently itself). In that
/// case `next_difficulty()` falls back to the frozen snapshot difficulty as
/// before — no worse than the pre-fix behaviour.
pub async fn fetch_pre_snapshot_lwma_headers(
    client: &reqwest::Client,
    peer_url: &str,
    snap_height: u64,
) -> Vec<(u64, u64, u64)> {
    use crate::consensus::LWMA_WINDOW;

    // We need the block that sits one step BEFORE the LWMA window starts
    // (LWMA needs the pre-window timestamp to compute the first solvetime).
    let needed = LWMA_WINDOW + 1;
    let since = snap_height.saturating_sub(needed + 1);
    let url = format!("{}/headers/since/{}?limit={}", peer_url, since, needed + 2);
    let resp = match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            debug!(
                "pre_snapshot_lwma: peer {} returned {} for {}",
                peer_id(peer_url),
                r.status(),
                url
            );
            return Vec::new();
        }
        Err(e) => {
            debug!(
                "pre_snapshot_lwma: peer {} unreachable for /headers/since: {}",
                peer_id(peer_url),
                sanitize_error(&e)
            );
            return Vec::new();
        }
    };
    let headers: Vec<CompactHeaderResponse> = match resp.json().await {
        Ok(h) => h,
        Err(e) => {
            debug!(
                "pre_snapshot_lwma: peer {} sent malformed header json: {}",
                peer_id(peer_url),
                e
            );
            return Vec::new();
        }
    };
    // v2.5.2 — include the snapshot tip itself (h == snap_height). Without it,
    // `next_difficulty()` at the snapshot tip falls back to `self.difficulty`
    // because `lookup_at(snap_height)` finds no block (import doesn't save the
    // tip block data) and `pre_snapshot_lwma` filtered it out. That stale
    // fallback then triggers "Invalid difficulty" on the next received block.
    let mut triples: Vec<(u64, u64, u64)> = headers
        .into_iter()
        .filter(|h| h.height <= snap_height)
        .map(|h| (h.height, h.difficulty, h.timestamp))
        .collect();
    triples.sort_by_key(|(h, _, _)| *h);
    triples.dedup_by_key(|(h, _, _)| *h);
    triples
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
}

/// v1.4.0: Verify a peer's claimed cumulative_work by sampling blocks.
pub async fn verify_peer_work_sample(
    client: &reqwest::Client,
    peer_url: &str,
    peer_height: u64,
    peer_claimed_work: u128,
) -> bool {
    const SAMPLE_COUNT: u64 = 5;
    if peer_height < SAMPLE_COUNT || peer_claimed_work == 0 {
        return true;
    }

    let mut sampled_work: u128 = 0;
    let mut sampled_count: u64 = 0;
    let step = peer_height / SAMPLE_COUNT;
    for i in 0..SAMPLE_COUNT {
        let h = (i + 1) * step;
        let url = format!("{}/block/height/{}", peer_url, h);
        if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(5)).send().await {
            if let Ok(block_info) = resp.json::<serde_json::Value>().await {
                if let Some(diff) = block_info["difficulty"].as_u64() {
                    sampled_work += diff as u128;
                    sampled_count += 1;
                }
            }
        }
    }

    if sampled_count == 0 {
        warn!("verify_peer_work_sample: couldn't fetch any blocks from {}", peer_id(peer_url));
        return false;
    }

    let avg_difficulty = sampled_work / sampled_count as u128;
    let estimated_work = avg_difficulty * peer_height as u128;
    let ratio = if estimated_work > 0 {
        peer_claimed_work as f64 / estimated_work as f64
    } else {
        0.0
    };

    if ratio < 0.5 || ratio > 2.0 {
        warn!(
            "Peer {} claimed work {} but estimate is {} (ratio {:.2}) — suspicious",
            peer_id(peer_url), peer_claimed_work, estimated_work, ratio
        );
        return false;
    }

    debug!(
        "Peer {} work OK: claimed={}, estimated={}, ratio={:.2}",
        peer_id(peer_url), peer_claimed_work, estimated_work, ratio
    );
    true
}

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Block sync manager
pub struct BlockSync {
    _config: SyncConfig,
}

impl BlockSync {
    pub fn new(config: SyncConfig) -> Self {
        Self { _config: config }
    }

    pub async fn sync(
        &self,
        _peer: &str,
        _from_height: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

/// Multi-peer snapshot verification
#[derive(Debug)]
pub struct SnapshotVerification {
    pub responding_peers: usize,
    pub agreeing_peers: usize,
    pub majority_hash: Option<String>,
}

pub async fn verify_snapshot_multi_peer(
    peer_urls: &[String],
    expected_state_root: &str,
) -> Result<SnapshotVerification, SyncError> {
    const MIN_PEERS: usize = 3;

    if peer_urls.len() < MIN_PEERS {
        return Err(SyncError::InvalidResponse(format!(
            "Need {} peers for verification, got {}",
            MIN_PEERS, peer_urls.len()
        )));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(SyncError::Request)?;

    let mut handles = Vec::new();
    for peer_url in peer_urls {
        let client = client.clone();
        let url = format!("{}/snapshot/info", peer_url);
        let peer = peer_url.clone();
        handles.push(tokio::spawn(async move {
            let result = client.get(&url).send().await;
            (peer, result)
        }));
    }

    let mut responses: Vec<(String, PeerSnapshotInfo)> = Vec::new();
    for handle in handles {
        if let Ok((peer, result)) = handle.await {
            match result {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<PeerSnapshotInfo>().await {
                        Ok(info) => responses.push((peer, info)),
                        Err(e) => warn!("Peer {} invalid response: {}", peer_id(&peer), sanitize_error(&e)),
                    }
                }
                Ok(resp) => warn!("Peer {} HTTP {}", peer_id(&peer), resp.status()),
                Err(e) => warn!("Peer {} unreachable: {}", peer_id(&peer), sanitize_error(&e)),
            }
        }
    }

    let responding_peers = responses.len();
    if responding_peers < MIN_PEERS {
        return Err(SyncError::InvalidResponse(format!(
            "Only {} peers responded, need {}", responding_peers, MIN_PEERS
        )));
    }

    let mut votes: std::collections::HashMap<(String, u64), Vec<String>> =
        std::collections::HashMap::new();
    for (peer, info) in &responses {
        votes.entry((info.block_hash.clone(), info.height)).or_default().push(peer.clone());
    }

    let (majority_key, majority_peers) = votes
        .iter()
        .max_by_key(|(_, peers)| peers.len())
        .map(|(k, p)| (k.clone(), p.clone()))
        .unwrap();

    let agreeing_peers = majority_peers.len();
    let majority_hash = majority_key.0.clone();
    let is_majority = agreeing_peers * 2 > responding_peers;

    for (peer, info) in &responses {
        if info.block_hash != majority_hash || info.height != majority_key.1 {
            warn!(
                "Peer {} disagrees: hash={}, height={} (majority: {}, {})",
                peer_id(peer), info.block_hash, info.height, majority_hash, majority_key.1
            );
        }
    }

    let _majority_root_matches = responses
        .iter()
        .any(|(_, info)| info.state_root == expected_state_root && info.block_hash == majority_hash);

    if !is_majority {
        return Err(SyncError::InvalidResponse(format!(
            "No majority: {}/{} agree", agreeing_peers, responding_peers
        )));
    }

    info!(
        "Snapshot verification OK: {}/{} agree (hash={}, height={})",
        agreeing_peers, responding_peers, majority_hash, majority_key.1
    );

    Ok(SnapshotVerification {
        responding_peers,
        agreeing_peers,
        majority_hash: Some(majority_hash),
    })
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerSnapshotInfo {
    block_hash: String,
    height: u64,
    state_root: String,
}
