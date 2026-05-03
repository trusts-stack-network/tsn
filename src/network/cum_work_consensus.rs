//! Multi-peer consensus for chain tip + cumulative_work.
//!
//! Created post-incident 2026-05-02 to fix three related failure modes:
//!
//! - **KF-007** (`fast-sync mono-source`): a fresh node fast-syncs from a
//!   single peer and inherits whatever chain that peer is on, even if the
//!   peer is on a fork. Fix: cross-validate against ≥3 peers before
//!   importing the snapshot.
//!
//! - **KF-008** (`cumulative_work drift`): two nodes with the same tip
//!   hash report different `cumulative_work` because each one inherited a
//!   different seed value from a different snapshot at fast_sync_base.
//!   Fix: at startup and after fast-sync, observe peers' cum_work for our
//!   own tip hash; if local is an outlier vs the median, log a structured
//!   warning and (optionally) adjust to match the median.
//!
//! - **KF-009** (`solo fork via hashpower asymmetry`): one over-powered
//!   miner produces blocks faster than the rest, eventually the divergence
//!   crosses `MAX_REORG_DEPTH` and the network splits permanently. Fix:
//!   the watchdog uses this module's consensus view to confirm the local
//!   node is the outlier, then triggers `reset_for_snapshot_resync()`.
//!
//! The module is intentionally pure data + small helpers. The integration
//! points (sync.rs / blockchain.rs / main.rs watchdog) call into it.

use serde::Deserialize;
use std::time::Duration;
use tracing::warn;

/// What we ask a peer for.
#[derive(Debug, Clone, Deserialize)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
    /// `cumulative_work` is u128 in the chain but JSON serializes as number/string.
    /// We accept both (see `parse_cum_work`).
    #[serde(default)]
    cumulative_work: serde_json::Value,
}

/// Single peer observation, normalized.
#[derive(Debug, Clone)]
pub struct PeerObservation {
    pub peer_url: String,
    pub height: u64,
    pub latest_hash: [u8; 32],
    pub cumulative_work: u128,
}

/// Consensus among peers that share the most-common (height, hash) pair.
#[derive(Debug, Clone)]
pub struct PeerConsensus {
    /// The (height, hash) that the majority of responding peers report.
    pub height: u64,
    pub hash: [u8; 32],
    /// Median cumulative_work among peers that report this (height, hash).
    pub median_cumulative_work: u128,
    /// Min/max cum_work among the agreeing peers (drift indicator).
    pub min_cumulative_work: u128,
    pub max_cumulative_work: u128,
    /// Number of peers agreeing on (height, hash).
    pub agreement_count: usize,
    /// Number of peers that responded at all.
    pub responding_peers: usize,
    /// Verbose list of agreeing observations.
    pub agreeing: Vec<PeerObservation>,
    /// Disagreeing observations (different (height, hash)).
    pub disagreeing: Vec<PeerObservation>,
}

/// Discrepancy between local node and peer consensus.
#[derive(Debug, Clone)]
pub struct Discrepancy {
    pub kind: DiscrepancyKind,
    /// Local view.
    pub local_height: u64,
    pub local_hash: [u8; 32],
    pub local_cumulative_work: u128,
    /// Consensus view.
    pub consensus_height: u64,
    pub consensus_hash: [u8; 32],
    pub consensus_median_cum_work: u128,
    pub consensus_agreement_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiscrepancyKind {
    /// Local hash at height H disagrees with peers' hash at height H.
    /// Local node is on a fork.
    HashFork,
    /// Local hash matches peers' hash, but local cum_work differs from
    /// the median by more than the tolerance. Drift.
    CumWorkDrift,
    /// Local height is far from consensus height. Possibly stuck or running ahead.
    HeightOutlier,
}

/// How tolerant we are of cum_work disagreement when hashes match.
/// 5% of the consensus median = empirically the residual drift seen
/// post-v2.9.15. Larger than that = real mismatch.
pub const CUM_WORK_DRIFT_TOLERANCE_PCT: u128 = 5;

/// How far ahead/behind a node can be without being labelled a height outlier.
pub const HEIGHT_OUTLIER_DISTANCE: u64 = 50;

/// Minimum responding peers before we trust the consensus.
pub const MIN_RESPONDING_PEERS: usize = 3;

/// Minimum agreement count before we consider a (height, hash) pair canonical.
pub const MIN_AGREEMENT_COUNT: usize = 3;

fn parse_cum_work(v: &serde_json::Value) -> Option<u128> {
    if let Some(s) = v.as_str() {
        s.parse::<u128>().ok()
    } else if let Some(n) = v.as_u64() {
        Some(n as u128)
    } else if let Some(n) = v.as_f64() {
        if n.is_finite() && n >= 0.0 {
            Some(n as u128)
        } else {
            None
        }
    } else {
        None
    }
}

/// Poll a list of peers for `/chain/info` and assemble a `PeerConsensus`.
///
/// Returns `None` if fewer than [`MIN_RESPONDING_PEERS`] peers responded
/// or if no (height, hash) pair has at least [`MIN_AGREEMENT_COUNT`]
/// agreeing peers.
pub async fn observe_peers(
    client: &reqwest::Client,
    peer_urls: &[String],
    timeout: Duration,
) -> Option<PeerConsensus> {
    let mut handles = Vec::new();
    for peer_url in peer_urls {
        let client = client.clone();
        let url = format!("{}/chain/info", peer_url.trim_end_matches('/'));
        let peer = peer_url.clone();
        handles.push(tokio::spawn(async move {
            let result = client.get(&url).timeout(timeout).send().await;
            (peer, result)
        }));
    }

    let mut observations: Vec<PeerObservation> = Vec::new();
    for handle in handles {
        let (peer, result) = match handle.await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let resp = match result {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let info: PeerChainInfo = match resp.json().await {
            Ok(i) => i,
            Err(_) => continue,
        };
        // Filter bootstrapping peers (h<10 or zero-hash tip): they are not
        // reporting "canonical chain at h=0", they are reporting "I have not
        // yet synced anything". Counting them as voters would tilt consensus
        // toward (h=0, hash=zeros) and lock the cluster out of fast-sync from
        // the single peer that actually has the chain. Encountered live
        // 2026-05-03 during Ring 0 RC rollout when 4 of 5 seeds were
        // simultaneously force-resynced and only 1 had data.
        if info.height < 10 {
            continue;
        }
        let hash_bytes = match hex::decode(&info.latest_hash) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => continue,
        };
        if hash_bytes == [0u8; 32] {
            continue;
        }
        let cum_work = match parse_cum_work(&info.cumulative_work) {
            Some(c) => c,
            None => continue,
        };
        observations.push(PeerObservation {
            peer_url: peer,
            height: info.height,
            latest_hash: hash_bytes,
            cumulative_work: cum_work,
        });
    }

    let responding_peers = observations.len();
    if responding_peers < MIN_RESPONDING_PEERS {
        warn!(
            target: "cum_work_consensus",
            "observe_peers: only {}/{} peers responded — below MIN_RESPONDING_PEERS={}",
            responding_peers, peer_urls.len(), MIN_RESPONDING_PEERS
        );
        return None;
    }

    // Group by (height, hash). Pick the largest group.
    let mut groups: std::collections::HashMap<(u64, [u8; 32]), Vec<PeerObservation>> =
        std::collections::HashMap::new();
    for obs in &observations {
        groups
            .entry((obs.height, obs.latest_hash))
            .or_default()
            .push(obs.clone());
    }
    let (best_key, agreeing) = groups
        .into_iter()
        .max_by_key(|(_, v)| v.len())
        .unwrap_or(((0, [0u8; 32]), Vec::new()));

    let agreement_count = agreeing.len();
    if agreement_count < MIN_AGREEMENT_COUNT {
        warn!(
            target: "cum_work_consensus",
            "observe_peers: best agreement {}/{} below MIN_AGREEMENT_COUNT={}",
            agreement_count, responding_peers, MIN_AGREEMENT_COUNT
        );
        return None;
    }

    // Median cum_work among agreeing peers.
    let mut works: Vec<u128> = agreeing.iter().map(|o| o.cumulative_work).collect();
    works.sort_unstable();
    let median = works[works.len() / 2];
    let min_cw = *works.first().unwrap();
    let max_cw = *works.last().unwrap();

    let disagreeing: Vec<PeerObservation> = observations
        .into_iter()
        .filter(|o| (o.height, o.latest_hash) != best_key)
        .collect();

    Some(PeerConsensus {
        height: best_key.0,
        hash: best_key.1,
        median_cumulative_work: median,
        min_cumulative_work: min_cw,
        max_cumulative_work: max_cw,
        agreement_count,
        responding_peers,
        agreeing,
        disagreeing,
    })
}

/// Detect whether the local node disagrees with the consensus.
///
/// Returns `None` if local view is consistent with the consensus (within
/// [`CUM_WORK_DRIFT_TOLERANCE_PCT`] for cum_work). Returns `Some(Discrepancy)`
/// otherwise, classified by [`DiscrepancyKind`].
///
/// Callers decide what to do with a discrepancy: log only, reject snapshot,
/// trigger auto-recovery, etc.
pub fn detect_local_discrepancy(
    local_height: u64,
    local_hash: [u8; 32],
    local_cum_work: u128,
    consensus: &PeerConsensus,
) -> Option<Discrepancy> {
    // Build a discrepancy template; we'll set kind below.
    let template = |kind: DiscrepancyKind| Discrepancy {
        kind,
        local_height,
        local_hash,
        local_cumulative_work: local_cum_work,
        consensus_height: consensus.height,
        consensus_hash: consensus.hash,
        consensus_median_cum_work: consensus.median_cumulative_work,
        consensus_agreement_count: consensus.agreement_count,
    };

    // Height outlier check (low priority — only if no other discrepancy).
    let height_diff = if local_height >= consensus.height {
        local_height - consensus.height
    } else {
        consensus.height - local_height
    };

    // Same height but different hash → fork
    if local_height == consensus.height && local_hash != consensus.hash {
        return Some(template(DiscrepancyKind::HashFork));
    }

    // Far from consensus height → outlier (could be either direction)
    if height_diff > HEIGHT_OUTLIER_DISTANCE {
        return Some(template(DiscrepancyKind::HeightOutlier));
    }

    // Same height, same hash: check cum_work drift.
    if local_height == consensus.height && local_hash == consensus.hash {
        let median = consensus.median_cumulative_work;
        if median == 0 {
            return None;
        }
        // Tolerance = CUM_WORK_DRIFT_TOLERANCE_PCT% of median.
        let tolerance = median.saturating_mul(CUM_WORK_DRIFT_TOLERANCE_PCT) / 100;
        let diff = if local_cum_work > median {
            local_cum_work - median
        } else {
            median - local_cum_work
        };
        if diff > tolerance {
            return Some(template(DiscrepancyKind::CumWorkDrift));
        }
    }

    None
}

/// Format a Discrepancy as a structured log line.
pub fn format_discrepancy(d: &Discrepancy) -> String {
    format!(
        "kind={:?} local=(h={} hash={} cw={}) consensus=(h={} hash={} median_cw={} agree={})",
        d.kind,
        d.local_height,
        hex::encode(&d.local_hash[..8]),
        d.local_cumulative_work,
        d.consensus_height,
        hex::encode(&d.consensus_hash[..8]),
        d.consensus_median_cum_work,
        d.consensus_agreement_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(peer: &str, h: u64, hash: u8, cw: u128) -> PeerObservation {
        PeerObservation {
            peer_url: peer.to_string(),
            height: h,
            latest_hash: [hash; 32],
            cumulative_work: cw,
        }
    }

    #[test]
    fn detect_local_no_discrepancy() {
        let consensus = PeerConsensus {
            height: 1000, hash: [1; 32],
            median_cumulative_work: 1_000_000,
            min_cumulative_work: 1_000_000, max_cumulative_work: 1_000_000,
            agreement_count: 3, responding_peers: 5,
            agreeing: vec![], disagreeing: vec![],
        };
        // Local matches exactly
        assert!(detect_local_discrepancy(1000, [1; 32], 1_000_000, &consensus).is_none());
        // Within 5% tolerance
        assert!(detect_local_discrepancy(1000, [1; 32], 1_040_000, &consensus).is_none());
    }

    #[test]
    fn detect_hash_fork() {
        let consensus = PeerConsensus {
            height: 1000, hash: [1; 32],
            median_cumulative_work: 1_000_000,
            min_cumulative_work: 1_000_000, max_cumulative_work: 1_000_000,
            agreement_count: 3, responding_peers: 5,
            agreeing: vec![], disagreeing: vec![],
        };
        let d = detect_local_discrepancy(1000, [2; 32], 1_000_000, &consensus).unwrap();
        assert_eq!(d.kind, DiscrepancyKind::HashFork);
    }

    #[test]
    fn detect_cum_work_drift() {
        let consensus = PeerConsensus {
            height: 1000, hash: [1; 32],
            median_cumulative_work: 1_000_000,
            min_cumulative_work: 1_000_000, max_cumulative_work: 1_000_000,
            agreement_count: 3, responding_peers: 5,
            agreeing: vec![], disagreeing: vec![],
        };
        // 10% drift > 5% tolerance
        let d = detect_local_discrepancy(1000, [1; 32], 1_100_000, &consensus).unwrap();
        assert_eq!(d.kind, DiscrepancyKind::CumWorkDrift);
    }

    #[test]
    fn detect_height_outlier() {
        let consensus = PeerConsensus {
            height: 1000, hash: [1; 32],
            median_cumulative_work: 1_000_000,
            min_cumulative_work: 1_000_000, max_cumulative_work: 1_000_000,
            agreement_count: 3, responding_peers: 5,
            agreeing: vec![], disagreeing: vec![],
        };
        // 200 blocks ahead (well beyond 50)
        let d = detect_local_discrepancy(1200, [1; 32], 1_000_000, &consensus).unwrap();
        assert_eq!(d.kind, DiscrepancyKind::HeightOutlier);
    }

    #[test]
    fn parse_cum_work_handles_string_and_number() {
        assert_eq!(parse_cum_work(&serde_json::json!("123456")), Some(123456));
        assert_eq!(parse_cum_work(&serde_json::json!(123456u64)), Some(123456));
        assert_eq!(parse_cum_work(&serde_json::json!("not a number")), None);
        assert_eq!(parse_cum_work(&serde_json::Value::Null), None);
    }
}
