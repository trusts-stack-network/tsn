//! Network activity counters and event stream.
//!
//! v2.3.9 — used by the explorer to render typed traffic particles from real
//! node telemetry instead of a random simulation.
//!
//! Two parallel surfaces:
//! - `ActivityCounters` — rolling AtomicU64 counts exposed at `GET /stats/activity`,
//!   polled by the explorer every few seconds.
//! - `ActivityBus` — `tokio::sync::broadcast` channel exposed at `GET /events/stream`
//!   (Server-Sent Events) for push-based, low-latency updates.
//!
//! Both surfaces are strictly additive and read-only from the node's point of
//! view: they cannot affect consensus. Incrementing a counter on every block
//! accept or peer handshake is cheap (one atomic add).

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Seven kinds of network events the explorer animates with distinct particles.
/// Keep this in sync with `PARTICLE_TYPES` in `network.js`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    /// Tip announcement received from a peer (POST /tip).
    Tip,
    /// Full block received from a peer (POST /blocks).
    Block,
    /// V2 transaction received or gossiped (post-quantum).
    Tx,
    /// Block-range sync request received (GET /blocks/since/...).
    Sync,
    /// Snapshot download served (GET /snapshot/download).
    Snapshot,
    /// Peer handshake / Identify event processed.
    Peer,
    /// Block rejected as orphan / invalid / fork.
    Reject,
}

/// Cumulative counter per activity kind.
/// Counters never reset; the explorer computes deltas between polls.
#[derive(Debug, Default)]
pub struct ActivityCounters {
    pub tip: AtomicU64,
    pub block: AtomicU64,
    pub tx: AtomicU64,
    pub sync: AtomicU64,
    pub snapshot: AtomicU64,
    pub peer: AtomicU64,
    pub reject: AtomicU64,
}

impl ActivityCounters {
    pub fn bump(&self, kind: ActivityKind) {
        let counter = match kind {
            ActivityKind::Tip => &self.tip,
            ActivityKind::Block => &self.block,
            ActivityKind::Tx => &self.tx,
            ActivityKind::Sync => &self.sync,
            ActivityKind::Snapshot => &self.snapshot,
            ActivityKind::Peer => &self.peer,
            ActivityKind::Reject => &self.reject,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot_view(&self) -> ActivitySnapshot {
        ActivitySnapshot {
            tip: self.tip.load(Ordering::Relaxed),
            block: self.block.load(Ordering::Relaxed),
            tx: self.tx.load(Ordering::Relaxed),
            sync: self.sync.load(Ordering::Relaxed),
            snapshot: self.snapshot.load(Ordering::Relaxed),
            peer: self.peer.load(Ordering::Relaxed),
            reject: self.reject.load(Ordering::Relaxed),
        }
    }
}

/// JSON snapshot shape returned by `/stats/activity`.
#[derive(Debug, Clone, Serialize)]
pub struct ActivitySnapshot {
    pub tip: u64,
    pub block: u64,
    pub tx: u64,
    pub sync: u64,
    pub snapshot: u64,
    pub peer: u64,
    pub reject: u64,
}

/// One event pushed through the SSE `/events/stream` endpoint.
/// `from_peer` is only populated when the source is known and safe to expose
/// (peer short-id, never a raw IP or token).
#[derive(Debug, Clone, Serialize)]
pub struct ActivityEvent {
    pub kind: ActivityKind,
    pub at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// Broadcast bus shared across the app. The receiver is cloned per SSE client.
/// Buffer size 256 is a comfortable safety margin — a slow client that lags
/// more than 256 events drops the oldest ones (standard broadcast semantics)
/// instead of blocking the producer.
pub struct ActivityBus {
    sender: tokio::sync::broadcast::Sender<ActivityEvent>,
}

impl ActivityBus {
    pub fn new() -> Self {
        let (sender, _recv) = tokio::sync::broadcast::channel(256);
        Self { sender }
    }

    pub fn publish(&self, event: ActivityEvent) {
        // Ignore send errors: no receivers means no one cares, not a failure.
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ActivityEvent> {
        self.sender.subscribe()
    }
}

impl Default for ActivityBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper: current Unix timestamp in seconds. Never panics.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convenience: record a kind and publish an event in one call.
pub fn record(
    counters: &ActivityCounters,
    bus: &ActivityBus,
    kind: ActivityKind,
    height: Option<u64>,
    from_peer: Option<String>,
    bytes: Option<u64>,
) {
    counters.bump(kind);
    bus.publish(ActivityEvent {
        kind,
        at_unix: now_secs(),
        height,
        from_peer,
        bytes,
    });
}
