//! Peer management for TSN P2P network
//! TODO: to be properly implemented by the NETWORK bot

use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Handle to communicate with a peer
#[derive(Debug, Clone)]
pub struct PeerHandle {
    pub addr: SocketAddr,
    pub connected: bool,
}

/// Handles active peers
#[derive(Debug, Clone)]
pub struct PeerManager {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerHandle>>>,
    #[allow(dead_code)]
    max_peers: usize,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            max_peers,
        }
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}
