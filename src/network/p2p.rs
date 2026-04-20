//! TSN P2P Network Layer using libp2p
//!
//! Provides:
//! - **GossipSub** for block/transaction propagation (push-based)
//! - **Kademlia DHT** for peer discovery
//! - **AutoNAT + Relay + DCUtR** for NAT traversal
//! - **Identify** for peer metadata exchange
//! - Node identity via Ed25519 keypair (PeerID)
//!
//! This module runs alongside the existing HTTP API (which serves
//! wallet, explorer, and external tools). The P2P layer handles
//! real-time block/tx propagation between nodes.

use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
    futures::StreamExt,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error, debug};

/// GossipSub topic names
const TOPIC_BLOCKS: &str = "tsn/blocks/1";
const TOPIC_TRANSACTIONS: &str = "tsn/transactions/1";
const TOPIC_BLOCK_REQUEST: &str = "tsn/block-request/1";
const TOPIC_TIP: &str = "tsn/tip/1";
const TOPIC_BLOCK_RESPONSE: &str = "tsn/block-response/1";

/// P2P configuration
pub struct P2pConfig {
    /// Port to listen on for P2P connections
    pub listen_port: u16,
    /// Bootstrap peer addresses with known PeerIDs (multiaddr format)
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Seed addresses to dial (PeerID unknown — discovered via Identify)
    pub dial_seeds: Vec<Multiaddr>,
    /// Whether to act as a relay server (seeds should enable this)
    pub relay_server: bool,
    /// Network name for protocol identification
    pub protocol_version: String,
    /// v2.3.0 Phase 2.3: free-form agent_version string exchanged via Identify.
    /// Used to carry a startup-time height hint (format "h=<number>") so peers
    /// can cache our height at connection without an HTTP round-trip.
    /// Backward-compatible: peers that don't parse this simply ignore it.
    /// Empty string disables the hint.
    pub agent_version: String,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_port: 9334,
            bootstrap_peers: Vec::new(),
            dial_seeds: Vec::new(),
            relay_server: false,
            protocol_version: format!("tsn/{}", env!("CARGO_PKG_VERSION")),
            agent_version: String::new(),
        }
    }
}

/// v2.3.0 Phase 2.3: extract a height hint from a libp2p Identify agent_version
/// field. Accepts `h=<u64>` as a whitespace-delimited token anywhere in the
/// string; returns `None` if no such token is present or the value cannot be
/// parsed. Case-sensitive (`H=...` is ignored).
///
/// Backward-compatible: peers with an empty or unrelated `agent_version`
/// produce `None` and are handled by the usual fallback paths (tip gossip,
/// HTTP `/chain/info`).
pub fn parse_agent_version_height(agent_version: &str) -> Option<u64> {
    for token in agent_version.split_whitespace() {
        if let Some(num) = token.strip_prefix("h=") {
            if let Ok(h) = num.parse::<u64>() {
                return Some(h);
            }
        }
    }
    None
}

/// Events emitted by the P2P layer to the application
#[derive(Debug)]
pub enum P2pEvent {
    /// A new block was received via GossipSub
    NewBlock(Vec<u8>),
    /// A new transaction was received via GossipSub
    NewTransaction(Vec<u8>),
    /// A new peer connected
    PeerConnected(PeerId),
    /// A peer disconnected
    PeerDisconnected(PeerId),
    /// NAT status detected
    NatStatus(String),
    /// A peer was identified with HTTP-reachable addresses
    PeerHttpAddr(String), // e.g. "http://1.2.3.4:9333"
    /// A peer requested blocks (from_height, to_height)
    BlockRequest(u64, u64),
}

/// Commands sent to the P2P layer from the application
#[derive(Debug)]
pub enum P2pCommand {
    /// Broadcast a mined block to the network
    BroadcastBlock(Vec<u8>),
    /// Broadcast a transaction to the network
    BroadcastTransaction(Vec<u8>),
    /// Get the list of connected peers
    GetPeers(tokio::sync::oneshot::Sender<Vec<PeerInfo>>),
    /// Request missing blocks from the network (from_height, to_height)
    RequestBlocks(u64, u64),
    /// Send blocks in response to a BlockRequest (serialized blocks)
    SendBlocks(Vec<Vec<u8>>),
    /// Broadcast our current tip (height + hash) to P2P peers
    BroadcastTip(u64, String),
}

/// Information about a connected peer
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub height: Option<u64>,
    pub protocol: String,
    /// Epoch seconds when height was last updated (for staleness detection)
    pub height_updated_at: Option<u64>,
}

/// Combined libp2p behaviour for TSN
#[derive(NetworkBehaviour)]
pub struct TsnBehaviour {
    /// Block and transaction propagation
    pub gossipsub: gossipsub::Behaviour,
    /// Peer discovery via DHT
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Peer identification and metadata exchange
    pub identify: identify::Behaviour,
    /// NAT detection
    pub autonat: autonat::Behaviour,
    /// Relay client (for nodes behind NAT)
    pub relay_client: relay::client::Behaviour,
    /// Relay server (for seed nodes that help NAT traversal)
    pub relay_server: relay::Behaviour,
    /// Direct connection upgrade through relay (hole punching)
    pub dcutr: dcutr::Behaviour,
}

/// Shared peer list — updated by the P2P event loop, read by the HTTP API.
/// This avoids going through the mpsc channel (which blocks when the loop is busy).
pub type SharedPeerList = Arc<std::sync::RwLock<Vec<PeerInfo>>>;

/// The P2P node handle — used by the application to interact with the P2P layer
pub struct P2pNode {
    /// Send commands to the P2P event loop
    pub command_tx: mpsc::Sender<P2pCommand>,
    /// Receive events from the P2P event loop
    pub event_rx: mpsc::Receiver<P2pEvent>,
    /// Our PeerId
    pub peer_id: PeerId,
    /// Shared peer list for instant read by API (no channel wait)
    pub shared_peers: SharedPeerList,
    /// Our local keypair (for signing)
    local_key: libp2p::identity::Keypair,
}

impl P2pNode {
    /// Create and start a new P2P node.
    /// Returns the node handle and spawns the event loop as a tokio task.
    pub async fn start(config: P2pConfig) -> anyhow::Result<Self> {
        // Generate or load Ed25519 keypair for P2P identity
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        info!("P2P node starting with PeerID: {}", peer_id);

        // Build the swarm with all behaviours
        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                // GossipSub with message deduplication
                // M7 audit fix: use Blake2s (crypto hash) instead of DefaultHasher (SipHash)
                // SipHash is not collision-resistant — an attacker could craft messages
                // with the same SipHash to bypass deduplication.
                let message_id_fn = |message: &gossipsub::Message| {
                    use blake2::{Blake2s256, Digest};
                    let mut hasher = Blake2s256::new();
                    hasher.update(&message.data);
                    let hash = hasher.finalize();
                    gossipsub::MessageId::from(hex::encode(hash))
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(700)) // ETH2/Polkadot standard (was 5s)
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .max_transmit_size(1 * 1024 * 1024) // M6 audit fix: 1MB max (was 4MB — too large for gossip)
                    .flood_publish(false) // Mesh-only propagation: O(D×N) instead of O(N²) flood
                    .mesh_n_low(4)        // ETH2-inspired mesh params for 100+ nodes
                    .mesh_n(6)            // 6 mesh peers (scales to log_6(500) = 3.5 hops)
                    .mesh_n_high(12)      // Prune if too many mesh connections
                    .mesh_outbound_min(2) // Min outbound for partition resistance
                    .gossip_lazy(6)       // IHAVE/IWANT backup for nodes outside mesh
                    // v2.3.0 propagation fix: extend retention so v2 txs survive
                    // long enough to reach miners that join the mesh later.
                    // 600 heartbeats × 700 ms = 7 min message retention.
                    // 60 heartbeats × 700 ms = ~42 s IHAVE announcement window.
                    .history_length(600)
                    .history_gossip(60)
                    .fanout_ttl(Duration::from_secs(60))
                    .build()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // Kademlia DHT with explicit config
                let mut kad_config = kad::Config::default();
                kad_config.set_query_timeout(Duration::from_secs(60));
                kad_config.set_parallelism(std::num::NonZeroUsize::new(3).unwrap());
                kad_config.set_record_ttl(Some(Duration::from_secs(3600)));
                kad_config.set_provider_record_ttl(Some(Duration::from_secs(3600)));
                let mut kademlia = kad::Behaviour::with_config(
                    peer_id,
                    kad::store::MemoryStore::new(peer_id),
                    kad_config,
                );
                kademlia.set_mode(Some(kad::Mode::Server));

                // Identify protocol
                let mut identify_cfg = identify::Config::new(
                    config.protocol_version.clone(),
                    key.public(),
                )
                .with_push_listen_addr_updates(true)
                .with_interval(Duration::from_secs(60));
                // v2.3.0 Phase 2.3: ship startup-time height hint via agent_version.
                // Set only if the caller provided one; empty string leaves libp2p default.
                if !config.agent_version.is_empty() {
                    identify_cfg = identify_cfg.with_agent_version(config.agent_version.clone());
                }
                let identify = identify::Behaviour::new(identify_cfg);

                // AutoNAT
                let autonat = autonat::Behaviour::new(
                    peer_id,
                    autonat::Config {
                        retry_interval: Duration::from_secs(30),
                        refresh_interval: Duration::from_secs(60),
                        ..Default::default()
                    },
                );

                // Relay server
                let relay_server = relay::Behaviour::new(
                    peer_id,
                    relay::Config::default(),
                );

                // DCUtR (hole punching)
                let dcutr = dcutr::Behaviour::new(peer_id);

                Ok(TsnBehaviour {
                    gossipsub,
                    kademlia,
                    identify,
                    autonat,
                    relay_client,
                    relay_server,
                    dcutr,
                })
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(120))
                 .with_max_negotiating_inbound_streams(128)
            })
            .build();

        // Subscribe to topics
        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
        let req_topic = gossipsub::IdentTopic::new(TOPIC_BLOCK_REQUEST);
        let tip_topic = gossipsub::IdentTopic::new(TOPIC_TIP);
        let resp_topic = gossipsub::IdentTopic::new(TOPIC_BLOCK_RESPONSE);
        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&req_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&tip_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&resp_topic)?;

        // Listen on TCP and QUIC
        let listen_addr_tcp: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port).parse()?;
        let listen_addr_quic: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.listen_port).parse()?;
        swarm.listen_on(listen_addr_tcp)?;
        swarm.listen_on(listen_addr_quic)?;

        // Add bootstrap peers with known PeerIDs to Kademlia
        for (peer, addr) in &config.bootstrap_peers {
            swarm.behaviour_mut().kademlia.add_address(peer, addr.clone());
            swarm.dial(addr.clone()).ok();
            info!("Dialing bootstrap peer: {}", &peer.to_string()[..16.min(peer.to_string().len())]);
        }

        // Dial seed nodes (PeerID unknown — Identify protocol will exchange them)
        for addr in &config.dial_seeds {
            match swarm.dial(addr.clone()) {
                Ok(_) => info!("Dialing P2P seed..."),
                Err(_) => warn!("Failed to dial P2P seed"),
            }
        }

        // Bootstrap Kademlia if we have peers
        if !config.bootstrap_peers.is_empty() {
            if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                warn!("Kademlia bootstrap failed: {:?}", e);
            }
        }

        // Schedule a delayed Kademlia bootstrap (after Identify exchanges PeerIDs)
        let delayed_bootstrap = !config.dial_seeds.is_empty();

        // Create channels for communication with application
        let (event_tx, event_rx) = mpsc::channel(1024);
        let (command_tx, command_rx) = mpsc::channel(1024);
        let shared_peers: SharedPeerList = Arc::new(std::sync::RwLock::new(Vec::new()));

        // Spawn the event loop (with seed addresses for periodic redial)
        let seed_addrs = config.dial_seeds.clone();
        let loop_peers = shared_peers.clone();
        tokio::spawn(p2p_event_loop(swarm, event_tx, command_rx, seed_addrs, loop_peers));

        Ok(P2pNode {
            command_tx,
            event_rx,
            peer_id,
            shared_peers,
            local_key,
        })
    }

    /// Broadcast a block to the network
    pub async fn broadcast_block(&self, block_data: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx.send(P2pCommand::BroadcastBlock(block_data)).await?;
        Ok(())
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&self, tx_data: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx.send(P2pCommand::BroadcastTransaction(tx_data)).await?;
        Ok(())
    }

    /// Broadcast our current tip (height + hash) to P2P peers via GossipSub
    pub async fn broadcast_tip(&self, height: u64, hash: String) -> anyhow::Result<()> {
        self.command_tx.send(P2pCommand::BroadcastTip(height, hash)).await?;
        Ok(())
    }

    /// Get connected peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.command_tx.send(P2pCommand::GetPeers(tx)).await.is_ok() {
            rx.await.unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}

/// The main P2P event loop — runs as a background task
async fn p2p_event_loop(
    mut swarm: Swarm<TsnBehaviour>,
    event_tx: mpsc::Sender<P2pEvent>,
    mut command_rx: mpsc::Receiver<P2pCommand>,
    seed_addrs: Vec<Multiaddr>,
    shared_peers: SharedPeerList,
) {
    let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
    let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
    let req_topic = gossipsub::IdentTopic::new(TOPIC_BLOCK_REQUEST);
    let tip_topic = gossipsub::IdentTopic::new(TOPIC_TIP);
    let resp_topic = gossipsub::IdentTopic::new(TOPIC_BLOCK_RESPONSE);

    // Track identified peers to avoid spam logging
    let mut identified_peers: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
    // Track peer heights (updated via block-announces and identify)
    let mut peer_heights: std::collections::HashMap<PeerId, u64> = std::collections::HashMap::new();
    // Track when each peer's height was last updated (epoch seconds)
    let mut peer_height_times: std::collections::HashMap<PeerId, u64> = std::collections::HashMap::new();
    // Track peer protocol versions (updated via identify)
    let mut peer_versions: std::collections::HashMap<PeerId, String> = std::collections::HashMap::new();
    // Backoff for outdated peers: don't spam disconnect logs every 30s
    // Maps PeerID → (next_allowed_log_time, disconnect_count)
    let mut outdated_backoff: std::collections::HashMap<PeerId, (std::time::Instant, u32)> = std::collections::HashMap::new();
    // v2.3.7 — Last meaningful activity per peer (message received, identify, etc.).
    // Peers whose TCP stays open but stop broadcasting for 120s are evicted from the
    // visible SharedPeerList so the explorer stops showing ghost entries.
    let mut peer_last_activity: std::collections::HashMap<PeerId, std::time::Instant> = std::collections::HashMap::new();
    const PEER_GHOST_TTL: std::time::Duration = std::time::Duration::from_secs(120);

    // Helper: refresh the shared peer list from current swarm state
    macro_rules! refresh_shared_peers {
        () => {
            let local_proto = format!("tsn/{}/relay", env!("CARGO_PKG_VERSION"));
            let now_ttl = std::time::Instant::now();
            let peers_snapshot: Vec<PeerInfo> = swarm.connected_peers()
                .filter(|p| {
                    // v2.3.7: hide peers with no activity for PEER_GHOST_TTL.
                    // Eviction from the visible list does not disconnect them
                    // at the libp2p layer — they just stop polluting the explorer.
                    match peer_last_activity.get(*p) {
                        Some(t) => now_ttl.duration_since(*t) < PEER_GHOST_TTL,
                        None => true, // never-seen peers shown until first event window closes
                    }
                })
                .map(|p| PeerInfo {
                    peer_id: p.to_string(),
                    height: peer_heights.get(p).copied(),
                    protocol: peer_versions.get(p).cloned().unwrap_or_else(|| local_proto.clone()),
                    height_updated_at: peer_height_times.get(p).copied(),
                })
                .collect();
            if let Ok(mut sp) = shared_peers.write() {
                *sp = peers_snapshot;
            }
        };
    }

    // Periodic redial timer for seeds (every 30s if not enough peers)
    let mut redial_interval = tokio::time::interval(Duration::from_secs(30));
    redial_interval.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            // Periodically redial seeds if we have few P2P peers
            _ = redial_interval.tick() => {
                let connected = swarm.connected_peers().count();
                if connected < 3 && !seed_addrs.is_empty() {
                    debug!("P2P: {} peers connected, redialing {} seeds...", connected, seed_addrs.len());
                    for addr in &seed_addrs {
                        swarm.dial(addr.clone()).ok();
                    }
                }
                // v2.3.7 — force a shared-peers refresh every 30s so ghost peers
                // (connected but silent for > PEER_GHOST_TTL) are evicted from
                // the explorer view even without an incoming event.
                refresh_shared_peers!();
            }
            // Handle incoming swarm events
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(TsnBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message, .. }
                    )) => {
                        // v2.3.7 — mark this peer as active so the ghost-peer TTL resets.
                        peer_last_activity.insert(propagation_source, std::time::Instant::now());
                        if let Some(source) = message.source {
                            peer_last_activity.insert(source, std::time::Instant::now());
                        }
                        let topic = message.topic.as_str();
                        if topic == block_topic.hash().as_str() {
                            debug!("Received block via GossipSub ({} bytes)", message.data.len());
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                                if let Some(h) = v.get("coinbase").and_then(|c| c.get("height")).and_then(|h| h.as_u64()) {
                                    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                    // Track original source's height
                                    if let Some(source) = message.source {
                                        peer_heights.insert(source, h);
                                        peer_height_times.insert(source, now_secs);
                                    }
                                    // v2.1.3: Also track propagation_source — the peer that
                                    // forwarded us this block must be at least at this height.
                                    // This keeps peer heights fresh even when tip broadcasts
                                    // are delayed (mesh formation after restart).
                                    let prev = peer_heights.get(&propagation_source).copied().unwrap_or(0);
                                    if h > prev {
                                        peer_heights.insert(propagation_source, h);
                                        peer_height_times.insert(propagation_source, now_secs);
                                    }
                                    refresh_shared_peers!();
                                }
                            }
                            event_tx.send(P2pEvent::NewBlock(message.data)).await.ok();
                        } else if topic == resp_topic.hash().as_str() {
                            // Block response (requested blocks) — treat as new block
                            debug!("Received block response via GossipSub ({} bytes)", message.data.len());
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                                if let Some(h) = v.get("coinbase").and_then(|c| c.get("height")).and_then(|h| h.as_u64()) {
                                    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                    if let Some(source) = message.source {
                                        peer_heights.insert(source, h);
                                        peer_height_times.insert(source, now_secs);
                                    }
                                    let prev = peer_heights.get(&propagation_source).copied().unwrap_or(0);
                                    if h > prev {
                                        peer_heights.insert(propagation_source, h);
                                        peer_height_times.insert(propagation_source, now_secs);
                                    }
                                    refresh_shared_peers!();
                                }
                            }
                            event_tx.send(P2pEvent::NewBlock(message.data)).await.ok();
                        } else if topic == tx_topic.hash().as_str() {
                            debug!("Received transaction via GossipSub ({} bytes)", message.data.len());
                            event_tx.send(P2pEvent::NewTransaction(message.data)).await.ok();
                        } else if topic == tip_topic.hash().as_str() {
                            // Tip announcement received — update peer height.
                            // v2.3.9 — always accept the broadcast value (including downgrades).
                            // A peer that legitimately wipes/resets its chain needs us to
                            // reflect its new lower height; the previous `if h > prev` check
                            // trapped us in a stale cache (e.g. EPYC1 at 2150 pre-wipe stayed
                            // cached even after the peer fast-synced back to h=2133).
                            if let Some(source) = message.source {
                                if let Ok(tip) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                                    if let Some(h) = tip.get("height").and_then(|v| v.as_u64()) {
                                        let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                        peer_heights.insert(source, h);
                                        peer_height_times.insert(source, now_secs);
                                        peer_last_activity.insert(source, std::time::Instant::now());
                                        refresh_shared_peers!();
                                    }
                                }
                            }
                        } else if topic == req_topic.hash().as_str() {
                            // Block request received — forward to application to serve blocks
                            if let Ok(req) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                                let from = req.get("from").and_then(|v| v.as_u64()).unwrap_or(0);
                                let to = req.get("to").and_then(|v| v.as_u64()).unwrap_or(0);
                                if from > 0 && to >= from && to - from <= 50 {
                                    debug!("P2P: block request received: {} → {}", from, to);
                                    event_tx.send(P2pEvent::BlockRequest(from, to)).await.ok();
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(TsnBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        // v2.3.7 — mark active on identify too.
                        peer_last_activity.insert(peer_id, std::time::Instant::now());
                        // Process peer identification (log only first time or if not in backoff)
                        {
                            let is_new = identified_peers.insert(peer_id);
                            let in_backoff = outdated_backoff.contains_key(&peer_id);
                            if is_new && !in_backoff {
                                debug!("P2P: identified peer {} — {}",
                                    &peer_id.to_string()[..16],
                                    info.protocol_version,
                                );
                            }

                            // FORK PROTECTION: disconnect peers with incompatible protocol version
                            if !info.protocol_version.starts_with("tsn/") {
                                warn!("P2P: disconnecting peer {} — not a TSN node ({})",
                                    &peer_id.to_string()[..16], info.protocol_version);
                                let _ = swarm.disconnect_peer_id(peer_id);
                                continue;
                            }
                            // REJECT outdated peers: disconnect if below MINIMUM_VERSION
                            if let Some(ver) = info.protocol_version.strip_prefix("tsn/") {
                                if !crate::network::version_check::version_meets_minimum(ver) {
                                    let _ = swarm.disconnect_peer_id(peer_id);
                                    // Don't remove from identified_peers — prevents re-logging on reconnect

                                    // Backoff logging: escalate silence from 2min → 5min → 10min → 30min
                                    let now = std::time::Instant::now();
                                    let (next_log, count) = outdated_backoff
                                        .entry(peer_id)
                                        .or_insert((now, 0));
                                    if now >= *next_log {
                                        let backoff_secs = match *count {
                                            0 => 0,       // first time: log immediately
                                            1 => 120,     // 2 min
                                            2 => 300,     // 5 min
                                            3 => 600,     // 10 min
                                            _ => 1800,    // 30 min
                                        };
                                        *count += 1;
                                        warn!("P2P: disconnecting outdated peer {} — {} (minimum: tsn/{}) [seen {} times]",
                                            &peer_id.to_string()[..16], info.protocol_version,
                                            crate::network::version_check::MINIMUM_VERSION, *count);
                                        *next_log = now + std::time::Duration::from_secs(backoff_secs);
                                    }
                                    continue;
                                }
                                // Peer updated! Clear backoff and re-allow identification logging
                                outdated_backoff.remove(&peer_id);
                                identified_peers.remove(&peer_id);
                                crate::network::auto_update::notify_peer_version(ver);
                            }
                            // Store peer version
                            peer_versions.insert(peer_id, info.protocol_version.clone());
                            // v2.3.0 Phase 2.3: extract startup height hint from agent_version
                            // if present. Peers without a parseable hint are silently ignored
                            // (backward-compatible). Gossip tip broadcasts override stale hints
                            // within ~10s.
                            if let Some(hint_h) = parse_agent_version_height(&info.agent_version) {
                                let prev = peer_heights.get(&peer_id).copied().unwrap_or(0);
                                if hint_h > prev {
                                    let now_secs = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    peer_heights.insert(peer_id, hint_h);
                                    peer_height_times.insert(peer_id, now_secs);
                                    refresh_shared_peers!();
                                }
                            }
                        }
                        // Add discovered addresses to Kademlia
                        for addr in &info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                        }
                        // Extract HTTP-reachable address from peer's listen addrs
                        // Look for /ip4/X.X.X.X/tcp/PORT patterns and derive HTTP URL
                        for addr in &info.listen_addrs {
                            let addr_str = addr.to_string();
                            // Parse multiaddr: /ip4/1.2.3.4/tcp/9334 → http://1.2.3.4:9333
                            if let Some(ip_start) = addr_str.find("/ip4/") {
                                let rest = &addr_str[ip_start + 5..];
                                if let Some(ip_end) = rest.find('/') {
                                    let ip = &rest[..ip_end];
                                    // Skip loopback, wildcard, and RFC1918 private ranges.
                                    // Private IPs in a peer's listen_addrs are LAN-only and
                                    // unreachable from public nodes; adding them to state.peers
                                    // just produces doomed HTTP relays. v2.3.0 propagation fix.
                                    if ip == "127.0.0.1" || ip == "0.0.0.0" { continue; }
                                    if ip.starts_with("10.") { continue; }
                                    if ip.starts_with("192.168.") { continue; }
                                    if let Some(second) = ip.strip_prefix("172.") {
                                        if let Some(octet_end) = second.find('.') {
                                            if let Ok(octet) = second[..octet_end].parse::<u8>() {
                                                if (16..=31).contains(&octet) { continue; }
                                            }
                                        }
                                    }
                                    // P2P port is typically API port + 1 (9334 → 9333)
                                    if let Some(tcp_idx) = rest.find("/tcp/") {
                                        let port_str = &rest[tcp_idx + 5..];
                                        let port_end = port_str.find('/').unwrap_or(port_str.len());
                                        if let Ok(p2p_port) = port_str[..port_end].parse::<u16>() {
                                            let api_port = if p2p_port > 1 { p2p_port - 1 } else { p2p_port };
                                            let http_url = format!("http://{}:{}", ip, api_port);
                                            event_tx.send(P2pEvent::PeerHttpAddr(http_url)).await.ok();
                                        }
                                    }
                                }
                            }
                        }
                        // Update shared peer list with new version info
                        refresh_shared_peers!();
                        // Bootstrap Kademlia now that we know a peer
                        let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    }
                    SwarmEvent::Behaviour(TsnBehaviourEvent::Autonat(
                        autonat::Event::StatusChanged { old, new }
                    )) => {
                        let status_str = match &new {
                            autonat::NatStatus::Public(_) => "public".to_string(),
                            autonat::NatStatus::Private => "private (behind NAT)".to_string(),
                            autonat::NatStatus::Unknown => "unknown".to_string(),
                        };
                        info!("P2P: NAT status = {}", status_str);

                        // If behind NAT, listen on relay circuit through connected peers
                        if matches!(new, autonat::NatStatus::Private) {
                            let connected: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                            for relay_peer in connected.iter().take(2) {
                                let relay_addr: Multiaddr = format!(
                                    "/p2p/{}/p2p-circuit",
                                    relay_peer
                                ).parse().unwrap();
                                match swarm.listen_on(relay_addr) {
                                    Ok(_) => info!("P2P: listening via relay through {}", &relay_peer.to_string()[..16]),
                                    Err(e) => debug!("P2P: relay listen failed: {:?}", e),
                                }
                            }
                        }

                        event_tx.send(P2pEvent::NatStatus(status_str)).await.ok();
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        debug!("P2P peer connected: {}", peer_id);
                        // v2.3.7 — seed activity marker on connect.
                        peer_last_activity.insert(peer_id, std::time::Instant::now());
                        refresh_shared_peers!();
                        event_tx.send(P2pEvent::PeerConnected(peer_id)).await.ok();
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        debug!("P2P peer disconnected: {}", peer_id);
                        identified_peers.remove(&peer_id);
                        peer_heights.remove(&peer_id);
                        peer_height_times.remove(&peer_id);
                        peer_last_activity.remove(&peer_id);
                        refresh_shared_peers!();
                        event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await.ok();
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        // Log relay circuit addresses (not direct IPs)
                        let addr_str = address.to_string();
                        if addr_str.contains("p2p-circuit") {
                            info!("P2P: reachable via relay at {}", &addr_str[..addr_str.len().min(60)]);
                        }
                    }
                    _ => {}
                }
            }
            // Handle commands from the application
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    P2pCommand::BroadcastBlock(data) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(block_topic.clone(), data) {
                            warn!("Failed to publish block: {:?}", e);
                        }
                    }
                    P2pCommand::BroadcastTransaction(data) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(tx_topic.clone(), data) {
                            warn!("Failed to publish transaction: {:?}", e);
                        }
                    }
                    P2pCommand::GetPeers(reply) => {
                        let local_proto = format!("tsn/{}/relay", env!("CARGO_PKG_VERSION"));
                        let peers: Vec<PeerInfo> = swarm.connected_peers()
                            .map(|p| PeerInfo {
                                peer_id: p.to_string(),
                                height: peer_heights.get(p).copied(),
                                protocol: peer_versions.get(p).cloned().unwrap_or_else(|| local_proto.clone()),
                                height_updated_at: peer_height_times.get(p).copied(),
                            })
                            .collect();
                        reply.send(peers).ok();
                    }
                    P2pCommand::RequestBlocks(from, to) => {
                        // Publish a block request on the P2P network
                        let req = serde_json::json!({"from": from, "to": to});
                        if let Ok(data) = serde_json::to_vec(&req) {
                            debug!("P2P: requesting blocks {} → {}", from, to);
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(req_topic.clone(), data) {
                                debug!("P2P: block request publish failed: {:?}", e);
                            }
                        }
                    }
                    P2pCommand::SendBlocks(blocks) => {
                        // v2.1.3: Send via dedicated response topic to bypass GossipSub dedup.
                        // Publishing on block_topic would be deduplicated (same message_id as
                        // the original broadcast), so requested blocks would be silently dropped.
                        for block_data in blocks {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(resp_topic.clone(), block_data) {
                                debug!("P2P: failed to send requested block: {:?}", e);
                                break;
                            }
                        }
                    }
                    P2pCommand::BroadcastTip(height, hash) => {
                        let payload = serde_json::json!({"height": height, "hash": hash});
                        if let Ok(data) = serde_json::to_vec(&payload) {
                            swarm.behaviour_mut().gossipsub.publish(tip_topic.clone(), data).ok();
                        }
                    }
                }
            }
        }
    }
}

/// Convert DNS seed URLs to libp2p multiaddrs.
/// Extracts the IP and HTTP port from each seed URL, then uses HTTP_port + 1 as the P2P port.
/// This ensures that nodes on any HTTP port correctly dial seeds on their actual P2P port.
pub fn seeds_to_bootstrap(seed_urls: &[String], _local_p2p_port: u16) -> Vec<Multiaddr> {
    seed_urls.iter().filter_map(|url| {
        // Extract host and port from "http://<host>:9333"
        let stripped = url.trim_start_matches("http://").trim_start_matches("https://");
        let mut parts = stripped.split(':');
        let host = parts.next()?;
        // Parse the seed's HTTP port (default 9333), then P2P = HTTP + 1
        let seed_http_port: u16 = parts.next()
            .and_then(|p| p.trim_matches('/').parse().ok())
            .unwrap_or(9333);
        let seed_p2p_port = seed_http_port + 1;
        // Pick the correct multiaddr scheme: /ip4 for a dotted-quad, /dns4
        // for a DNS name. v2.4.0 fix — seeds migrated to DNS names in v2.3.9
        // were silently producing empty dial lists under the /ip4 hard-coding,
        // which made relay/miner peers invisible to the libp2p mesh and to
        // the explorer's peer list.
        let is_ipv4 = host.parse::<std::net::Ipv4Addr>().is_ok();
        let multiaddr_str = if is_ipv4 {
            format!("/ip4/{}/tcp/{}", host, seed_p2p_port)
        } else {
            format!("/dns4/{}/tcp/{}", host, seed_p2p_port)
        };
        multiaddr_str.parse().ok()
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::parse_agent_version_height;

    #[test]
    fn parse_agent_version_empty_returns_none() {
        assert_eq!(parse_agent_version_height(""), None);
    }

    #[test]
    fn parse_agent_version_legacy_no_hint() {
        // Backward-compat: peers still sending a plain version string like
        // "tsn/2.3.0" must be handled without error.
        assert_eq!(parse_agent_version_height("tsn/2.3.0"), None);
        assert_eq!(parse_agent_version_height("rust-libp2p/0.54.0"), None);
    }

    #[test]
    fn parse_agent_version_simple_hint() {
        assert_eq!(parse_agent_version_height("h=4944"), Some(4944));
        assert_eq!(parse_agent_version_height("h=0"), Some(0));
    }

    #[test]
    fn parse_agent_version_hint_with_surrounding_tokens() {
        assert_eq!(parse_agent_version_height("tsn/2.3.0 h=1000"), Some(1000));
        assert_eq!(parse_agent_version_height("h=42 foo bar"), Some(42));
        assert_eq!(parse_agent_version_height("a b h=99 c d"), Some(99));
    }

    #[test]
    fn parse_agent_version_malformed_returns_none() {
        assert_eq!(parse_agent_version_height("h="), None);
        assert_eq!(parse_agent_version_height("h=abc"), None);
        assert_eq!(parse_agent_version_height("h=-5"), None);
        assert_eq!(parse_agent_version_height("H=100"), None); // case-sensitive
        assert_eq!(parse_agent_version_height("height=100"), None);
    }

    #[test]
    fn parse_agent_version_first_valid_wins() {
        // If multiple h= tokens are present, the first parseable one wins.
        assert_eq!(
            parse_agent_version_height("h=1 h=2"),
            Some(1)
        );
    }

    #[test]
    fn parse_agent_version_skip_malformed_then_parse_valid() {
        assert_eq!(parse_agent_version_height("h=abc h=42"), Some(42));
    }

    #[test]
    fn parse_agent_version_max_u64() {
        let s = format!("h={}", u64::MAX);
        assert_eq!(parse_agent_version_height(&s), Some(u64::MAX));
    }
}
