//! Kademlia DHT engine for TSN
//! 
//! Implements the core DHT system with iterative lookup, bootstrap,
//! local storage and peer maintenance. Designed for robustness
//! in adversarial networks with partitions and malicious nodes.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{timeout, interval};
use tracing::{debug, info, warn, trace};

use super::kademlia::{
    NodeId, KademliaNode, RoutingTable, KADEMLIA_K, KADEMLIA_ALPHA, 
    LOOKUP_TIMEOUT
};
use super::kademlia_messages::{
    KademliaMessage, KademliaContact, DhtKey, DhtValue,
    RequestId, generate_request_id, DhtError, builders
};

/// DHT engine configuration
#[derive(Debug, Clone)]
pub struct KademliaConfig {
    /// Notre NodeId local  
    pub local_id: NodeId,
    /// Listening address
    pub listen_addr: SocketAddr,
    /// Seed nodes for bootstrap
    pub seed_nodes: Vec<SocketAddr>,
    /// Default TTL for stored values (secondes)
    pub default_value_ttl: u64,
    /// Routing table maintenance interval
    pub maintenance_interval: Duration,
    /// Timeout for network requests
    pub request_timeout: Duration,
    /// Maximum parallel requests during a lookup
    pub max_concurrent_requests: usize,
}

impl Default for KademliaConfig {
    fn default() -> Self {
        Self {
            local_id: NodeId::random(),
            listen_addr: "0.0.0.0:8000".parse().unwrap(),
            seed_nodes: Vec::new(),
            default_value_ttl: 3600, // 1 heure
            maintenance_interval: Duration::from_secs(300), // 5 minutes
            request_timeout: Duration::from_secs(10),
            max_concurrent_requests: KADEMLIA_ALPHA,
        }
    }
}

/// State d'un lookup iterative in progress
#[derive(Debug)]
struct LookupState {
    target: NodeId,
    queried: HashSet<NodeId>,
    pending: HashSet<NodeId>,
    closest_nodes: Vec<KademliaNode>,
    started_at: Instant,
    lookup_type: LookupType,
}

#[derive(Debug, Clone)]
enum LookupType {
    FindNode,
    FindValue(DhtKey),
}

/// Request in pending de response
#[derive(Debug)]
struct PendingRequest {
    sender: oneshot::Sender<KademliaMessage>,
    target_node: NodeId,
    sent_at: Instant,
}

/// Main Kademlia DHT engine
#[derive(Clone)]
pub struct KademliaEngine {
    config: KademliaConfig,
    routing_table: Arc<RwLock<RoutingTable>>,
    local_storage: Arc<RwLock<HashMap<DhtKey, DhtValue>>>,
    pending_requests: Arc<RwLock<HashMap<RequestId, PendingRequest>>>,
    
    // Channels for internal communication
    message_tx: mpsc::UnboundedSender<(SocketAddr, KademliaMessage)>,
    message_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<(SocketAddr, KademliaMessage)>>>>,
    
    // Engine state
    is_bootstrapped: Arc<RwLock<bool>>,
    last_maintenance: Arc<RwLock<Instant>>,
}

impl KademliaEngine {
    /// Creates a new moteur DHT
    pub fn new(config: KademliaConfig) -> Self {
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        
        Self {
            routing_table: Arc::new(RwLock::new(RoutingTable::new(config.local_id))),
            local_storage: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            message_rx: Arc::new(RwLock::new(Some(message_rx))),
            is_bootstrapped: Arc::new(RwLock::new(false)),
            last_maintenance: Arc::new(RwLock::new(Instant::now())),
            config,
        }
    }
    
    /// Starts the DHT engine with bootstrap
    pub async fn start(&self) -> Result<(), DhtError> {
        info!("Starting du moteur DHT Kademlia [{}]", self.config.local_id);
        
        // Start the message processing loop
        let message_rx = self.message_rx.write().await.take()
            .ok_or_else(|| DhtError::SerializationError("Engine already started".to_string()))?;
        
        let engine = self.clone();
        tokio::spawn(async move {
            engine.message_processing_loop(message_rx).await;
        });
        
        // Start periodic maintenance
        let engine = self.clone();
        tokio::spawn(async move {
            engine.maintenance_loop().await;
        });
        
        // Bootstrap from seed nodes
        self.bootstrap().await?;
        
        info!("Moteur DHT started avec success");
        Ok(())
    }
    
    /// Bootstrap from seed nodes
    async fn bootstrap(&self) -> Result<(), DhtError> {
        if self.config.seed_nodes.is_empty() {
            warn!("No seed node configured - bootstrap manuel requis");
            return Ok(());
        }
        
        info!("Bootstrap DHT depuis {} seed nodes", self.config.seed_nodes.len());
        
        // Connecte aux seed nodes
        let mut bootstrap_nodes = Vec::new();
        for seed_addr in &self.config.seed_nodes {
            match self.ping_node(*seed_addr).await {
                Ok(node) => {
                    bootstrap_nodes.push(node);
                    info!("Seed node connected: {} @ {}", node.id, seed_addr);
                }
                Err(e) => {
                    warn!("Failure connection seed node {}: {}", seed_addr, e);
                }
            }
        }
        
        if bootstrap_nodes.is_empty() {
            return Err(DhtError::NodeUnreachable(NodeId::new([0; 20])));
        }
        
        // Add seed nodes to routing table
        {
            let mut table = self.routing_table.write().await;
            for node in &bootstrap_nodes {
                table.add_node(node.clone());
            }
        }
        
        // Perform a lookup of our own ID to populate the table
        if let Ok(nodes) = self.iterative_find_node(self.config.local_id).await {
            let mut table = self.routing_table.write().await;
            for node in nodes {
                table.add_node(node);
            }
        }
        
        *self.is_bootstrapped.write().await = true;
        info!("Bootstrap DHT completed - {} nodes dans la table", 
              self.routing_table.read().await.stats().total_nodes);
        
        Ok(())
    }
    
    /// Ping a node and returns ses informations
    async fn ping_node(&self, addr: SocketAddr) -> Result<KademliaNode, DhtError> {
        let request_id = generate_request_id();
        let ping_msg = builders::ping(self.config.local_id);
        
        let (response_tx, response_rx) = oneshot::channel();
        
        // Register the pending request
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(request_id, PendingRequest {
                sender: response_tx,
                target_node: NodeId::new([0; 20]), // Unknown for now
                sent_at: Instant::now(),
            });
        }
        
        // Send ping (simulation - real impl would use UDP/TCP)
        if let Err(_) = self.send_message(addr, ping_msg).await {
            self.pending_requests.write().await.remove(&request_id);
            return Err(DhtError::NodeUnreachable(NodeId::new([0; 20])));
        }
        
        // Wait for response with timeout
        match timeout(self.config.request_timeout, response_rx).await {
            Ok(Ok(response)) => {
                if let KademliaMessage::Pong { sender_id, .. } = response {
                    Ok(KademliaNode::new(sender_id, addr))
                } else {
                    Err(DhtError::SerializationError("Response ping invalid".to_string()))
                }
            },
            _ => Err(DhtError::RequestTimeout)
        }
    }
    
    /// Iterative lookup for FIND_NODE
    pub async fn iterative_find_node(&self, target: NodeId) -> Result<Vec<KademliaNode>, DhtError> {
        debug!("Start lookup iterative pour node {}", target);
        
        let mut lookup_state = LookupState {
            target,
            queried: HashSet::new(),
            pending: HashSet::new(),
            closest_nodes: Vec::new(),
            started_at: Instant::now(),
            lookup_type: LookupType::FindNode,
        };
        
        // Find starting nodes from the routing table
        let initial_nodes = {
            let table = self.routing_table.read().await;
            table.closest_nodes(&target, KADEMLIA_K)
        };
        
        if initial_nodes.is_empty() {
            return Err(DhtError::NodeUnreachable(target));
        }
        
        lookup_state.closest_nodes = initial_nodes;
        
        // Main lookup loop
        loop {
            // Select next nodes to query
            let candidates = self.select_lookup_candidates(&mut lookup_state);
            
            if candidates.is_empty() {
                break; // Plus de nodes to interroger
            }
            
            // Send requests in parallel (limited by ALPHA)
            let mut tasks = Vec::new();
            for node in candidates.into_iter().take(self.config.max_concurrent_requests) {
                lookup_state.queried.insert(node.id);
                lookup_state.pending.insert(node.id);
                
                let engine = self.clone();
                let node_clone = node.clone();
                tasks.push(tokio::spawn(async move {
                    engine.query_node_for_target(node_clone, target).await
                }));
            }
            
            // Wait for responses
            for task in tasks {
                if let Ok(Ok(new_nodes)) = task.await {
                    // Integrate new nodes
                    self.integrate_lookup_response(&mut lookup_state, new_nodes).await;
                }
            }
            
            // Verifies timeout global
            if lookup_state.started_at.elapsed() > LOOKUP_TIMEOUT {
                warn!("Lookup timeout pour {}", target);
                break;
            }
        }
        
        // Sort and return the K closest nodes
        lookup_state.closest_nodes.sort_by_key(|n| n.id.distance(&target));
        Ok(lookup_state.closest_nodes.into_iter().take(KADEMLIA_K).collect())
    }
    
    /// Selects candidates for the next lookup iteration
    fn select_lookup_candidates(&self, state: &mut LookupState) -> Vec<KademliaNode> {
        state.closest_nodes
            .iter()
            .filter(|node| !state.queried.contains(&node.id) && !state.pending.contains(&node.id))
            .take(KADEMLIA_ALPHA)
            .cloned()
            .collect()
    }
    
    /// Queries a specific node for a target
    async fn query_node_for_target(&self, node: KademliaNode, target: NodeId) 
        -> Result<Vec<KademliaNode>, DhtError> 
    {
        let request_id = generate_request_id();
        let find_node_msg = builders::find_node(self.config.local_id, target);
        
        let (response_tx, response_rx) = oneshot::channel();
        
        // Register the request
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(request_id, PendingRequest {
                sender: response_tx,
                target_node: node.id,
                sent_at: Instant::now(),
            });
        }
        
        // Envoie FIND_NODE
        if let Err(_) = self.send_message(node.addr, find_node_msg).await {
            self.pending_requests.write().await.remove(&request_id);
            return Err(DhtError::NodeUnreachable(node.id));
        }
        
        // Wait for response
        match timeout(self.config.request_timeout, response_rx).await {
            Ok(Ok(response)) => {
                if let KademliaMessage::FoundNodes { nodes, .. } = response {
                    Ok(nodes.into_iter().map(KademliaNode::from).collect())
                } else {
                    Err(DhtError::SerializationError("Response FIND_NODE invalid".to_string()))
                }
            },
            _ => Err(DhtError::RequestTimeout)
        }
    }
    
    /// Integrates a node's response into the lookup state
    async fn integrate_lookup_response(&self, state: &mut LookupState, new_nodes: Vec<KademliaNode>) {
        for node in new_nodes {
            // Avoid loops and our own ID
            if node.id == self.config.local_id || state.queried.contains(&node.id) {
                continue;
            }
            
            // Add to routing table if close enough
            {
                let mut table = self.routing_table.write().await;
                table.add_node(node.clone());
            }
            
            // Add to lookup candidates if closer
            let distance = node.id.distance(&state.target);
            if let Some(furthest_distance) = state.closest_nodes
                .last()
                .map(|n| n.id.distance(&state.target))
            {
                if distance < furthest_distance || state.closest_nodes.len() < KADEMLIA_K {
                    state.closest_nodes.push(node);
                    state.closest_nodes.sort_by_key(|n| n.id.distance(&state.target));
                    state.closest_nodes.truncate(KADEMLIA_K);
                }
            } else {
                state.closest_nodes.push(node);
            }
        }
        
        // Clean up pending nodes
        state.pending.retain(|id| {
            !state.queried.contains(id)
        });
    }
    
    /// Stores a value in the DHT
    pub async fn store_value(&self, key: DhtKey, value: Vec<u8>) -> Result<(), DhtError> {
        let dht_value = DhtValue::new(value, self.config.default_value_ttl, self.config.local_id);
        
        // Stores localement
        {
            let mut storage = self.local_storage.write().await;
            storage.insert(key, dht_value.clone());
        }
        
        // Find the K closest nodes to the key
        let key_node_id = NodeId::new(key);
        let closest_nodes = self.iterative_find_node(key_node_id).await
            .unwrap_or_else(|_| Vec::new());
        
        // Replicate to the K closest nodes
        let mut store_tasks = Vec::new();
        for node in closest_nodes.into_iter().take(KADEMLIA_K) {
            let engine = self.clone();
            let dht_value_clone = dht_value.clone();
            store_tasks.push(tokio::spawn(async move {
                engine.store_at_node(node, key, dht_value_clone).await
            }));
        }
        
        // Wait for at least majority success
        let mut success_count = 0;
        for task in store_tasks {
            if task.await.is_ok() {
                success_count += 1;
            }
        }
        
        if success_count >= (KADEMLIA_K / 2) {
            Ok(())
        } else {
            Err(DhtError::StorageFull)
        }
    }
    
    /// Stores a value on a specific node
    async fn store_at_node(&self, node: KademliaNode, key: DhtKey, value: DhtValue) -> Result<(), DhtError> {
        let request_id = generate_request_id();
        let store_msg = builders::store(self.config.local_id, key, value, self.config.default_value_ttl);
        
        let (response_tx, response_rx) = oneshot::channel();
        
        // Register the request
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(request_id, PendingRequest {
                sender: response_tx,
                target_node: node.id,
                sent_at: Instant::now(),
            });
        }
        
        // Envoie STORE
        if let Err(_) = self.send_message(node.addr, store_msg).await {
            self.pending_requests.write().await.remove(&request_id);
            return Err(DhtError::NodeUnreachable(node.id));
        }
        
        // Wait for response
        match timeout(self.config.request_timeout, response_rx).await {
            Ok(Ok(KademliaMessage::StoreAck { success: true, .. })) => Ok(()),
            Ok(Ok(KademliaMessage::StoreAck { success: false, error, .. })) => {
                Err(DhtError::SerializationError(error.unwrap_or_default()))
            },
            _ => Err(DhtError::RequestTimeout)
        }
    }
    
    /// Searches for a value in the DHT
    pub async fn find_value(&self, key: DhtKey) -> Result<Option<DhtValue>, DhtError> {
        // Check local storage first
        {
            let storage = self.local_storage.read().await;
            if let Some(value) = storage.get(&key) {
                if !value.is_expired() {
                    return Ok(Some(value.clone()));
                }
            }
        }
        
        // Iterative lookup for FIND_VALUE
        let key_node_id = NodeId::new(key);
        let closest_nodes = self.iterative_find_node(key_node_id).await?;
        
        // Query the closest nodes
        for node in closest_nodes.into_iter().take(KADEMLIA_K) {
            if let Ok(Some(value)) = self.find_value_at_node(node, key).await {
                return Ok(Some(value));
            }
        }
        
        Ok(None)
    }
    
    /// Searches for a value on a specific node
    async fn find_value_at_node(&self, node: KademliaNode, key: DhtKey) -> Result<Option<DhtValue>, DhtError> {
        let request_id = generate_request_id();
        let find_value_msg = builders::find_value(self.config.local_id, key);
        
        let (response_tx, response_rx) = oneshot::channel();
        
        // Register the request
        {
            let mut pending = self.pending_requests.write().await;
            pending.insert(request_id, PendingRequest {
                sender: response_tx,
                target_node: node.id,
                sent_at: Instant::now(),
            });
        }
        
        // Envoie FIND_VALUE
        if let Err(_) = self.send_message(node.addr, find_value_msg).await {
            self.pending_requests.write().await.remove(&request_id);
            return Err(DhtError::NodeUnreachable(node.id));
        }
        
        // Wait for response
        match timeout(self.config.request_timeout, response_rx).await {
            Ok(Ok(KademliaMessage::FoundValue { result, .. })) => {
                match result {
                    super::kademlia_messages::FindValueResult::Value(value) => Ok(Some(value)),
                    super::kademlia_messages::FindValueResult::CloserNodes(_) => Ok(None),
                }
            },
            _ => Err(DhtError::RequestTimeout)
        }
    }
    
    /// Sendinge a message to a node (simulation)
    async fn send_message(&self, _addr: SocketAddr, _message: KademliaMessage) -> Result<(), DhtError> {
        // In a real implementation, this would send the message via UDP/TCP
        // For now, we just simulate a success
        trace!("Sending simulated DHT message to {}", _addr);
        Ok(())
    }
    
    /// Incoming message processing loop
    async fn message_processing_loop(&self, mut message_rx: mpsc::UnboundedReceiver<(SocketAddr, KademliaMessage)>) {
        while let Some((sender_addr, message)) = message_rx.recv().await {
            self.handle_incoming_message(sender_addr, message).await;
        }
    }
    
    /// Processes a message entrant
    async fn handle_incoming_message(&self, sender_addr: SocketAddr, message: KademliaMessage) {
        match message {
            KademliaMessage::Ping { request_id, sender_id, .. } => {
                let pong = builders::pong(request_id, self.config.local_id, 3600);
                let _ = self.send_message(sender_addr, pong).await;
                
                // Add node to routing table
                let node = KademliaNode::new(sender_id, sender_addr);
                let mut table = self.routing_table.write().await;
                table.add_node(node);
            },
            
            KademliaMessage::FindNode { request_id, target_id, .. } => {
                let table = self.routing_table.read().await;
                let closest = table.closest_nodes(&target_id, KADEMLIA_K);
                let contacts: Vec<KademliaContact> = closest.iter().map(KademliaContact::from).collect();
                
                let response = builders::found_nodes(request_id, self.config.local_id, contacts);
                let _ = self.send_message(sender_addr, response).await;
            },
            
            KademliaMessage::Store { request_id, key, value, .. } => {
                let mut storage = self.local_storage.write().await;
                storage.insert(key, value);
                
                let ack = builders::store_ack(request_id, self.config.local_id, true, None);
                let _ = self.send_message(sender_addr, ack).await;
            },
            
            // Process responses
            _ if !message.is_request() => {
                let request_id = message.request_id();
                if let Some(pending) = self.pending_requests.write().await.remove(&request_id) {
                    let _ = pending.sender.send(message);
                }
            },
            
            _ => {
                debug!("Message DHT non managed: {:?}", message);
            }
        }
    }
    
    /// Boucle de maintenance periodic
    async fn maintenance_loop(&self) {
        let mut interval = interval(self.config.maintenance_interval);
        
        loop {
            interval.tick().await;
            
            // Clean up stale nodes
            let removed = {
                let mut table = self.routing_table.write().await;
                table.maintenance()
            };
            
            if removed > 0 {
                debug!("Maintenance DHT: {} nodes stale removeds", removed);
            }
            
            // Clean up expired values
            {
                let mut storage = self.local_storage.write().await;
                storage.retain(|_, value| !value.is_expired());
            }
            
            // Clean up timed-out requests
            {
                let mut pending = self.pending_requests.write().await;
                let timeout_threshold = Instant::now() - self.config.request_timeout;
                pending.retain(|_, req| req.sent_at > timeout_threshold);
            }
            
            *self.last_maintenance.write().await = Instant::now();
        }
    }
    
    /// Returns DHT engine statistics
    pub async fn stats(&self) -> KademliaStats {
        let table_stats = self.routing_table.read().await.stats();
        let storage_count = self.local_storage.read().await.len();
        let pending_count = self.pending_requests.read().await.len();
        let is_bootstrapped = *self.is_bootstrapped.read().await;
        
        KademliaStats {
            table_stats,
            storage_count,
            pending_requests: pending_count,
            is_bootstrapped,
        }
    }
}

/// Kademlia engine statistics
#[derive(Debug, Clone)]
pub struct KademliaStats {
    pub table_stats: super::kademlia::RoutingTableStats,
    pub storage_count: usize,
    pub pending_requests: usize,
    pub is_bootstrapped: bool,
}

impl std::fmt::Display for KademliaStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "DHT Kademlia: {}, {} valeurs stored, {} requests pendantes, bootstrap: {}",
            self.table_stats, self.storage_count, self.pending_requests, self.is_bootstrapped
        )
    }
}