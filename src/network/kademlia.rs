//! Module DHT Kademlia de base for TSN
//! 
//! Implements the structures fondamentales : NodeId, table de routage k-buckets,
//! and the constantes of the protocole Kademlia. Designed for the robustesse dans
//! of networkx adversariaux with partitions and nodes malveillants.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Constantes of the protocole Kademlia
pub const KADEMLIA_K: usize = 20;           // Size of k-buckets et responses
pub const KADEMLIA_ALPHA: usize = 3;        // Parallelism des requests
pub const KADEMLIA_B: usize = 160;          // Bits in a NodeId (SHA-1)
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
pub const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(3600); // 1h

/// NodeId : identifiant unique de 160 bits (compatible SHA-1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 20]);

impl NodeId {
    /// Creates a NodeId from a array de 20 bytes
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
    
    /// Generates a NodeId random
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
    
    /// Creates a NodeId from a key publique or adresse
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        let mut node_id = [0u8; 20];
        node_id.copy_from_slice(&hash[..20]); // Prend les 20 premiers bytes
        Self(node_id)
    }
    
    /// Distance XOR entre deux NodeId (metric Kademlia)
    pub fn distance(&self, other: &NodeId) -> NodeDistance {
        let mut result = [0u8; 20];
        for i in 0..20 {
            result[i] = self.0[i] ^ other.0[i];
        }
        NodeDistance(result)
    }
    
    /// Returns the bit to the position data (0 = MSB)
    pub fn bit(&self, position: usize) -> bool {
        if position >= 160 {
            return false;
        }
        let byte_index = position / 8;
        let bit_index = 7 - (position % 8);
        (self.0[byte_index] >> bit_index) & 1 == 1
    }
    
    /// Prefix commun the plus long with a other NodeId
    pub fn common_prefix_len(&self, other: &NodeId) -> usize {
        for i in 0..160 {
            if self.bit(i) != other.bit(i) {
                return i;
            }
        }
        160 // Identiques
    }
    
    /// Returns the bytes bruts
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8])) // Affiche onlyment les 8 premiers bytes
    }
}

impl From<[u8; 20]> for NodeId {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

/// Distance XOR entre deux NodeId
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeDistance([u8; 20]);

impl NodeDistance {
    /// Returns the distance like a array de bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
    
    /// Calculates the number of leading zero prefix bits (to determine the bucket)
    pub fn leading_zeros(&self) -> usize {
        for i in 0..160 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            if (self.0[byte_index] >> bit_index) & 1 == 1 {
                return i;
            }
        }
        160 // Distance nulle
    }
}

impl PartialOrd for NodeDistance {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeDistance {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare byte par byte (big-endian)
        self.0.cmp(&other.0)
    }
}

/// Node Kademlia with metadata
#[derive(Debug, Clone)]
pub struct KademliaNode {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub rtt: Option<Duration>,      // Round-trip time
    pub failures: u32,             // Failures consecutive
    pub capabilities: Vec<String>,  // Capacitys du node
}

impl KademliaNode {
    pub fn new(id: NodeId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            last_seen: Instant::now(),
            rtt: None,
            failures: 0,
            capabilities: Vec::new(),
        }
    }
    
    /// Updates the stats after a ping successful
    pub fn update_success(&mut self, rtt: Duration) {
        self.last_seen = Instant::now();
        self.rtt = Some(rtt);
        self.failures = 0;
    }
    
    /// Increments the failures
    pub fn record_failure(&mut self) {
        self.failures += 1;
    }
    
    /// Checks if the node is considered like "stale"
    pub fn is_stale(&self, threshold: Duration) -> bool {
        self.last_seen.elapsed() > threshold
    }
    
    /// Node quality score (for sorting)
    pub fn quality_score(&self) -> u64 {
        let base_score = 1000u64;
        let failure_penalty = self.failures as u64 * 100;
        let age_penalty = self.last_seen.elapsed().as_secs() / 60; // 1 point par minute
        
        base_score.saturating_sub(failure_penalty + age_penalty)
    }
}

impl PartialEq for KademliaNode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for KademliaNode {}

// Implementation Serialize/Deserialize for KademliaNode
impl Serialize for KademliaNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let last_seen_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let mut state = serializer.serialize_struct("KademliaNode", 5)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("addr", &self.addr)?;
        state.serialize_field("last_seen", &last_seen_timestamp)?;
        state.serialize_field("failures", &self.failures)?;
        state.serialize_field("capabilities", &self.capabilities)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KademliaNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct KademliaNodeData {
            id: NodeId,
            addr: SocketAddr,
            last_seen: u64,
            failures: u32,
            capabilities: Vec<String>,
        }
        
        let data = KademliaNodeData::deserialize(deserializer)?;
        
        Ok(KademliaNode {
            id: data.id,
            addr: data.addr,
            last_seen: Instant::now(), // Use current time during deserialization
            rtt: None,
            failures: data.failures,
            capabilities: data.capabilities,
        })
    }
}

/// K-bucket : liste de nodes for a plage de distance
#[derive(Debug, Clone)]
pub struct KBucket {
    pub nodes: Vec<KademliaNode>, // Made public for kademlia_engine
    last_updated: Instant,
    max_size: usize,
}

impl KBucket {
    pub fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            last_updated: Instant::now(),
            max_size,
        }
    }
    
    /// Adds a node at the bucket (LRU eviction)
    pub fn add_node(&mut self, node: KademliaNode) -> bool {
        // Si the node exists already, the met up to date and the moves to the fin
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push(node);
            self.last_updated = Instant::now();
            return true;
        }
        
        // Si the bucket n'est pas plein, ajoute directement
        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
            self.last_updated = Instant::now();
            return true;
        }
        
        // Bucket plein : verifies if on can remplacer a node stale
        if let Some(pos) = self.nodes.iter().position(|n| n.is_stale(Duration::from_secs(900))) {
            self.nodes.remove(pos);
            self.nodes.push(node);
            self.last_updated = Instant::now();
            return true;
        }
        
        false // Bucket full with active nodes
    }
    
    /// Removes a node of the bucket
    pub fn remove_node(&mut self, node_id: &NodeId) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == *node_id) {
            self.nodes.remove(pos);
            self.last_updated = Instant::now();
            true
        } else {
            false
        }
    }
    
    /// Returns all nodes of the bucket
    pub fn nodes(&self) -> &[KademliaNode] {
        &self.nodes
    }
    
    /// Returns the nodes sorted par quality
    pub fn nodes_by_quality(&self) -> Vec<KademliaNode> {
        let mut sorted = self.nodes.clone();
        sorted.sort_by_key(|n| std::cmp::Reverse(n.quality_score()));
        sorted
    }
    
    /// Checks if the bucket is plein
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.max_size
    }
    
    /// Number of nodes in the bucket
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    
    /// Checks if the bucket is vide
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    
    /// Last update of the bucket
    pub fn last_updated(&self) -> Instant {
        self.last_updated
    }
}

/// Table de routage Kademlia with k-buckets
#[derive(Debug)]
pub struct RoutingTable {
    local_id: NodeId,
    buckets: Vec<KBucket>,
    bucket_size: usize,
}

impl RoutingTable {
    /// Creates a new table de routage
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            buckets: vec![KBucket::new(KADEMLIA_K); KADEMLIA_B],
            bucket_size: KADEMLIA_K,
        }
    }
    
    /// Adds a node to the table de routage
    pub fn add_node(&mut self, node: KademliaNode) -> bool {
        if node.id == self.local_id {
            return false; // Ne s'adds pas itself
        }
        
        let bucket_index = self.bucket_index(&node.id);
        self.buckets[bucket_index].add_node(node)
    }
    
    /// Removes a node de the table
    pub fn remove_node(&mut self, node_id: &NodeId) -> bool {
        let bucket_index = self.bucket_index(node_id);
        self.buckets[bucket_index].remove_node(node_id)
    }
    
    /// Trouve the K nodes the plus proches d'une cible
    pub fn closest_nodes(&self, target: &NodeId, count: usize) -> Vec<KademliaNode> {
        let mut candidates = Vec::new();
        
        // Collect all nodes de all buckets
        for bucket in &self.buckets {
            candidates.extend(bucket.nodes().iter().cloned());
        }
        
        // Trie par distance to the cible
        candidates.sort_by_key(|node| node.id.distance(target));
        
        // Returns the count premiers
        candidates.into_iter().take(count).collect()
    }
    
    /// Trouve the nodes in a bucket specific
    pub fn bucket_nodes(&self, bucket_index: usize) -> Vec<KademliaNode> {
        if bucket_index < self.buckets.len() {
            self.buckets[bucket_index].nodes().to_vec()
        } else {
            Vec::new()
        }
    }
    
    /// Calculationates l'index of the bucket for a NodeId given
    fn bucket_index(&self, node_id: &NodeId) -> usize {
        let distance = self.local_id.distance(node_id);
        let leading_zeros = distance.leading_zeros();
        
        // The bucket index is the number of common prefix bits
        // Bucket 0 = distance maximale, Bucket 159 = distance minimale
        if leading_zeros >= KADEMLIA_B {
            KADEMLIA_B - 1
        } else {
            leading_zeros
        }
    }
    
    /// Returns of statistics on the table
    pub fn stats(&self) -> RoutingTableStats {
        let mut total_nodes = 0;
        let mut full_buckets = 0;
        let mut empty_buckets = 0;
        
        for bucket in &self.buckets {
            total_nodes += bucket.len();
            if bucket.is_full() {
                full_buckets += 1;
            } else if bucket.is_empty() {
                empty_buckets += 1;
            }
        }
        
        RoutingTableStats {
            total_nodes,
            full_buckets,
            empty_buckets,
            total_buckets: self.buckets.len(),
        }
    }
    
    /// Returns all nodes de the table
    pub fn all_nodes(&self) -> Vec<KademliaNode> {
        let mut all = Vec::new();
        for bucket in &self.buckets {
            all.extend(bucket.nodes().iter().cloned());
        }
        all
    }
    
    /// Clean up stale nodes
    pub fn cleanup_stale_nodes(&mut self, threshold: Duration) -> usize {
        let mut removed = 0;
        for bucket in &mut self.buckets {
            let initial_len = bucket.len();
            bucket.nodes.retain(|node| !node.is_stale(threshold));
            removed += initial_len - bucket.len();
        }
        removed
    }
    
    /// Maintenance periodic de the table de routage
    pub fn maintenance(&mut self) -> usize {
        self.cleanup_stale_nodes(Duration::from_secs(1800)) // 30 minutes
    }
}

/// Statistiques de the table de routage
#[derive(Debug, Clone)]
pub struct RoutingTableStats {
    pub total_nodes: usize,
    pub full_buckets: usize,
    pub empty_buckets: usize,
    pub total_buckets: usize,
}

impl std::fmt::Display for RoutingTableStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "RoutingTable: {} nodes, {}/{} buckets pleins, {} vides",
            self.total_nodes, self.full_buckets, self.total_buckets, self.empty_buckets
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::new([0u8; 20]);
        let id2 = NodeId::new([255u8; 20]);
        
        let distance = id1.distance(&id2);
        assert_eq!(distance.as_bytes(), &[255u8; 20]);
        assert_eq!(distance.leading_zeros(), 0);
    }
    
    #[test]
    fn test_node_id_common_prefix() {
        let id1 = NodeId::new([0b10101010u8; 20]);
        let id2 = NodeId::new([0b10101011u8; 20]);
        
        // Differ at the last bit of the first byte
        assert_eq!(id1.common_prefix_len(&id2), 7);
    }
    
    #[test]
    fn test_kbucket_operations() {
        let mut bucket = KBucket::new(2);
        let node1 = KademliaNode::new(NodeId::new([1u8; 20]), "127.0.0.1:8001".parse().unwrap());
        let node2 = KademliaNode::new(NodeId::new([2u8; 20]), "127.0.0.1:8002".parse().unwrap());
        let node3 = KademliaNode::new(NodeId::new([3u8; 20]), "127.0.0.1:8003".parse().unwrap());
        
        assert!(bucket.add_node(node1.clone()));
        assert!(bucket.add_node(node2.clone()));
        assert_eq!(bucket.len(), 2);
        assert!(bucket.is_full());
        
        // Bucket plein, not can pas ajouter a nouveau node
        assert!(!bucket.add_node(node3));
        
        // But can update an existing node
        assert!(bucket.add_node(node1.clone()));
        assert_eq!(bucket.len(), 2);
    }
    
    #[test]
    fn test_routing_table() {
        let local_id = NodeId::new([0u8; 20]);
        let mut table = RoutingTable::new(local_id);
        
        let node1 = KademliaNode::new(NodeId::new([1u8; 20]), "127.0.0.1:8001".parse().unwrap());
        let node2 = KademliaNode::new(NodeId::new([255u8; 20]), "127.0.0.1:8002".parse().unwrap());
        
        assert!(table.add_node(node1.clone()));
        assert!(table.add_node(node2.clone()));
        
        let closest = table.closest_nodes(&NodeId::new([2u8; 20]), 10);
        assert_eq!(closest.len(), 2);
        
        // Le node [1u8; 20] should be plus proche de [2u8; 20] que [255u8; 20]
        assert_eq!(closest[0].id, node1.id);
    }
}