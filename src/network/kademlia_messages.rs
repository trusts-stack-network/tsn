//! Kademlia DHT protocol messages for TSN
//! 
//! Implements the 4 main Kademlia operations:
//! - PING: verify if a node is alive
//! - FIND_NODE: find the K closest nodes to a target
//! - FIND_VALUE: search for a value stored in the DHT
//! - STORE: store a key-value pair

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use super::kademlia::{NodeId, KademliaNode};

/// Unique identifier for requests/responses
pub type RequestId = [u8; 8];

/// Generates a ID de request random
pub fn generate_request_id() -> RequestId {
    use rand::RngCore;
    let mut id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Types de messages DHT Kademlia
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KademliaMessage {
    /// Ping : test de connectivity
    Ping {
        request_id: RequestId,
        sender_id: NodeId,
        timestamp: u64,
    },
    
    /// Pong: response to ping
    Pong {
        request_id: RequestId,
        sender_id: NodeId,
        timestamp: u64,
        uptime_secs: u64,
    },
    
    /// FIND_NODE: find the K closest nodes to a target
    FindNode {
        request_id: RequestId,
        sender_id: NodeId,
        target_id: NodeId,
        timestamp: u64,
    },
    
    /// Response to FIND_NODE with node list
    FoundNodes {
        request_id: RequestId,
        sender_id: NodeId,
        nodes: Vec<KademliaContact>,
        timestamp: u64,
    },
    
    /// FIND_VALUE: search for a value in the DHT
    FindValue {
        request_id: RequestId,
        sender_id: NodeId,
        key: DhtKey,
        timestamp: u64,
    },
    
    /// Response to FIND_VALUE: either the value or closer nodes
    FoundValue {
        request_id: RequestId,
        sender_id: NodeId,
        result: FindValueResult,
        timestamp: u64,
    },
    
    /// STORE: store a key-value pair
    Store {
        request_id: RequestId,
        sender_id: NodeId,
        key: DhtKey,
        value: DhtValue,
        ttl_secs: u64, // Time-to-live
        timestamp: u64,
    },
    
    /// Response to STORE
    StoreAck {
        request_id: RequestId,
        sender_id: NodeId,
        success: bool,
        error: Option<String>,
        timestamp: u64,
    },
}

impl KademliaMessage {
    /// Returns the request ID for request/response matching
    pub fn request_id(&self) -> RequestId {
        match self {
            KademliaMessage::Ping { request_id, .. } => *request_id,
            KademliaMessage::Pong { request_id, .. } => *request_id,
            KademliaMessage::FindNode { request_id, .. } => *request_id,
            KademliaMessage::FoundNodes { request_id, .. } => *request_id,
            KademliaMessage::FindValue { request_id, .. } => *request_id,
            KademliaMessage::FoundValue { request_id, .. } => *request_id,
            KademliaMessage::Store { request_id, .. } => *request_id,
            KademliaMessage::StoreAck { request_id, .. } => *request_id,
        }
    }
    
    /// Returns the sender node ID
    pub fn sender_id(&self) -> NodeId {
        match self {
            KademliaMessage::Ping { sender_id, .. } => *sender_id,
            KademliaMessage::Pong { sender_id, .. } => *sender_id,
            KademliaMessage::FindNode { sender_id, .. } => *sender_id,
            KademliaMessage::FoundNodes { sender_id, .. } => *sender_id,
            KademliaMessage::FindValue { sender_id, .. } => *sender_id,
            KademliaMessage::FoundValue { sender_id, .. } => *sender_id,
            KademliaMessage::Store { sender_id, .. } => *sender_id,
            KademliaMessage::StoreAck { sender_id, .. } => *sender_id,
        }
    }
    
    /// Checks if this is a request (requires a response)
    pub fn is_request(&self) -> bool {
        matches!(self,
            KademliaMessage::Ping { .. } |
            KademliaMessage::FindNode { .. } |
            KademliaMessage::FindValue { .. } |
            KademliaMessage::Store { .. }
        )
    }
    
    /// Generates a timestamp actuel
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Compact contact for FIND_NODE responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KademliaContact {
    pub id: NodeId,
    pub addr: std::net::SocketAddr,
    pub last_seen: u64, // timestamp
}

impl From<&KademliaNode> for KademliaContact {
    fn from(node: &KademliaNode) -> Self {
        Self {
            id: node.id,
            addr: node.addr,
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl From<KademliaContact> for KademliaNode {
    fn from(contact: KademliaContact) -> Self {
        Self::new(contact.id, contact.addr)
    }
}

/// DHT key: 160-bit SHA-1 hash (compatible with NodeId)
pub type DhtKey = [u8; 20];

/// DHT value: arbitrary data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtValue {
    pub data: Vec<u8>,
    pub stored_at: u64,    // storage timestamp
    pub ttl_secs: u64,     // duration de vie
    pub publisher_id: NodeId, // who published this value
}

impl DhtValue {
    pub fn new(data: Vec<u8>, ttl_secs: u64, publisher_id: NodeId) -> Self {
        Self {
            data,
            stored_at: KademliaMessage::current_timestamp(),
            ttl_secs,
            publisher_id,
        }
    }
    
    /// Checks if the value has expired
    pub fn is_expired(&self) -> bool {
        let now = KademliaMessage::current_timestamp();
        now > self.stored_at + self.ttl_secs
    }
    
    /// Time remaining before expiration
    pub fn time_to_expiry(&self) -> Option<u64> {
        let now = KademliaMessage::current_timestamp();
        let expiry = self.stored_at + self.ttl_secs;
        if now < expiry {
            Some(expiry - now)
        } else {
            None
        }
    }
}

/// Result of a FIND_VALUE request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindValueResult {
    /// Valeur founde
    Value(DhtValue),
    /// Value not found, but here are closer nodes
    CloserNodes(Vec<KademliaContact>),
}

/// Configuration for DHT messages
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// Size maximale d'un message DHT (in bytes)
    pub max_message_size: usize,
    /// Default TTL for stored values
    pub default_value_ttl: u64,
    /// Maximum contacts in a FIND_NODE response
    pub max_contacts_per_response: usize,
    /// Timeout for DHT requests
    pub request_timeout: std::time::Duration,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            default_value_ttl: 3600,       // 1 heure
            max_contacts_per_response: 20, // K nodes
            request_timeout: std::time::Duration::from_secs(10),
        }
    }
}

/// Helpers for creating Kademlia messages
pub mod builders {
    use super::*;
    
    pub fn ping(sender_id: NodeId) -> KademliaMessage {
        KademliaMessage::Ping {
            request_id: generate_request_id(),
            sender_id,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
    
    pub fn pong(request_id: RequestId, sender_id: NodeId, uptime_secs: u64) -> KademliaMessage {
        KademliaMessage::Pong {
            request_id,
            sender_id,
            timestamp: KademliaMessage::current_timestamp(),
            uptime_secs,
        }
    }
    
    pub fn find_node(sender_id: NodeId, target_id: NodeId) -> KademliaMessage {
        KademliaMessage::FindNode {
            request_id: generate_request_id(),
            sender_id,
            target_id,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
    
    pub fn found_nodes(request_id: RequestId, sender_id: NodeId, nodes: Vec<KademliaContact>) -> KademliaMessage {
        KademliaMessage::FoundNodes {
            request_id,
            sender_id,
            nodes,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
    
    pub fn find_value(sender_id: NodeId, key: DhtKey) -> KademliaMessage {
        KademliaMessage::FindValue {
            request_id: generate_request_id(),
            sender_id,
            key,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
    
    pub fn found_value(request_id: RequestId, sender_id: NodeId, result: FindValueResult) -> KademliaMessage {
        KademliaMessage::FoundValue {
            request_id,
            sender_id,
            result,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
    
    pub fn store(sender_id: NodeId, key: DhtKey, value: DhtValue, ttl_secs: u64) -> KademliaMessage {
        KademliaMessage::Store {
            request_id: generate_request_id(),
            sender_id,
            key,
            value,
            ttl_secs,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
    
    pub fn store_ack(request_id: RequestId, sender_id: NodeId, success: bool, error: Option<String>) -> KademliaMessage {
        KademliaMessage::StoreAck {
            request_id,
            sender_id,
            success,
            error,
            timestamp: KademliaMessage::current_timestamp(),
        }
    }
}

/// Errors specific to the DHT
#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("Timeout de request DHT")]
    RequestTimeout,
    
    #[error("Message DHT trop large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },
    
    #[error("Key DHT invalid: {0}")]
    InvalidKey(String),
    
    #[error("Valeur DHT expired")]
    ValueExpired,
    
    #[error("Stockage DHT plein")]
    StorageFull,
    
    #[error("Node inaccessible: {0}")]
    NodeUnreachable(NodeId),
    
    #[error("Serialization failed: {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dht_value_expiration() {
        let publisher_id = NodeId::new([1u8; 20]);
        let value = DhtValue::new(b"test data".to_vec(), 10, publisher_id);
        
        assert!(!value.is_expired());
        assert!(value.time_to_expiry().is_some());
    }
    
    #[test]
    fn test_message_builders() {
        let node_id = NodeId::new([2u8; 20]);
        let target_id = NodeId::new([3u8; 20]);
        
        let ping = builders::ping(node_id);
        assert!(ping.is_request());
        assert_eq!(ping.sender_id(), node_id);
        
        let find_node = builders::find_node(node_id, target_id);
        assert!(find_node.is_request());
    }
    
    #[test]
    fn test_contact_conversion() {
        let node = super::super::kademlia::KademliaNode::new(
            NodeId::new([4u8; 20]),
            "127.0.0.1:8080".parse().unwrap()
        );
        
        let contact = KademliaContact::from(&node);
        assert_eq!(contact.id, node.id);
        assert_eq!(contact.addr, node.addr);
        
        let converted_back = KademliaNode::from(contact);
        assert_eq!(converted_back.id, node.id);
        assert_eq!(converted_back.addr, node.addr);
    }
}