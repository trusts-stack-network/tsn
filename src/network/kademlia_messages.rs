//! Messages du protocole DHT Kademlia pour TSN
//! 
//! Implemente les 4 operations principales de Kademlia :
//! - PING : checksr si un node est vivant
//! - FIND_NODE : trouver les K nodes les plus proches d'une cible
//! - FIND_VALUE : chercher une valeur stockee dans la DHT
//! - STORE : stocker une paire key-valeur

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use super::kademlia::{NodeId, KademliaNode};

/// Identifiant unique pour les requests/responses
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
    /// Ping : test de connectivite
    Ping {
        request_id: RequestId,
        sender_id: NodeId,
        timestamp: u64,
    },
    
    /// Pong : response au ping
    Pong {
        request_id: RequestId,
        sender_id: NodeId,
        timestamp: u64,
        uptime_secs: u64,
    },
    
    /// FIND_NODE : chercher les K nodes les plus proches d'une cible
    FindNode {
        request_id: RequestId,
        sender_id: NodeId,
        target_id: NodeId,
        timestamp: u64,
    },
    
    /// Reponse a FIND_NODE avec liste de nodes
    FoundNodes {
        request_id: RequestId,
        sender_id: NodeId,
        nodes: Vec<KademliaContact>,
        timestamp: u64,
    },
    
    /// FIND_VALUE : chercher une valeur dans la DHT
    FindValue {
        request_id: RequestId,
        sender_id: NodeId,
        key: DhtKey,
        timestamp: u64,
    },
    
    /// Reponse a FIND_VALUE : soit la valeur, soit des nodes plus proches
    FoundValue {
        request_id: RequestId,
        sender_id: NodeId,
        result: FindValueResult,
        timestamp: u64,
    },
    
    /// STORE : stocker une paire key-valeur
    Store {
        request_id: RequestId,
        sender_id: NodeId,
        key: DhtKey,
        value: DhtValue,
        ttl_secs: u64, // Time-to-live
        timestamp: u64,
    },
    
    /// Reponse au STORE
    StoreAck {
        request_id: RequestId,
        sender_id: NodeId,
        success: bool,
        error: Option<String>,
        timestamp: u64,
    },
}

impl KademliaMessage {
    /// Retourne l'ID de la request pour matching request/response
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
    
    /// Retourne l'ID du node expediteur
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
    
    /// Checks if c'est une request (requires une response)
    pub fn is_request(&self) -> bool {
        matches!(self,
            KademliaMessage::Ping { .. } |
            KademliaMessage::FindNode { .. } |
            KademliaMessage::FindValue { .. } |
            KademliaMessage::Store { .. }
        )
    }
    
    /// Generates a timestamp current
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Contact compact pour les responses FIND_NODE
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

/// Key DHT : hash SHA-1 de 160 bits (compatible avec NodeId)
pub type DhtKey = [u8; 20];

/// Valeur DHT : data arbitraires avec metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtValue {
    pub data: Vec<u8>,
    pub stored_at: u64,    // timestamp du stockage
    pub ttl_secs: u64,     // duration de vie
    pub publisher_id: NodeId, // qui a publie cette valeur
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
    
    /// Checks if la valeur a expire
    pub fn is_expired(&self) -> bool {
        let now = KademliaMessage::current_timestamp();
        now > self.stored_at + self.ttl_secs
    }
    
    /// Temps restant avant expiration
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

/// Resultat d'une request FIND_VALUE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindValueResult {
    /// Valeur trouvee
    Value(DhtValue),
    /// Valeur non trouvee, mais voici des nodes plus proches
    CloserNodes(Vec<KademliaContact>),
}

/// Configuration pour les messages DHT
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// Taille maximale d'un message DHT (en bytes)
    pub max_message_size: usize,
    /// TTL by default pour les valeurs stockees
    pub default_value_ttl: u64,
    /// Nombre max de contacts dans une response FIND_NODE
    pub max_contacts_per_response: usize,
    /// Timeout pour les requests DHT
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

/// Helpers pour create les messages Kademlia
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

/// Erreurs specifiques a la DHT
#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("Timeout de request DHT")]
    RequestTimeout,
    
    #[error("Message DHT trop large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },
    
    #[error("Key DHT invalid: {0}")]
    InvalidKey(String),
    
    #[error("Valeur DHT expiree")]
    ValueExpired,
    
    #[error("Stockage DHT plein")]
    StorageFull,
    
    #[error("Noeud inaccessible: {0}")]
    NodeUnreachable(NodeId),
    
    #[error("Serialization echouee: {0}")]
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