//! Fuzzing des messages network P2P
//!
//! Teste la robustesse du parsing et de la validation des messages
//! network contre des inputs malformeds ou malveillants.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

// Structures de messages network a fuzzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMessage {
    pub msg_type: String,
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnnouncement {
    pub block_hash: [u8; 32],
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnnouncement {
    pub tx_hash: [u8; 32],
    pub fee: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub start_height: u64,
    pub end_height: u64,
    pub max_blocks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListRequest {
    pub max_peers: u32,
    pub exclude_localhost: bool,
}

/// Simule le parsing d'un message network
fn parse_network_message(data: &[u8]) -> Result<PeerMessage, Box<dyn std::error::Error>> {
    // Checks the taille minimale
    if data.len() < 8 {
        return Err("Message too short".into());
    }
    
    // Checks the taille maximale (protection DoS)
    if data.len() > 1024 * 1024 {
        return Err("Message too large".into());
    }
    
    // Tente de deserialiser
    let msg: PeerMessage = bincode::deserialize(data)?;
    
    // Validations de security
    validate_peer_message(&msg)?;
    
    Ok(msg)
}

/// Valide un message peer contre les attaques
fn validate_peer_message(msg: &PeerMessage) -> Result<(), Box<dyn std::error::Error>> {
    // Checks the type de message
    if msg.msg_type.len() > 64 {
        return Err("Message type too long".into());
    }
    
    // Checks the peer_id
    if msg.peer_id.len() > 256 {
        return Err("Peer ID too long".into());
    }
    
    // Checks the payload
    if msg.payload.len() > 512 * 1024 {
        return Err("Payload too large".into());
    }
    
    // Checks the timestamp (pas trop dans le futur)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if msg.timestamp > now + 3600 {
        return Err("Timestamp too far in future".into());
    }
    
    // Checks thes caracteres du type de message
    if !msg.msg_type.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Invalid characters in message type".into());
    }
    
    Ok(())
}

/// Simule le traitement d'une annonce de bloc
fn process_block_announcement(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 72 {
        return Err("Block announcement too short".into());
    }
    
    let announcement: BlockAnnouncement = bincode::deserialize(data)?;
    
    // Validations
    if announcement.height > 1_000_000_000 {
        return Err("Block height too high".into());
    }
    
    if announcement.timestamp == 0 {
        return Err("Invalid timestamp".into());
    }
    
    // Checks that le hash n'est pas null
    if announcement.block_hash == [0u8; 32] {
        return Err("Null block hash".into());
    }
    
    Ok(())
}

/// Simule le traitement d'une request de sync
fn process_sync_request(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let request: SyncRequest = bincode::deserialize(data)?;
    
    // Validations anti-DoS
    if request.start_height > request.end_height {
        return Err("Invalid height range".into());
    }
    
    if request.end_height - request.start_height > 10_000 {
        return Err("Range too large".into());
    }
    
    if request.max_blocks > 1000 {
        return Err("Too many blocks requested".into());
    }
    
    if request.max_blocks == 0 {
        return Err("Zero blocks requested".into());
    }
    
    Ok(())
}

/// Simule le rate limiting
struct RateLimiter {
    requests: HashMap<String, (u32, std::time::Instant)>,
    max_requests: u32,
    window_secs: u64,
}

impl RateLimiter {
    fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window_secs,
        }
    }
    
    fn check_rate_limit(&mut self, peer_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let now = std::time::Instant::now();
        
        // Cleans up the entrees expirees
        self.requests.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp).as_secs() < self.window_secs
        });
        
        // Checks the rate limit pour ce peer
        let (count, first_request) = self.requests
            .entry(peer_id.to_string())
            .or_insert((0, now));
        
        if now.duration_since(*first_request).as_secs() >= self.window_secs {
            // Nouvelle fenbe
            *count = 1;
            *first_request = now;
        } else {
            *count += 1;
            if *count > self.max_requests {
                return Err("Rate limit exceeded".into());
            }
        }
        
        Ok(())
    }
}

/// Simule la validation d'une liste de peers
fn validate_peer_list(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() > 64 * 1024 {
        return Err("Peer list too large".into());
    }
    
    let peer_list: Vec<String> = bincode::deserialize(data)?;
    
    if peer_list.len() > 1000 {
        return Err("Too many peers".into());
    }
    
    for peer in &peer_list {
        if peer.len() > 256 {
            return Err("Peer URL too long".into());
        }
        
        // Checks the format basique
        if !peer.starts_with("http://") && !peer.starts_with("https://") {
            return Err("Invalid peer URL format".into());
        }
        
        // Bloque les adresses privates/localhost en production
        if peer.contains("127.0.0.1") || peer.contains("localhost") || 
           peer.contains("192.168.") || peer.contains("10.") {
            return Err("Private IP address not allowed".into());
        }
    }
    
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Test 1: Parsing de message generique
    let _ = parse_network_message(data);
    
    // Test 2: Si assez of data, teste les messages specialises
    if data.len() >= 72 {
        let _ = process_block_announcement(data);
    }
    
    if data.len() >= 20 {
        let _ = process_sync_request(data);
    }
    
    // Test 3: Rate limiting avec peer_id fuzze
    if data.len() >= 4 {
        let mut rate_limiter = RateLimiter::new(10, 60);
        let peer_id = format!("peer_{}", data.len());
        let _ = rate_limiter.check_rate_limit(&peer_id);
    }
    
    // Test 4: Validation de liste de peers
    let _ = validate_peer_list(data);
    
    // Test 5: Test de deni de service par taille
    if data.len() > 10 * 1024 * 1024 {
        // Le fuzzer ne devrait jamais generate des inputs si gros
        // mais si c'est le cas, on doit les rejeter immediatement
        panic!("Input too large for fuzzing");
    }
    
    // Test 6: Parsing JSON malformed (attaque courante)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<serde_json::Value>(s);
    }
    
    // Test 7: Test de debordement d'entiers
    if data.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        let value = u64::from_le_bytes(bytes);
        
        // Teste les operations qui pourraient deborder
        let _ = value.checked_add(1);
        let _ = value.checked_mul(2);
        
        // Teste la conversion en timestamp
        if value < u64::MAX / 1000 {
            let _ = std::time::UNIX_EPOCH + std::time::Duration::from_secs(value);
        }
    }
});