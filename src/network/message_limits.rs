//! Limites de size of messages network TSN
//!
//! This module defines of limits strictes de size for all messages
//! of the protocole network afin de prevent the attaques DoS par messages oversized.
//!
//! Les limits are definedes par type de message for allowstre a utilisation
//! optimale de the bande passante tout in now the security.

use bytes::BytesMut;
use std::time::{Duration, Instant};
use tracing::{debug, warn, error};

use super::{NetworkError, Result};
use super::protocol::{TsnMessage, ProtocolError};

/// Limite globale absolue for all messages (protection ultime)
pub const GLOBAL_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// Limite for the messages de handshake (doit rester petit)
pub const HANDSHAKE_MAX_SIZE: usize = 16 * 1024; // 16 KB

/// Limite for the heartbeats (very light)
pub const HEARTBEAT_MAX_SIZE: usize = 1024; // 1 KB

/// Limite for the exchanges de peers
pub const PEER_EXCHANGE_MAX_SIZE: usize = 256 * 1024; // 256 KB

/// Limite for the messages of data applicatives
pub const DATA_MAX_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// Limite for the messages de disconnection
pub const DISCONNECT_MAX_SIZE: usize = 4 * 1024; // 4 KB

/// Size maximale of the buffer de lecture par connection
pub const MAX_READ_BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Size of the header de framing (magic + length)
pub const FRAMING_HEADER_SIZE: usize = 8; // 4 bytes magic + 4 bytes length

/// Timeout for the lecture d'un message complet
pub const MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum messages per second per peer
pub const MAX_MESSAGES_PER_SECOND: u32 = 1000;

/// Configuration completee of limits de messages
#[derive(Debug, Clone, Copy)]
pub struct MessageLimitsConfig {
    /// Limite globale absolue
    pub global_max: usize,
    /// Limite for the handshakes
    pub handshake_max: usize,
    /// Limite for the heartbeats
    pub heartbeat_max: usize,
    /// Limite for the exchanges de peers
    pub peer_exchange_max: usize,
    /// Limite for the data
    pub data_max: usize,
    /// Limite for the disconnections
    pub disconnect_max: usize,
    /// Size max of the buffer de lecture
    pub max_buffer_size: usize,
    /// Timeout de lecture
    pub read_timeout: Duration,
}

impl Default for MessageLimitsConfig {
    fn default() -> Self {
        Self {
            global_max: GLOBAL_MAX_MESSAGE_SIZE,
            handshake_max: HANDSHAKE_MAX_SIZE,
            heartbeat_max: HEARTBEAT_MAX_SIZE,
            peer_exchange_max: PEER_EXCHANGE_MAX_SIZE,
            data_max: DATA_MAX_SIZE,
            disconnect_max: DISCONNECT_MAX_SIZE,
            max_buffer_size: MAX_READ_BUFFER_SIZE,
            read_timeout: MESSAGE_READ_TIMEOUT,
        }
    }
}

/// Result de the validation de taille
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeValidationResult {
    /// La size is acceptable
    Accept,
    /// La size exceeds the limite for this type de message
    Reject { limit: usize, actual: usize },
    /// La size exceeds the limite globale (attaque DoS suspected)
    RejectGlobal { limit: usize, actual: usize },
}

/// Checks if a size de payload is acceptable for a type de message given
pub fn validate_message_size(message_type: &str, size: usize) -> SizeValidationResult {
    // Verification de the limite globale in premier
    if size > GLOBAL_MAX_MESSAGE_SIZE {
        return SizeValidationResult::RejectGlobal {
            limit: GLOBAL_MAX_MESSAGE_SIZE,
            actual: size,
        };
    }

    // Limite specific selon the type de message
    let limit = match message_type {
        "Handshake" => HANDSHAKE_MAX_SIZE,
        "Heartbeat" => HEARTBEAT_MAX_SIZE,
        "PeerExchange" => PEER_EXCHANGE_MAX_SIZE,
        "Data" => DATA_MAX_SIZE,
        "Disconnect" => DISCONNECT_MAX_SIZE,
        _ => GLOBAL_MAX_MESSAGE_SIZE, // Type inconnu = limite globale
    };

    if size > limit {
        SizeValidationResult::Reject { limit, actual: size }
    } else {
        SizeValidationResult::Accept
    }
}

/// Verifies the size d'un message TSN complete
pub fn check_tsn_message_size(msg: &TsnMessage) -> Result<()> {
    // Estimation de the size serializede
    let estimated_size = estimate_serialized_size(msg);
    
    let message_type = match msg {
        TsnMessage::Handshake(_) => "Handshake",
        TsnMessage::Heartbeat { .. } => "Heartbeat",
        TsnMessage::PeerExchange { .. } => "PeerExchange",
        TsnMessage::Data { .. } => "Data",
        TsnMessage::Disconnect { .. } => "Disconnect",
        TsnMessage::HandshakeAck { .. } => "Handshake", // Same limite que Handshake
    };

    match validate_message_size(message_type, estimated_size) {
        SizeValidationResult::Accept => Ok(()),
        SizeValidationResult::Reject { limit, actual } => {
            warn!(
                "Message {} rejected: taille {} > limite {}",
                message_type, actual, limit
            );
            Err(ProtocolError::MessageTooLarge(actual, limit).into())
        }
        SizeValidationResult::RejectGlobal { limit, actual } => {
            error!(
                "ATTENTION: Message {} exceeds la limite globale! {} > {} - Possible attaque DoS",
                message_type, actual, limit
            );
            Err(ProtocolError::MessageTooLarge(actual, limit).into())
        }
    }
}

/// Estime the size serializede d'un message
fn estimate_serialized_size(msg: &TsnMessage) -> usize {
    match msg {
        TsnMessage::Handshake(data) => {
            // Version + timestamp + node_id + port + capabilities
            let base_size = 1 + 8 + 32 + 2 + 8;
            let caps_size = data.capabilities.len() * 8;
            base_size + caps_size + 64 // overhead serialization
        }
        TsnMessage::Heartbeat { .. } => 32, // Very petit
        TsnMessage::PeerExchange { peers, .. } => {
            // Each peer: addr (max 16 bytes IPv6 + 2 port) + node_id (32) + overhead
            let peer_size = 64;
            peers.len() * peer_size + 64
        }
        TsnMessage::Data { payload, .. } => {
            // priority + timestamp + payload
            1 + 8 + payload.len() + 64
        }
        TsnMessage::Disconnect { reason, .. } => {
            // timestamp + reason string
            8 + reason.len() + 64
        }
        TsnMessage::HandshakeAck { .. } => 48, // accepted + timestamp + node_id
    }
}

/// Checks if a buffer de lecture exceeds the size maximale authorized
pub fn check_buffer_size(buffer: &BytesMut, peer_addr: std::net::SocketAddr) -> Result<()> {
    if buffer.len() > MAX_READ_BUFFER_SIZE {
        error!(
            "Buffer de lecture trop gros pour {}: {} > {} - Fermeture de la connection",
            peer_addr, buffer.len(), MAX_READ_BUFFER_SIZE
        );
        Err(NetworkError::InvalidMessage(
            format!("Buffer size exceeded: {} > {}", buffer.len(), MAX_READ_BUFFER_SIZE)
        ))
    } else {
        Ok(())
    }
}

/// Structure for tracker the statistics de size of messages
#[derive(Debug)]
pub struct MessageSizeTracker {
    /// Number of accepted messages by type
    pub accepted_counts: std::collections::HashMap<String, u64>,
    /// Number of rejected messages by type
    pub rejected_counts: std::collections::HashMap<String, u64>,
    /// Size totale of data acceptedes
    pub total_accepted_bytes: u64,
    /// Size totale of data rejectedes
    pub total_rejected_bytes: u64,
    /// Timestamp de start of the tracking
    pub started_at: Instant,
}

impl Default for MessageSizeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageSizeTracker {
    /// Creates a new tracker
    pub fn new() -> Self {
        Self {
            accepted_counts: std::collections::HashMap::new(),
            rejected_counts: std::collections::HashMap::new(),
            total_accepted_bytes: 0,
            total_rejected_bytes: 0,
            started_at: Instant::now(),
        }
    }

    /// Records a message accepted
    pub fn record_accepted(&mut self, message_type: &str, size: usize) {
        *self.accepted_counts.entry(message_type.to_string()).or_insert(0) += 1;
        self.total_accepted_bytes += size as u64;
    }

    /// Records a message rejected
    pub fn record_rejected(&mut self, message_type: &str, size: usize) {
        *self.rejected_counts.entry(message_type.to_string()).or_insert(0) += 1;
        self.total_rejected_bytes += size as u64;
    }

    /// Returns the statistics sous forme de chain
    pub fn stats_string(&self) -> String {
        let elapsed = self.started_at.elapsed().as_secs();
        let accepted_msgs: u64 = self.accepted_counts.values().sum();
        let rejected_msgs: u64 = self.rejected_counts.values().sum();
        
        format!(
            "MessageSizeTracker: {} accepted ({} bytes), {} rejected ({} bytes) over {}s",
            accepted_msgs, self.total_accepted_bytes,
            rejected_msgs, self.total_rejected_bytes,
            elapsed
        )
    }
}

/// Verifies the size declarede in a header before lecture completee
/// Returns the payload size if valid, otherwise an error
pub fn validate_framed_message_size(
    declared_size: u32,
    peer_addr: std::net::SocketAddr,
) -> Result<usize> {
    let size = declared_size as usize;
    
    if size == 0 {
        debug!("Message vide received de {}", peer_addr);
        return Err(ProtocolError::InvalidPayloadLength(0).into());
    }
    
    if size > GLOBAL_MAX_MESSAGE_SIZE {
        error!(
            "Message oversize detected de {}: declared {} > limite {} - Rejet immediate",
            peer_addr, size, GLOBAL_MAX_MESSAGE_SIZE
        );
        return Err(ProtocolError::MessageTooLarge(size, GLOBAL_MAX_MESSAGE_SIZE).into());
    }
    
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::{HandshakeData, ProtocolVersion, Capability};

    #[test]
    fn test_validate_message_size_accept() {
        // Heartbeat de 500 bytes must passer
        assert_eq!(
            validate_message_size("Heartbeat", 500),
            SizeValidationResult::Accept
        );
        
        // Handshake de 8KB must passer
        assert_eq!(
            validate_message_size("Handshake", 8 * 1024),
            SizeValidationResult::Accept
        );
    }

    #[test]
    fn test_validate_message_size_reject() {
        // Heartbeat de 2KB must be rejected (> 1KB)
        match validate_message_size("Heartbeat", 2 * 1024) {
            SizeValidationResult::Reject { limit, actual } => {
                assert_eq!(limit, HEARTBEAT_MAX_SIZE);
                assert_eq!(actual, 2 * 1024);
            }
            _ => panic!("Expected Reject"),
        }
    }

    #[test]
    fn test_validate_message_size_reject_global() {
        // Message de 5MB must be rejected globalement
        match validate_message_size("Data", 5 * 1024 * 1024) {
            SizeValidationResult::RejectGlobal { limit, actual } => {
                assert_eq!(limit, GLOBAL_MAX_MESSAGE_SIZE);
                assert_eq!(actual, 5 * 1024 * 1024);
            }
            _ => panic!("Expected RejectGlobal"),
        }
    }

    #[test]
    fn test_validate_framed_message_size() {
        // Size valid
        assert!(validate_framed_message_size(1024, "127.0.0.1:8000".parse().unwrap()).is_ok());
        
        // Size zero
        assert!(validate_framed_message_size(0, "127.0.0.1:8000".parse().unwrap()).is_err());
        
        // Size trop large
        assert!(validate_framed_message_size(5 * 1024 * 1024, "127.0.0.1:8000".parse().unwrap()).is_err());
    }

    #[test]
    fn test_message_size_tracker() {
        let mut tracker = MessageSizeTracker::new();
        
        tracker.record_accepted("Heartbeat", 100);
        tracker.record_accepted("Data", 1000);
        tracker.record_rejected("Data", 5 * 1024 * 1024);
        
        assert_eq!(tracker.accepted_counts.get("Heartbeat"), Some(&1));
        assert_eq!(tracker.accepted_counts.get("Data"), Some(&1));
        assert_eq!(tracker.rejected_counts.get("Data"), Some(&1));
        assert_eq!(tracker.total_accepted_bytes, 1100);
        assert_eq!(tracker.total_rejected_bytes, 5 * 1024 * 1024);
    }
}