//! TSN network message size limits
//!
//! This module defines strict size limits for all network protocol messages
//! to prevent DoS attacks via oversized messages.
//!
//! Limits are defined per message type to allow optimal bandwidth usage
//! while ensuring security.

use bytes::BytesMut;
use std::time::{Duration, Instant};
use tracing::{debug, warn, error};

use super::{NetworkError, Result};
use super::protocol::{TsnMessage, ProtocolError};

/// Absolute global limit for all messages (ultimate protection)
pub const GLOBAL_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// Limit for handshake messages (must remain small)
pub const HANDSHAKE_MAX_SIZE: usize = 16 * 1024; // 16 KB

/// Limit for heartbeats (very light)
pub const HEARTBEAT_MAX_SIZE: usize = 1024; // 1 KB

/// Limit for peer exchange messages
pub const PEER_EXCHANGE_MAX_SIZE: usize = 256 * 1024; // 256 KB

/// Limit for application data messages
pub const DATA_MAX_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// Limit for disconnect messages
pub const DISCONNECT_MAX_SIZE: usize = 4 * 1024; // 4 KB

/// Maximum read buffer size per connection
pub const MAX_READ_BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Size of the framing header (magic + length)
pub const FRAMING_HEADER_SIZE: usize = 8; // 4 bytes magic + 4 bytes length

/// Timeout for reading a complete message
pub const MESSAGE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum messages per second per peer
pub const MAX_MESSAGES_PER_SECOND: u32 = 1000;

/// Complete message limits configuration
#[derive(Debug, Clone, Copy)]
pub struct MessageLimitsConfig {
    /// Absolute global limit
    pub global_max: usize,
    /// Limit for handshakes
    pub handshake_max: usize,
    /// Limit for heartbeats
    pub heartbeat_max: usize,
    /// Limit for peer exchanges
    pub peer_exchange_max: usize,
    /// Limit for data
    pub data_max: usize,
    /// Limit for disconnections
    pub disconnect_max: usize,
    /// Maximum read buffer size
    pub max_buffer_size: usize,
    /// Read timeout
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

/// Size validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeValidationResult {
    /// The size is acceptable
    Accept,
    /// The size exceeds the limit for this message type
    Reject { limit: usize, actual: usize },
    /// The size exceeds the global limit (DoS attack suspected)
    RejectGlobal { limit: usize, actual: usize },
}

/// Checks if a payload size is acceptable for a given message type
pub fn validate_message_size(message_type: &str, size: usize) -> SizeValidationResult {
    // Verify the global limit first
    if size > GLOBAL_MAX_MESSAGE_SIZE {
        return SizeValidationResult::RejectGlobal {
            limit: GLOBAL_MAX_MESSAGE_SIZE,
            actual: size,
        };
    }

    // Specific limit based on message type
    let limit = match message_type {
        "Handshake" => HANDSHAKE_MAX_SIZE,
        "Heartbeat" => HEARTBEAT_MAX_SIZE,
        "PeerExchange" => PEER_EXCHANGE_MAX_SIZE,
        "Data" => DATA_MAX_SIZE,
        "Disconnect" => DISCONNECT_MAX_SIZE,
        _ => GLOBAL_MAX_MESSAGE_SIZE, // Unknown type = global limit
    };

    if size > limit {
        SizeValidationResult::Reject { limit, actual: size }
    } else {
        SizeValidationResult::Accept
    }
}

/// Verifies the size of a complete TSN message
pub fn check_tsn_message_size(msg: &TsnMessage) -> Result<()> {
    // Estimate serialized size
    let estimated_size = estimate_serialized_size(msg);
    
    let message_type = match msg {
        TsnMessage::Handshake(_) => "Handshake",
        TsnMessage::Heartbeat { .. } => "Heartbeat",
        TsnMessage::PeerExchange { .. } => "PeerExchange",
        TsnMessage::Data { .. } => "Data",
        TsnMessage::Disconnect { .. } => "Disconnect",
        TsnMessage::HandshakeAck { .. } => "Handshake", // Same limit as Handshake
    };

    match validate_message_size(message_type, estimated_size) {
        SizeValidationResult::Accept => Ok(()),
        SizeValidationResult::Reject { limit, actual } => {
            warn!(
                "Message {} rejected: size {} > limit {}",
                message_type, actual, limit
            );
            Err(ProtocolError::MessageTooLarge(actual, limit).into())
        }
        SizeValidationResult::RejectGlobal { limit, actual } => {
            error!(
                "WARNING: Message {} exceeds global limit! {} > {} - Possible DoS attack",
                message_type, actual, limit
            );
            Err(ProtocolError::MessageTooLarge(actual, limit).into())
        }
    }
}

/// Estimates the serialized size of a message
fn estimate_serialized_size(msg: &TsnMessage) -> usize {
    match msg {
        TsnMessage::Handshake(data) => {
            // Version + timestamp + node_id + port + capabilities
            let base_size = 1 + 8 + 32 + 2 + 8;
            let caps_size = data.capabilities.len() * 8;
            base_size + caps_size + 64 // overhead serialization
        }
        TsnMessage::Heartbeat { .. } => 32, // Very small
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

/// Checks if a read buffer exceeds the maximum authorized size
pub fn check_buffer_size(buffer: &BytesMut, peer_addr: std::net::SocketAddr) -> Result<()> {
    if buffer.len() > MAX_READ_BUFFER_SIZE {
        error!(
            "Read buffer too large for {}: {} > {} - Closing connection",
            peer_addr, buffer.len(), MAX_READ_BUFFER_SIZE
        );
        Err(NetworkError::InvalidMessage(
            format!("Buffer size exceeded: {} > {}", buffer.len(), MAX_READ_BUFFER_SIZE)
        ))
    } else {
        Ok(())
    }
}

/// Structure for tracking message size statistics
#[derive(Debug)]
pub struct MessageSizeTracker {
    /// Number of accepted messages by type
    pub accepted_counts: std::collections::HashMap<String, u64>,
    /// Number of rejected messages by type
    pub rejected_counts: std::collections::HashMap<String, u64>,
    /// Total size of accepted data
    pub total_accepted_bytes: u64,
    /// Total size of rejected data
    pub total_rejected_bytes: u64,
    /// Tracking start timestamp
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

    /// Returns the statistics as a string
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

/// Verifies the declared size in a header before complete reading
/// Returns the payload size if valid, otherwise an error
pub fn validate_framed_message_size(
    declared_size: u32,
    peer_addr: std::net::SocketAddr,
) -> Result<usize> {
    let size = declared_size as usize;
    
    if size == 0 {
        debug!("Empty message received from {}", peer_addr);
        return Err(ProtocolError::InvalidPayloadLength(0).into());
    }
    
    if size > GLOBAL_MAX_MESSAGE_SIZE {
        error!(
            "Oversized message detected from {}: declared {} > limit {} - Immediate rejection",
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
        // 500-byte heartbeat should pass
        assert_eq!(
            validate_message_size("Heartbeat", 500),
            SizeValidationResult::Accept
        );
        
        // 8KB handshake should pass
        assert_eq!(
            validate_message_size("Handshake", 8 * 1024),
            SizeValidationResult::Accept
        );
    }

    #[test]
    fn test_validate_message_size_reject() {
        // 2KB heartbeat should be rejected (> 1KB)
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
        // 5MB message should be rejected globally
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
        // Valid size
        assert!(validate_framed_message_size(1024, "127.0.0.1:8000".parse().unwrap()).is_ok());
        
        // Zero size
        assert!(validate_framed_message_size(0, "127.0.0.1:8000".parse().unwrap()).is_err());
        
        // Size too large
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