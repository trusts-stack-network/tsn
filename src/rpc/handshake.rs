use serde::{Serialize, Deserialize};
use log::info;

// Request de handshake RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub id: String,
    pub version: String,
}

// Response de handshake RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub id: String,
}