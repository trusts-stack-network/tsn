use serde::{Serialize, Deserialize};
use log::info;

// Requete de handshake RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub id: String,
    pub version: String,
}

// Reponse de handshake RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub id: String,
}