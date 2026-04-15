//! Module RPC JSON-RPC 2.0 for TSN
//!  
//! Expose :
//! - HTTP : POST /rpc
//! - WebSocket : ws://host/ws
//! - Authentification par API keys with permissions
//! - Rate limiting par key

pub mod auth;
pub mod rate_limiter;
pub mod server;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Contexte RPC shared
#[derive(Clone)]
pub struct RpcContext {
    /// Gestionnaire de keys API
    pub auth_manager: Arc<tokio::sync::RwLock<auth::ApiKeyManager>>,
    /// Rate limiter
    pub rate_limiter: Arc<tokio::sync::RwLock<rate_limiter::RateLimiter>>,
}

impl RpcContext {
    /// Creates a new contexte RPC
    pub fn new() -> Self {
        let mut auth_manager = auth::ApiKeyManager::new();
        
        // Create of keys by default (to remplacer par a config in production)
        let _ = auth_manager.create_key("default-read", vec![auth::Permission::Read]);
        let _ = auth_manager.create_key("default-write", vec![auth::Permission::Read, auth::Permission::Write]);
        let _ = auth_manager.create_key("default-admin", vec![auth::Permission::Read, auth::Permission::Write, auth::Permission::Admin]);
        
        Self {
            auth_manager: Arc::new(tokio::sync::RwLock::new(auth_manager)),
            rate_limiter: Arc::new(tokio::sync::RwLock::new(crate_limiter::RateLimiter::new())),
        }
    }
}

impl Default for RpcContext {
    fn default() -> Self {
        Self::new()
    }
}