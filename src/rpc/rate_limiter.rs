//! Rate limiting par endpoint for the RPC TSN
//!
//! Supporte :
//! - Rate limiting par method RPC (read vs write vs admin)
//! - Rate limiting par IP source
//! - Rate limiting par key API
//! - Burst allowance for the pics de trafic
//! - Sliding window for a distribution uniforme

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Category de method RPC for the rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RpcMethodCategory {
    /// Methods de lecture (getblock, gettransaction, etc.)
    Read,
    /// Methods d'writing (sendtransaction, submitblock)
    Write,
    /// Methods d'administration (peer management, debug)
    Admin,
    /// Methods de gossip (propagation de blocs/tx)
    Gossip,
}

impl RpcMethodCategory {
    /// Determines the category d'une method RPC
    pub fn from_method(method: &str) -> Self {
        match method {
            // Methods de lecture
            "getblock" | "getblockhash" | "getblockheader" | "gettransaction" |
            "getbalance" | "getutxos" | "getmempool" | "getpeers" |
            "getchaininfo" | "getdifficulty" | "getbestblockhash" |
            "getblockcount" | "getrawtransaction" | "decoderawtransaction" |
            "getfeerate" | "getstakinginfo" => Self::Read,
            
            // Methods d'writing
            "sendtransaction" | "sendrawtransaction" | "submitblock" |
            "createrawtransaction" | "signrawtransaction" => Self::Write,
            
            // Methods d'admin
            "addpeer" | "removepeer" | "banpeer" | "unbanpeer" |
            "getpeerinfo" | "setban" | "clearbanned" |
            "getdebuginfo" | "getnetworkinfo" | "stop" | "restart" => Self::Admin,
            
            // Methods de gossip
            "gossipblock" | "gossiptransaction" | "announcepeer" => Self::Gossip,
            
            // By default: lecture
            _ => Self::Read,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests par minute for the methods de lecture
    pub read_rpm: u32,
    /// Requests par minute for the methods d'writing
    pub write_rpm: u32,
    /// Requests par minute for the methods d'admin
    pub admin_rpm: u32,
    /// Requests par minute for the methods de gossip
    pub gossip_rpm: u32,
    /// Burst allowance (multiplicateur)
    pub burst_multiplier: f32,
    /// Window de temps in secondes
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            read_rpm: 1000,
            write_rpm: 100,
            admin_rpm: 60,
            gossip_rpm: 500,
            burst_multiplier: 2.0,
            window_seconds: 60,
        }
    }
}

impl RateLimitConfig {
    /// Gets the rate limit for a category
    pub fn get_limit(&self, category: RpcMethodCategory) -> u32 {
        match category {
            RpcMethodCategory::Read => self.read_rpm,
            RpcMethodCategory::Write => self.write_rpm,
            RpcMethodCategory::Admin => self.admin_rpm,
            RpcMethodCategory::Gossip => self.gossip_rpm,
        }
    }
}

/// State of the rate limiting for a source
#[derive(Debug)]
struct RateLimitState {
    /// Last request
    last_request: Instant,
    /// Number of requests in the current window
    request_count: u32,
    /// Available tokens (for token bucket)
    tokens: f32,
    /// Dernier refill of tokens
    last_refill: Instant,
}

impl RateLimitState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            last_request: now,
            request_count: 0,
            tokens: 0.0,
            last_refill: now,
        }
    }
}

/// Rate limiter par endpoint
pub struct EndpointRateLimiter {
    /// Configuration
    config: RateLimitConfig,
    /// State par source IP (category -> IP -> state)
    ip_states: Arc<RwLock<HashMap<RpcMethodCategory, HashMap<String, RateLimitState>>>>,
    /// State par key API (category -> hash key -> state)
    key_states: Arc<RwLock<HashMap<RpcMethodCategory, HashMap<String, RateLimitState>>>>,
}

impl EndpointRateLimiter {
    /// Creates a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_states: Arc::new(RwLock::new(HashMap::new())),
            key_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Checks if a request is authorized (without API key)
    pub async fn check_ip(&self, method: &str, ip: SocketAddr) -> bool {
        let category = RpcMethodCategory::from_method(method);
        let ip_str = ip.ip().to_string();
        let limit = self.config.get_limit(category);
        let burst = (limit as f32 * self.config.burst_multiplier) as u32;
        
        let mut states = self.ip_states.write().await;
        let category_states = states.entry(category).or_insert_with(HashMap::new);
        let state = category_states.entry(ip_str).or_insert_with(RateLimitState::new);
        
        self.check_state(state, limit, burst)
    }

    /// Checks if a request is authorized (with API key)
    pub async fn check_key(&self, method: &str, key_hash: &str, key_limit: u32) -> bool {
        let category = RpcMethodCategory::from_method(method);
        let limit = key_limit.min(self.config.get_limit(category));
        let burst = (limit as f32 * self.config.burst_multiplier) as u32;
        
        let mut states = self.key_states.write().await;
        let category_states = states.entry(category).or_insert_with(HashMap::new);
        let state = category_states.entry(key_hash.to_string()).or_insert_with(RateLimitState::new);
        
        self.check_state(state, limit, burst)
    }

    /// Verifies l'state and met up to date the compteurs
    fn check_state(&self,
        state: &mut RateLimitState,
        limit: u32,
        burst: u32,
    ) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        
        // Token bucket refill
        let elapsed = now.duration_since(state.last_refill).as_secs_f32();
        let refill_rate = limit as f32 / 60.0; // tokens par seconde
        state.tokens = (state.tokens + elapsed * refill_rate).min(burst as f32);
        state.last_refill = now;
        
        // Check if on a enough de tokens
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            state.last_request = now;
            true
        } else {
            false
        }
    }

    /// Cleans up the states expireds (to appeler periodically)
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let expiry = Duration::from_secs(self.config.window_seconds * 2);
        
        // Cleanup IP states
        let mut ip_states = self.ip_states.write().await;
        for (_, category_states) in ip_states.iter_mut() {
            category_states.retain(|_, state| {
                now.duration_since(state.last_request) < expiry
            });
        }
        drop(ip_states);
        
        // Cleanup key states
        let mut key_states = self.key_states.write().await;
        for (_, category_states) in key_states.iter_mut() {
            category_states.retain(|_, state| {
                now.duration_since(state.last_request) < expiry
            });
        }
    }

    /// Gets rate limiting stats for monitoring
    pub async fn get_stats(&self,
    ) -> RateLimitStats {
        let ip_states = self.ip_states.read().await;
        let key_states = self.key_states.read().await;
        
        let mut total_tracked_ips = 0usize;
        let mut total_tracked_keys = 0usize;
        
        for (_, category_states) in ip_states.iter() {
            total_tracked_ips += category_states.len();
        }
        
        for (_, category_states) in key_states.iter() {
            total_tracked_keys += category_states.len();
        }
        
        RateLimitStats {
            total_tracked_ips,
            total_tracked_keys,
            config: self.config.clone(),
        }
    }
}

/// Statistiques de rate limiting
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStats {
    pub total_tracked_ips: usize,
    pub total_tracked_keys: usize,
    pub config: RateLimitConfig,
}

/// Middleware Axum for the rate limiting
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<EndpointRateLimiter>,
}

impl RateLimitLayer {
    pub fn new(limiter: Arc<EndpointRateLimiter>) -> Self {
        Self { limiter }
    }
}

/// Rate limiting error
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for method {method}")]
    RateLimitExceeded { method: String },
    #[error("Invalid method: {0}")]
    InvalidMethod(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_method_categorization() {
        assert_eq!(RpcMethodCategory::from_method("getblock"), RpcMethodCategory::Read);
        assert_eq!(RpcMethodCategory::from_method("sendtransaction"), RpcMethodCategory::Write);
        assert_eq!(RpcMethodCategory::from_method("addpeer"), RpcMethodCategory::Admin);
        assert_eq!(RpcMethodCategory::from_method("gossipblock"), RpcMethodCategory::Gossip);
        assert_eq!(RpcMethodCategory::from_method("unknown"), RpcMethodCategory::Read);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = RateLimitConfig {
            read_rpm: 10,
            write_rpm: 5,
            admin_rpm: 2,
            burst_multiplier: 1.0,
            window_seconds: 60,
        };
        
        let limiter = EndpointRateLimiter::new(config);
        let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // 10 read requests should pass
        for _ in 0..10 {
            assert!(limiter.check_ip("getblock", ip).await);
        }
        
        // La 11th should be rejectede
        assert!(!limiter.check_ip("getblock", ip).await);
    }

    #[tokio::test]
    async fn test_burst_allowance() {
        let config = RateLimitConfig {
            read_rpm: 10,
            write_rpm: 5,
            admin_rpm: 2,
            burst_multiplier: 2.0,
            window_seconds: 60,
        };
        
        let limiter = EndpointRateLimiter::new(config);
        let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Avec burst=2.0, on should pouvoir faire 20 requests
        let mut passed = 0;
        for _ in 0..25 {
            if limiter.check_ip("getblock", ip).await {
                passed += 1;
            }
        }
        
        assert_eq!(passed, 20);
    }

    #[tokio::test]
    async fn test_key_rate_limiting() {
        let config = RateLimitConfig {
            read_rpm: 100,
            write_rpm: 50,
            admin_rpm: 10,
            burst_multiplier: 1.0,
            window_seconds: 60,
        };
        
        let limiter = EndpointRateLimiter::new(config);
        let key_hash = "test_key_hash";
        
        // 5 requests with limit of 5
        for _ in 0..5 {
            assert!(limiter.check_key("getblock", key_hash, 5).await);
        }
        
        // La 6th should be rejectede
        assert!(!limiter.check_key("getblock", key_hash, 5).await);
    }
}
