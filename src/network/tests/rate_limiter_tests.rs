//! Tests unitaires pour le rate limiter TSN
//! 
//! Tests isoles avec controle total du temps et des parameters.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{advance, pause, Instant};

use crate::network::rate_limiter::{RateLimiter, RateLimitConfig};

/// Test basique: un rate limiter frais accepte les requests
#[tokio::test]
async fn test_rate_limiter_accepts_initial_requests() {
    let config = RateLimitConfig::default();
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();

    // Les firsts requests devraient be acceptees
    for _ in 0..10 {
        assert!(limiter.check(&addr), "Fresh rate limiter should accept requests");
    }
}

/// Test: le rate limiter bloque after depassement du seuil
#[tokio::test]
async fn test_rate_limiter_blocks_after_threshold() {
    let config = RateLimitConfig {
        max_requests_per_second: 5,
        ban_duration: Duration::from_secs(300),
    };
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();

    // Accepte les 5 firsts requests
    for i in 0..5 {
        assert!(limiter.check(&addr), "Request {} should be allowed", i + 1);
    }

    // Bloque la 6eme
    assert!(!limiter.check(&addr), "6th request should be rate limited");
}

/// Test: le rate limiter reinitialise after 1 seconde
#[tokio::test]
async fn test_rate_limiter_resets_after_window() {
    pause();
    
    let config = RateLimitConfig {
        max_requests_per_second: 3,
        ban_duration: Duration::from_secs(300),
    };
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:8003".parse().unwrap();

    // Exhausts le quota
    for _ in 0..3 {
        assert!(limiter.check(&addr));
    }
    assert!(!limiter.check(&addr), "Should be rate limited");

    // Avance le temps de 1 seconde
    advance(Duration::from_secs(1)).await;

    // Le quota devrait be reinitialise
    assert!(limiter.check(&addr), "Should accept after window reset");
}

/// Test: chaque pair a son propre bucket
#[tokio::test]
async fn test_rate_limiter_per_peer_isolation() {
    let config = RateLimitConfig {
        max_requests_per_second: 2,
        ban_duration: Duration::from_secs(300),
    };
    let mut limiter = RateLimiter::new(config);
    
    let addr1: SocketAddr = "127.0.0.1:8004".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:8005".parse().unwrap();

    // Exhausts le quota du premier peer
    assert!(limiter.check(&addr1));
    assert!(limiter.check(&addr1));
    assert!(!limiter.check(&addr1), "Peer 1 should be rate limited");

    // Le second pair devrait toujours avoir son quota
    assert!(limiter.check(&addr2), "Peer 2 should not be affected");
    assert!(limiter.check(&addr2));
}

/// Test: gestion de nombreux pairs simultanes
#[tokio::test]
async fn test_rate_limiter_many_peers() {
    let config = RateLimitConfig::default();
    let mut limiter = RateLimiter::new(config);

    // Cree 1000 pairs differents
    for i in 0..1000 {
        let addr: SocketAddr = format!("127.0.0.1:{}", 9000 + i).parse().unwrap();
        assert!(limiter.check(&addr), "Peer {} should be accepted", i);
    }
}

/// Test: configuration by default raisonnable
#[test]
fn test_default_config() {
    let config = RateLimitConfig::default();
    assert_eq!(config.max_requests_per_second, 100);
    assert_eq!(config.ban_duration, Duration::from_secs(300));
}

/// Test edge case: adresse IPv6
#[tokio::test]
async fn test_rate_limiter_ipv6() {
    let config = RateLimitConfig::default();
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "[::1]:8006".parse().unwrap();

    assert!(limiter.check(&addr), "IPv6 address should be handled");
}

/// Test edge case: port 0 (ephemeral)
#[tokio::test]
async fn test_rate_limiter_ephemeral_port() {
    let config = RateLimitConfig::default();
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    assert!(limiter.check(&addr), "Ephemeral port should be handled");
}

/// Test de stress: burst de requests
#[tokio::test]
async fn test_rate_limiter_burst() {
    let config = RateLimitConfig {
        max_requests_per_second: 1000,
        ban_duration: Duration::from_secs(300),
    };
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:8007".parse().unwrap();

    // Burst de 1000 requests
    for i in 0..1000 {
        assert!(limiter.check(&addr), "Burst request {} should be allowed", i);
    }
    
    // La 1001eme devrait be bloquee
    assert!(!limiter.check(&addr), "1001st request should be blocked");
}

/// Test: comportement avec max_requests_per_second = 0
#[tokio::test]
async fn test_rate_limiter_zero_threshold() {
    let config = RateLimitConfig {
        max_requests_per_second: 0,
        ban_duration: Duration::from_secs(300),
    };
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:8008".parse().unwrap();

    // Toutes les requests devraient be bloquees
    assert!(!limiter.check(&addr), "Zero threshold should block all");
}

/// Test: comportement avec max_requests_per_second very eleve
#[tokio::test]
async fn test_rate_limiter_high_threshold() {
    let config = RateLimitConfig {
        max_requests_per_second: u32::MAX,
        ban_duration: Duration::from_secs(300),
    };
    let mut limiter = RateLimiter::new(config);
    let addr: SocketAddr = "127.0.0.1:8009".parse().unwrap();

    // Beaucoup de requests devraient passer
    for _ in 0..10000 {
        assert!(limiter.check(&addr), "High threshold should allow many");
    }
}
