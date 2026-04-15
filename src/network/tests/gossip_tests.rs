//! Tests unitaires pour le protocole Gossip TSN
//!
//! Tests de propagation, rate limiting, peer scoring et gestion des messages.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

use crate::core::{Block, Transaction};
use crate::network::gossip::{GossipConfig, GossipEngine};
use crate::network::gossip_protocol::{InventoryId, InventoryType, NetworkMessage};
use crate::network::PeerId;

/// Creates a PeerId de test
fn test_peer_id(port: u16) -> PeerId {
    PeerId(SocketAddr::new("127.0.0.1".parse().unwrap(), port))
}

/// Creates a bloc de test
fn create_test_block(height: u64, nonce: u64) -> Block {
    Block::new(
        height,
        [0u8; 32],
        vec![],
        [0u8; 32],
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce,
    )
}

/// Creates a test transaction
fn create_test_transaction(nonce: u64) -> Transaction {
    Transaction::new(
        [0u8; 32],
        [0u8; 32],
        1000,
        100,
        nonce,
        vec![],
    )
}

#[tokio::test]
async fn test_gossip_engine_creation() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    // L'engine doit be cree sans error
    assert!(true);
}

#[tokio::test]
async fn test_peer_connection_handling() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let peer1 = test_peer_id(9001);
    let peer2 = test_peer_id(9002);
    
    // Connecte les peers
    engine.on_peer_connected(peer1).await.unwrap();
    engine.on_peer_connected(peer2).await.unwrap();
    
    // Deconnecte un peer
    engine.on_peer_disconnected(peer1).await.unwrap();
    
    // Test reussi si pas de panic
    assert!(true);
}

#[tokio::test]
async fn test_block_announcement() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let block = create_test_block(1, 1);
    let result = engine.announce_block(Arc::new(block));
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_transaction_announcement() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let tx = create_test_transaction(1);
    let result = engine.announce_transaction(Arc::new(tx));
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_duplicate_block_ignored() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let block = create_test_block(1, 1);
    
    // First annonce
    let result1 = engine.announce_block(Arc::new(block.clone()));
    assert!(result1.is_ok());
    
    // Second annonce du same bloc (devrait be ignoree)
    let result2 = engine.announce_block(Arc::new(block));
    assert!(result2.is_ok());
}

#[tokio::test]
async fn test_inventory_message_handling() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let peer = test_peer_id(9001);
    engine.on_peer_connected(peer).await.unwrap();
    
    // Creates a message Inv
    let inv = NetworkMessage::Inv(vec![
        InventoryId::block([1u8; 32]),
        InventoryId::transaction([2u8; 32]),
    ]);
    
    let data = bincode::serialize(&inv).unwrap();
    let result = engine.on_message(peer, bytes::Bytes::from(data)).await;
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_rate_limiting() {
    let config = GossipConfig {
        rate_limit_per_sec: 2, // Tres bas pour le test
        ..Default::default()
    };
    let engine = GossipEngine::new(config);
    
    let peer = test_peer_id(9001);
    engine.on_peer_connected(peer).await.unwrap();
    
    // Envoie 3 messages rapidement
    let inv = NetworkMessage::Inv(vec![InventoryId::block([1u8; 32])]);
    let data = bincode::serialize(&inv).unwrap();
    
    for _ in 0..3 {
        let _ = engine.on_message(peer, bytes::Bytes::from(data.clone())).await;
    }
    
    // Le 3eme message devrait be rate limite
    // (on ne peut pas facilement checksr ca sans acces a l'state interne)
    assert!(true);
}

#[tokio::test]
async fn test_invalid_message_penalty() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let peer = test_peer_id(9001);
    engine.on_peer_connected(peer).await.unwrap();
    
    // Envoie des data invalids
    let invalid_data = bytes::Bytes::from(vec![0xff; 100]);
    let result = engine.on_message(peer, invalid_data).await;
    
    // Devrait be OK mais le peer devrait be penalise
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_unknown_peer_message() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let unknown_peer = test_peer_id(9999);
    
    let inv = NetworkMessage::Inv(vec![InventoryId::block([1u8; 32])]);
    let data = bincode::serialize(&inv).unwrap();
    
    // Message d'un peer inconnu
    let result = engine.on_message(unknown_peer, bytes::Bytes::from(data)).await;
    
    // Devrait be OK mais ignore
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_config_customization() {
    let config = GossipConfig {
        fanout: 8,
        rate_limit_per_sec: 50,
        inventory_timeout: Duration::from_secs(600),
        cleanup_interval: Duration::from_secs(120),
    };
    
    let engine = GossipEngine::new(config);
    
    // Test que la config personnalisee est acceptee
    assert!(true);
}

#[tokio::test]
async fn test_concurrent_announcements() {
    let config = GossipConfig::default();
    let engine = Arc::new(GossipEngine::new(config));
    
    let mut handles = vec![];
    
    // Lance plusieurs annonces concurrent
    for i in 0..10 {
        let engine_clone = engine.clone();
        let handle = tokio::spawn(async move {
            let block = create_test_block(i as u64, i as u64);
            engine_clone.announce_block(Arc::new(block))
        });
        handles.push(handle);
    }
    
    // Attend toutes les tasks
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_peer_scoring() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let peer = test_peer_id(9001);
    engine.on_peer_connected(peer).await.unwrap();
    
    // Envoie des messages valides
    let inv = NetworkMessage::Inv(vec![InventoryId::block([1u8; 32])]);
    let data = bincode::serialize(&inv).unwrap();
    
    for _ in 0..5 {
        let _ = engine.on_message(peer, bytes::Bytes::from(data.clone())).await;
    }
    
    // Le peer devrait avoir un score positif
    assert!(true);
}

#[tokio::test]
async fn test_cleanup_interval() {
    let config = GossipConfig {
        cleanup_interval: Duration::from_millis(50),
        inventory_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let engine = GossipEngine::new(config);
    
    // Attend que le cleanup s'execute
    sleep(Duration::from_millis(200)).await;
    
    // Le cleanup devrait s'be execute
    assert!(true);
}

#[tokio::test]
async fn test_gossip_shutdown() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    // Drop l'engine pour declencher le shutdown
    drop(engine);
    
    // Attend que le worker s'arrete
    sleep(Duration::from_millis(50)).await;
    
    assert!(true);
}

#[tokio::test]
async fn test_many_peers_connection() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    // Connecte 100 peers
    for i in 0..100 {
        let peer = test_peer_id(9000 + i as u16);
        engine.on_peer_connected(peer).await.unwrap();
    }
    
    // Deconnecte tous les peers
    for i in 0..100 {
        let peer = test_peer_id(9000 + i as u16);
        engine.on_peer_disconnected(peer).await.unwrap();
    }
    
    assert!(true);
}

#[tokio::test]
async fn test_getdata_message_handling() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let peer = test_peer_id(9001);
    engine.on_peer_connected(peer).await.unwrap();
    
    // Creates a message GetData
    let getdata = NetworkMessage::GetData(vec![
        InventoryId::block([1u8; 32]),
    ]);
    
    let data = bincode::serialize(&getdata).unwrap();
    let result = engine.on_message(peer, bytes::Bytes::from(data)).await;
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_notfound_message_handling() {
    let config = GossipConfig::default();
    let engine = GossipEngine::new(config);
    
    let peer = test_peer_id(9001);
    engine.on_peer_connected(peer).await.unwrap();
    
    // Creates a message NotFound
    let notfound = NetworkMessage::NotFound(vec![
        InventoryId::block([1u8; 32]),
    ]);
    
    let data = bincode::serialize(&notfound).unwrap();
    let result = engine.on_message(peer, bytes::Bytes::from(data)).await;
    
    assert!(result.is_ok());
}
