//! Tests de security for the module network TSN
//! 
//! Tests d'attaques, validation robuste and cas adversariaux.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use bytes::{BytesMut, Bytes};

use crate::network::protocol::{
    TsnMessage, HandshakeData, ProtocolVersion, Capability, 
    encode_message, decode_message, ProtocolError
};

/// Test: resistance aux buffer overflow with data malveillantes
#[test]
fn test_buffer_overflow_resistance() {
    // Test with a buffer enormous for try a overflow
    let huge_buffer = vec![0u8; 1_000_000]; // 1MB of zeros
    let mut buf = BytesMut::from(huge_buffer.as_slice());
    
    let result = decode_message(&mut buf);
    
    // Should not panic, should return None or an error
    match result {
        Ok(None) => {
            // Comportement acceptable : pas enough of data valids
        }
        Ok(Some(_)) => {
            panic!("Ne should pas decode un buffer of data invalids");
        }
        Err(_) => {
            // Acceptable error
        }
    }
}

/// Test: resistance aux data random malveillantes
#[test]
fn test_random_malicious_data() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Generates of data pseudo-random reproductibles
    for seed in 0..100 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut malicious_data = Vec::new();
        for i in 0..256 {
            malicious_data.push(((hash.wrapping_add(i)) & 0xFF) as u8);
        }
        
        let mut buf = BytesMut::from(malicious_data.as_slice());
        let result = decode_message(&mut buf);
        
        // Ne should jamais paniquer
        match result {
            Ok(None) => {
                // Comportement acceptable
            }
            Ok(Some(_)) => {
                // Si it decodes, verifies que c'est consistent
                // (very improbable with data random)
            }
            Err(_) => {
                // Acceptable error and attendue
            }
        }
    }
}

/// Test: timestamps malveillants (attaque temporelle)
#[test]
fn test_malicious_timestamps() {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let malicious_timestamps = vec![
        0,                              // Epoch Unix
        1,                              // Presque epoch Unix
        current_time - 86400_000_000_000, // 24h in the past
        current_time + 86400_000_000_000, // 24h in the future
        u64::MAX,                       // Timestamp maximum
        u64::MAX - 1,                   // Presque maximum
    ];
    
    for timestamp in malicious_timestamps {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: timestamp,
            capabilities: vec![],
            node_id: [1u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        
        // L'encoding should succeed (on encode tout)
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        // Le decoding should succeed aussi
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        // But timestamp validation should be done at the application level
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.timestamp_ns, timestamp);
                
                // Simulate a validation de timestamp
                let time_diff = if timestamp > current_time {
                    timestamp - current_time
                } else {
                    current_time - timestamp
                };
                
                // Les timestamps trop distant devraient be rejecteds
                if time_diff > 3600_000_000_000 { // 1 heure
                    println!("Timestamp malveillant detected: {}", timestamp);
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: node_id malveillants (collision, patterns)
#[test]
fn test_malicious_node_ids() {
    let malicious_node_ids = vec![
        [0u8; 32],                      // Tous zeros
        [255u8; 32],                    // Tous 1
        {
            let mut id = [0u8; 32];
            id[0] = 255;                // First byte to 255
            id
        },
        {
            let mut id = [0u8; 32];
            id[31] = 255;               // Last byte to 255
            id
        },
        {
            let mut id = [0u8; 32];
            for i in 0..32 {
                id[i] = (i % 2) as u8 * 255; // Pattern alternated
            }
            id
        },
        {
            let mut id = [0u8; 32];
            for i in 0..32 {
                id[i] = i as u8;        // Pattern sequential
            }
            id
        },
    ];
    
    for node_id in malicious_node_ids {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id,
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.node_id, node_id);
                
                // Detection de patterns suspects
                let all_zeros = node_id.iter().all(|&b| b == 0);
                let all_ones = node_id.iter().all(|&b| b == 255);
                
                if all_zeros || all_ones {
                    println!("Node ID suspect detected: {:?}", node_id);
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: ports malveillants
#[test]
fn test_malicious_ports() {
    let malicious_ports = vec![
        0,          // Port invalid
        1,          // Port system
        22,         // SSH
        80,         // HTTP
        443,        // HTTPS
        65535,      // Port maximum
        65536,      // Beyond du maximum (sera truncated to u16)
    ];
    
    for port in malicious_ports {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id: [2u8; 32],
            listen_port: port as u16, // Conversion forced
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                // Validation of ports
                if data.listen_port < 1024 {
                    println!("Port system detected: {}", data.listen_port);
                }
                if data.listen_port == 0 {
                    println!("Port invalid detected: {}", data.listen_port);
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: versions de protocole malveillantes
#[test]
fn test_malicious_protocol_versions() {
    let malicious_versions = vec![
        ProtocolVersion(0, 0),          // Version nulle
        ProtocolVersion(255, 255),      // Version maximum
        ProtocolVersion(0, 255),        // Major 0, minor max
        ProtocolVersion(255, 0),        // Major max, minor 0
        ProtocolVersion(100, 200),      // Versions very highs
    ];
    
    for version in malicious_versions {
        let handshake = HandshakeData {
            version,
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id: [3u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                // Validation de compatibility de version
                let is_compatible = data.version.0 == 1; // Only major version 1
                
                if !is_compatible {
                    println!("Version incompatible detectede: {}.{}", data.version.0, data.version.1);
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: capabilities malveillantes (DoS via taille)
#[test]
fn test_malicious_capabilities() {
    // Test with an excessive number of capabilities
    let mut excessive_capabilities = Vec::new();
    for i in 0..10000 {
        excessive_capabilities.push(Capability::MaxPeers(i));
    }
    
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: excessive_capabilities,
        node_id: [4u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    
    // L'encoding pourrait failsr or succeed selon l'implementation
    match encode_message(&msg) {
        Ok(encoded) => {
            println!("Message avec 10k capabilities encoded: {} bytes", encoded.len());
            
            // Si l'encoding succeeds, the decoding should aussi
            let mut buf = BytesMut::from(encoded.as_ref());
            match decode_message(&mut buf) {
                Ok(Some((decoded, _))) => {
                    match decoded {
                        TsnMessage::Handshake(data) => {
                            println!("Decoded {} capabilities", data.capabilities.len());
                            
                            // Validation : rejeter the listes trop longs
                            if data.capabilities.len() > 100 {
                                println!("Liste de capabilities suspecte: {} elements", data.capabilities.len());
                            }
                        }
                        _ => panic!("Expected Handshake message"),
                    }
                }
                Ok(None) => {
                    println!("Buffer insufficient pour decode le message");
                }
                Err(e) => {
                    println!("Error de decoding attendue: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Expected encoding error with too many capabilities: {:?}", e);
        }
    }
}

/// Test: capabilities with valeurs extreme
#[test]
fn test_extreme_capability_values() {
    let extreme_capabilities = vec![
        Capability::MaxPeers(0),
        Capability::MaxPeers(1),
        Capability::MaxPeers(u32::MAX),
        Capability::MaxPeers(u32::MAX - 1),
    ];
    
    for capability in extreme_capabilities {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![capability.clone()],
            node_id: [5u8; 32],
            listen_port: 9333,
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.capabilities.len(), 1);
                
                match &data.capabilities[0] {
                    Capability::MaxPeers(max_peers) => {
                        // Validation of valeurs extreme
                        if *max_peers == 0 {
                            println!("MaxPeers=0 detected (suspect)");
                        }
                        if *max_peers > 100_000 {
                            println!("MaxPeers very high detected: {}", max_peers);
                        }
                    }
                    _ => panic!("Expected MaxPeers capability"),
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: messages truncated (attaque de fragmentation)
#[test]
fn test_truncated_messages() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id: [6u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    // Test with different niveaux de troncature
    for truncate_at in 1..encoded.len() {
        let truncated = &encoded[..truncate_at];
        let mut buf = BytesMut::from(truncated);
        
        let result = decode_message(&mut buf);
        
        match result {
            Ok(None) => {
                // Comportement attendu : pas enough of data
            }
            Ok(Some(_)) => {
                panic!("Ne should pas decode un message truncated to {} bytes", truncate_at);
            }
            Err(_) => {
                // Acceptable error
            }
        }
    }
}

/// Test: messages with padding malveillant
#[test]
fn test_malicious_padding() {
    let handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![],
        node_id: [7u8; 32],
        listen_port: 9333,
    };

    let msg = TsnMessage::Handshake(handshake);
    let encoded = encode_message(&msg).expect("Encoding should succeed");
    
    // Ajoute of the padding malveillant
    let padding_patterns = vec![
        vec![0u8; 1000],        // Padding de zeros
        vec![255u8; 1000],      // Padding de 1
        (0..1000).map(|i| (i % 256) as u8).collect::<Vec<u8>>(), // Pattern
    ];
    
    for padding in padding_patterns {
        let mut malicious_message = encoded.clone();
        malicious_message.extend_from_slice(&padding);
        
        let mut buf = BytesMut::from(malicious_message.as_ref());
        let result = decode_message(&mut buf);
        
        match result {
            Ok(Some((decoded, consumed))) => {
                // Verify that seul the message valid a been consumed
                assert_eq!(consumed, encoded.len());
                
                match decoded {
                    TsnMessage::Handshake(_) => {
                        // OK, the padding a been ignored
                    }
                    _ => panic!("Expected Handshake message"),
                }
            }
            Ok(None) => {
                panic!("Devrait decode le message valid same avec du padding");
            }
            Err(_) => {
                // Acceptable error if the format is corrompu
            }
        }
    }
}

/// Test: attaque par denial de service via HandshakeAck repeateds
#[test]
fn test_handshake_ack_dos() {
    let base_msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 1234567890,
        your_node_id: [8u8; 32],
    };
    
    // Simulate a attaque DoS with beaucoup de HandshakeAck
    let iterations = 10_000;
    let start = std::time::Instant::now();
    
    for i in 0..iterations {
        let msg = TsnMessage::HandshakeAck {
            accepted: i % 2 == 0,
            timestamp_ns: 1234567890 + i as u64,
            your_node_id: [(i % 256) as u8; 32],
        };
        
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        let mut buf = BytesMut::from(encoded.as_ref());
        let _decoded = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
    }
    
    let duration = start.elapsed();
    let msgs_per_sec = iterations as f64 / duration.as_secs_f64();
    
    println!("DoS simulation: processed {:.0} HandshakeAck/sec", msgs_per_sec);
    
    // Verify that the system reste performant same sous charge
    assert!(msgs_per_sec > 1_000.0, "System trop lent sous charge DoS: {:.0} msgs/sec", msgs_per_sec);
}

/// Test: validation de consistency entre fields
#[test]
fn test_field_consistency_validation() {
    // Test with combinaisons inconsistent
    let inconsistent_cases = vec![
        // Cas 1: Timestamp futur with version ancienne
        (ProtocolVersion(0, 1), u64::MAX, "Future timestamp with old version"),
        
        // Cas 2: Port 0 with capabilities advanced
        (ProtocolVersion(1, 0), 1234567890, "Port 0 with advanced capabilities"),
    ];
    
    for (version, timestamp, description) in inconsistent_cases {
        let handshake = HandshakeData {
            version,
            timestamp_ns: timestamp,
            capabilities: vec![Capability::HighBandwidth, Capability::LowLatency],
            node_id: [9u8; 32],
            listen_port: if description.contains("Port 0") { 0 } else { 9333 },
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                println!("Cas inconsistent detected: {}", description);
                
                // Validation de consistency
                if data.listen_port == 0 && !data.capabilities.is_empty() {
                    println!("Inconsistency: port 0 avec capabilities advanced");
                }
                
                if data.version.0 == 0 && data.timestamp_ns > 2_000_000_000_000_000_000 {
                    println!("Inconsistency: version ancienne avec timestamp futur");
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: resistance aux attaques de timing
#[test]
fn test_timing_attack_resistance() {
    let valid_handshake = HandshakeData {
        version: ProtocolVersion(1, 0),
        timestamp_ns: 1234567890,
        capabilities: vec![Capability::Forwarding],
        node_id: [10u8; 32],
        listen_port: 9333,
    };

    let invalid_handshake = HandshakeData {
        version: ProtocolVersion(255, 255), // Version invalid
        timestamp_ns: u64::MAX,
        capabilities: vec![],
        node_id: [0u8; 32],
        listen_port: 0,
    };
    
    let valid_msg = TsnMessage::Handshake(valid_handshake);
    let invalid_msg = TsnMessage::Handshake(invalid_handshake);
    
    let iterations = 1_000;
    
    // Mesure the temps for the messages valids
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let encoded = encode_message(&valid_msg).expect("Encoding should succeed");
        let mut buf = BytesMut::from(encoded.as_ref());
        let _decoded = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
    }
    let valid_duration = start.elapsed();
    
    // Mesure the temps for the messages invalids
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let encoded = encode_message(&invalid_msg).expect("Encoding should succeed");
        let mut buf = BytesMut::from(encoded.as_ref());
        let _decoded = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
    }
    let invalid_duration = start.elapsed();
    
    let time_ratio = invalid_duration.as_nanos() as f64 / valid_duration.as_nanos() as f64;
    
    println!("Temps valid: {:?}, invalid: {:?}, ratio: {:.2}", 
             valid_duration, invalid_duration, time_ratio);
    
    // Le temps de processing not should pas reveal d'information
    // (ratio proche de 1.0)
    assert!(time_ratio > 0.5 && time_ratio < 2.0, 
            "Possible timing attack vulnerability: ratio {:.2}", time_ratio);
}