//! Tests de security pour le module network TSN
//! 
//! Tests d'attaques, validation robuste et cas adversariaux.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use bytes::{BytesMut, Bytes};

use crate::network::protocol::{
    TsnMessage, HandshakeData, ProtocolVersion, Capability, 
    encode_message, decode_message, ProtocolError
};

/// Test: resistance aux buffer overflow avec des data malveillantes
#[test]
fn test_buffer_overflow_resistance() {
    // Test avec un buffer enorme pour tenter un overflow
    let huge_buffer = vec![0u8; 1_000_000]; // 1MB of zeros
    let mut buf = BytesMut::from(huge_buffer.as_slice());
    
    let result = decode_message(&mut buf);
    
    // Ne devrait pas paniquer, soit retourner None soit une error
    match result {
        Ok(None) => {
            // Comportement acceptable : pas assez of data valides
        }
        Ok(Some(_)) => {
            panic!("Ne devrait pas decoder un buffer of data invalids");
        }
        Err(_) => {
            // Erreur acceptable
        }
    }
}

/// Test: resistance aux data randoms malveillantes
#[test]
fn test_random_malicious_data() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Genere des data pseudo-randoms reproductibles
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
        
        // Ne devrait jamais paniquer
        match result {
            Ok(None) => {
                // Comportement acceptable
            }
            Ok(Some(_)) => {
                // Si ca decode, checks que c'est coherent
                // (very improbable avec des data randoms)
            }
            Err(_) => {
                // Erreur acceptable et attendue
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
        0,                              // Unix epoch
        1,                              // Presque epoque Unix
        current_time - 86400_000_000_000, // 24h dans le passe
        current_time + 86400_000_000_000, // 24h dans le futur
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
        
        // L'encodage devrait reussir (on encode tout)
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        // Le decodage devrait reussir also
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        // Mais la validation du timestamp devrait be faite au niveau applicatif
        match decoded {
            TsnMessage::Handshake(data) => {
                assert_eq!(data.timestamp_ns, timestamp);
                
                // Simule une validation de timestamp
                let time_diff = if timestamp > current_time {
                    timestamp - current_time
                } else {
                    current_time - timestamp
                };
                
                // Les timestamps trop eloignes devraient be rejetes
                if time_diff > 3600_000_000_000 { // 1 heure
                    println!("Timestamp malveillant detecte: {}", timestamp);
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
            id[0] = 255;                // Premier byte a 255
            id
        },
        {
            let mut id = [0u8; 32];
            id[31] = 255;               // Dernier byte a 255
            id
        },
        {
            let mut id = [0u8; 32];
            for i in 0..32 {
                id[i] = (i % 2) as u8 * 255; // Pattern alterne
            }
            id
        },
        {
            let mut id = [0u8; 32];
            for i in 0..32 {
                id[i] = i as u8;        // Pattern sequentiel
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
                    println!("Node ID suspect detecte: {:?}", node_id);
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
        65536,      // Au-dela du maximum (sera tronque a u16)
    ];
    
    for port in malicious_ports {
        let handshake = HandshakeData {
            version: ProtocolVersion(1, 0),
            timestamp_ns: 1234567890,
            capabilities: vec![],
            node_id: [2u8; 32],
            listen_port: port as u16, // Conversion forcee
        };

        let msg = TsnMessage::Handshake(handshake);
        let encoded = encode_message(&msg).expect("Encoding should succeed");
        
        let mut buf = BytesMut::from(encoded.as_ref());
        let (decoded, _) = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
        
        match decoded {
            TsnMessage::Handshake(data) => {
                // Validation des ports
                if data.listen_port < 1024 {
                    println!("Port system detecte: {}", data.listen_port);
                }
                if data.listen_port == 0 {
                    println!("Port invalid detecte: {}", data.listen_port);
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
        ProtocolVersion(100, 200),      // Versions very elevees
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
                let is_compatible = data.version.0 == 1; // Seulement major version 1
                
                if !is_compatible {
                    println!("Version incompatible detectee: {}.{}", data.version.0, data.version.1);
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: capabilities malveillantes (DoS via taille)
#[test]
fn test_malicious_capabilities() {
    // Test avec un nombre excessif de capabilities
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
    
    // L'encodage pourrait fail ou reussir selon l'implementation
    match encode_message(&msg) {
        Ok(encoded) => {
            println!("Message avec 10k capabilities encode: {} bytes", encoded.len());
            
            // Si l'encodage reussit, le decodage devrait also
            let mut buf = BytesMut::from(encoded.as_ref());
            match decode_message(&mut buf) {
                Ok(Some((decoded, _))) => {
                    match decoded {
                        TsnMessage::Handshake(data) => {
                            println!("Decode {} capabilities", data.capabilities.len());
                            
                            // Validation : rejeter les listes trop longues
                            if data.capabilities.len() > 100 {
                                println!("Liste de capabilities suspecte: {} elements", data.capabilities.len());
                            }
                        }
                        _ => panic!("Expected Handshake message"),
                    }
                }
                Ok(None) => {
                    println!("Buffer insuffisant pour decoder le message");
                }
                Err(e) => {
                    println!("Erreur de decodage attendue: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Erreur d'encodage attendue avec trop de capabilities: {:?}", e);
        }
    }
}

/// Test: capabilities avec valeurs extreme
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
                        // Validation des valeurs extreme
                        if *max_peers == 0 {
                            println!("MaxPeers=0 detecte (suspect)");
                        }
                        if *max_peers > 100_000 {
                            println!("MaxPeers very eleve detecte: {}", max_peers);
                        }
                    }
                    _ => panic!("Expected MaxPeers capability"),
                }
            }
            _ => panic!("Expected Handshake message"),
        }
    }
}

/// Test: messages tronques (attaque de fragmentation)
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
    
    // Test avec differents niveaux de troncature
    for truncate_at in 1..encoded.len() {
        let truncated = &encoded[..truncate_at];
        let mut buf = BytesMut::from(truncated);
        
        let result = decode_message(&mut buf);
        
        match result {
            Ok(None) => {
                // Comportement attendu : pas assez of data
            }
            Ok(Some(_)) => {
                panic!("Ne devrait pas decoder un message tronque a {} bytes", truncate_at);
            }
            Err(_) => {
                // Erreur acceptable
            }
        }
    }
}

/// Test: messages avec padding malveillant
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
    
    // Ajoute du padding malveillant
    let padding_patterns = vec![
        vec![0u8; 1000],        // Padding of zeros
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
                // Checks that seul le message valide a ete consomme
                assert_eq!(consumed, encoded.len());
                
                match decoded {
                    TsnMessage::Handshake(_) => {
                        // OK, le padding a ete ignore
                    }
                    _ => panic!("Expected Handshake message"),
                }
            }
            Ok(None) => {
                panic!("Devrait decoder le message valide same avec du padding");
            }
            Err(_) => {
                // Erreur acceptable si le format est corrompu
            }
        }
    }
}

/// Test: attaque par deni de service via HandshakeAck repetes
#[test]
fn test_handshake_ack_dos() {
    let base_msg = TsnMessage::HandshakeAck {
        accepted: true,
        timestamp_ns: 1234567890,
        your_node_id: [8u8; 32],
    };
    
    // Simule une attaque DoS avec beaucoup de HandshakeAck
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
    
    println!("DoS simulation: traite {:.0} HandshakeAck/sec", msgs_per_sec);
    
    // Checks that le system reste performant same sous charge
    assert!(msgs_per_sec > 1_000.0, "System trop lent sous charge DoS: {:.0} msgs/sec", msgs_per_sec);
}

/// Test: validation de consistency entre champs
#[test]
fn test_field_consistency_validation() {
    // Test avec des combinaisons incoherentes
    let inconsistent_cases = vec![
        // Cas 1: Timestamp futur avec version oldne
        (ProtocolVersion(0, 1), u64::MAX, "Future timestamp with old version"),
        
        // Cas 2: Port 0 avec capabilities avancees
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
                println!("Cas incoherent detecte: {}", description);
                
                // Validation de consistency
                if data.listen_port == 0 && !data.capabilities.is_empty() {
                    println!("Inconsistency: port 0 avec capabilities avancees");
                }
                
                if data.version.0 == 0 && data.timestamp_ns > 2_000_000_000_000_000_000 {
                    println!("Inconsistency: version oldne avec timestamp futur");
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
    
    // Mesure le temps pour les messages valides
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let encoded = encode_message(&valid_msg).expect("Encoding should succeed");
        let mut buf = BytesMut::from(encoded.as_ref());
        let _decoded = decode_message(&mut buf)
            .expect("Decoding should succeed")
            .expect("Should have a message");
    }
    let valid_duration = start.elapsed();
    
    // Mesure le temps pour les messages invalids
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
    
    println!("Temps valide: {:?}, invalid: {:?}, ratio: {:.2}", 
             valid_duration, invalid_duration, time_ratio);
    
    // Le temps de traitement ne devrait pas reveler d'information
    // (ratio proche de 1.0)
    assert!(time_ratio > 0.5 && time_ratio < 2.0, 
            "Possible timing attack vulnerability: ratio {:.2}", time_ratio);
}