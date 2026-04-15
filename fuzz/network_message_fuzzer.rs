//! Fuzzer: Messages network malformeds
//!
//! Ce fuzzer teste la robustesse du parser de messages network TSN
//! contre des entrees malveillantes.
//!
//! # Surfaces d'attaque testees
//! - Deserialization de messages
//! - Parsing de headers
//! - Validation de tailles
//! - Gestion des buffers
//!
//! # Usage
//! ```bash
//! cargo fuzz run network_message_fuzzer
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsn::network::message::{Message, MessageParser};

fuzz_target!(|data: &[u8]| {
    // Test 1: Parsing de message brut
    // Ne doit jamais paniquer, same avec des data randoms
    let _ = MessageParser::parse(data);

    // Test 2: Si le parsing reussit, checksr les invariants
    if let Ok(msg) = MessageParser::parse(data) {
        // Check that la taille est coherente
        if let Some(size) = msg.payload_size() {
            assert!(size <= 10_000_000, "Payload trop grand: {}", size);
        }

        // Check that le type de message est valide
        assert!(
            msg.message_type().is_valid(),
            "Type de message invalid"
        );
    }

    // Test 3: Round-trip serialization/deserialization
    if let Ok(original) = MessageParser::parse(data) {
        if let Ok(serialized) = original.serialize() {
            // La reserialization doit produire le same message
            if let Ok(roundtrip) = MessageParser::parse(&serialized) {
                assert_eq!(
                    original.message_type(),
                    roundtrip.message_type(),
                    "Round-trip incoherent pour le type"
                );
            }
        }
    }
});
