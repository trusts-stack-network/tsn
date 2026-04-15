use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::pq::dilithium::DilithiumKeypair;
use rand::rngs::OsRng;

/// Test la validation des keys post-quantiques
#[test]
fn test_pq_key_validation() {
    let mut rng = OsRng;
    
    // Generates ae key valide
    let (pk, sk) = DilithiumKeypair::generate(&mut rng).into_keys();
    
    // Doit passer la validation
    assert!(pk.validate().is_ok());
    
    // Test avec une key sur la courbe incorrecte
    let mut invalid_pk_bytes = pk.to_bytes();
    invalid_pk_bytes[0] ^= 0xff; // Modifie le premier byte
    
    let invalid_pk = match PublicKey::from_bytes(&invalid_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return, // Si la parsing fails, c'est acceptable
    };
    
    // Doit fail la validation
    assert!(invalid_pk.validate().is_err(), 
        "Invalid public key non detectee");
}

/// Test que les keys faibles sont rejetees
#[test]
fn test_weak_key_rejection() {
    let weak_keys = vec![
        [0u8; 32],  // Key nulle
        [1u8; 32],  // Key repetitive
    ];
    
    for weak_key in weak_keys {
        let result = PublicKey::from_bytes(&weak_key);
        assert!(result.is_err() || result.unwrap().validate().is_err(),
            "Key faible acceptee: {:?}", weak_key);
    }
}