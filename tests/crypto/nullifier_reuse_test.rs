use tsn_crypto::nullifier::Nullifier;
use tsn_crypto::note::Note;
use rand::rngs::OsRng;

/// Test que les nullifiers ne peuvent pas be reutilises
#[test]
fn test_nullifier_double_spend() {
    let mut rng = OsRng;
    
    // Creates a note
    let note = Note::new(100, &mut rng);
    let nullifier = note.nullify();
    
    // Premier spend doit reussir
    assert!(nullifier.verify(&note).is_ok());
    
    // Second spend doit fail
    assert!(nullifier.verify(&note).is_err(),
        "Double depense non detectee");
}

/// Test la persistance des nullifiers utilises
#[test]
