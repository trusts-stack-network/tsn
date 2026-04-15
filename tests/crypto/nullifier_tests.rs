use crate::crypto::nullifier::NullifierGenerator;
use crate::crypto::note::Note;
use proptest::prelude::*;
use rand::rngs::OsRng;

proptest! {
    #[test]
    fn nullifier_uniqueness(
        note_value in any::<u64>(),
        note_blinding in any::<[u8; 32]>(),
        nullifier_key1 in any::<[u8; 32]>(),
        nullifier_key2 in any::<[u8; 32]>()
    ) {
        let gen = NullifierGenerator::new();
        let note = Note::new(note_value, &note_blinding);
        
        let nf1 = gen.generate(&note, &nullifier_key1);
        let nf2 = gen.generate(&note, &nullifier_key2);
        
        // Keys differentes = nullifiers differents
        prop_assert_ne!(nf1, nf2);
    }
    
    #[test]
    fn nullifier_deterministic(
        note_value in any::<u64>(),
        note_blinding in any::<[u8; 32]>(),
        nullifier_key in any::<[u8; 32]>()
    ) {
        let gen = NullifierGenerator::new();
        let note = Note::new(note_value, &note_blinding);
        
        let nf1 = gen.generate(&note, &nullifier_key);
        let nf2 = gen.generate(&note, &nullifier_key);
        
        // Same entree = same nullifier
        prop_assert_eq!(nf1, nf2);
    }
}

#[test]
fn test_nullifier_collision_resistance() {
    let gen = NullifierGenerator::new();
    let mut nullifiers = std::collections::HashSet::new();
    
    // Generate 100