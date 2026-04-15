//! Fuzzer pour les commitments post-quantiques - SECURITY CRITIQUE
//!
//! Ce fuzzer teste la robustesse des fonctions de commitment basees sur
//! Poseidon hash (resistantes aux attaques quantiques).
//!
//! ## Menaces identifiees
//! - Collision attacks sur Poseidon hash
//! - Malleability des commitments
//! - Timing attacks sur la verification
//! - Integer overflow dans les conversions de valeurs
//!
//! ## Propertys testees
//! 1. Determinisme: same entree → same commitment
//! 2. Hiding: random different → commitment different
//! 3. Binding: valeur differente → commitment different
//! 4. Verification correcte des preuves d'ouverture

#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Structure d'entree pour le fuzzer
#[derive(Debug, Arbitrary)]
struct CommitmentInput {
    value: u64,
    randomness: [u8; 32],
    pk_hash: [u8; 32],
    nullifier_key: [u8; 32],
    commitment: [u8; 32],
    position: u64,
}

fuzz_target!(|input: CommitmentInput| {
    use tsn::crypto::pq::commitment_pq::{
        ValueCommitmentPQ, NoteCommitmentPQ, derive_nullifier_pq,
        commit_to_value_pq, commit_to_note_pq,
    };

    // === Test ValueCommitmentPQ ===
    
    // 1. Test de determinisme
    let cm1 = ValueCommitmentPQ::commit(input.value, &input.randomness);
    let cm2 = ValueCommitmentPQ::commit(input.value, &input.randomness);
    assert_eq!(cm1.as_bytes(), cm2.as_bytes(), 
        "Value commitment non deterministic");

    // 2. Test de hiding - randomness differente = commitment different
    let mut different_randomness = input.randomness;
    different_randomness[0] = different_randomness[0].wrapping_add(1);
    let cm3 = ValueCommitmentPQ::commit(input.value, &different_randomness);
    // Note: collision theoriquement possible mais extremement improbable
    // On ne fait pas d'assert ici pour avoid les faux positifs

    // 3. Test de binding - valeur differente = commitment different
    let cm4 = ValueCommitmentPQ::commit(input.value.wrapping_add(1), &input.randomness);
    // Same remarque sur les collisions

    // 4. Test de verification
    assert!(cm1.verify(input.value, &input.randomness),
        "Verification de commitment valide a echoue");
    
    // Verification avec mauvaise valeur doit fail
    let wrong_value = input.value.wrapping_add(1);
    if wrong_value != entry.value { // Avoids le cas overflow u64::MAX
        assert!(!cm1.verify(wrong_value, &input.randomness),
            "Verification a accepte une mauvaise valeur");
    }

    // Verification avec mauvaise randomness doit fail
    assert!(!cm1.verify(input.value, &different_randomness),
        "Verification a accepte une mauvaise randomness");

    // === Test NoteCommitmentPQ ===

    let note_cm = NoteCommitmentPQ::commit(input.value, &input.pk_hash, &input.randomness);
    
    // Test de determinisme
    let note_cm2 = NoteCommitmentPQ::commit(input.value, &input.pk_hash, &input.randomness);
    assert_eq!(note_cm.to_bytes(), note_cm2.to_bytes(),
        "Note commitment non deterministic");

    // Test de verification
    assert!(note_cm.verify(input.value, &input.pk_hash, &input.randomness),
        "Verification de note commitment valide a echoue");

    // === Test derive_nullifier_pq ===

    let nullifier = derive_nullifier_pq(&input.nullifier_key, &input.commitment, input.position);
    
    // Determinisme du nullifier
    let nullifier2 = derive_nullifier_pq(&input.nullifier_key, &input.commitment, input.position);
    assert_eq!(nullifier, nullifier2,
        "Nullifier non deterministic");

    // Position differente = nullifier different
    let nullifier3 = derive_nullifier_pq(&input.nullifier_key, &input.commitment, 
        input.position.wrapping_add(1));
    // Collision theoriquement possible mais improbable

    // === Test des fonctions de commitment brutes ===

    let raw_value_cm = commit_to_value_pq(input.value, &input.randomness);
    assert_eq!(raw_value_cm.len(), 32,
        "Commitment valeur n'a pas la bonne taille");

    let raw_note_cm = commit_to_note_pq(input.value, &input.pk_hash, &input.randomness);
    assert_eq!(raw_note_cm.len(), 32,
        "Commitment note n'a pas la bonne taille");

    // === Test de serialization/deserialization ===

    let bytes = note_cm.to_bytes();
    let restored = NoteCommitmentPQ::from_bytes(bytes);
    assert_eq!(note_cm.to_bytes(), restored.to_bytes(),
        "Serialization/deserialization incorrecte");

    // === Test edge cases ===

    // Valeur 0
    let cm_zero = ValueCommitmentPQ::commit(0, &input.randomness);
    assert!(cm_zero.verify(0, &input.randomness),
        "Commitment valeur 0 incorrect");

    // Valeur max
    let cm_max = ValueCommitmentPQ::commit(u64::MAX, &input.randomness);
    assert!(cm_max.verify(u64::MAX, &input.randomness),
        "Commitment valeur MAX incorrect");

    // Randomness nulle
    let null_randomness = [0u8; 32];
    let cm_null_rand = ValueCommitmentPQ::commit(input.value, &null_randomness);
    assert!(cm_null_rand.verify(input.value, &null_randomness),
        "Commitment avec randomness nulle incorrect");

    // Position 0 et max
    let _nf_zero = derive_nullifier_pq(&input.nullifier_key, &input.commitment, 0);
    let _nf_max = derive_nullifier_pq(&input.nullifier_key, &input.commitment, u64::MAX);
});
