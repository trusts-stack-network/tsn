#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::commitment::{Commitment, CommitmentScheme};
use tsn_crypto::poseidon::PoseidonHash;

fuzz_target!(|data: &[u8]| {
    // Test 1: Deserialization sans panic
    let _commitment = Commitment::from_bytes(data);
    
    // Test 2: Commitment avec inputs randoms
    if data.len() >= 64 {
        let (blinding, value) = data.split_at(32);
        let commitment = Commitment::new(value, blinding);
        
        // Doit pas paniquer same avec valeurs invalids
        let _root = commitment.root();
    }
    
    // Test 3: Verification de consistency
    if data.len() >= 128 {
        let (input1, rest) = data.split_at(64);
        let (input2, _) = rest.split_at(64);
        
        let comm1 = Commitment::new(&input1[32..], &input1[..32]);
        let comm2 = Commitment::new(&input2[32..], &input2[..32]);
        
        // Check that commitments differents != egaux
        if input1 != input2 {
            assert_ne!(comm1.root(), comm2.root());
        }
    }
});