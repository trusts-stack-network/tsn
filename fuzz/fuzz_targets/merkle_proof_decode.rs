#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::merkle_tree::MerkleProof;

fuzz_target!(|data: &[u8]| {
    // Le decode doit jamais panic, same sur entrees randoms
    let _ = MerkleProof::try_from(data);
});