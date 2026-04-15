// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Tests de regression : comparaisons constant-time et side-channels
use subtle::ConstantTimeEq;
use tsn_crypto::signature::PublicKey;

#[test]
fn pubkey_compare_constant_time() {
    let pk1 = PublicKey::random(&mut rand::thread_rng());
    let pk2 = PublicKey::random(&mut rand::thread_rng());

    let start = std::time::Instant::now();
    let eq1 = pk1.ct_eq(&pk1).unwrap_u8();
    let d1 = start.elapsed();

    let start = std::time::Instant::now();
    let eq2 = pk1.ct_eq(&pk2).unwrap_u8();
    let d2 = start.elapsed();

    // Differences de temps ≤ 20 % (relache sur CI, mais detecta une egalite naive)
    let ratio = if d1 > d2 { d1.as_nanos() as f64 / d2.as_nanos() as f64 } else { d2.as_nanos() as f64 / d1.as_nanos() as f64 };
    assert!(ratio < 1.20, "Comparaison non constant-time detectee");
}
