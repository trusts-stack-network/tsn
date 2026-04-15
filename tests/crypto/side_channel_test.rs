use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::poseidon::PoseidonHash;
use std::time::{Duration, Instant};
use std::hint::black_box;

/// Test de resistance aux attaques par canal auxiliaire
/// VULNERABILITY: Le hash-to-scalar peut fuiter des infos via timing
#[test]
fn test_poseidon_side_channel_resistance() {
    let mut hasher = PoseidonHash::new();
    
    // Mesure le temps pour differentes tailles d'input
    let small_input = [1u8; 16];
    let large_input = [1u8; 1024];
    
    // Petit input
    let start = Instant::now();
    for _ in 0..1000 {
        hasher.reset();
        hasher.update(&small_input);
        black_box(hasher.finalize());
    }
    let small_time = start.elapsed();
    
    // Grand input
    let start = Instant::now();
    for _ in 0..1000 {
        hasher.reset();
        hasher.update(&large_input);
        black_box(hasher.finalize());
    }
    let large_time = start.elapsed();
    
    // Le temps devrait be proportionnel a la taille
    // Si on voit des patterns bases sur le contenu, c'est une fuite
    let ratio = large_time.as_nanos() as f64 / small_time.as_nanos() as f64;
    
    // Ratio attendu: ~64 (1024/16)
    // Tolerance de 20% pour le overhead
    assert!(ratio > 50.0 && ratio < 80.0, 
        "Timing anormal: ratio = {}", ratio);
}

/// Test de cache-timing resistance
#[test]
fn test_cache_timing_resistance() {
    let sk = SecretKey::generate(&mut thread_rng());
    
    // Acces a la key devrait prendre le same temps peu importe la valeur
    let accesses = 10000;
    let mut times = Vec::with_capacity(accesses);
    
    for _ in 0..accesses {
        let start = Instant::now();
        black_box(sk.as_bytes());
        times.push(start.elapsed());
    }
    
    // Calcule la variance des temps
    let mean = times.iter().sum::<Duration>() / accesses as u32;
    let variance: f64 = times.iter()
        .map(|t| {
            let diff = t.as_nanos() as i128 - mean.as_nanos() as i128;
            (diff * diff) as f64
        })
        .sum::<f64>() / accesses as f64;
    
    let std_dev = variance.sqrt();
    let cv = std_dev / mean.as_nanos() as f64;
    
    // Coefficient de variation devrait be faible (< 0.1)
    assert!(cv < 0.1, "Haute variance detectee: CV = {}", cv);
}