//! Benchmark de parallelisme SLH-DSA batch verification
//!
//! Mesure l'acceleration obtenue avec la verification batch parallele
//! (vs sequentielle) sur des workloads realistes (1000+ signatures).

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::rngs::OsRng;
use tsn::crypto::pq::slh_dsa::{SecretKey as SlhSecretKey, PublicKey as SlhPublicKey};
use tsn::crypto::pq::slh_dsa_batch::{verify_batch, verify_batch_sequential, verify_batch_parallel, BatchVerificationEntry, BatchVerificationConfig};

/// Genere N paires de keys et signatures SLH-DSA
fn generate_slh_batch(n: usize) -> Vec<BatchVerificationEntry<'static>> {
    let mut entries = Vec::with_capacity(n);
    let msg = [0u8; 32];
    for _ in 0..n {
        let (sk, pk) = SlhSecretKey::generate_rng(&mut OsRng);
        let sig = sk.sign(&msg);
        entries.push(BatchVerificationEntry {
            public_key: &pk,
            message: &msg,
            signature: &sig,
        });
    }
    entries
}

/// Benchmark batch parallele SLH-DSA (1000 signatures)
fn bench_parallel_batch_1k(c: &mut Criterion) {
    let entries = generate_slh_batch(1000);
    
    let mut group = c.benchmark_group("parallel_batch_1k");
    group.throughput(Throughput::Elements(1000));
    
    // Sequentiel
    group.bench_function("sequential", |b| {
        b.iter(|| {
            let _ = verify_batch_sequential(&entries, false);
        });
    });
    
    // Parallele
    group.bench_function("parallel", |b| {
        b.iter(|| {
            let config = BatchVerificationConfig {
                use_parallel: true,
                early_abort: false,
                chunk_size: Some(128),
            };
            let _ = verify_batch(&entries, &config);
        });
    });
    
    group.finish();
}

/// Benchmark batch parallele SLH-DSA (5000 signatures)
fn bench_parallel_batch_5k(c: &mut Criterion) {
    let entries = generate_slh_batch(5000);
    
    let mut group = c.benchmark_group("parallel_batch_5k");
    group.throughput(Throughput::Elements(5000));
    
    // Sequentiel
    group.bench_function("sequential", |b| {
        b.iter(|| {
            let _ = verify_batch_sequential(&entries, false);
        });
    });
    
    // Parallele
    group.bench_function("parallel", |b| {
        b.iter(|| {
            let config = BatchVerificationConfig {
                use_parallel: true,
                early_abort: false,
                chunk_size: Some(256),
            };
            let _ = verify_batch(&entries, &config);
        });
    });
    
    group.finish();
}

/// Benchmark batch parallele SLH-DSA (10000 signatures)
fn bench_parallel_batch_10k(c: &mut Criterion) {
    let entries = generate_slh_batch(10000);
    
    let mut group = c.benchmark_group("parallel_batch_10k");
    group.throughput(Throughput::Elements(10000));
    
    // Sequentiel
    group.bench_function("sequential", |b| {
        b.iter(|| {
            let _ = verify_batch_sequential(&entries, false);
        });
    });
    
    // Parallele
    group.bench_function("parallel", |b| {
        b.iter(|| {
            let config = BatchVerificationConfig {
                use_parallel: true,
                early_abort: false,
                chunk_size: Some(512),
            };
            let _ = verify_batch(&entries, &config);
        });
    });
    
    group.finish();
}

criterion_group!(
    parallel_benches,
    bench_parallel_batch_1k,
    bench_parallel_batch_5k,
    bench_parallel_batch_10k
);
criterion_main!(parallel_benches);
