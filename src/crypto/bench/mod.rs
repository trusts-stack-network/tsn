//! Benchmarks for the circuits ZK de TSN
//! 
//! This module provides benchmarks comparatifs entre:
//! - Plonky2 STARKs (system ZK principal de TSN, post-quantique)
//! - Legacy Groth16 (via arkworks, for reference)
//! 
//! Contexte de security:
//! - Tous the benchmarks utilisent of parameters 128-bit security
//! - Les benchmarks are designed for be reproductibles
//! 
//! Usage:
//! ```bash
//! cargo test --lib crypto::bench
//! ```

// Modules de benchmarks
pub mod halo2_commitment_bench;
pub mod plonky2_bench;
pub mod memory_bench;
pub mod halo2_plonky2_comparison;

// Re-exports for utilisation externe
pub use halo2_commitment_bench::{BenchmarkResult, BenchmarkRunner, run_all_benchmarks};
pub use plonky2_bench::run_plonky2_benchmarks;
pub use memory_bench::run_memory_benchmarks;
pub use halo2_plonky2_comparison::run_comparison;

/// Executes the suite completee de benchmarks
/// 
/// This fonction is the point d'entry principal for all benchmarks ZK.
/// Elle mesure:
/// - Temps de generation de preuve
/// - Temps de verification
/// - Consommation memory
/// - Scaling with the size of the circuit
/// 
/// # Returns
/// Une liste de all results de benchmarks
/// 
/// # Example
/// ```
/// use tsn::crypto::bench::run_full_benchmark_suite;
/// 
/// let results = run_full_benchmark_suite();
/// for result in results {
///     println!("{}: {:?}", result.name, result.avg_time);
/// }
/// ```
pub fn run_full_benchmark_suite() -> Vec<BenchmarkResult> {
    let mut all_results = Vec::new();
    
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║     TSN ZK CIRCUITS FULL BENCHMARK SUITE                       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();
    
    // Benchmarks Plonky2
    all_results.extend(run_plonky2_benchmarks());
    
    // Benchmarks memory
    all_results.extend(run_memory_benchmarks());
    
    // Comparaison
    let _ = run_comparison();
    
    println!();
    println!("Benchmark suite completed.");
    
    all_results
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_full_suite() {
        // Test que the suite completee runs without paniquer
        let results = run_full_benchmark_suite();
        assert!(!results.is_empty());
    }
}
