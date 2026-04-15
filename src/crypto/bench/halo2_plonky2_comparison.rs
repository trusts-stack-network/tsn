//! Benchmark comparatif Halo2 vs Plonky2 for TSN
//! 
//! This module provides a comparison completee entre:
//! - Legacy: Groth16/Arkworks (BN254, non post-quantique)
//! - Current: Plonky2 STARKs (FRI-based, post-quantique)
//! 
//! Contexte de security:
//! - TSN utilise Plonky2 like system de preuve ZK principal
//! - Plonky2 offre a security post-quantique via FRI (Fast Reed-Solomon IOP)
//! - Les preuves are transparentes (no trusted setup)
//! 
//! References:
//! - Plonky2: https://github.com/mir-protocol/plonky2
//! - FRI: Ben-Sasson and al., "Fast Reed-Solomon Interactive Oracle Proofs"
//! - STARKs: Ben-Sasson and al., "Scalable, transparent, and post-quantum secure..."

use crate::crypto::bench::halo2_commitment_bench::{
    BenchmarkResult, BenchmarkRunner, run_all_benchmarks
};

/// Structure de comparaison entre systems de preuve
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub system_a: String,
    pub system_b: String,
    pub metric: String,
    pub ratio: f64, // system_a_time / system_b_time
    pub winner: String,
}

impl ComparisonResult {
    pub fn new(system_a: &str, system_b: &str, metric: &str, time_a: Duration, time_b: Duration) -> Self {
        let ratio = time_a.as_secs_f64() / time_b.as_secs_f64();
        let winner = if ratio < 1.0 {
            system_a.to_string()
        } else {
            system_b.to_string()
        };
        
        Self {
            system_a: system_a.to_string(),
            system_b: system_b.to_string(),
            metric: metric.to_string(),
            ratio,
            winner,
        }
    }
    
    pub fn print(&self) {
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│ COMPARISON: {} vs {}", self.system_a, self.system_b);
        println!("│ Metric: {}", self.metric);
        println!("│ Ratio: {:.2}x ({} est {:.2}x plus rapide)", 
            self.ratio, 
            self.winner,
            if self.ratio < 1.0 { 1.0 / self.ratio } else { self.ratio }
        );
        println!("│ Winner: {}", self.winner);
        println!("└─────────────────────────────────────────────────────────────┘");
    }
}

use std::time::Duration;

/// Executes the comparison completee
pub fn run_comparison() -> Vec<ComparisonResult> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║     TSN ZK SYSTEMS COMPARISON: Plonky2 vs Legacy                ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();
    
    // Executes all benchmarks
    let results = run_all_benchmarks();
    
    // Analyse the results
    let mut comparisons = Vec::new();
    
    // Trouve the results Plonky2
    let plonky2_gen = results.iter().find(|r| r.name.contains("Plonky2") && r.name.contains("generation"));
    let plonky2_ver = results.iter().find(|r| r.name.contains("Plonky2") && r.name.contains("verification"));
    
    // Affiche the rapport
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                    ANALYSIS SUMMARY                             ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    
    if let Some(gen) = plonky2_gen {
        println!("Plonky2 Generation: {:?}", gen.avg_time);
    }
    if let Some(ver) = plonky2_ver {
        println!("Plonky2 Verification: {:?}", ver.avg_time);
    }
    
    println!("\nNote: Halo2 n'est pas inclus car la crate n'est pas dans les dependencies.");
    println!("      Utilisez 'cargo add halo2_proofs pasta_curves ff rand_core criterion'");
    println!("      pour ajouter le support Halo2.");
    
    comparisons
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_comparison_result() {
        let comp = ComparisonResult::new(
            "SystemA",
            "SystemB",
            "generation",
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        
        assert!((comp.ratio - 0.5).abs() < 0.01);
        assert_eq!(comp.winner, "SystemA");
    }
    
    #[test]
    fn test_run_comparison() {
        // Ce test verifies que the comparison runs without paniquer
        let _results = run_comparison();
    }
}
