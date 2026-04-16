use crate::core::{Block, Transaction};
use crate::crypto::signature::verify_transaction_signature;
use crate::crypto::proof::verify_transaction_proof;
use crate::network::api::ApiClient;
use anyhow::{Context, Result};
use serde_json;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Interactive transaction validator with step-by-step debugging
pub async fn validate_transaction_interactive(
    transaction_file: PathBuf,
    verbose: bool,
    skip_proofs: bool,
) -> Result<()> {
    println!("Loading transaction from {:?}", transaction_file);

    let transaction_data = std::fs::read_to_string(&transaction_file)
        .with_context(|| format!("Failed to read file {:?}", transaction_file))?;

    let transaction: Transaction = serde_json::from_str(&transaction_data)
        .with_context(|| "Failed to parse transaction JSON")?;

    println!("Transaction loaded: {}", transaction.hash());

    if verbose {
        println!("Transaction details:");
        println!("  - Hash: {}", transaction.hash());
        println!("  - Type: {:?}", transaction.transaction_type());
        println!("  - Timestamp: {}", transaction.timestamp());
        println!("  - Size: {} bytes", serde_json::to_vec(&transaction)?.len());
    }

    // Step 1: Structure validation
    println!("\nStep 1: Validating structure...");
    if let Err(e) = transaction.validate_structure() {
        println!("Structure error: {}", e);
        return Err(e);
    }
    println!("Structure valid");

    // Step 2: Signature validation
    println!("\nStep 2: Validating signature...");
    match verify_transaction_signature(&transaction) {
        Ok(true) => println!("Signature valid"),
        Ok(false) => {
            println!("Signature invalid");
            return Err(anyhow::anyhow!("Signature invalid"));
        }
        Err(e) => {
            println!("Error during signature verification: {}", e);
            return Err(e);
        }
    }

    // Step 3: ZK proof validation (optional)
    if !skip_proofs {
        println!("\nStep 3: Validating ZK proofs...");
        match verify_transaction_proof(&transaction) {
            Ok(true) => println!("ZK proofs valid"),
            Ok(false) => {
                println!("ZK proofs invalid");
                return Err(anyhow::anyhow!("ZK proofs invalid"));
            }
            Err(e) => {
                println!("Error during proof verification: {}", e);
                return Err(e);
            }
        }
    } else {
        println!("\nStep 3: ZK proof validation skipped");
    }

    println!("\nTransaction valid!");
    Ok(())
}

/// Interactive block validator with step-by-step debugging
pub async fn validate_block_interactive(
    block_file: PathBuf,
    verbose: bool,
    skip_proofs: bool,
) -> Result<()> {
    println!("Loading block from {:?}", block_file);

    let block_data = std::fs::read_to_string(&block_file)
        .with_context(|| format!("Failed to read file {:?}", block_file))?;

    let block: Block = serde_json::from_str(&block_data)
        .with_context(|| "Failed to parse block JSON")?;

    println!("Block loaded: {}", block.hash());

    if verbose {
        println!("Block details:");
        println!("  - Hash: {}", block.hash());
        println!("  - Height: {}", block.height());
        println!("  - Parent: {}", block.parent_hash());
        println!("  - Timestamp: {}", block.timestamp());
        println!("  - Transactions: {}", block.transactions().len());
        println!("  - Size: {} bytes", serde_json::to_vec(&block)?.len());
    }

    // Step 1: Block structure validation
    println!("\nStep 1: Validating block structure...");
    if let Err(e) = block.validate_structure() {
        println!("Structure error: {}", e);
        return Err(e);
    }
    println!("Block structure valid");

    // Step 2: Proof-of-work validation
    println!("\nStep 2: Validating proof-of-work...");
    if let Err(e) = block.validate_pow() {
        println!("Proof-of-work invalid: {}", e);
        return Err(e);
    }
    println!("Proof-of-work valid");

    // Step 3: Transaction validation
    println!("\nStep 3: Validating transactions ({})...", block.transactions().len());
    for (i, tx) in block.transactions().iter().enumerate() {
        if verbose {
            println!("  Validating transaction {}/{}: {}", i + 1, block.transactions().len(), tx.hash());
        }

        // Signature validation
        match verify_transaction_signature(tx) {
            Ok(true) => {
                if verbose { println!("    Signature valid"); }
            }
            Ok(false) => {
                println!("    Signature invalid for tx {}", tx.hash());
                return Err(anyhow::anyhow!("Transaction {} has invalid signature", tx.hash()));
            }
            Err(e) => {
                println!("    Signature error for tx {}: {}", tx.hash(), e);
                return Err(e);
            }
        }

        // ZK proof validation (optional)
        if !skip_proofs {
            match verify_transaction_proof(tx) {
                Ok(true) => {
                    if verbose { println!("    ZK proofs valid"); }
                }
                Ok(false) => {
                    println!("    ZK proofs invalid for tx {}", tx.hash());
                    return Err(anyhow::anyhow!("Transaction {} has invalid ZK proofs", tx.hash()));
                }
                Err(e) => {
                    println!("    ZK proof error for tx {}: {}", tx.hash(), e);
                    return Err(e);
                }
            }
        }
    }
    println!("All transactions valid");

    println!("\nBlock valid!");
    Ok(())
}

/// Trace transaction execution on the network
pub async fn trace_transaction_execution(
    tx_hash: String,
    node_url: String,
    show_state: bool,
) -> Result<()> {
    println!("Tracing transaction {} on {}", tx_hash, node_url);

    let client = ApiClient::new(&node_url)?;

    // Retrieve transaction details
    println!("\nRetrieving transaction details...");
    let tx_details = client.get_transaction(&tx_hash).await
        .with_context(|| format!("Failed to retrieve transaction {}", tx_hash))?;

    println!("Transaction found in block {}", tx_details.block_hash);
    println!("Details:");
    println!("  - Status: {:?}", tx_details.status);
    println!("  - Block: {} (height {})", tx_details.block_hash, tx_details.block_height);
    println!("  - Index in block: {}", tx_details.transaction_index);
    println!("  - Gas used: {}", tx_details.gas_used);
    println!("  - Fee: {} TSN", tx_details.fee);

    if show_state {
        println!("\nState changes:");
        for change in &tx_details.state_changes {
            println!("  - {}: {} -> {}", change.account, change.before, change.after);
        }
    }

    // Trace network propagation
    println!("\nTracing network propagation...");
    let propagation_info = client.get_transaction_propagation(&tx_hash).await
        .with_context(|| "Failed to retrieve propagation info")?;

    println!("Propagation statistics:");
    println!("  - First seen: {}", propagation_info.first_seen);
    println!("  - Confirmed: {}", propagation_info.confirmed_at);
    println!("  - Propagation delay: {}ms", propagation_info.propagation_delay_ms);
    println!("  - Nodes that saw tx: {}", propagation_info.nodes_seen);

    Ok(())
}

/// Performance profiler for different operations
pub async fn profile_operation(
    operation: String,
    duration: u64,
    output_file: PathBuf,
) -> Result<()> {
    println!("Profiling operation '{}' for {}s", operation, duration);

    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration);

    let mut samples = Vec::new();
    let mut sample_count = 0;

    while Instant::now() < end_time {
        let sample_start = Instant::now();

        // Execute the operation by type
        let result = match operation.as_str() {
            "mining" => profile_mining_operation().await,
            "validation" => profile_validation_operation().await,
            "sync" => profile_sync_operation().await,
            _ => {
                return Err(anyhow::anyhow!("Operation '{}' not supported", operation));
            }
        };

        let sample_duration = sample_start.elapsed();
        sample_count += 1;

        let sample = ProfileSample {
            timestamp: sample_start,
            duration_ms: sample_duration.as_millis() as u64,
            operation: operation.clone(),
            success: result.is_ok(),
            error: result.err().map(|e| e.to_string()),
        };

        samples.push(sample);

        if sample_count % 10 == 0 {
            println!("{} samples collected...", sample_count);
        }

        // Wait before next sample
        sleep(Duration::from_millis(100)).await;
    }

    // Calculate statistics
    let total_samples = samples.len();
    let successful_samples = samples.iter().filter(|s| s.success).count();
    let avg_duration = samples.iter().map(|s| s.duration_ms).sum::<u64>() / total_samples as u64;
    let min_duration = samples.iter().map(|s| s.duration_ms).min().unwrap_or(0);
    let max_duration = samples.iter().map(|s| s.duration_ms).max().unwrap_or(0);

    println!("\nProfiling results:");
    println!("  - Total samples: {}", total_samples);
    println!("  - Successful samples: {} ({:.1}%)", successful_samples,
             (successful_samples as f64 / total_samples as f64) * 100.0);
    println!("  - Average duration: {}ms", avg_duration);
    println!("  - Min/max duration: {}ms / {}ms", min_duration, max_duration);

    // Save data
    let profile_data = ProfileData {
        operation,
        duration_seconds: duration,
        total_samples,
        successful_samples,
        avg_duration_ms: avg_duration,
        min_duration_ms: min_duration,
        max_duration_ms: max_duration,
        samples,
    };

    let json_data = serde_json::to_string_pretty(&profile_data)?;
    std::fs::write(&output_file, json_data)
        .with_context(|| format!("Failed to write file {:?}", output_file))?;

    println!("Profile data saved to {:?}", output_file);

    Ok(())
}

/// Memory usage analyzer
pub async fn analyze_memory_usage(
    node_url: String,
    interval: u64,
    duration: u64,
) -> Result<()> {
    println!("Analyzing memory on {} (sampling: {}s, duration: {}s)",
             node_url, interval, duration);

    let client = ApiClient::new(&node_url)?;
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration);

    let mut samples = Vec::new();

    while Instant::now() < end_time {
        let sample_start = Instant::now();

        // Retrieve memory stats from node
        match client.get_memory_stats().await {
            Ok(stats) => {
                samples.push(MemorySample {
                    timestamp: sample_start,
                    heap_used_mb: stats.heap_used / 1024 / 1024,
                    heap_total_mb: stats.heap_total / 1024 / 1024,
                    rss_mb: stats.rss / 1024 / 1024,
                    mempool_size: stats.mempool_transactions,
                    blockchain_size_mb: stats.blockchain_size / 1024 / 1024,
                });

                println!("Heap: {}MB / {}MB, RSS: {}MB, Mempool: {} tx",
                         stats.heap_used / 1024 / 1024,
                         stats.heap_total / 1024 / 1024,
                         stats.rss / 1024 / 1024,
                         stats.mempool_transactions);
            }
            Err(e) => {
                println!("Warning: failed to retrieve stats: {}", e);
            }
        }

        sleep(Duration::from_secs(interval)).await;
    }

    // Analyze trends
    if !samples.is_empty() {
        let avg_heap = samples.iter().map(|s| s.heap_used_mb).sum::<u64>() / samples.len() as u64;
        let max_heap = samples.iter().map(|s| s.heap_used_mb).max().unwrap_or(0);
        let avg_rss = samples.iter().map(|s| s.rss_mb).sum::<u64>() / samples.len() as u64;
        let max_rss = samples.iter().map(|s| s.rss_mb).max().unwrap_or(0);

        println!("\nMemory analysis:");
        println!("  - Avg/max heap: {}MB / {}MB", avg_heap, max_heap);
        println!("  - Avg/max RSS: {}MB / {}MB", avg_rss, max_rss);

        // Detect potential leaks
        if samples.len() >= 10 {
            let first_half_avg = samples[..samples.len()/2].iter()
                .map(|s| s.heap_used_mb).sum::<u64>() / (samples.len()/2) as u64;
            let second_half_avg = samples[samples.len()/2..].iter()
                .map(|s| s.heap_used_mb).sum::<u64>() / (samples.len()/2) as u64;

            if second_half_avg > first_half_avg * 110 / 100 {
                println!("Warning: potential memory leak detected (+{}MB)",
                         second_half_avg - first_half_avg);
            }
        }
    }

    Ok(())
}

// Helper functions for profiling
async fn profile_mining_operation() -> Result<()> {
    // Simulate mining operation
    sleep(Duration::from_millis(50)).await;
    Ok(())
}

async fn profile_validation_operation() -> Result<()> {
    // Simulate transaction validation
    sleep(Duration::from_millis(10)).await;
    Ok(())
}

async fn profile_sync_operation() -> Result<()> {
    // Simulate synchronization
    sleep(Duration::from_millis(100)).await;
    Ok(())
}

// Data structures for profiling
#[derive(serde::Serialize, serde::Deserialize)]
struct ProfileSample {
    timestamp: Instant,
    duration_ms: u64,
    operation: String,
    success: bool,
    error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProfileData {
    operation: String,
    duration_seconds: u64,
    total_samples: usize,
    successful_samples: usize,
    avg_duration_ms: u64,
    min_duration_ms: u64,
    max_duration_ms: u64,
    samples: Vec<ProfileSample>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MemorySample {
    timestamp: Instant,
    heap_used_mb: u64,
    heap_total_mb: u64,
    rss_mb: u64,
    mempool_size: usize,
    blockchain_size_mb: u64,
}
