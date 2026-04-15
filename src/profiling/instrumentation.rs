//! Instrumentation des operations critiques pour profiling
//!
//! Ce module fournit des wrappers pratiques pour profiler :
//! - Operations cryptographiques (sign, verify, hash)
//! - Operations base of data (read, write, scan)
//! - Serialization/deserialization

use super::metrics::{CRYPTO_METRICS, DB_METRICS, SERDE_METRICS};
use super::{OperationCategory, OperationTimer};
use std::time::Instant;

// ============================================================================
// Operations Cryptographiques
// ============================================================================

/// Profile une operation de signature ML-DSA-65
/// 
/// # Exemple
/// ```rust,ignore
/// let signature = profile_crypto_sign("transaction", || {
///     sign_transaction(&tx, keypair)
/// });
/// ```
pub fn profile_crypto_sign<T, F>(context: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("sign", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "sign",
        context = %context,
        duration_ms = %duration.as_millis(),
        "Signature crypto profiled"
    );
    
    result
}

/// Profile une operation de verification de signature
pub fn profile_crypto_verify<T, F>(context: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("verify", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "verify",
        context = %context,
        duration_ms = %duration.as_millis(),
        "Verification crypto profiled"
    );
    
    result
}

/// Profile une operation de verification batch
pub fn profile_crypto_batch_verify<T, F>(batch_size: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("batch_verify", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "batch_verify",
        batch_size = %batch_size,
        duration_ms = %duration.as_millis(),
        "Verification batch profiled"
    );
    
    result
}

/// Profile une operation de hachage
pub fn profile_crypto_hash<T, F>(algorithm: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("hash", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "hash",
        algorithm = %algorithm,
        duration_ms = %duration.as_millis(),
        "Hachage profiled"
    );
    
    result
}

/// Profile une operation de generation de preuve ZK
pub fn profile_zk_proof_generate<T, F>(proof_type: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("zk_proof_generate", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::debug!(
        operation = "zk_proof_generate",
        proof_type = %proof_type,
        duration_ms = %duration.as_millis(),
        "Generation de preuve ZK profiled"
    );
    
    result
}

/// Profile une operation de verification de preuve ZK
pub fn profile_zk_proof_verify<T, F>(proof_type: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("zk_proof_verify", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::debug!(
        operation = "zk_proof_verify",
        proof_type = %proof_type,
        duration_ms = %duration.as_millis(),
        "Verification de preuve ZK profiled"
    );
    
    result
}

/// Wrapper generic pour les operations crypto
pub fn profile_crypto_op<T, F>(operation: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(operation, OperationCategory::Crypto);
    f()
}

// ============================================================================
// Operations Base de Data
// ============================================================================

/// Profile une operation de lecture DB
pub fn profile_db_read<T, F>(table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    DB_METRICS.record_operation("read", table, duration.as_secs_f64());
    
    tracing::trace!(
        operation = "db_read",
        table = %table,
        duration_ms = %duration.as_millis(),
        "Lecture DB profiled"
    );
    
    result
}

/// Profile une operation d'writing DB
pub fn profile_db_write<T, F>(table: &str, data_size: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    DB_METRICS.record_operation_with_size("write", table, duration.as_secs_f64(), data_size);
    
    tracing::trace!(
        operation = "db_write",
        table = %table,
        data_size = %data_size,
        duration_ms = %duration.as_millis(),
        "Writing DB profiled"
    );
    
    result
}

/// Profile une operation de scan DB (iteration)
pub fn profile_db_scan<T, F>(table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("scan", OperationCategory::Database);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "db_scan",
        table = %table,
        duration_ms = %duration.as_millis(),
        "Scan DB profiled"
    );
    
    result
}

/// Profile une operation de deletion DB
pub fn profile_db_delete<T, F>(table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("delete", OperationCategory::Database);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "db_delete",
        table = %table,
        duration_ms = %duration.as_millis(),
        "Deletion DB profiled"
    );
    
    result
}

/// Profile une operation batch DB
pub fn profile_db_batch_write<T, F>(table: &str, item_count: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("batch_write", OperationCategory::Database);
    let result = f();
    let duration = timer.stop();
    
    tracing::debug!(
        operation = "db_batch_write",
        table = %table,
        item_count = %item_count,
        duration_ms = %duration.as_millis(),
        "Writing batch DB profiled"
    );
    
    result
}

/// Wrapper generic pour les operations DB
pub fn profile_db_op<T, F>(operation: &str, table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(operation, OperationCategory::Database);
    f()
}

// ============================================================================
// Operations de Serialization
// ============================================================================

/// Profile une operation de serialization
pub fn profile_serde_serialize<T, F>(type_name: &str, f: F) -> (T, usize)
where
    F: FnOnce() -> (T, usize),
{
    let start = Instant::now();
    let (result, bytes) = f();
    let duration = start.elapsed();
    
    SERDE_METRICS.record_operation("serialize", type_name, duration.as_secs_f64(), bytes);
    
    tracing::trace!(
        operation = "serialize",
        type_name = %type_name,
        bytes = %bytes,
        duration_ms = %duration.as_millis(),
        "Serialization profiled"
    );
    
    (result, bytes)
}

/// Profile une operation de deserialization
pub fn profile_serde_deserialize<T, F>(type_name: &str, data_size: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    SERDE_METRICS.record_operation("deserialize", type_name, duration.as_secs_f64(), data_size);
    
    tracing::trace!(
        operation = "deserialize",
        type_name = %type_name,
        data_size = %data_size,
        duration_ms = %duration.as_millis(),
        "Deserialization profiled"
    );
    
    result
}

/// Wrapper generic pour les operations de serialization
pub fn profile_serde_op<T, F>(operation: &str, type_name: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(operation, OperationCategory::Serialization);
    f()
}

// ============================================================================
// Versions Async
// ============================================================================

/// Profile une operation crypto async
pub async fn profile_crypto_op_async<T, F>(operation: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(operation, OperationCategory::Crypto);
    let result = f.await;
    timer.stop();
    result
}

/// Profile une operation DB async
pub async fn profile_db_op_async<T, F>(operation: &str, table: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(operation, OperationCategory::Database);
    let result = f.await;
    timer.stop();
    result
}

/// Profile une operation de serialization async
pub async fn profile_serde_op_async<T, F>(operation: &str, type_name: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(operation, OperationCategory::Serialization);
    let result = f.await;
    timer.stop();
    result
}

// ============================================================================
// Fonctions utilitaires pour les types specific TSN
// ============================================================================

/// Profile la serialization d'un bloc
pub fn profile_block_serialize<F>(f: F) -> Vec<u8>
where
    F: FnOnce() -> Vec<u8>,
{
    let (result, bytes) = profile_serde_serialize("ShieldedBlock", || {
        let data = f();
        let len = data.len();
        (data, len)
    });
    result
}

/// Profile la deserialization d'un bloc
pub fn profile_block_deserialize<T, F>(data: &[u8], f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_serde_deserialize("ShieldedBlock", data.len(), f)
}

/// Profile la serialization d'une transaction
pub fn profile_tx_serialize<F>(f: F) -> Vec<u8>
where
    F: FnOnce() -> Vec<u8>,
{
    let (result, _) = profile_serde_serialize("ShieldedTransaction", || {
        let data = f();
        let len = data.len();
        (data, len)
    });
    result
}

/// Profile la deserialization d'une transaction
pub fn profile_tx_deserialize<T, F>(data: &[u8], f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_serde_deserialize("ShieldedTransaction", data.len(), f)
}

/// Profile la verification d'une transaction completee
pub fn profile_tx_verify<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_crypto_verify("transaction", f)
}

/// Profile la verification d'un spend proof
pub fn profile_spend_proof_verify<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_zk_proof_verify("spend", f)
}

/// Profile la verification d'un output proof
pub fn profile_output_proof_verify<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_zk_proof_verify("output", f)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_profile_crypto_op() {
        let result = profile_crypto_op("test", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            42
        });
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_profile_db_op() {
        let result = profile_db_op("read", "blocks", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            "data"
        });
        assert_eq!(result, "data");
    }
    
    #[test]
    fn test_profile_serde_op() {
        let result = profile_serde_op("serialize", "Block", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            vec![1u8, 2, 3]
        });
        assert_eq!(result, vec![1, 2, 3]);
    }
}