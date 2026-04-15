//! Pool de memory optimized for the validations cryptographiques
//!
//! Handles of buffers reusable for avoidr the allocations repeateds
//! in the hot paths de validation de signatures and preuves ZK.
//!
//! Based sur of techniques de memory pooling for reduce the pression
//! sur l'allocateur and improve the performances of validations crypto.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::fmt;

/// Size by default of buffers in the pool (32KB)
pub const DEFAULT_BUFFER_SIZE: usize = 32 * 1024;

/// Maximum number of buffers in the pool
pub const MAX_POOL_SIZE: usize = 128;

/// Duration de vie maximale d'un buffer in the pool (5 minutes)
pub const MAX_BUFFER_AGE: Duration = Duration::from_secs(300);

/// Buffer pooled with metadata de gestion
#[derive(Debug)]
pub struct PooledBuffer {
    data: Vec<u8>,
    created_at: Instant,
    last_used: Instant,
    usage_count: u64,
}

impl PooledBuffer {
    /// Creates a new buffer pooled
    fn new(size: usize) -> Self {
        let now = Instant::now();
        Self {
            data: vec![0u8; size],
            created_at: now,
            last_used: now,
            usage_count: 0,
        }
    }

    /// Returns a reference mutable aux data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.last_used = Instant::now();
        self.usage_count += 1;
        &mut self.data
    }

    /// Returns a reference aux data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns the size of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Checks if the buffer is vide
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Efface the contenu of the buffer (security)
    pub fn clear(&mut self) {
        // Effacement secure of data sensibles
        for byte in &mut self.data {
            *byte = 0;
        }
        self.last_used = Instant::now();
    }

    /// Checks if the buffer is trop ancien
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > MAX_BUFFER_AGE
    }

    /// Returns the statistics d'utilisation
    pub fn usage_stats(&self) -> (Duration, u64) {
        (self.created_at.elapsed(), self.usage_count)
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Effacement secure during the destruction
        self.clear();
    }
}

/// Pool de buffers for optimiser the allocations memory
pub struct MemoryPool {
    buffers: VecDeque<PooledBuffer>,
    buffer_size: usize,
    max_size: usize,
    stats: PoolStats,
}

#[derive(Debug, Default)]
struct PoolStats {
    total_allocations: u64,
    cache_hits: u64,
    cache_misses: u64,
    expired_buffers: u64,
}

impl MemoryPool {
    /// Creates a new pool de memory
    pub fn new(buffer_size: usize, max_size: usize) -> Self {
        Self {
            buffers: VecDeque::with_capacity(max_size),
            buffer_size,
            max_size,
            stats: PoolStats::default(),
        }
    }

    /// Gets a buffer from the pool or creates a new one
    pub fn get_buffer(&mut self) -> PooledBuffer {
        self.stats.total_allocations += 1;

        // Clean up the buffers expireds
        self.cleanup_expired();

        // Essaie de reuse a buffer existant
        if let Some(mut buffer) = self.buffers.pop_front() {
            buffer.clear(); // Security : efface les data previouss
            self.stats.cache_hits += 1;
            buffer
        } else {
            // Creates a nouveau buffer
            self.stats.cache_misses += 1;
            PooledBuffer::new(self.buffer_size)
        }
    }

    /// Returns a buffer at the pool
    pub fn return_buffer(&mut self, buffer: PooledBuffer) {
        if self.buffers.len() < self.max_size && !buffer.is_expired() {
            self.buffers.push_back(buffer);
        }
        // Otherwise the buffer will be destroyed automatically
    }

    /// Cleans up the buffers expireds
    fn cleanup_expired(&mut self) {
        let initial_len = self.buffers.len();
        self.buffers.retain(|buffer| !buffer.is_expired());
        let removed = initial_len - self.buffers.len();
        self.stats.expired_buffers += removed as u64;
    }

    /// Returns the statistics of the pool
    pub fn stats(&self) -> PoolStatsSummary {
        PoolStatsSummary {
            total_allocations: self.stats.total_allocations,
            cache_hits: self.stats.cache_hits,
            cache_misses: self.stats.cache_misses,
            expired_buffers: self.stats.expired_buffers,
            current_pool_size: self.buffers.len(),
            max_pool_size: self.max_size,
            buffer_size: self.buffer_size,
            hit_rate: if self.stats.total_allocations > 0 {
                (self.stats.cache_hits as f64 / self.stats.total_allocations as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    /// Vide completeely the pool
    pub fn clear(&mut self) {
        self.buffers.clear();
    }
}

/// Summary of statistics of the pool
#[derive(Debug, Clone)]
pub struct PoolStatsSummary {
    pub total_allocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub expired_buffers: u64,
    pub current_pool_size: usize,
    pub max_pool_size: usize,
    pub buffer_size: usize,
    pub hit_rate: f64,
}

impl fmt::Display for PoolStatsSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryPool Stats: {} allocs, {:.1}% hit rate, {}/{} buffers, {}KB each",
            self.total_allocations,
            self.hit_rate,
            self.current_pool_size,
            self.max_pool_size,
            self.buffer_size / 1024
        )
    }
}

/// Manager global de pools de memory thread-safe
pub struct MemoryPoolManager {
    signature_pool: Arc<Mutex<MemoryPool>>,
    proof_pool: Arc<Mutex<MemoryPool>>,
    hash_pool: Arc<Mutex<MemoryPool>>,
    stats: Arc<RwLock<GlobalStats>>,
}

#[derive(Debug, Default)]
struct GlobalStats {
    signature_validations: u64,
    proof_validations: u64,
    hash_operations: u64,
    total_memory_saved: u64, // Estimation en bytes
}

impl MemoryPoolManager {
    /// Creates a new manager of pools
    pub fn new() -> Self {
        Self {
            signature_pool: Arc::new(Mutex::new(MemoryPool::new(DEFAULT_BUFFER_SIZE, MAX_POOL_SIZE))),
            proof_pool: Arc::new(Mutex::new(MemoryPool::new(DEFAULT_BUFFER_SIZE * 4, MAX_POOL_SIZE / 2))),
            hash_pool: Arc::new(Mutex::new(MemoryPool::new(DEFAULT_BUFFER_SIZE / 4, MAX_POOL_SIZE * 2))),
            stats: Arc::new(RwLock::new(GlobalStats::default())),
        }
    }

    /// Gets a buffer for signature validation
    pub fn get_signature_buffer(&self) -> Result<PooledBuffer, String> {
        let mut pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
        let buffer = pool.get_buffer();
        
        if let Ok(mut stats) = self.stats.write() {
            stats.signature_validations += 1;
            stats.total_memory_saved += DEFAULT_BUFFER_SIZE as u64;
        }
        
        Ok(buffer)
    }

    /// Returns a buffer de signature at the pool
    pub fn return_signature_buffer(&self, buffer: PooledBuffer) -> Result<(), String> {
        let mut pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
        pool.return_buffer(buffer);
        Ok(())
    }

    /// Gets a buffer for ZK proof validation
    pub fn get_proof_buffer(&self) -> Result<PooledBuffer, String> {
        let mut pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
        let buffer = pool.get_buffer();
        
        if let Ok(mut stats) = self.stats.write() {
            stats.proof_validations += 1;
            stats.total_memory_saved += (DEFAULT_BUFFER_SIZE * 4) as u64;
        }
        
        Ok(buffer)
    }

    /// Returns a buffer de preuve at the pool
    pub fn return_proof_buffer(&self, buffer: PooledBuffer) -> Result<(), String> {
        let mut pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
        pool.return_buffer(buffer);
        Ok(())
    }

    /// Gets a buffer for hash operations
    pub fn get_hash_buffer(&self) -> Result<PooledBuffer, String> {
        let mut pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
        let buffer = pool.get_buffer();
        
        if let Ok(mut stats) = self.stats.write() {
            stats.hash_operations += 1;
            stats.total_memory_saved += (DEFAULT_BUFFER_SIZE / 4) as u64;
        }
        
        Ok(buffer)
    }

    /// Returns a buffer de hash at the pool
    pub fn return_hash_buffer(&self, buffer: PooledBuffer) -> Result<(), String> {
        let mut pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
        pool.return_buffer(buffer);
        Ok(())
    }

    /// Returns a summary of statistics globales
    pub fn summary(&self) -> Result<MemoryPoolSummary, String> {
        let sig_stats = {
            let pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.stats()
        };
        
        let proof_stats = {
            let pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.stats()
        };
        
        let hash_stats = {
            let pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.stats()
        };
        
        let global_stats = self.stats.read().map_err(|_| "Stats lock failed")?.clone();
        
        Ok(MemoryPoolSummary {
            signature_pool: sig_stats,
            proof_pool: proof_stats,
            hash_pool: hash_stats,
            total_operations: global_stats.signature_validations + global_stats.proof_validations + global_stats.hash_operations,
            estimated_memory_saved_mb: global_stats.total_memory_saved as f64 / (1024.0 * 1024.0),
        })
    }

    /// Cleans all pools
    pub fn cleanup(&self) -> Result<(), String> {
        {
            let mut pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.clear();
        }
        {
            let mut pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.clear();
        }
        {
            let mut pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.clear();
        }
        Ok(())
    }
}

impl Default for MemoryPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary complete of pools de memory
#[derive(Debug, Clone)]
pub struct MemoryPoolSummary {
    pub signature_pool: PoolStatsSummary,
    pub proof_pool: PoolStatsSummary,
    pub hash_pool: PoolStatsSummary,
    pub total_operations: u64,
    pub estimated_memory_saved_mb: f64,
}

impl fmt::Display for MemoryPoolSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Memory Pool Manager Summary ===")?;
        writeln!(f, "Signature Pool: {}", self.signature_pool)?;
        writeln!(f, "Proof Pool: {}", self.proof_pool)?;
        writeln!(f, "Hash Pool: {}", self.hash_pool)?;
        writeln!(f, "Total Operations: {}", self.total_operations)?;
        writeln!(f, "Estimated Memory Saved: {:.2} MB", self.estimated_memory_saved_mb)?;
        Ok(())
    }
}

// Global instance of the manager of pools
lazy_static::lazy_static! {
    static ref GLOBAL_POOL_MANAGER: MemoryPoolManager = MemoryPoolManager::new();
}

/// Access to the global pool manager instance
pub fn global_pool_manager() -> &'static MemoryPoolManager {
    &GLOBAL_POOL_MANAGER
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_pooled_buffer_basic() {
        let mut buffer = PooledBuffer::new(1024);
        assert_eq!(buffer.len(), 1024);
        assert!(!buffer.is_empty());
        
        let data = buffer.as_mut_slice();
        data[0] = 42;
        assert_eq!(buffer.as_slice()[0], 42);
        
        buffer.clear();
        assert_eq!(buffer.as_slice()[0], 0);
    }

    #[test]
    fn test_memory_pool_reuse() {
        let mut pool = MemoryPool::new(1024, 10);
        
        // Gets a buffer
        let buffer1 = pool.get_buffer();
        assert_eq!(buffer1.len(), 1024);
        
        // Le returns at the pool
        pool.return_buffer(buffer1);
        
        // Gets a nouveau buffer (should be reused)
        let buffer2 = pool.get_buffer();
        assert_eq!(buffer2.len(), 1024);
        
        let stats = pool.stats();
        assert_eq!(stats.total_allocations, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn test_pool_manager_thread_safety() {
        let manager = MemoryPoolManager::new();
        let manager_arc = Arc::new(manager);
        
        let mut handles = vec![];
        
        // Lance multiple threads that utilisent the pools
        for _ in 0..4 {
            let manager_clone = Arc::clone(&manager_arc);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    if let Ok(buffer) = manager_clone.get_signature_buffer() {
                        // Simulate a utilisation
                        thread::sleep(Duration::from_millis(1));
                        let _ = manager_clone.return_signature_buffer(buffer);
                    }
                }
            });
            handles.push(handle);
        }
        
        // Attend que all threads terminent
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify the statistics
        let summary = manager_arc.summary().unwrap();
        assert!(summary.total_operations > 0);
    }

    #[test]
    fn test_buffer_expiration() {
        let mut pool = MemoryPool::new(1024, 10);
        
        // Creates a buffer with a age artificiel
        let mut buffer = PooledBuffer::new(1024);
        buffer.created_at = Instant::now() - Duration::from_secs(400); // Plus ancien que MAX_BUFFER_AGE
        
        pool.return_buffer(buffer);
        
        // Force the cleanup
        pool.cleanup_expired();
        
        let stats = pool.stats();
        assert_eq!(stats.expired_buffers, 1);
        assert_eq!(stats.current_pool_size, 0);
    }
}