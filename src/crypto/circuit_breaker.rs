//! Circuit breaker for expensive cryptographic operations
//!
//! Protects against cryptographic DoS attacks by automatically limiting
//! intensive operations (ZK proof generation, signature verification,
//! Merkle tree construction).
//!
//! References:
//! - Martin Fowler, "CircuitBreaker" (2014)
//! - Release It! Design Patterns for Stability (Michael Nygard)
//! - OWASP Application Security Verification Standard v4.0

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Types of monitored cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoOperation {
    /// ZK Halo2 proof generation (very expensive)
    Halo2ProofGeneration,
    /// ZK Halo2 proof verification (expensive)
    Halo2ProofVerification,
    /// ML-DSA-65 signature (moderately expensive)
    MlDsaSignature,
    /// ML-DSA-65 signature verification (moderately expensive)
    MlDsaVerification,
    /// Merkle tree construction (expensive for large trees)
    MerkleTreeConstruction,
    /// Merkle path generation (moderately expensive)
    MerklePathGeneration,
    /// Poseidon2 hash (inexpensive but can be spammed)
    Poseidon2Hash,
}

impl CryptoOperation {
    /// Relative cost of the operation (1-10, 10 = very expensive)
    pub fn cost_weight(&self) -> u32 {
        match self {
            Self::Halo2ProofGeneration => 10,
            Self::Halo2ProofVerification => 6,
            Self::MlDsaSignature => 4,
            Self::MlDsaVerification => 3,
            Self::MerkleTreeConstruction => 5,
            Self::MerklePathGeneration => 2,
            Self::Poseidon2Hash => 1,
        }
    }

    /// Timeout maximum recommended for this operation
    pub fn max_timeout(&self) -> Duration {
        match self {
            Self::Halo2ProofGeneration => Duration::from_secs(30),
            Self::Halo2ProofVerification => Duration::from_secs(5),
            Self::MlDsaSignature => Duration::from_millis(500),
            Self::MlDsaVerification => Duration::from_millis(200),
            Self::MerkleTreeConstruction => Duration::from_secs(2),
            Self::MerklePathGeneration => Duration::from_millis(100),
            Self::Poseidon2Hash => Duration::from_millis(10),
        }
    }
}

/// State of the circuit breaker
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit closed - operations authorizeds
    Closed,
    /// Circuit ouvert - operations blockedes
    Open,
    /// Circuit semi-ouvert - test de retrieval
    HalfOpen,
}

/// Statistiques d'une operation cryptographique
#[derive(Debug, Clone)]
struct OperationStats {
    /// Total number of operations attempted
    total_attempts: u64,
    /// Number d'failures (timeout, erreur)
    failures: u64,
    /// Temps de response recents (sliding window)
    recent_times: VecDeque<Duration>,
    /// Last attempt
    last_attempt: Option<Instant>,
    /// Last success
    last_success: Option<Instant>,
}

impl Default for OperationStats {
    fn default() -> Self {
        Self {
            total_attempts: 0,
            failures: 0,
            recent_times: VecDeque::with_capacity(100),
            last_attempt: None,
            last_success: None,
        }
    }
}

impl OperationStats {
    /// Taux d'failure recent (sur the 100 lasts operations)
    fn failure_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.0;
        }
        
        let recent_count = self.recent_times.len() as u64;
        if recent_count == 0 {
            return 0.0;
        }
        
        // Approximation: on considers que the failures are distributed uniformly
        let recent_failures = (self.failures * recent_count) / self.total_attempts.max(1);
        recent_failures as f64 / recent_count as f64
    }

    /// Temps de response moyen recent
    fn avg_response_time(&self) -> Duration {
        if self.recent_times.is_empty() {
            // Retourner a temps conservateur instead of 0ms for avoidr the deadlocks
            return Duration::from_millis(100);
        }
        
        let total: Duration = self.recent_times.iter().sum();
        total / self.recent_times.len() as u32
    }

    /// Register a attempt d'operation
    fn record_attempt(&mut self, duration: Duration, success: bool) {
        self.total_attempts += 1;
        self.last_attempt = Some(Instant::now());
        
        if success {
            self.last_success = Some(Instant::now());
        } else {
            self.failures += 1;
        }
        
        // Sliding window of temps de response
        self.recent_times.push_back(duration);
        if self.recent_times.len() > 100 {
            self.recent_times.pop_front();
        }
    }
}

/// Configuration of the circuit breaker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Seuil de taux d'failure for open the circuit (0.0-1.0)
    pub failure_threshold: f64,
    /// Number minimum d'operations before d'evaluate the taux d'failure
    pub min_operations: u32,
    /// Duration d'ouverture of the circuit before test de retrieval
    pub recovery_timeout: Duration,
    /// Number d'operations de test in mode HalfOpen
    pub test_operations: u32,
    /// Limite de charge globale (operations/seconde)
    pub global_rate_limit: u32,
    /// Window de temps for the rate limiting
    pub rate_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 0.5, // 50% d'failures
            min_operations: 10,
            recovery_timeout: Duration::from_secs(60),
            test_operations: 5,
            global_rate_limit: 100, // 100 ops/sec max
            rate_window: Duration::from_secs(1),
        }
    }
}

/// Circuit breaker for operations cryptographiques
pub struct CryptoCircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// State global of the circuit
    state: Arc<RwLock<CircuitState>>,
    /// Statistiques par type d'operation
    stats: Arc<Mutex<std::collections::HashMap<CryptoOperation, OperationStats>>>,
    /// Timestamp de the last ouverture of the circuit
    last_opened: Arc<Mutex<Option<Instant>>>,
    /// Counter d'operations de test in mode HalfOpen
    test_count: Arc<Mutex<u32>>,
    /// Rate limiter global
    rate_limiter: Arc<Mutex<VecDeque<Instant>>>,
}

impl Default for CryptoCircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

impl CryptoCircuitBreaker {
    /// Create a nouveau circuit breaker with the configuration data
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            stats: Arc::new(Mutex::new(std::collections::HashMap::new())),
            last_opened: Arc::new(Mutex::new(None)),
            test_count: Arc::new(Mutex::new(0)),
            rate_limiter: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Verify if a operation is authorized
    pub async fn check_operation(&self, op: CryptoOperation) -> Result<OperationGuard<'_>, CircuitBreakerError> {
        // 1. Verify the rate limiting global
        self.check_rate_limit().await?;
        
        // 2. Verify circuit state
        let state = *self.state.read().unwrap();
        
        match state {
            CircuitState::Closed => {
                // Circuit closed - autoriser l'operation
                Ok(OperationGuard::new(self, op))
            }
            
            CircuitState::Open => {
                // Verify if on can passer in mode HalfOpen
                let last_opened = self.last_opened.lock().unwrap();
                if let Some(opened_time) = *last_opened {
                    if opened_time.elapsed() >= self.config.recovery_timeout {
                        drop(last_opened);
                        self.transition_to_half_open();
                        // Count this first operation as a test operation
                        *self.test_count.lock().unwrap() += 1;
                        return Ok(OperationGuard::new(self, op));
                    }
                }
                
                Err(CircuitBreakerError::CircuitOpen {
                    operation: op,
                    retry_after: self.config.recovery_timeout,
                })
            }
            
            CircuitState::HalfOpen => {
                // Mode test - autoriser a number limited d'operations
                let mut test_count = self.test_count.lock().unwrap();
                if *test_count < self.config.test_operations {
                    *test_count += 1;
                    Ok(OperationGuard::new(self, op))
                } else {
                    Err(CircuitBreakerError::CircuitOpen {
                        operation: op,
                        retry_after: Duration::from_secs(1),
                    })
                }
            }
        }
    }

    /// Check rate limiting global
    async fn check_rate_limit(&self) -> Result<(), CircuitBreakerError> {
        let mut limiter = self.rate_limiter.lock().unwrap();
        let now = Instant::now();
        
        // Clean up the entries anciennes
        while let Some(&front) = limiter.front() {
            if now.duration_since(front) > self.config.rate_window {
                limiter.pop_front();
            } else {
                break;
            }
        }
        
        // Verify the limite
        if limiter.len() >= self.config.global_rate_limit as usize {
            return Err(CircuitBreakerError::RateLimitExceeded {
                current_rate: limiter.len() as u32,
                limit: self.config.global_rate_limit,
            });
        }
        
        // Register this operation
        limiter.push_back(now);
        Ok(())
    }

    /// Transition vers l'state HalfOpen
    fn transition_to_half_open(&self) {
        *self.state.write().unwrap() = CircuitState::HalfOpen;
        *self.test_count.lock().unwrap() = 0;
        // Reset stats so HalfOpen test period starts fresh
        self.stats.lock().unwrap().clear();
    }

    /// Register the result d'une operation
    fn record_operation(&self, op: CryptoOperation, duration: Duration, success: bool) {
        let mut stats = self.stats.lock().unwrap();
        let op_stats = stats.entry(op).or_default();
        op_stats.record_attempt(duration, success);
        
        // Evaluate if the circuit must changer d'state
        self.evaluate_circuit_state(op, op_stats);
    }

    /// Evaluate if the circuit must changer d'state
    fn evaluate_circuit_state(&self, _op: CryptoOperation, stats: &OperationStats) {
        let current_state = *self.state.read().unwrap();
        
        match current_state {
            CircuitState::Closed => {
                // Verify if on must open the circuit
                if stats.total_attempts >= self.config.min_operations as u64 {
                    if stats.failure_rate() >= self.config.failure_threshold {
                        self.open_circuit();
                    }
                }
            }
            
            CircuitState::HalfOpen => {
                let test_count = *self.test_count.lock().unwrap();
                
                if test_count >= self.config.test_operations {
                    // Evaluate the results of the test
                    if stats.failure_rate() < self.config.failure_threshold {
                        // Retrieval successful - close the circuit
                        *self.state.write().unwrap() = CircuitState::Closed;
                    } else {
                        // Failure de retrieval - rouvrir the circuit
                        self.open_circuit();
                    }
                }
            }
            
            CircuitState::Open => {
                // Rien to faire - the circuit s'ouvrira automatically after timeout
            }
        }
    }

    /// Open the circuit
    fn open_circuit(&self) {
        *self.state.write().unwrap() = CircuitState::Open;
        *self.last_opened.lock().unwrap() = Some(Instant::now());
        *self.test_count.lock().unwrap() = 0;
    }

    /// Get l'state current of the circuit
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }

    /// Get the statistics d'une operation
    pub fn operation_stats(&self, op: CryptoOperation) -> Option<(f64, Duration, u64)> {
        let stats = self.stats.lock().unwrap();
        stats.get(&op).map(|s| (s.failure_rate(), s.avg_response_time(), s.total_attempts))
    }

    /// Reset the circuit breaker
    pub fn reset(&self) {
        *self.state.write().unwrap() = CircuitState::Closed;
        *self.last_opened.lock().unwrap() = None;
        *self.test_count.lock().unwrap() = 0;
        self.stats.lock().unwrap().clear();
        self.rate_limiter.lock().unwrap().clear();
    }
}

/// Guard for a operation cryptographique
/// Records automatically the result to the fin
pub struct OperationGuard<'a> {
    breaker: &'a CryptoCircuitBreaker,
    operation: CryptoOperation,
    start_time: Instant,
    reported: bool,
}

impl<'a> OperationGuard<'a> {
    fn new(breaker: &'a CryptoCircuitBreaker, operation: CryptoOperation) -> Self {
        Self {
            breaker,
            operation,
            reported: false,
            start_time: Instant::now(),
        }
    }

    /// Marquer l'operation like successful
    pub fn success(mut self) {
        self.reported = true;
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, true);
    }

    /// Marquer l'operation like failed
    pub fn failure(mut self) {
        self.reported = true;
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, false);
    }
}

impl<'a> Drop for OperationGuard<'a> {
    fn drop(&mut self) {
        if !self.reported {
            // By default, consider like a failure if pas explicitement marked
            let duration = self.start_time.elapsed();
            self.breaker.record_operation(self.operation, duration, false);
        }
    }
}

/// Errors of the circuit breaker
#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("Circuit ouvert pour l'operation {operation:?}, retry dans {retry_after:?}")]
    CircuitOpen {
        operation: CryptoOperation,
        retry_after: Duration,
    },
    
    #[error("Rate limit exceeded: {current_rate}/s > {limit}/s")]
    RateLimitExceeded {
        current_rate: u32,
        limit: u32,
    },
    
    #[error("Operation timeout after {timeout:?}")]
    OperationTimeout {
        timeout: Duration,
    },
}

// Global instance of the circuit breaker (singleton)
lazy_static::lazy_static! {
    static ref GLOBAL_CIRCUIT_BREAKER: CryptoCircuitBreaker = {
        CryptoCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 0.3, // 30% failures to open
            min_operations: 5,
            recovery_timeout: Duration::from_secs(30),
            test_operations: 3,
            global_rate_limit: 50, // 50 ops/sec max
            rate_window: Duration::from_secs(1),
        })
    };
}

/// Obtenir l'instance globale of the circuit breaker
pub fn global_circuit_breaker() -> &'static CryptoCircuitBreaker {
    &GLOBAL_CIRCUIT_BREAKER
}

/// Macro for protect a operation cryptographique
#[macro_export]
macro_rules! protected_crypto_op {
    ($op:expr, $code:block) => {{
        let guard = $crate::crypto::circuit_breaker::global_circuit_breaker()
            .check_operation($op)
            .await?;
        
        let result = $code;
        
        match &result {
            Ok(_) => guard.success(),
            Err(_) => guard.failure(),
        }
        
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker_basic() {
        let breaker = CryptoCircuitBreaker::default();
        
        // Circuit must be closed initially
        assert_eq!(breaker.state(), CircuitState::Closed);
        
        // Operation authorized
        let guard = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
        guard.success();
    }

    #[tokio::test]
    async fn test_circuit_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 0.5,
            min_operations: 3,
            ..Default::default()
        };
        let breaker = CryptoCircuitBreaker::new(config);

        // Simuler of failures — circuit may open before all 5 iterations
        for _ in 0..5 {
            match breaker.check_operation(CryptoOperation::Halo2ProofGeneration).await {
                Ok(guard) => guard.failure(),
                Err(_) => break, // Circuit already opened
            }
        }

        // Circuit must be ouvert
        assert_eq!(breaker.state(), CircuitState::Open);

        // Nouvelle operation must be rejectede
        let result = breaker.check_operation(CryptoOperation::Halo2ProofGeneration).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen { .. })));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = CircuitBreakerConfig {
            global_rate_limit: 2,
            rate_window: Duration::from_millis(100),
            ..Default::default()
        };
        let breaker = CryptoCircuitBreaker::new(config);
        
        // First operation OK
        let _guard1 = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
        
        // Second operation OK
        let _guard2 = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
        
        // Third operation must be rejectede
        let result = breaker.check_operation(CryptoOperation::Poseidon2Hash).await;
        assert!(matches!(result, Err(CircuitBreakerError::RateLimitExceeded { .. })));
        
        // Wait and retry
        sleep(Duration::from_millis(150)).await;
        let _guard3 = breaker.check_operation(CryptoOperation::Poseidon2Hash).await.unwrap();
    }

    #[tokio::test]
    async fn test_recovery_cycle() {
        let config = CircuitBreakerConfig {
            failure_threshold: 0.5,
            min_operations: 2,
            recovery_timeout: Duration::from_millis(50),
            test_operations: 2,
            ..Default::default()
        };
        let breaker = CryptoCircuitBreaker::new(config);

        // Provoquer l'ouverture of the circuit
        for _ in 0..3 {
            match breaker.check_operation(CryptoOperation::MlDsaSignature).await {
                Ok(guard) => guard.failure(),
                Err(_) => break,
            }
        }
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Wait the timeout de retrieval
        sleep(Duration::from_millis(60)).await;
        
        // First operation after timeout must passer in HalfOpen
        let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
        guard.success();
        
        // Second operation de test
        let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
        guard.success();
        
        // Circuit must be closed after success of tests
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}