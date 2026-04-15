//! Circuit breaker pour operations cryptographiques couteuses
//!
//! Protege contre les attaques DoS cryptographiques en limitant automatiquement
//! les operations intensives (generation de preuves ZK, verification de signatures,
//! construction d'arbres de Merkle).
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

/// Types d'operations cryptographiques surveillees
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoOperation {
    /// Generation de preuve ZK Halo2 (very couteuse)
    Halo2ProofGeneration,
    /// Verification de preuve ZK Halo2 (couteuse)
    Halo2ProofVerification,
    /// Signature ML-DSA-65 (moderement couteuse)
    MlDsaSignature,
    /// Verification signature ML-DSA-65 (moderement couteuse)
    MlDsaVerification,
    /// Construction arbre de Merkle (couteuse pour gros arbres)
    MerkleTreeConstruction,
    /// Generation de path Merkle (moderement couteuse)
    MerklePathGeneration,
    /// Hash Poseidon2 (peu couteuse mais peut be spammee)
    Poseidon2Hash,
}

impl CryptoOperation {
    /// Cout relatif de l'operation (1-10, 10 = very couteux)
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

    /// Timeout maximum recommande pour cette operation
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

/// State du circuit breaker
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit ferme - operations autorisees
    Closed,
    /// Circuit ouvert - operations bloquees
    Open,
    /// Circuit semi-ouvert - test de recuperation
    HalfOpen,
}

/// Statistiques d'une operation cryptographique
#[derive(Debug, Clone)]
struct OperationStats {
    /// Nombre total d'operations tentees
    total_attempts: u64,
    /// Nombre d'echecs (timeout, error)
    failures: u64,
    /// Temps de response recents (sliding window)
    recent_times: VecDeque<Duration>,
    /// Derniere tentative
    last_attempt: Option<Instant>,
    /// Derniere reussite
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
    /// Taux d'echec recent (sur les 100 dernieres operations)
    fn failure_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.0;
        }
        
        let recent_count = self.recent_times.len() as u64;
        if recent_count == 0 {
            return 0.0;
        }
        
        // Approximation: on considere que les echecs sont distribues uniformement
        let recent_failures = (self.failures * recent_count) / self.total_attempts.max(1);
        recent_failures as f64 / recent_count as f64
    }

    /// Temps de response moyen recent
    fn avg_response_time(&self) -> Duration {
        if self.recent_times.is_empty() {
            // Retourner un temps conservateur au lieu de 0ms pour avoid les deadlocks
            return Duration::from_millis(100);
        }
        
        let total: Duration = self.recent_times.iter().sum();
        total / self.recent_times.len() as u32
    }

    /// Enregistrer une tentative d'operation
    fn record_attempt(&mut self, duration: Duration, success: bool) {
        self.total_attempts += 1;
        self.last_attempt = Some(Instant::now());
        
        if success {
            self.last_success = Some(Instant::now());
        } else {
            self.failures += 1;
        }
        
        // Sliding window des temps de response
        self.recent_times.push_back(duration);
        if self.recent_times.len() > 100 {
            self.recent_times.pop_front();
        }
    }
}

/// Configuration du circuit breaker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Seuil de taux d'echec pour ouvrir le circuit (0.0-1.0)
    pub failure_threshold: f64,
    /// Nombre minimum d'operations avant d'evaluer le taux d'echec
    pub min_operations: u32,
    /// Duration d'ouverture du circuit avant test de recuperation
    pub recovery_timeout: Duration,
    /// Nombre d'operations de test en mode HalfOpen
    pub test_operations: u32,
    /// Limite de charge globale (operations/seconde)
    pub global_rate_limit: u32,
    /// Fenbe de temps pour le rate limiting
    pub rate_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 0.5, // 50% d'echecs
            min_operations: 10,
            recovery_timeout: Duration::from_secs(60),
            test_operations: 5,
            global_rate_limit: 100, // 100 ops/sec max
            rate_window: Duration::from_secs(1),
        }
    }
}

/// Circuit breaker pour operations cryptographiques
pub struct CryptoCircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// State global du circuit
    state: Arc<RwLock<CircuitState>>,
    /// Statistiques par type d'operation
    stats: Arc<Mutex<std::collections::HashMap<CryptoOperation, OperationStats>>>,
    /// Timestamp de la derniere ouverture du circuit
    last_opened: Arc<Mutex<Option<Instant>>>,
    /// Compteur d'operations de test en mode HalfOpen
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
    /// Create a nouveau circuit breaker avec la configuration donnee
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

    /// Check if une operation est autorisee
    pub async fn check_operation(&self, op: CryptoOperation) -> Result<OperationGuard<'_>, CircuitBreakerError> {
        // 1. Check the rate limiting global
        self.check_rate_limit().await?;
        
        // 2. Check the state du circuit
        let state = *self.state.read().unwrap();
        
        match state {
            CircuitState::Closed => {
                // Circuit ferme - autoriser l'operation
                Ok(OperationGuard::new(self, op))
            }
            
            CircuitState::Open => {
                // Check if on peut passer en mode HalfOpen
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
                // Mode test - autoriser un nombre limite d'operations
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

    /// Check the rate limiting global
    async fn check_rate_limit(&self) -> Result<(), CircuitBreakerError> {
        let mut limiter = self.rate_limiter.lock().unwrap();
        let now = Instant::now();
        
        // Nettoyer les entrees oldnes
        while let Some(&front) = limiter.front() {
            if now.duration_since(front) > self.config.rate_window {
                limiter.pop_front();
            } else {
                break;
            }
        }
        
        // Check the limite
        if limiter.len() >= self.config.global_rate_limit as usize {
            return Err(CircuitBreakerError::RateLimitExceeded {
                current_rate: limiter.len() as u32,
                limit: self.config.global_rate_limit,
            });
        }
        
        // Enregistrer cette operation
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

    /// Enregistrer le result d'une operation
    fn record_operation(&self, op: CryptoOperation, duration: Duration, success: bool) {
        let mut stats = self.stats.lock().unwrap();
        let op_stats = stats.entry(op).or_default();
        op_stats.record_attempt(duration, success);
        
        // Evaluate si le circuit doit changer d'state
        self.evaluate_circuit_state(op, op_stats);
    }

    /// Evaluate si le circuit doit changer d'state
    fn evaluate_circuit_state(&self, _op: CryptoOperation, stats: &OperationStats) {
        let current_state = *self.state.read().unwrap();
        
        match current_state {
            CircuitState::Closed => {
                // Check if on doit ouvrir le circuit
                if stats.total_attempts >= self.config.min_operations as u64 {
                    if stats.failure_rate() >= self.config.failure_threshold {
                        self.open_circuit();
                    }
                }
            }
            
            CircuitState::HalfOpen => {
                let test_count = *self.test_count.lock().unwrap();
                
                if test_count >= self.config.test_operations {
                    // Evaluate les results du test
                    if stats.failure_rate() < self.config.failure_threshold {
                        // Recuperation reussie - fermer le circuit
                        *self.state.write().unwrap() = CircuitState::Closed;
                    } else {
                        // Failure de recuperation - rouvrir le circuit
                        self.open_circuit();
                    }
                }
            }
            
            CircuitState::Open => {
                // Rien a faire - le circuit s'ouvrira automatiquement after timeout
            }
        }
    }

    /// Open the circuit
    fn open_circuit(&self) {
        *self.state.write().unwrap() = CircuitState::Open;
        *self.last_opened.lock().unwrap() = Some(Instant::now());
        *self.test_count.lock().unwrap() = 0;
    }

    /// Obtenir l'state current du circuit
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }

    /// Obtenir les statistiques d'une operation
    pub fn operation_stats(&self, op: CryptoOperation) -> Option<(f64, Duration, u64)> {
        let stats = self.stats.lock().unwrap();
        stats.get(&op).map(|s| (s.failure_rate(), s.avg_response_time(), s.total_attempts))
    }

    /// Reinitialiser le circuit breaker
    pub fn reset(&self) {
        *self.state.write().unwrap() = CircuitState::Closed;
        *self.last_opened.lock().unwrap() = None;
        *self.test_count.lock().unwrap() = 0;
        self.stats.lock().unwrap().clear();
        self.rate_limiter.lock().unwrap().clear();
    }
}

/// Guard pour une operation cryptographique
/// Enregistre automatiquement le result a la fin
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

    /// Marquer l'operation comme reussie
    pub fn success(mut self) {
        self.reported = true;
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, true);
    }

    /// Marquer l'operation comme echouee
    pub fn failure(mut self) {
        self.reported = true;
        let duration = self.start_time.elapsed();
        self.breaker.record_operation(self.operation, duration, false);
    }
}

impl<'a> Drop for OperationGuard<'a> {
    fn drop(&mut self) {
        if !self.reported {
            // Par defaut, considerer comme un echec si pas explicitement marque
            let duration = self.start_time.elapsed();
            self.breaker.record_operation(self.operation, duration, false);
        }
    }
}

/// Erreurs du circuit breaker
#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("Circuit ouvert pour l'operation {operation:?}, reessayer dans {retry_after:?}")]
    CircuitOpen {
        operation: CryptoOperation,
        retry_after: Duration,
    },
    
    #[error("Rate limit depasse: {current_rate}/s > {limit}/s")]
    RateLimitExceeded {
        current_rate: u32,
        limit: u32,
    },
    
    #[error("Operation timeout after {timeout:?}")]
    OperationTimeout {
        timeout: Duration,
    },
}

// Instance globale du circuit breaker (singleton)
lazy_static::lazy_static! {
    static ref GLOBAL_CIRCUIT_BREAKER: CryptoCircuitBreaker = {
        CryptoCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 0.3, // 30% d'echecs pour ouvrir
            min_operations: 5,
            recovery_timeout: Duration::from_secs(30),
            test_operations: 3,
            global_rate_limit: 50, // 50 ops/sec max
            rate_window: Duration::from_secs(1),
        })
    };
}

/// Obtenir l'instance globale du circuit breaker
pub fn global_circuit_breaker() -> &'static CryptoCircuitBreaker {
    &GLOBAL_CIRCUIT_BREAKER
}

/// Macro pour proteger une operation cryptographique
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
        
        // Circuit doit be ferme initialement
        assert_eq!(breaker.state(), CircuitState::Closed);
        
        // Operation autorisee
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

        // Simuler des echecs — circuit may open before all 5 iterations
        for _ in 0..5 {
            match breaker.check_operation(CryptoOperation::Halo2ProofGeneration).await {
                Ok(guard) => guard.failure(),
                Err(_) => break, // Circuit already opened
            }
        }

        // Circuit doit be ouvert
        assert_eq!(breaker.state(), CircuitState::Open);

        // Nouvelle operation doit be rejetee
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
        
        // Troisieme operation doit be rejetee
        let result = breaker.check_operation(CryptoOperation::Poseidon2Hash).await;
        assert!(matches!(result, Err(CircuitBreakerError::RateLimitExceeded { .. })));
        
        // Attendre et reessayer
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

        // Provoquer l'ouverture du circuit
        for _ in 0..3 {
            match breaker.check_operation(CryptoOperation::MlDsaSignature).await {
                Ok(guard) => guard.failure(),
                Err(_) => break,
            }
        }
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Attendre le timeout de recuperation
        sleep(Duration::from_millis(60)).await;
        
        // First operation after timeout doit passer en HalfOpen
        let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
        guard.success();
        
        // Second operation de test
        let guard = breaker.check_operation(CryptoOperation::MlDsaSignature).await.unwrap();
        guard.success();
        
        // Circuit doit be ferme after success des tests
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}