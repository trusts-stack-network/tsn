//! Dev CLI - Outils de developpement et simulation pour TSN
//!
//! Ce module provides des outils pour tester la robustesse du network TSN
//! sous des conditions adversariales.

pub mod simulators;

use std::time::Duration;

/// Configuration globale pour les outils de developpement
#[derive(Debug, Clone)]
pub struct DevConfig {
    /// Activer les simulateurs network
    pub enable_network_simulators: bool,
    /// Niveau de log pour les simulations
    pub log_level: tracing::Level,
    /// Timeout by default pour les operations de test
    pub default_timeout: Duration,
}

impl Default for DevConfig {
    fn default() -> Self {
        Self {
            enable_network_simulators: true,
            log_level: tracing::Level::INFO,
            default_timeout: Duration::from_secs(30),
        }
    }
}

/// Initializes the module dev_cli avec la configuration donnee
pub fn init(config: DevConfig) {
    tracing::info!("Initialisation du module dev_cli");
    
    if config.enable_network_simulators {
        tracing::info!("Simulateurs network actives");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DevConfig::default();
        assert!(config.enable_network_simulators);
    }
}
