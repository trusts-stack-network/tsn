//! Post-quantum signature scheme abstraction
//! Support ML-DSA-65 (legacy) et SLH-DSA (nouveau) avec gouvernance configurable

use crate::crypto::pq::slh_dsa::{SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature};
use crate::crypto::pq::mldsa65::{Mldsa65PublicKey, Mldsa65SecretKey, Mldsa65Signature};
use crate::crypto::governance::{GovernanceManager, GovernanceConfig};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureVersion {
    /// ML-DSA-65 (FIPS 204) - version legacy
    V1Mldsa65,
    /// SLH-DSA (FIPS 205) - version actuelle
    V2SlhDsa,
}

impl SignatureVersion {
    /// Version actuelle recommended
    pub fn current() -> Self {
        Self::V2SlhDsa
    }
    
    /// Versions acceptsdes lors de la period de transition (avec gouvernance)
    pub fn is_accepted_during_transition(&self, block_height: u64, governance_config: &GovernanceConfig) -> bool {
        match self {
            Self::V2SlhDsa => true, // Toujours accepted
            Self::V1Mldsa65 => {
                // Period de transition configurable via gouvernance
                block_height < governance_config.signature_transition_period
            }
        }
    }
    
    /// Version legacy pour compatibility (utilise la valeur hardcoded)
    #[deprecated(note = "Utiliser is_accepted_during_transition avec GovernanceConfig")]
    pub fn is_accepted_during_transition_legacy(&self, block_height: u64) -> bool {
        match self {
            Self::V2SlhDsa => true,
            Self::V1Mldsa65 => block_height < 10_000, // Valeur hardcoded legacy
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Mldsa65(Mldsa65PublicKey),
    SlhDsa(SlhDsaPublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    Mldsa65(Mldsa65Signature),
    SlhDsa(SlhDsaSignature),
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Signature invalid")]
    InvalidSignature,
    #[error("Version non supported: {0:?}")]
    UnsupportedVersion(SignatureVersion),
    #[error("Key publique incompatible avec la version")]
    IncompatibleKeyVersion,
    #[error("Signature expired pour cette hauteur de bloc")]
    ExpiredSignatureVersion,
    #[error("Erreur de gouvernance: {0}")]
    GovernanceError(String),
}

/// Manager de schemas de signature avec gouvernance integrated
#[derive(Debug)]
pub struct SignatureSchemeManager {
    /// Gestionnaire de gouvernance
    governance: Arc<RwLock<GovernanceManager>>,
}

impl SignatureSchemeManager {
    /// Creates un nouveau gestionnaire avec gouvernance
    pub fn new() -> Self {
        Self {
            governance: Arc::new(RwLock::new(GovernanceManager::new())),
        }
    }

    /// Creates un gestionnaire avec une configuration de gouvernance existante
    pub fn with_governance(governance: GovernanceManager) -> Self {
        Self {
            governance: Arc::new(RwLock::new(governance)),
        }
    }

    /// Verifies si une version de signature est acceptsde to une hauteur data
    pub fn is_version_accepted(&self, version: SignatureVersion, block_height: u64) -> Result<bool, SignatureError> {
        let governance = self.governance.read()
            .map_err(|e| SignatureError::GovernanceError(format!("Lock error: {}", e)))?;
        
        let config = governance.get_config();
        Ok(version.is_accepted_during_transition(block_height, config))
    }

    /// Retourne la configuration de gouvernance actuelle
    pub fn get_governance_config(&self) -> Result<GovernanceConfig, SignatureError> {
        let governance = self.governance.read()
            .map_err(|e| SignatureError::GovernanceError(format!("Lock error: {}", e)))?;
        
        Ok(governance.get_config().clone())
    }

    /// Access to governance manager (read only)
    pub fn governance_manager(&self) -> Arc<RwLock<GovernanceManager>> {
        self.governance.clone()
    }

    /// Met up to date la gouvernance (cleanup des propositions expireds)
    pub fn update_governance(&self, current_height: u64) -> Result<(), SignatureError> {
        let mut governance = self.governance.write()
            .map_err(|e| SignatureError::GovernanceError(format!("Lock error: {}", e)))?;
        
        governance.cleanup_expired_proposals(current_height);
        Ok(())
    }
}

impl Default for SignatureSchemeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicKey {
    /// Verifies une signature avec le manager de schemas
    pub fn verify_with_manager(
        &self, 
        message: &[u8], 
        signature: &Signature,
        manager: &SignatureSchemeManager,
        block_height: u64,
    ) -> Result<(), SignatureError> {
        // Verification de la compatibility version/hauteur
        let version = self.version();
        if !manager.is_version_accepted(version, block_height)? {
            return Err(SignatureError::ExpiredSignatureVersion);
        }

        // Verification cryptographique standard
        self.verify(message, signature)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        match (self, signature) {
            (PublicKey::Mldsa65(pk), Signature::Mldsa65(sig)) => {
                pk.verify(message, sig)
                    .map_err(|_| SignatureError::InvalidSignature)
            }
            (PublicKey::SlhDsa(pk), Signature::SlhDsa(sig)) => {
                pk.verify(message, sig)
                    .map_err(|_| SignatureError::InvalidSignature)
            }
            _ => Err(SignatureError::IncompatibleKeyVersion),
        }
    }
    
    pub fn version(&self) -> SignatureVersion {
        match self {
            PublicKey::Mldsa65(_) => SignatureVersion::V1Mldsa65,
            PublicKey::SlhDsa(_) => SignatureVersion::V2SlhDsa,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::governance::{ConfigParameter, ProposalId};
    use rand::rngs::OsRng;

    #[test]
    fn test_version_transition_with_governance() {
        let manager = SignatureSchemeManager::new();
        
        // Test avec configuration by default (10_000 blocs)
        let version = SignatureVersion::V1Mldsa65;
        assert!(manager.is_version_accepted(version, 0).unwrap());
        assert!(manager.is_version_accepted(version, 9_999).unwrap());
        assert!(!manager.is_version_accepted(version, 10_000).unwrap());
        
        let version = SignatureVersion::V2SlhDsa;
        assert!(manager.is_version_accepted(version, 0).unwrap());
        assert!(manager.is_version_accepted(version, 10_000).unwrap());
        assert!(manager.is_version_accepted(version, u64::MAX).unwrap());
    }

    #[test]
    fn test_governance_config_modification() {
        let mut governance = GovernanceManager::new();
        
        // Create une proposition pour extend la period de transition
        let parameter = ConfigParameter::SignatureTransitionPeriod(20_000);
        let proposal_id = governance.create_proposal(parameter, 100, 1).unwrap();
        
        // Add un membre au committee et voter
        let voter_key = crate::crypto::pq::slh_dsa::SlhDsaSecretKey::generate(&mut OsRng);
        let voter_pubkey = voter_key.public_key();
        governance.add_committee_member(voter_pubkey).unwrap();
        governance.submit_vote(proposal_id, &voter_key, true, 150, 1).unwrap();
        
        // Appliquer la proposition
        governance.apply_proposal(proposal_id, 200).unwrap();
        
        // Verify la new configuration
        let manager = SignatureSchemeManager::with_governance(governance);
        let config = manager.get_governance_config().unwrap();
        assert_eq!(config.signature_transition_period, 20_000);
        
        // Tester la new period
        let version = SignatureVersion::V1Mldsa65;
        assert!(manager.is_version_accepted(version, 19_999).unwrap());
        assert!(!manager.is_version_accepted(version, 20_000).unwrap());
    }

    #[test]
    fn test_legacy_compatibility() {
        let version = SignatureVersion::V1Mldsa65;
        
        // Test de la method legacy
        #[allow(deprecated)]
        {
            assert!(version.is_accepted_during_transition_legacy(0));
            assert!(version.is_accepted_during_transition_legacy(9_999));
            assert!(!version.is_accepted_during_transition_legacy(10_000));
        }
        
        let version = SignatureVersion::V2SlhDsa;
        #[allow(deprecated)]
        {
            assert!(version.is_accepted_during_transition_legacy(0));
            assert!(version.is_accepted_during_transition_legacy(10_000));
            assert!(version.is_accepted_during_transition_legacy(u64::MAX));
        }
    }

    #[test]
    fn test_signature_verification_with_manager() {
        let manager = SignatureSchemeManager::new();
        
        // Generate une key SLH-DSA
        let secret_key = crate::crypto::pq::slh_dsa::SlhDsaSecretKey::generate(&mut OsRng);
        let public_key = PublicKey::SlhDsa(secret_key.public_key());
        
        let message = b"test message";
        let signature = Signature::SlhDsa(secret_key.sign(message));
        
        // Verification avec le gestionnaire (SLH-DSA toujours accepted)
        assert!(public_key.verify_with_manager(message, &signature, &manager, 0).is_ok());
        assert!(public_key.verify_with_manager(message, &signature, &manager, 100_000).is_ok());
    }

    #[test]
    fn test_governance_update() {
        let manager = SignatureSchemeManager::new();
        
        // Test de update (cleanup)
        assert!(manager.update_governance(1000).is_ok());
        
        // Verify que la configuration est toujours accessible
        let config = manager.get_governance_config().unwrap();
        assert_eq!(config.signature_transition_period, 10_000);
    }
}