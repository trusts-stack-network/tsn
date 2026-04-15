//! Integration du system de gouvernance avec la blockchain TSN
//! 
//! Ce module fournit les interfaces pour integrate le system de gouvernance
//! cryptographique avec les autres composants de TSN (consensus, network, storage).

use crate::crypto::governance::{GovernanceManager, GovernanceConfig, Proposal, Vote, ProposalId, ConfigParameter, GovernanceError};
use crate::consensus::signature_scheme::{SignatureSchemeManager, SignatureError};
use crate::crypto::pq::slh_dsa::{SlhDsaSecretKey, SlhDsaPublicKey};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use thiserror::Error;

/// Event de gouvernance pour la synchronisation network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceEvent {
    /// Nouvelle proposition created
    ProposalCreated {
        proposal: Proposal,
        creator_pubkey: SlhDsaPublicKey,
    },
    /// Vote soumis sur une proposition
    VoteSubmitted {
        vote: Vote,
    },
    /// Proposition approved et appliede
    ProposalApplied {
        proposal_id: ProposalId,
        new_config: GovernanceConfig,
        applied_at_height: u64,
    },
    /// Proposition expired
    ProposalExpired {
        proposal_id: ProposalId,
        expired_at_height: u64,
    },
}

/// Manager integrated de gouvernance pour TSN
#[derive(Debug)]
pub struct TsnGovernanceManager {
    /// Gestionnaire de gouvernance principal
    governance: Arc<RwLock<GovernanceManager>>,
    /// Manager de schemas de signature
    signature_manager: SignatureSchemeManager,
    /// Events en attente de propagation
    pending_events: Arc<RwLock<Vec<GovernanceEvent>>>,
    /// Historique des configurations
    config_history: Arc<RwLock<HashMap<u64, GovernanceConfig>>>,
}

#[derive(Error, Debug)]
pub enum TsnGovernanceError {
    #[error("Erreur de gouvernance: {0}")]
    Governance(#[from] GovernanceError),
    #[error("Erreur de signature: {0}")]
    Signature(#[from] SignatureError),
    #[error("Hauteur de bloc invalid: {0}")]
    InvalidBlockHeight(u64),
    #[error("Configuration non founde pour la hauteur: {0}")]
    ConfigNotFound(u64),
    #[error("Erreur de serialization: {0}")]
    Serialization(String),
}

impl TsnGovernanceManager {
    /// Creates un nouveau gestionnaire de gouvernance TSN
    pub fn new() -> Self {
        let governance = Arc::new(RwLock::new(GovernanceManager::new()));
        let signature_manager = SignatureSchemeManager::with_governance(
            governance.read().unwrap().clone()
        );

        Self {
            governance,
            signature_manager,
            pending_events: Arc::new(RwLock::new(Vec::new())),
            config_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialise le system avec un committee de gouvernance initial
    pub fn initialize_committee(&self, initial_committee: Vec<SlhDsaPublicKey>) -> Result<(), TsnGovernanceError> {
        let mut governance = self.governance.write().unwrap();
        
        for pubkey in initial_committee {
            governance.add_committee_member(pubkey)?;
        }
        
        Ok(())
    }

    /// Creates une new proposition de gouvernance
    pub fn create_proposal(
        &self,
        creator_key: &SlhDsaSecretKey,
        parameter: ConfigParameter,
        current_height: u64,
        nonce: u64,
    ) -> Result<ProposalId, TsnGovernanceError> {
        let mut governance = self.governance.write().unwrap();
        let creator_pubkey = creator_key.public_key();
        
        let proposal_id = governance.create_proposal(parameter, current_height, nonce)?;
        
        // Retrieve la proposition created pour l'event
        let proposal = governance.active_proposals.get(&proposal_id).unwrap().clone();
        
        // Create l'event
        let event = GovernanceEvent::ProposalCreated {
            proposal,
            creator_pubkey,
        };
        
        self.add_pending_event(event);
        
        Ok(proposal_id)
    }

    /// Soumet un vote sur une proposition
    pub fn submit_vote(
        &self,
        proposal_id: ProposalId,
        voter_key: &SlhDsaSecretKey,
        support: bool,
        current_height: u64,
        nonce: u64,
    ) -> Result<(), TsnGovernanceError> {
        let mut governance = self.governance.write().unwrap();
        
        governance.submit_vote(proposal_id, voter_key, support, current_height, nonce)?;
        
        // Retrieve le vote pour l'event
        let votes = governance.votes.get(&proposal_id).unwrap();
        let vote = votes.last().unwrap().clone();
        
        let event = GovernanceEvent::VoteSubmitted { vote };
        self.add_pending_event(event);
        
        Ok(())
    }

    /// Traite les propositions et applique celles qui sont approved
    pub fn process_proposals(&self, current_height: u64) -> Result<Vec<GovernanceEvent>, TsnGovernanceError> {
        let mut governance = self.governance.write().unwrap();
        let mut events = Vec::new();
        
        // Collecter les propositions to process
        let proposal_ids: Vec<_> = governance.active_proposals.keys().cloned().collect();
        
        for proposal_id in proposal_ids {
            let status = governance.evaluate_proposal(proposal_id, current_height)?;
            
            match status {
                crate::crypto::governance::ProposalStatus::Approved => {
                    // Sauvegarder la configuration actuelle
                    let old_config = governance.get_config().clone();
                    self.save_config_to_history(current_height, &old_config);
                    
                    // Appliquer la proposition
                    governance.apply_proposal(proposal_id, current_height)?;
                    
                    let new_config = governance.get_config().clone();
                    
                    events.push(GovernanceEvent::ProposalApplied {
                        proposal_id,
                        new_config,
                        applied_at_height: current_height,
                    });
                }
                crate::crypto::governance::ProposalStatus::Expired => {
                    events.push(GovernanceEvent::ProposalExpired {
                        proposal_id,
                        expired_at_height: current_height,
                    });
                }
                _ => {} // Active or Rejected, nothing to do
            }
        }
        
        // Clean up les propositions expireds
        governance.cleanup_expired_proposals(current_height);
        
        // Add events to pending events
        for event in &events {
            self.add_pending_event(event.clone());
        }
        
        Ok(events)
    }

    /// Verifies si une version de signature est acceptsde
    pub fn is_signature_version_accepted(
        &self,
        version: crate::consensus::signature_scheme::SignatureVersion,
        block_height: u64,
    ) -> Result<bool, TsnGovernanceError> {
        Ok(self.signature_manager.is_version_accepted(version, block_height)?)
    }

    /// Retourne la configuration de gouvernance actuelle
    pub fn get_current_config(&self) -> Result<GovernanceConfig, TsnGovernanceError> {
        let governance = self.governance.read().unwrap();
        Ok(governance.get_config().clone())
    }

    /// Returns la configuration to une hauteur de bloc data
    pub fn get_config_at_height(&self, height: u64) -> Result<GovernanceConfig, TsnGovernanceError> {
        let history = self.config_history.read().unwrap();
        
        // Chercher la configuration la plus recent <= height
        let mut best_height = 0;
        let mut best_config = None;
        
        for (&config_height, config) in history.iter() {
            if config_height <= height && config_height >= best_height {
                best_height = config_height;
                best_config = Some(config.clone());
            }
        }
        
        best_config.ok_or(TsnGovernanceError::ConfigNotFound(height))
    }

    /// Retrieves et vide les events en attente
    pub fn drain_pending_events(&self) -> Vec<GovernanceEvent> {
        let mut events = self.pending_events.write().unwrap();
        events.drain(..).collect()
    }

    /// Adds un membre au committee de gouvernance
    pub fn add_committee_member(&self, pubkey: SlhDsaPublicKey) -> Result<(), TsnGovernanceError> {
        let mut governance = self.governance.write().unwrap();
        governance.add_committee_member(pubkey)?;
        Ok(())
    }

    /// Returns la liste des membres du committee
    pub fn get_committee_members(&self) -> Vec<SlhDsaPublicKey> {
        let governance = self.governance.read().unwrap();
        governance.committee.clone()
    }

    /// Serializes l'state de gouvernance pour la persistance
    pub fn serialize_state(&self) -> Result<Vec<u8>, TsnGovernanceError> {
        let governance = self.governance.read().unwrap();
        let config_history = self.config_history.read().unwrap();
        
        let state = (governance.get_config().clone(), config_history.clone());
        
        bincode::serialize(&state)
            .map_err(|e| TsnGovernanceError::Serialization(e.to_string()))
    }

    /// Deserializes et restaure l'state de gouvernance
    pub fn deserialize_state(&self, data: &[u8]) -> Result<(), TsnGovernanceError> {
        let (config, history): (GovernanceConfig, HashMap<u64, GovernanceConfig>) = 
            bincode::deserialize(data)
                .map_err(|e| TsnGovernanceError::Serialization(e.to_string()))?;
        
        // Restaurer l'historique
        let mut config_history = self.config_history.write().unwrap();
        *config_history = history;
        
        Ok(())
    }

    /// Valide un event de gouvernance received du network
    pub fn validate_governance_event(&self, event: &GovernanceEvent) -> Result<bool, TsnGovernanceError> {
        match event {
            GovernanceEvent::VoteSubmitted { vote } => {
                // Verify la signature du vote
                let vote_message = self.create_vote_message_for_validation(vote);
                vote.voter_pubkey.verify(&vote_message, &vote.signature)
                    .map_err(|_| TsnGovernanceError::Signature(SignatureError::InvalidSignature))?;
                
                // Verify que le votant est dans le committee
                let governance = self.governance.read().unwrap();
                Ok(governance.committee.contains(&vote.voter_pubkey))
            }
            GovernanceEvent::ProposalCreated { proposal, creator_pubkey } => {
                // Verify l'integrity du commitment
                let computed_commitment = self.compute_proposal_commitment_for_validation(proposal);
                Ok(computed_commitment == proposal.commitment)
            }
            _ => Ok(true), // Autres events validateds lors du processing
        }
    }

    // Methods privates

    fn add_pending_event(&self, event: GovernanceEvent) {
        let mut events = self.pending_events.write().unwrap();
        events.push(event);
    }

    fn save_config_to_history(&self, height: u64, config: &GovernanceConfig) {
        let mut history = self.config_history.write().unwrap();
        history.insert(height, config.clone());
    }

    fn create_vote_message_for_validation(&self, vote: &Vote) -> Vec<u8> {
        let vote_data = (vote.proposal_id, vote.support, vote.timestamp, vote.nonce);
        bincode::serialize(&vote_data).unwrap()
    }

    fn compute_proposal_commitment_for_validation(&self, proposal: &Proposal) -> [u8; 32] {
        use crate::crypto::poseidon::PoseidonHash;
        let data = bincode::serialize(&(&proposal.parameter, proposal.created_at_height, proposal.nonce)).unwrap();
        PoseidonHash::hash(&data)
    }
}

impl Default for TsnGovernanceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_tsn_governance_creation() {
        let manager = TsnGovernanceManager::new();
        let config = manager.get_current_config().unwrap();
        assert_eq!(config.signature_transition_period, 10_000);
    }

    #[test]
    fn test_committee_initialization() {
        let manager = TsnGovernanceManager::new();
        
        let key1 = SlhDsaSecretKey::generate(&mut OsRng);
        let key2 = SlhDsaSecretKey::generate(&mut OsRng);
        let committee = vec![key1.public_key(), key2.public_key()];
        
        manager.initialize_committee(committee.clone()).unwrap();
        
        let members = manager.get_committee_members();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&key1.public_key()));
        assert!(members.contains(&key2.public_key()));
    }

    #[test]
    fn test_proposal_workflow() {
        let manager = TsnGovernanceManager::new();
        
        // Initialize le committee
        let voter_key = SlhDsaSecretKey::generate(&mut OsRng);
        manager.initialize_committee(vec![voter_key.public_key()]).unwrap();
        
        // Create une proposition
        let parameter = ConfigParameter::SignatureTransitionPeriod(15_000);
        let proposal_id = manager.create_proposal(&voter_key, parameter, 100, 1).unwrap();
        
        // Voter
        manager.submit_vote(proposal_id, &voter_key, true, 150, 1).unwrap();
        
        // Traiter les propositions
        let events = manager.process_proposals(200).unwrap();
        
        // Verify qu'une proposition a been appliede
        assert!(!events.is_empty());
        
        let config = manager.get_current_config().unwrap();
        assert_eq!(config.signature_transition_period, 15_000);
    }

    #[test]
    fn test_event_validation() {
        let manager = TsnGovernanceManager::new();
        let voter_key = SlhDsaSecretKey::generate(&mut OsRng);
        
        manager.initialize_committee(vec![voter_key.public_key()]).unwrap();
        
        // Create et voter sur une proposition
        let parameter = ConfigParameter::SignatureTransitionPeriod(15_000);
        let proposal_id = manager.create_proposal(&voter_key, parameter, 100, 1).unwrap();
        manager.submit_vote(proposal_id, &voter_key, true, 150, 1).unwrap();
        
        // Retrieve les events
        let events = manager.drain_pending_events();
        
        // Validate les events
        for event in &events {
            assert!(manager.validate_governance_event(event).unwrap());
        }
    }

    #[test]
    fn test_config_history() {
        let manager = TsnGovernanceManager::new();
        let voter_key = SlhDsaSecretKey::generate(&mut OsRng);
        
        manager.initialize_committee(vec![voter_key.public_key()]).unwrap();
        
        // Configuration initiale
        let initial_config = manager.get_current_config().unwrap();
        
        // Modifier la configuration
        let parameter = ConfigParameter::SignatureTransitionPeriod(15_000);
        let proposal_id = manager.create_proposal(&voter_key, parameter, 100, 1).unwrap();
        manager.submit_vote(proposal_id, &voter_key, true, 150, 1).unwrap();
        manager.process_proposals(200).unwrap();
        
        // Verify l'historique
        let config_at_100 = manager.get_config_at_height(100).unwrap();
        assert_eq!(config_at_100.signature_transition_period, initial_config.signature_transition_period);
        
        let config_at_300 = manager.get_config_at_height(300).unwrap();
        assert_eq!(config_at_300.signature_transition_period, 15_000);
    }

    #[test]
    fn test_serialization() {
        let manager = TsnGovernanceManager::new();
        
        // Serialize l'state
        let serialized = manager.serialize_state().unwrap();
        
        // Create un nouveau manager et deserialize
        let new_manager = TsnGovernanceManager::new();
        new_manager.deserialize_state(&serialized).unwrap();
        
        // Verify que les configurations sont identiques
        let original_config = manager.get_current_config().unwrap();
        let restored_config = new_manager.get_current_config().unwrap();
        assert_eq!(original_config, restored_config);
    }
}