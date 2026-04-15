use thiserror::Error;
use crate::crypto::{nullifier::Nullifier, commitment::Commitment, range_proof::RangeProof};
use sled::Tree;

#[derive(Debug, Error)]
pub enum ShieldedValidationError {
    #[error("Invalid nullifier")]
    InvalidNullifier,
    
    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Invalid range proof")]
    InvalidRangeProof,
}

/// Valide une transaction shielded.
///
/// Cette fonction verifies les elements suivants :
/// - Le nullifier est valid
/// - Le commitment est valid et n'a pas been used previously
/// - Le preuve de plage (range proof) est valid
pub fn validate_shielded_transaction(
    tx: &ShieldedTransaction,
    nullifiers_tree: &Tree,
    commitments_tree: &Tree,
) -> Result<(), ShieldedValidationError> {
    // Verifies le nullifier
    if !Nullifier::is_valid(&tx.nullifier) {
        return Err(ShieldedValidationError::InvalidNullifier);
    }

    // Verifies que le commitment n'a pas been used previously
    let commitment_exists = commitments_tree.contains_key(tx.commitment.as_bytes());
    if commitment_exists {
        return Err(ShieldedValidationError::InvalidCommitment);
    }

    // Verifies la preuve de plage (range proof)
    if !RangeProof::is_valid(&tx.range_proof) {
        return Err(ShieldedValidationError::InvalidRangeProof);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{nullifier::Nullifier, commitment::Commitment, range_proof::RangeProof};
    use sled::Tree;

    #[test]
    fn test_validate_shielded_transaction_valid() {
        let nullifier = Nullifier::new([0; 32]);
        let commitment = Commitment::new([0; 32]);
        let range_proof = RangeProof::new(vec![]);

        let tx = ShieldedTransaction { nullifier, commitment, range_proof };

        let mut tree = sled::open("test_db").unwrap();
        let nullifiers_tree = tree.open_tree(b"nullifiers").unwrap();
        let commitments_tree = tree.open_tree(b"commitments").unwrap();

        assert!(validate_shielded_transaction(&tx, &nullifiers_tree, &commitments_tree).is_ok());
    }

    #[test]
    fn test_validate_shielded_transaction_invalid_nullifier() {
        let nullifier = Nullifier::new([1; 32]);
        let commitment = Commitment::new([0; 32]);
        let range_proof = RangeProof::new(vec![]);

        let tx = ShieldedTransaction { nullifier, commitment, range_proof };

        let mut tree = sled::open("test_db").unwrap();
        let nullifiers_tree = tree.open_tree(b"nullifiers").unwrap();
        let commitments_tree = tree.open_tree(b"commitments").unwrap();

        assert!(matches!(
            validate_shielded_transaction(&tx, &nullifiers_tree, &commitments_tree),
            Err(ShieldedValidationError::InvalidNullifier)
        ));
    }

    #[test]
    fn test_validate_shielded_transaction_invalid_commitment() {
        let nullifier = Nullifier::new([0; 32]);
        let commitment = Commitment::new([1; 32]);
        let range_proof = RangeProof::new(vec![]);

        let tx = ShieldedTransaction { nullifier, commitment, range_proof };

        let mut tree = sled::open("test_db").unwrap();
        let nullifiers_tree = tree.open_tree(b"nullifiers").unwrap();
        let commitments_tree = tree.open_tree(b"commitments").unwrap();

        assert!(matches!(
            validate_shielded_transaction(&tx, &nullifiers_tree, &commitments_tree),
            Err(ShieldedValidationError::InvalidCommitment)
        ));
    }

    #[test]
    fn test_validate_shielded_transaction_invalid_range_proof() {
        let nullifier = Nullifier::new([0; 32]);
        let commitment = Commitment::new([0; 32]);
        let range_proof = RangeProof::new(vec![1]);

        let tx = ShieldedTransaction { nullifier, commitment, range_proof };

        let mut tree = sled::open("test_db").unwrap();
        let nullifiers_tree = tree.open_tree(b"nullifiers").unwrap();
        let commitments_tree = tree.open_tree(b"commitments").unwrap();

        assert!(matches!(
            validate_shielded_transaction(&tx, &nullifiers_tree, &commitments_tree),
            Err(ShieldedValidationError::InvalidRangeProof)
        ));
    }
}

#[derive(Debug)]
pub struct ShieldedTransaction {
    pub nullifier: Nullifier,
    pub commitment: Commitment,
    pub range_proof: RangeProof,
}