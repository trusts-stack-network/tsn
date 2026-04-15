use crate::crypto::{PublicKey, Signature};
use thiserror::Error;

// Error custom for the operations on the transactions
#[derive(Error, Debug)]
enum TransactionError {
    #[error("Invalid transaction hash")]
    InvalidTransactionHash,
    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,
}

// Structure for a transaction
pub struct Transaction {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    // Autres fields de the transaction...
}

impl Transaction {
    // Hash d'une transaction
    pub fn hash(&self) -> Vec<u8> {
        // Calcul of the hash...
        unimplemented!()
    }
}