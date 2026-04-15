use crate::crypto::{PublicKey, Signature};
use crate::transaction::Transaction;
use thiserror::Error;

// Error custom for the operations on the blocs
#[derive(Error, Debug)]
enum BlockError {
    #[error("Invalid block hash")]
    InvalidBlockHash,
    #[error("Invalid block signature")]
    InvalidBlockSignature,
}

// Structure for a bloc
pub struct Block {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub transactions: Vec<Transaction>,
    // Autres fields of the bloc...
}

impl Block {
    // Hash d'un bloc
    pub fn hash(&self) -> Vec<u8> {
        // Calcul of the hash...
        unimplemented!()
    }
}