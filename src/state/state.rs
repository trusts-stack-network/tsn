use std::convert::TryInto;
use std::error::Error;
use std::fmt;

use crate::consensus::ProofOfWork;
use crate::core::Block;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Invalid state")]
    InvalidState,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub struct State {
    pub blocks: Vec<Block>,
}

impl State {
    pub fn new() -> Self {
        State { blocks: Vec::new() }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn get_block(&self, index: usize) -> Option<&Block> {
        self.blocks.get(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_add_block() {
        // Create un state
        let mut state = State::new();

        // Create un bloc
        let block = Block::new();

        // Add block to state
        state.add_block(block);

        // Verify que le bloc est added
        assert!(state.get_block(0).is_some());
    }
}