//! Module de tests for the network TSN
//! 
//! Organisation of tests in modules separateds for a meilleure maintainability.

pub mod unit_tests;
pub mod handshake_tests;
pub mod security_tests;
pub mod performance_tests;
pub mod integration_tests;

// Re-export of tests for compatibility
pub use unit_tests::*;
pub use handshake_tests::*;
pub use security_tests::*;
pub use performance_tests::*;
pub use integration_tests::*;