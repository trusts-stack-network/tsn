//! Module de tests pour le network TSN
//! 
//! Organisation des tests en modules separes pour une meilleure maintenabilite.

pub mod unit_tests;
pub mod handshake_tests;
pub mod security_tests;
pub mod performance_tests;
pub mod integration_tests;

// Re-export des tests pour compatibility
pub use unit_tests::*;
pub use handshake_tests::*;
pub use security_tests::*;
pub use performance_tests::*;
pub use integration_tests::*;