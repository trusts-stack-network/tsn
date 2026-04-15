//! Gestion des keys SLH-DSA dans le wallet
//! Compatible avec la derivation hierarchique (non-BIP32) pour keys post-quantiques

use crate::crypto::pq::slh_dsa::{self, PublicKey, SecretKey, Signature};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

/// Portefeuille SLH-DSA unique (HD simplifie : 1 key par compte)
#[derive(ZeroizeOnDrop)]
pub struct SlhWallet {
    sk: SecretKey,
    pk: PublicKey,
}

impl SlhWallet {
    /// Creates a nouveau wallet
    pub fn new() -> Self {
        let (sk, pk) = sl