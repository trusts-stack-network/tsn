//! Gestion of keys SLH-DSA in the wallet
//! Compatible with the derivation hierarchical (non-BIP32) for keys post-quantiques

use crate::crypto::pq::slh_dsa::{self, PublicKey, SecretKey, Signature};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

/// Portefeuille SLH-DSA unique (HD simplified : 1 key par compte)
#[derive(ZeroizeOnDrop)]
pub struct SlhWallet {
    sk: SecretKey,
    pk: PublicKey,
}

impl SlhWallet {
    /// Creates a new wallet
    pub fn new() -> Self {
        let (sk, pk) = sl