//! TSN Snapshot Manifest System — Phase 1
//!
//! Provides signed, verified snapshots for safe chain restoration.
//! Each snapshot is produced only at finalized heights and includes:
//! - SHA256 of the snapshot data
//! - Ed25519 signature by the producing seed
//! - Confirmations signed by other seeds
//! - State root for post-import verification

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Snapshot manifest — the metadata that accompanies a snapshot file.
/// Signed by the producing seed and confirmed by other seeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Manifest format version
    pub version: u32,
    /// Chain identifier
    pub chain_id: String,
    /// Block height of the snapshot
    pub height: u64,
    /// Block hash at this height (hex)
    pub block_hash: String,
    /// State root computed from the snapshot (hex)
    pub state_root: String,
    /// SHA256 hash of the compressed snapshot file (hex)
    pub snapshot_sha256: String,
    /// Size of the compressed snapshot in bytes
    pub snapshot_size_bytes: u64,
    /// Snapshot format identifier
    pub format: String,
    /// TSN binary version that produced this snapshot
    pub binary_version: String,
    /// ISO 8601 timestamp
    pub created_at: String,
    /// Identity of the seed that produced this snapshot
    pub producer: SeedIdentity,
    /// Ed25519 signature of the manifest body (hex) by the producer
    pub signature: String,
    /// Confirmations from other seeds (each individually signed)
    #[serde(default)]
    pub confirmations: Vec<SeedConfirmation>,
}

/// Identity of a seed node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedIdentity {
    pub seed_name: String,
    pub peer_id: String,
    /// Ed25519 public key of this seed (hex)
    pub public_key: String,
}

/// A confirmation from another seed — individually signed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedConfirmation {
    pub seed_name: String,
    pub peer_id: String,
    pub height: u64,
    /// Whether the block hash at this height matches
    pub block_hash_match: bool,
    /// Whether the state root matches
    pub state_root_match: bool,
    /// ISO 8601 timestamp
    pub confirmed_at: String,
    /// Ed25519 signature of this confirmation (hex) by the confirming seed
    pub signature: String,
    /// Public key of the confirming seed (hex)
    pub public_key: String,
}

/// Snapshot entry for the history endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub snapshot_sha256: String,
    pub created_at: String,
    pub confirmations: usize,
}

impl SnapshotManifest {
    /// Compute the signing payload (deterministic JSON of the manifest without signature/confirmations)
    pub fn signing_payload(&self) -> Vec<u8> {
        let payload = serde_json::json!({
            "version": self.version,
            "chain_id": self.chain_id,
            "height": self.height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "snapshot_sha256": self.snapshot_sha256,
            "snapshot_size_bytes": self.snapshot_size_bytes,
            "format": self.format,
            "binary_version": self.binary_version,
            "created_at": self.created_at,
            "producer": {
                "seed_name": self.producer.seed_name,
                "peer_id": self.producer.peer_id,
                "public_key": self.producer.public_key,
            }
        });
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// Verify the producer signature
    pub fn verify_producer_signature(&self) -> bool {
        let payload = self.signing_payload();
        verify_ed25519(&self.producer.public_key, &payload, &self.signature)
    }

    /// Count valid confirmations (verified signatures)
    pub fn valid_confirmation_count(&self) -> usize {
        self.confirmations.iter().filter(|c| c.verify()).count()
    }

    /// Check if this manifest is fully valid:
    /// - Producer signature OK
    /// - At least `min_confirmations` valid confirmations from different seeds
    /// - SHA256 matches the provided data
    pub fn validate(&self, snapshot_data: &[u8], min_confirmations: usize) -> Result<(), String> {
        // Verify producer signature
        if !self.verify_producer_signature() {
            return Err("Invalid producer signature".into());
        }

        // Verify SHA256
        let computed_sha256 = hex::encode(Sha256::digest(snapshot_data));
        if computed_sha256 != self.snapshot_sha256 {
            return Err(format!(
                "SHA256 mismatch: computed={}, manifest={}",
                &computed_sha256[..16], &self.snapshot_sha256[..16]
            ));
        }

        // Verify confirmations
        let valid = self.valid_confirmation_count();
        if valid < min_confirmations {
            return Err(format!(
                "Insufficient confirmations: {} valid, {} required",
                valid, min_confirmations
            ));
        }

        Ok(())
    }
}

impl SeedConfirmation {
    /// Compute the signing payload for this confirmation
    pub fn signing_payload(&self) -> Vec<u8> {
        let payload = serde_json::json!({
            "seed_name": self.seed_name,
            "height": self.height,
            "block_hash_match": self.block_hash_match,
            "state_root_match": self.state_root_match,
            "confirmed_at": self.confirmed_at,
        });
        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// Verify this confirmation's signature
    pub fn verify(&self) -> bool {
        if !self.block_hash_match || !self.state_root_match {
            return false;
        }
        let payload = self.signing_payload();
        verify_ed25519(&self.public_key, &payload, &self.signature)
    }
}

/// Verify an Ed25519 signature
fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 32 => {
            let arr: [u8; 32] = b.try_into().unwrap();
            arr
        }
        _ => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => {
            let arr: [u8; 64] = b.try_into().unwrap();
            arr
        }
        _ => return false,
    };

    let pk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);

    pk.verify(message, &sig).is_ok()
}

/// Sign a message with an Ed25519 signing key
pub fn sign_ed25519(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(message);
    hex::encode(sig.to_bytes())
}

/// Generate or load a seed's Ed25519 keypair from a file
pub fn load_or_generate_seed_key(path: &std::path::Path) -> ed25519_dalek::SigningKey {
    if path.exists() {
        if let Ok(data) = std::fs::read(path) {
            if data.len() == 32 {
                let bytes: [u8; 32] = data.try_into().unwrap();
                return ed25519_dalek::SigningKey::from_bytes(&bytes);
            }
        }
    }
    // Generate new key from random bytes
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng{}.fill_bytes(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    let _ = std::fs::write(path, key.to_bytes());
    tracing::info!("Generated new seed signing key at {}", path.display());
    key
}

/// Check if a height is eligible for snapshot export:
/// - Must be finalized (below tip - MAX_REORG_DEPTH)
/// - Must be a multiple of the snapshot interval
pub fn is_snapshot_eligible(height: u64, tip: u64, interval: u64) -> bool {
    let max_reorg = crate::config::MAX_REORG_DEPTH;
    height > 0
        && height % interval == 0
        && tip >= height + max_reorg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        let key = { let mut s = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng{}, &mut s); SigningKey::from_bytes(&s) };
        let message = b"test snapshot manifest";
        let sig = sign_ed25519(&key, message);
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        assert!(verify_ed25519(&pk_hex, message, &sig));
    }

    #[test]
    fn test_invalid_signature_rejected() {
        use ed25519_dalek::SigningKey;
        let key = { let mut s = [0u8; 32]; rand::RngCore::fill_bytes(&mut rand::rngs::OsRng{}, &mut s); SigningKey::from_bytes(&s) };
        let message = b"test snapshot manifest";
        let sig = sign_ed25519(&key, message);
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        assert!(!verify_ed25519(&pk_hex, b"tampered", &sig));
    }

    #[test]
    fn test_snapshot_eligibility() {
        // height=1000, tip=1200, interval=1000 → eligible (1200 - 1000 = 200 > 100)
        assert!(is_snapshot_eligible(1000, 1200, 1000));
        // height=1000, tip=1050, interval=1000 → not eligible (only 50 deep)
        assert!(!is_snapshot_eligible(1000, 1050, 1000));
        // height=999, tip=1200, interval=1000 → not eligible (not a multiple)
        assert!(!is_snapshot_eligible(999, 1200, 1000));
        // height=0 → not eligible
        assert!(!is_snapshot_eligible(0, 1200, 1000));
    }
}
