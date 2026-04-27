//! Shielded wallet for private transactions.
//!
//! The wallet tracks owned notes and can:
//! - Scan blocks to discover incoming notes
//! - Calculate balance (sum of unspent notes)
//!
//! Note: Transaction proof generation is done in the browser wallet using
//! snarkjs/Circom. This Rust wallet is for balance tracking and note scanning.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::core::ShieldedBlock;
use crate::crypto::{
    commitment::NoteCommitment,
    note::{compute_pk_hash, decrypt_note_pq, Note, ViewingKey},
    nullifier::{derive_nullifier, Nullifier, NullifierKey},
    sign, Address, KeyPair,
};

/// A note owned by the wallet.
#[derive(Clone, Debug)]
pub struct WalletNote {
    /// The note itself.
    pub note: Note,
    /// The note commitment.
    pub commitment: NoteCommitment,
    /// Position in the commitment tree.
    pub position: u64,
    /// Block height where this note was created.
    pub height: u64,
    /// Whether this note has been spent.
    pub is_spent: bool,
    /// The nullifier for this note (computed lazily).
    nullifier: Option<Nullifier>,
    /// PQ randomness (for V2 spending). If set, use this instead of note.randomness.
    pub pq_randomness: Option<[u8; 32]>,
    /// PQ commitment bytes (for V2 spending).
    pub pq_commitment: Option<[u8; 32]>,
}

impl WalletNote {
    /// Create a new wallet note.
    pub fn new(note: Note, commitment: NoteCommitment, position: u64, height: u64) -> Self {
        Self {
            note,
            commitment,
            position,
            height,
            is_spent: false,
            nullifier: None,
            pq_randomness: None,
            pq_commitment: None,
        }
    }

    /// Get or compute the nullifier.
    pub fn nullifier(&mut self, nullifier_key: &NullifierKey) -> Nullifier {
        if self.nullifier.is_none() {
            self.nullifier = Some(derive_nullifier(nullifier_key, &self.commitment, self.position));
        }
        self.nullifier.unwrap()
    }

    /// Check if this note has been spent.
    pub fn mark_spent(&mut self) {
        self.is_spent = true;
    }
}

/// A shielded wallet with privacy features.
///
/// This wallet is used for:
/// - Generating keypeers (Dilithium for ownership proofs)
/// - Scanning blocks for incoming notes
/// - Tracking balance (sum of unspent notes)
///
/// Note: ZK proof generation for transactions is done in the browser wallet
/// using snarkjs/Circom. This Rust wallet doesn't generate proofs.
pub struct ShieldedWallet {
    /// The signing keypair (Dilithium for ownership proofs).
    keypair: KeyPair,
    /// Secret nullifier key (derived from keypair secret).
    nullifier_key: NullifierKey,
    /// Viewing key for scanning blockchain.
    viewing_key: ViewingKey,
    /// Hash of our public key (for note matching).
    pk_hash: [u8; 32],
    /// Notes owned by this wallet (in-memory, synced from DB when available).
    notes: Vec<WalletNote>,
    /// Last scanned block height.
    last_scanned_height: u64,
    /// Transaction history (sent + received).
    tx_history: Vec<WalletTxRecord>,
    /// SQLite database backend (None = legacy JSON mode).
    db: Option<super::wallet_db::WalletDb>,
    /// v2.7.4 Phase C — Local Poseidon/Goldilocks commitment tree.
    ///
    /// The wallet maintains its own copy of the network's V2 commitment
    /// tree, growing it leaf-by-leaf as blocks are scanned. This eliminates
    /// the round-trip to the node's `/witness/v2/position/{N}` endpoint when
    /// building a transaction: the wallet generates the Merkle path locally,
    /// using its own anchor (root) which is guaranteed to belong to a recent
    /// chain state because the wallet replays the same blocks the node did.
    ///
    /// The tree state is persisted via `CommitmentTreePQ::snapshot()` in
    /// `wallet_db` (or alongside the JSON wallet) so it survives restarts.
    pub(crate) local_tree: crate::crypto::pq::merkle_pq::CommitmentTreePQ,
}

impl ShieldedWallet {
    /// v2.7.4 Phase C — Append a single raw Poseidon leaf to the wallet's
    /// local commitment tree. Used by `sync_local_tree_pq` in the binary
    /// to rebuild the tree from the node's bulk-leaves API.
    pub fn append_local_leaf_pq(&mut self, leaf: [u8; 32]) {
        let cm = crate::crypto::pq::commitment_pq::NoteCommitmentPQ(leaf);
        self.local_tree.append(&cm);
    }

    /// v2.7.4 Phase C — Raw leaf bytes at the given position in the local
    /// V2 tree. Returns `None` if the position is past the wallet's tree
    /// (caller should refresh via `sync_local_tree_pq` and retry).
    pub fn local_leaf_at_v2(&self, position: u64) -> Option<[u8; 32]> {
        self.local_tree.leaf_at(position)
    }
}

impl ShieldedWallet {
    /// Generate a new random wallet.
    pub fn generate() -> Self {
        let keypair = KeyPair::generate();
        let secret_bytes = keypair.secret_key_bytes();

        let nullifier_key = NullifierKey::new(&secret_bytes);
        let viewing_key = ViewingKey::new(&secret_bytes);
        let pk_hash = compute_pk_hash(&keypair.public_key_bytes());

        Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes: Vec::new(),
            last_scanned_height: 0,
            tx_history: Vec::new(),
            db: None,
            local_tree: crate::crypto::pq::merkle_pq::CommitmentTreePQ::new(),
        }
    }

    /// Generate a wallet deterministically from a 32-byte seed.
    /// The same seed always produces the same wallet (same keys, same address).
    /// Used for BIP39 seed phrase recovery.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let keypair = KeyPair::from_seed(seed);
        let secret_bytes = keypair.secret_key_bytes();

        let nullifier_key = NullifierKey::new(&secret_bytes);
        let viewing_key = ViewingKey::new(&secret_bytes);
        let pk_hash = compute_pk_hash(&keypair.public_key_bytes());

        Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes: Vec::new(),
            last_scanned_height: 0,
            tx_history: Vec::new(),
            db: None,
            local_tree: crate::crypto::pq::merkle_pq::CommitmentTreePQ::new(),
        }
    }

    /// Load a wallet from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let data = std::fs::read_to_string(path).map_err(WalletError::IoError)?;
        let stored: StoredShieldedWallet =
            serde_json::from_str(&data).map_err(WalletError::ParseError)?;

        let public_key = hex::decode(&stored.public_key).map_err(|_| WalletError::InvalidKey)?;
        let secret_key = hex::decode(&stored.secret_key).map_err(|_| WalletError::InvalidKey)?;

        let keypair =
            KeyPair::from_bytes(&public_key, &secret_key).map_err(|_| WalletError::InvalidKey)?;

        let nullifier_key = NullifierKey::new(&secret_key);
        let viewing_key = ViewingKey::new(&secret_key);
        let pk_hash = compute_pk_hash(&public_key);

        // Load notes from stored data
        let notes = stored
            .notes
            .into_iter()
            .filter_map(|sn| {
                let note = Note::from_bytes(&hex::decode(&sn.note_data).ok()?).ok()?;
                let commitment = NoteCommitment::from_bytes(
                    hex::decode(&sn.commitment).ok()?.try_into().ok()?,
                );
                let pq_rand = sn.pq_randomness.and_then(|h| {
                    let b = hex::decode(&h).ok()?;
                    if b.len() == 32 { let mut a = [0u8;32]; a.copy_from_slice(&b); Some(a) } else { None }
                });
                let pq_cm = sn.pq_commitment.and_then(|h| {
                    let b = hex::decode(&h).ok()?;
                    if b.len() == 32 { let mut a = [0u8;32]; a.copy_from_slice(&b); Some(a) } else { None }
                });
                Some(WalletNote {
                    note,
                    commitment,
                    position: sn.position,
                    height: sn.height,
                    is_spent: sn.is_spent,
                    nullifier: None,
                    pq_randomness: pq_rand,
                    pq_commitment: pq_cm,
                })
            })
            .collect();

        Ok(Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes,
            last_scanned_height: stored.last_scanned_height,
            tx_history: stored.tx_history,
            db: None,
            local_tree: crate::crypto::pq::merkle_pq::CommitmentTreePQ::new(),
        })
    }

    /// Open a wallet from SQLite database, with automatic migration from JSON.
    ///
    /// This is the preferred entry point for v2.2.0+.
    /// - If wallet.db exists: opens it
    /// - If wallet.json exists but wallet.db does not: migrates to SQLite
    /// - If neither exists: returns an error
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let path = path.as_ref();

        // Determine DB and JSON paths
        let db_path = if path.extension().map_or(false, |e| e == "db") {
            path.to_path_buf()
        } else {
            path.with_extension("db")
        };

        let json_path = if path.extension().map_or(false, |e| e == "json") {
            path.to_path_buf()
        } else {
            path.with_extension("json")
        };

        let json_opt = if json_path.exists() { Some(json_path.as_path()) } else { None };
        let db = super::wallet_db::WalletDb::open_or_migrate(&db_path, json_opt)?;

        // v2.3.5: detect wallets from an older testnet and archive their
        // obsolete notes before loading. Previous testnets' notes are
        // unspendable on the current chain (different genesis, different
        // commitment tree) — carrying them forward would just display a
        // confusing "fake balance" that the user cannot actually send.
        // Keys are preserved; only the note set + tx history are cleared
        // and the scan cursor is reset to 0.
        {
            let current = crate::config::NETWORK_NAME;
            let stored = db.network_name().unwrap_or_default();
            if stored.is_empty() {
                // Pre-v2.3.5 wallet: record the current network but do not
                // archive (notes pre-reset are already lost on the chain
                // side; nothing to do here on this first-touch path).
                let _ = db.set_network_name(current);
            } else if stored != current {
                tracing::warn!(
                    "Wallet network mismatch: recorded '{}', current '{}'. Archiving old notes and tx history.",
                    stored,
                    current
                );
                db.archive_for_network_reset(current)?;
            }
        }

        // Load keys from database
        let (_, public_key, secret_key, pk_hash) = db.load_keys()
            .and_then(|opt| opt.ok_or(WalletError::InvalidKey))?;

        let keypair = KeyPair::from_bytes(&public_key, &secret_key)
            .map_err(|_| WalletError::InvalidKey)?;

        let nullifier_key = NullifierKey::new(&secret_key);
        let viewing_key = ViewingKey::new(&secret_key);

        // Load notes from database
        let raw_notes = db.all_notes_raw()?;
        let notes = raw_notes.into_iter().filter_map(|(note_data, commitment, position, height, is_spent, pq_rand, pq_cm)| {
            let note = Note::from_bytes(&note_data).ok()?;
            let cm = NoteCommitment::from_bytes(commitment);
            let mut wn = WalletNote::new(note, cm, position, height);
            wn.is_spent = is_spent;
            wn.pq_randomness = pq_rand;
            wn.pq_commitment = pq_cm;
            Some(wn)
        }).collect();

        let last_scanned_height = db.last_scanned_height()?;
        let tx_history = db.tx_history(10000)?; // load all

        // v2.7.4 Phase C — try to restore the local commitment tree from
        // its persisted snapshot. If the wallet has none yet (first run on
        // this network) we start with an empty tree; the next scan will
        // rebuild it leaf-by-leaf.
        let local_tree = match db.load_tree_snapshot() {
            Ok(Some(snap)) => crate::crypto::pq::merkle_pq::CommitmentTreePQ::from_snapshot(snap),
            _ => crate::crypto::pq::merkle_pq::CommitmentTreePQ::new(),
        };

        Ok(Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes,
            last_scanned_height,
            tx_history,
            db: Some(db),
            local_tree,
        })
    }

    /// Open a wallet from SQLite, or create a new one if nothing exists.
    pub fn open_or_create<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let db_path = if path.extension().map_or(false, |e| e == "db") {
            path.to_path_buf()
        } else {
            path.with_extension("db")
        };
        let json_path = if path.extension().map_or(false, |e| e == "json") {
            path.to_path_buf()
        } else {
            path.with_extension("json")
        };

        // If DB or JSON exists, delegate to open()
        if db_path.exists() || json_path.exists() {
            return Self::open(path);
        }

        // Create new wallet with SQLite backend
        let mut wallet = Self::generate();
        let db = super::wallet_db::WalletDb::open(&db_path)?;
        db.store_keys(
            &wallet.address().to_hex(),
            &wallet.keypair.public_key_bytes(),
            &wallet.keypair.secret_key_bytes(),
            &wallet.pk_hash,
        )?;
        // v2.3.5: tag the fresh wallet with the current network.
        db.set_network_name(crate::config::NETWORK_NAME)?;
        wallet.db = Some(db);
        Ok(wallet)
    }

    /// Persist current in-memory notes to the SQLite database.
    /// Called after scan_block or other operations that modify notes.
    pub fn persist_to_db(&self) -> Result<(), WalletError> {
        let db = self.db.as_ref().ok_or_else(|| WalletError::DbError("No database backend".into()))?;

        let batch: Vec<_> = self.notes.iter().map(|wn| {
            let note_data = wn.note.to_bytes();
            let commitment = wn.commitment.to_bytes();
            (note_data, commitment, wn.position, wn.height, wn.pq_randomness, wn.pq_commitment)
        }).collect();

        db.insert_notes_batch(&batch, self.last_scanned_height)?;

        // Sync spent status
        for wn in &self.notes {
            if wn.is_spent {
                db.mark_spent_by_commitment(&wn.commitment.to_bytes())?;
            }
        }

        // v2.7.4 Phase C — persist the local commitment-tree snapshot so
        // the next CLI invocation reuses it instead of bulk-pulling every
        // leaf from genesis.
        //
        // Guard: only overwrite the persisted snapshot when the in-memory
        // tree is at least as large as what's already on disk. Otherwise a
        // mining process whose local_tree was never populated would reset
        // the wallet's bootstrapped tree on every save, defeating the
        // whole point of persistence.
        let in_mem_size = self.local_tree.size();
        if in_mem_size > 0 {
            let persisted_size = db
                .load_tree_snapshot()
                .ok()
                .flatten()
                .map(|s| s.size)
                .unwrap_or(0);
            if in_mem_size >= persisted_size {
                let snap = self.local_tree.snapshot();
                if let Err(e) = db.save_tree_snapshot(&snap) {
                    tracing::warn!("failed to save tree snapshot: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Check if this wallet has a SQLite database backend.
    pub fn has_db(&self) -> bool {
        self.db.is_some()
    }

    /// Get reference to the database backend (if available).
    pub fn db(&self) -> Option<&super::wallet_db::WalletDb> {
        self.db.as_ref()
    }

    /// Flush the WAL checkpoint (for graceful shutdown).
    pub fn flush_db(&self) -> Result<(), WalletError> {
        if let Some(ref db) = self.db {
            db.flush()?;
        }
        Ok(())
    }

    /// Save the wallet state.
    /// If a SQLite backend is available, persists to database.
    /// Otherwise falls back to atomic JSON file write.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), WalletError> {
        // Prefer SQLite if available
        if self.db.is_some() {
            return self.persist_to_db();
        }
        let stored_notes: Vec<StoredNote> = self
            .notes
            .iter()
            .map(|wn| StoredNote {
                note_data: hex::encode(wn.note.to_bytes()),
                commitment: hex::encode(wn.commitment.to_bytes()),
                position: wn.position,
                height: wn.height,
                is_spent: wn.is_spent,
                pq_randomness: wn.pq_randomness.map(|r| hex::encode(r)),
                pq_commitment: wn.pq_commitment.map(|c| hex::encode(c)),
            })
            .collect();

        let stored = StoredShieldedWallet {
            address: self.address().to_hex(),
            public_key: hex::encode(self.keypair.public_key_bytes()),
            secret_key: hex::encode(self.keypair.secret_key_bytes()),
            pk_hash: hex::encode(self.pk_hash),
            notes: stored_notes,
            last_scanned_height: self.last_scanned_height,
            tx_history: self.tx_history.clone(),
        };

        let data =
            serde_json::to_string_pretty(&stored).map_err(|e| WalletError::ParseError(e))?;

        // Atomic write: write to temp file then rename (prevents corruption on crash)
        let path = path.as_ref();
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, &data).map_err(WalletError::IoError)?;
        std::fs::rename(&tmp, path).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the wallet's public key hash (for receiving notes).
    pub fn pk_hash(&self) -> [u8; 32] {
        self.pk_hash
    }

    /// Get the signing keypair.
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Get the viewing key.
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// Get the nullifier key.
    pub fn nullifier_key(&self) -> &NullifierKey {
        &self.nullifier_key
    }

    /// Get the nullifier key as raw bytes (for PQ proof witnesses).
    pub fn nullifier_key_bytes(&self) -> [u8; 32] {
        use blake2::Digest;
        use blake2::Blake2s256;
        let mut hasher = Blake2s256::new();
        hasher.update(b"tsn_nullifier_key");
        hasher.update(self.keypair.secret_key_bytes());
        hasher.finalize().into()
    }

    /// Get the current balance (sum of unspent notes).
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.is_spent)
            .map(|n| n.note.value)
            .sum()
    }

    /// Get unspent notes.
    pub fn unspent_notes(&self) -> Vec<&WalletNote> {
        self.notes.iter().filter(|n| !n.is_spent).collect()
    }

    /// v2.8.4 Phase 1 (Iron Fish core): notes that are confirmed enough to spend.
    /// A note is spendable iff it is unspent AND `note.height + MIN_SPEND_CONFIRMATIONS <= chain_tip_height`.
    /// Use this in place of `unspent_notes()` when selecting notes to send,
    /// so a reorg of depth <= MIN_SPEND_CONFIRMATIONS cannot invalidate the
    /// anchor used by an in-flight transaction.
    pub fn spendable_notes(&self, chain_tip_height: u64) -> Vec<&WalletNote> {
        let max_height = chain_tip_height
            .saturating_sub(crate::config::MIN_SPEND_CONFIRMATIONS);
        self.notes
            .iter()
            .filter(|n| !n.is_spent && n.height <= max_height)
            .collect()
    }

    /// v2.8.4 Phase 1: balance restricted to notes meeting the spendable
    /// confirmation threshold. Useful for `tsn balance` UX so users see what
    /// they can actually send right now (vs `balance()` which counts every
    /// unspent note including the just-mined one at the tip).
    pub fn spendable_balance(&self, chain_tip_height: u64) -> u64 {
        let max_height = chain_tip_height
            .saturating_sub(crate::config::MIN_SPEND_CONFIRMATIONS);
        self.notes
            .iter()
            .filter(|n| !n.is_spent && n.height <= max_height)
            .map(|n| n.note.value)
            .sum()
    }

    /// Get all notes.
    pub fn notes(&self) -> &[WalletNote] {
        &self.notes
    }

    /// Mutable access to notes (for marking spent).
    pub fn notes_mut(&mut self) -> &mut Vec<WalletNote> {
        &mut self.notes
    }

    /// Clear all notes (for rescanning from scratch).
    ///
    /// v2.3.2: also DELETE rows from the SQLite backend if one is attached.
    /// Previously this only cleared the in-memory `notes` Vec and reset the
    /// scan height; a subsequent `save()` would call `insert_notes_batch`
    /// with an empty slice which does NOT remove existing rows, so the DB
    /// kept all the stale notes. The interactive "Rescan wallet" menu and
    /// the `POST /wallet/rescan` HTTP endpoint both looked like they
    /// worked but left the database unchanged.
    pub fn clear_notes(&mut self) {
        self.notes.clear();
        self.last_scanned_height = 0;
        if let Some(ref db) = self.db {
            if let Err(e) = db.clear_notes() {
                tracing::error!("clear_notes: failed to clear notes in DB: {}", e);
            }
        }
    }

    /// Add a transaction to the wallet history.
    pub fn add_tx(&mut self, record: WalletTxRecord) {
        // Don't add duplicates
        if !self.tx_history.iter().any(|t| t.tx_hash == record.tx_hash) {
            self.tx_history.push(record);
        }
    }

    /// Get the transaction history.
    pub fn tx_history(&self) -> &[WalletTxRecord] {
        &self.tx_history
    }

    /// Get the number of unspent notes.
    pub fn unspent_count(&self) -> usize {
        self.notes.iter().filter(|n| !n.is_spent).count()
    }

    /// Alias for unspent_count.
    pub fn note_count(&self) -> usize {
        self.unspent_count()
    }

    /// v2.7.4 Phase C — Append every V2 commitment in `block` to the
    /// wallet's local Poseidon/Goldilocks tree, in the *exact same order*
    /// as `ShieldedState::apply_transaction_v2` + `apply_coinbase`. Run this
    /// once per block as it is scanned so the wallet's tree mirrors the
    /// network's. The wallet can then generate its own Merkle witnesses
    /// without calling the node's `/witness/v2/position/{N}` endpoint.
    pub fn append_block_pq_commitments(&mut self, block: &ShieldedBlock) {
        use crate::crypto::pq::commitment_pq::NoteCommitmentPQ;

        // (1) V2 transactions, output by output (matches state.rs:399-406).
        for tx in &block.transactions_v2 {
            for output in &tx.outputs {
                let cm = NoteCommitmentPQ(output.note_commitment);
                self.local_tree.append(&cm);
            }
        }

        // (2) Coinbase miner reward (matches state.rs:428-429).
        let cb_cm = NoteCommitmentPQ(block.coinbase.note_commitment_pq);
        self.local_tree.append(&cb_cm);

        // (3) Optional dev-fee output (matches state.rs:440-443).
        if let Some(dev_cm_pq) = block.coinbase.dev_fee_commitment_pq {
            let cm = NoteCommitmentPQ(dev_cm_pq);
            self.local_tree.append(&cm);
        }
    }

    /// v2.7.4 Phase C — Local Merkle witness for a known leaf position. Used
    /// by `cmd_send` to skip the network round-trip; equivalent to GET
    /// `/witness/v2/position/{position}` but served entirely from the
    /// wallet's in-memory tree.
    pub fn local_witness_v2(
        &self,
        position: u64,
    ) -> Option<crate::crypto::pq::merkle_pq::MerkleWitnessPQ> {
        self.local_tree.witness(position)
    }

    /// v2.7.4 Phase C — Current root of the wallet's local commitment tree,
    /// to be used as the anchor for newly built V2 transactions.
    pub fn local_anchor_v2(&self) -> [u8; 32] {
        // TreeHashPQ is already `[u8; 32]`.
        self.local_tree.root()
    }

    /// v2.7.4 Phase C — Number of leaves currently in the local tree.
    pub fn local_tree_size(&self) -> u64 {
        self.local_tree.size()
    }

    /// v2.8.4 Phase 1 (Iron Fish core): drop the locally-built commitment tree
    /// so the next `sync_local_tree_pq` rebuilds it from scratch. Called when
    /// a chain reorg is detected during `cmd_send` and the local tree may
    /// contain leaves from an abandoned fork. Phase 2 (BridgeTree) will
    /// replace this with a checkpoint-based rewind to avoid the full re-sync.
    pub fn reset_local_tree(&mut self) {
        self.local_tree.reset();
    }

    /// v2.8.0 — Replace the wallet's local commitment tree with the one
    /// reconstructed from a signed chain snapshot. Used by the bootstrap
    /// path so the wallet starts with a tree of size N matching the chain
    /// instead of pulling N leaves one batch at a time.
    pub fn restore_local_tree_from_snapshot(
        &mut self,
        snap: crate::crypto::pq::merkle_pq::CommitmentTreeSnapshot,
    ) {
        self.local_tree =
            crate::crypto::pq::merkle_pq::CommitmentTreePQ::from_snapshot(snap);
    }

    /// Scan a block for incoming notes.
    /// Returns the number of new notes discovered.
    pub fn scan_block(&mut self, block: &ShieldedBlock, start_position: u64) -> usize {
        let height = block.height();
        let mut position = start_position;
        let mut new_notes = 0;

        // Create decryption key from our pk_hash (matches how notes are encrypted)
        let decryption_key = ViewingKey::from_pk_hash(self.pk_hash);

        // Scan transaction outputs
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(note) = decryption_key.decrypt_note(&output.encrypted_note) {
                    // Check if this note is for us
                    if note.recipient_pk_hash == self.pk_hash {
                        let wallet_note = WalletNote::new(
                            note,
                            output.note_commitment,
                            position,
                            height,
                        );
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
                position += 1;
            }
        }

        // Scan V2 transaction outputs (post-quantum)
        for tx in &block.transactions_v2 {
            for output in &tx.outputs {
                if let Some((value, pk_hash, pq_rand)) = decrypt_note_pq(&output.encrypted_note, &self.pk_hash) {
                    if pk_hash == self.pk_hash {
                        let note = Note::with_randomness(value, pk_hash, ark_bn254::Fr::from(0u64));
                        let dummy_commitment = note.commitment();
                        let mut wallet_note = WalletNote::new(
                            note,
                            dummy_commitment,
                            position,
                            height,
                        );
                        wallet_note.pq_randomness = Some(pq_rand);
                        wallet_note.pq_commitment = Some(output.note_commitment);
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
                position += 1;
            }
        }

        // Scan coinbase (miner reward) — extract both V1 and PQ data
        if let Some(note) = decryption_key.decrypt_note(&block.coinbase.encrypted_note) {
            if note.recipient_pk_hash == self.pk_hash {
                let mut wallet_note = WalletNote::new(
                    note,
                    block.coinbase.note_commitment,
                    position,
                    height,
                );
                // Also extract PQ data for V2 spending
                if let Some((_, _, pq_rand)) = decrypt_note_pq(&block.coinbase.encrypted_note, &self.pk_hash) {
                    wallet_note.pq_randomness = Some(pq_rand);
                    wallet_note.pq_commitment = Some(block.coinbase.note_commitment_pq);
                }
                self.notes.push(wallet_note);
                new_notes += 1;
            }
        }

        // Scan coinbase dev fee note (in case this wallet is the treasury)
        if let Some(ref encrypted) = block.coinbase.dev_fee_encrypted_note {
            if let Some(note) = decryption_key.decrypt_note(encrypted) {
                if note.recipient_pk_hash == self.pk_hash {
                    if let Some(ref cm) = block.coinbase.dev_fee_commitment {
                        let wallet_note = WalletNote::new(note, *cm, position + 1, height);
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
            }
        }

        self.last_scanned_height = height;
        new_notes
    }

    /// Scan a single encrypted output (from /outputs/since API) and add if it belongs to us.
    /// Returns true if the note was added to the wallet.
    pub fn scan_encrypted_output(
        &mut self,
        encrypted_note: &crate::crypto::note::EncryptedNote,
        note_commitment_hex: &str,
        note_commitment_pq_hex: &str,
        position: u64,
        height: u64,
    ) -> bool {
        let decryption_key = ViewingKey::from_pk_hash(self.pk_hash);

        // Try V1 decryption first
        if let Some(note) = decryption_key.decrypt_note(encrypted_note) {
            if note.recipient_pk_hash == self.pk_hash {
                // Parse V1 commitment from hex (server-provided, matches merkle tree)
                let commitment = if !note_commitment_hex.is_empty() {
                    if let Ok(bytes) = hex::decode(note_commitment_hex) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            NoteCommitment(arr)
                        } else {
                            note.commitment()
                        }
                    } else {
                        note.commitment()
                    }
                } else {
                    note.commitment()
                };

                let mut wallet_note = WalletNote::new(note, commitment, position, height);

                // Also extract PQ data if available
                if let Some((_, _, pq_rand)) = decrypt_note_pq(encrypted_note, &self.pk_hash) {
                    wallet_note.pq_randomness = Some(pq_rand);
                    if !note_commitment_pq_hex.is_empty() {
                        if let Ok(bytes) = hex::decode(note_commitment_pq_hex) {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                wallet_note.pq_commitment = Some(arr);
                            }
                        }
                    }
                }

                self.notes.push(wallet_note);
                return true;
            }
        }

        // Try PQ-only decryption (V2 transactions)
        if let Some((value, pk_hash, pq_rand)) = decrypt_note_pq(encrypted_note, &self.pk_hash) {
            if pk_hash == self.pk_hash {
                let note = Note::with_randomness(value, pk_hash, ark_bn254::Fr::from(0u64));
                let dummy_commitment = note.commitment();
                let mut wallet_note = WalletNote::new(note, dummy_commitment, position, height);
                wallet_note.pq_randomness = Some(pq_rand);
                if !note_commitment_pq_hex.is_empty() {
                    if let Ok(bytes) = hex::decode(note_commitment_pq_hex) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            wallet_note.pq_commitment = Some(arr);
                        }
                    }
                }
                self.notes.push(wallet_note);
                return true;
            }
        }

        false
    }

    /// Mark notes as spent based on observed nullifiers.
    pub fn mark_spent_nullifiers(&mut self, nullifiers: &[Nullifier]) {
        for note in &mut self.notes {
            if !note.is_spent {
                let nf = note.nullifier(&self.nullifier_key);
                if nullifiers.contains(&nf) {
                    note.mark_spent();
                }
            }
        }
    }

    /// Get the last scanned block height.
    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }

    /// Set the last scanned block height (for external scanning via API).
    pub fn set_last_scanned_height(&mut self, height: u64) {
        self.last_scanned_height = height;
    }

    /// v2.5.4 — read the genesis_hash the wallet last synced against.
    /// Returns `Err` or empty string if the wallet has no SQLite backend
    /// (pre-v2.2.0 JSON wallets) or the field is not yet set.
    pub fn db_genesis_hash(&self) -> Result<String, WalletError> {
        match &self.db {
            Some(db) => db.genesis_hash(),
            None => Ok(String::new()),
        }
    }

    /// v2.5.4 — persist the genesis_hash seen on the last successful scan.
    /// Used by `try_scan_via_api` to detect local data/ wipes (new chain
    /// under the same network_name) and archive stale notes automatically.
    pub fn set_db_genesis_hash(&self, hash: &str) -> Result<(), WalletError> {
        match &self.db {
            Some(db) => db.set_genesis_hash(hash),
            None => Ok(()),
        }
    }

    /// v2.5.4 — highest `position` held across all unspent notes. Used as
    /// a rollback detector: if the current chain has fewer commitments
    /// than this value, some of our notes reference leaves that no longer
    /// exist in the tree and would 404 on witness fetch.
    pub fn unspent_note_max_position(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.is_spent)
            .map(|n| n.position)
            .max()
            .unwrap_or(0)
    }

    /// Export viewing key as hex string for sharing with third parties.
    ///
    /// The viewing key allows scanning the blockchain for incoming notes
    /// without granting spending capability.
    pub fn export_viewing_key(&self) -> String {
        hex::encode(self.viewing_key.to_bytes())
    }

    /// Create a watch-only wallet from an imported viewing key.
    ///
    /// A watch-only wallet can scan blocks and compute balances but cannot
    /// spend notes because it lacks the signing keypair and nullifier key.
    pub fn from_viewing_key(vk_hex: &str) -> Result<Self, WalletError> {
        let vk_bytes = hex::decode(vk_hex).map_err(|_| WalletError::InvalidKey)?;
        if vk_bytes.len() != 32 {
            return Err(WalletError::InvalidKey);
        }
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(&vk_bytes);

        let viewing_key = ViewingKey::from_bytes(vk_arr);

        // For a watch-only wallet we generate a throwaway keypair.
        // The pk_hash is derived from the viewing key itself so that
        // `scan_block_view_only` can attempt decryption using it.
        let keypair = KeyPair::generate();
        let nullifier_key = NullifierKey::new(&[0u8; 32]);

        // The viewing secret doubles as the pk_hash for decryption in the
        // watch-only context (ViewingKey::from_pk_hash uses pk_hash directly).
        let pk_hash = vk_arr;

        Ok(Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes: Vec::new(),
            last_scanned_height: 0,
            tx_history: Vec::new(),
            db: None,
            local_tree: crate::crypto::pq::merkle_pq::CommitmentTreePQ::new(),
        })
    }

    /// Scan a block using only the viewing key (no spending capability).
    ///
    /// This is used by watch-only wallets to discover incoming notes.
    /// Discovered notes can be viewed but not spent because the watch-only
    /// wallet lacks the nullifier key and signing keypair.
    pub fn scan_block_view_only(&self, block: &ShieldedBlock) -> Vec<WalletNote> {
        let height = block.height();
        let mut found = Vec::new();
        let mut position = 0u64;

        // Decrypt using our viewing key (which is pk_hash-based)
        let decryption_key = ViewingKey::from_pk_hash(self.pk_hash);

        // Scan transaction outputs
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(note) = decryption_key.decrypt_note(&output.encrypted_note) {
                    if note.recipient_pk_hash == self.pk_hash {
                        let wallet_note = WalletNote::new(
                            note,
                            output.note_commitment,
                            position,
                            height,
                        );
                        found.push(wallet_note);
                    }
                }
                position += 1;
            }
        }

        // Scan coinbase
        if let Some(note) = decryption_key.decrypt_note(&block.coinbase.encrypted_note) {
            if note.recipient_pk_hash == self.pk_hash {
                let wallet_note = WalletNote::new(
                    note,
                    block.coinbase.note_commitment,
                    position,
                    height,
                );
                found.push(wallet_note);
            }
        }

        found
    }
}

/// A recorded transaction in the wallet history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletTxRecord {
    pub tx_hash: String,
    pub direction: String, // "sent" or "received"
    pub amount: u64,       // in base units
    pub fee: u64,
    pub counterparty: String, // pk_hash of recipient (sent) or sender (received, if known)
    pub height: u64,       // block height (0 = pending)
    pub timestamp: u64,    // unix timestamp
}

/// Stored wallet format for serialization (JSON legacy + migration).
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredShieldedWallet {
    pub address: String,
    pub public_key: String,
    pub secret_key: String,
    pub pk_hash: String,
    pub notes: Vec<StoredNote>,
    pub last_scanned_height: u64,
    #[serde(default)]
    pub tx_history: Vec<WalletTxRecord>,
}

/// Stored note format (JSON legacy + migration).
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredNote {
    pub note_data: String,
    pub commitment: String,
    pub position: u64,
    pub height: u64,
    pub is_spent: bool,
    #[serde(default)]
    pub pq_randomness: Option<String>,
    #[serde(default)]
    pub pq_commitment: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("IO error: {0}")]
    IoError(#[source] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(#[source] serde_json::Error),

    #[error("Invalid key data")]
    InvalidKey,

    #[error("Lock error: {0}")]
    LockError(String),

    #[error("Database error: {0}")]
    DbError(String),

    #[error("Migration error: {0}")]
    MigrationError(String),
}

/// File lock for exclusive wallet access.
/// Prevents concurrent processes from corrupting wallet data.
/// The lock is released automatically when dropped (fd close).
pub struct WalletLock {
    _file: std::fs::File,
}

impl WalletLock {
    /// Acquire an exclusive lock on the wallet file.
    /// Blocks until the lock is available.
    pub fn acquire<P: AsRef<Path>>(wallet_path: P) -> Result<Self, WalletError> {
        use std::os::unix::io::AsRawFd;

        let lock_path = wallet_path.as_ref().with_extension("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(WalletError::IoError)?;

        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(WalletError::LockError(format!(
                "flock failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { _file: file })
    }

    /// Try to acquire the lock without blocking.
    /// Returns None if the lock is held by another process.
    pub fn try_acquire<P: AsRef<Path>>(wallet_path: P) -> Result<Option<Self>, WalletError> {
        use std::os::unix::io::AsRawFd;

        let lock_path = wallet_path.as_ref().with_extension("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(WalletError::IoError)?;

        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(WalletError::LockError(format!("flock failed: {}", err)));
        }

        Ok(Some(Self { _file: file }))
    }
}

// ============================================================================
// Legacy Wallet Support
// ============================================================================

use crate::core::LegacyTransaction;

/// Legacy wallet for backwards compatibility.
#[derive(Clone)]
pub struct LegacyWallet {
    keypair: KeyPair,
}

impl LegacyWallet {
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate(),
        }
    }

    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn create_transaction(
        &self,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> LegacyTransaction {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.keypair.address().as_bytes());
        msg.extend_from_slice(to.as_bytes());
        msg.extend_from_slice(&amount.to_le_bytes());
        msg.extend_from_slice(&fee.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());

        LegacyTransaction {
            from: self.keypair.address(),
            to,
            amount,
            fee,
            nonce,
            public_key: self.keypair.public_key_bytes().to_vec(),
            signature: Some(sign(&msg, &self.keypair)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_wallet() {
        let wallet = ShieldedWallet::generate();
        assert!(!wallet.address().is_zero());
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn test_wallet_keys() {
        let wallet = ShieldedWallet::generate();

        // pk_hash should be deterministic from public key
        let expected_pk_hash = compute_pk_hash(&wallet.keypair.public_key_bytes());
        assert_eq!(wallet.pk_hash(), expected_pk_hash);
    }

    #[test]
    fn test_save_and_load_wallet() {
        let wallet = ShieldedWallet::generate();
        let original_address = wallet.address();
        let original_pk_hash = wallet.pk_hash();

        let temp_file = NamedTempFile::new().unwrap();
        wallet.save(temp_file.path()).unwrap();

        let loaded = ShieldedWallet::load(temp_file.path()).unwrap();
        assert_eq!(loaded.address(), original_address);
        assert_eq!(loaded.pk_hash(), original_pk_hash);
    }

    #[test]
    fn test_note_discovery() {
        use crate::crypto::commitment::NoteCommitment;

        let mut wallet = ShieldedWallet::generate();

        // Create a note for this wallet
        let mut rng = ark_std::rand::thread_rng();
        let note = Note::new(1000, wallet.pk_hash(), &mut rng);
        let _commitment = note.commitment();

        // Create a mock encrypted note using pk_hash (new encryption scheme)
        let encryption_key = ViewingKey::from_pk_hash(wallet.pk_hash());
        let encrypted = encryption_key.encrypt_note(&note, &mut rng);

        // Try to decrypt using pk_hash
        let decryption_key = ViewingKey::from_pk_hash(wallet.pk_hash());
        let decrypted = decryption_key.decrypt_note(&encrypted).unwrap();
        assert_eq!(decrypted.value, 1000);
        assert_eq!(decrypted.recipient_pk_hash, wallet.pk_hash());
    }

    #[test]
    fn test_balance_calculation() {
        let mut wallet = ShieldedWallet::generate();

        // Add some fake notes
        let mut rng = ark_std::rand::thread_rng();
        for value in [100, 200, 300] {
            let note = Note::new(value, wallet.pk_hash(), &mut rng);
            let commitment = note.commitment();
            wallet.notes.push(WalletNote::new(note, commitment, 0, 0));
        }

        assert_eq!(wallet.balance(), 600);
        assert_eq!(wallet.unspent_count(), 3);

        // Mark one as spent
        wallet.notes[0].mark_spent();
        assert_eq!(wallet.balance(), 500);
        assert_eq!(wallet.unspent_count(), 2);
    }

}
