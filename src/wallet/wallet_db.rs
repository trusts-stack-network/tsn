//! SQLite-backed wallet database.
//!
//! Replaces the JSON file approach with a crash-safe SQLite WAL database.
//! Provides atomic writes, concurrent reader support, and automatic migration
//! from the legacy wallet.json format.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

use super::wallet::{StoredShieldedWallet, StoredNote, WalletError, WalletTxRecord};

/// SQLite wallet database with WAL mode for crash safety.
pub struct WalletDb {
    conn: Connection,
    path: PathBuf,
}

impl WalletDb {
    /// Open or create a wallet database at the given path.
    pub fn open(path: &Path) -> Result<Self, WalletError> {
        let conn = Connection::open(path)
            .map_err(|e| WalletError::DbError(format!("Failed to open wallet DB: {}", e)))?;

        // Enable WAL mode for crash safety and concurrent reads
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             PRAGMA foreign_keys=ON;"
        ).map_err(|e| WalletError::DbError(format!("Failed to set pragmas: {}", e)))?;

        let db = Self {
            conn,
            path: path.to_path_buf(),
        };
        db.create_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, WalletError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WalletError::DbError(format!("Failed to open in-memory DB: {}", e)))?;

        let db = Self {
            conn,
            path: PathBuf::from(":memory:"),
        };
        db.create_schema()?;
        Ok(db)
    }

    /// Open a wallet database, migrating from JSON if needed.
    /// If wallet.db exists, open it directly.
    /// If wallet.json exists but wallet.db does not, migrate.
    pub fn open_or_migrate(db_path: &Path, json_path: Option<&Path>) -> Result<Self, WalletError> {
        if db_path.exists() {
            return Self::open(db_path);
        }

        // Try to migrate from JSON
        if let Some(json_path) = json_path {
            if json_path.exists() {
                tracing::info!("Migrating wallet from JSON to SQLite...");
                let db = Self::open(db_path)?;
                db.migrate_from_json(json_path)?;

                // Rename old JSON file (keep as backup, don't delete)
                let migrated_path = json_path.with_extension("json.migrated");
                if let Err(e) = std::fs::rename(json_path, &migrated_path) {
                    tracing::warn!("Could not rename old wallet.json: {}", e);
                } else {
                    tracing::info!("Old wallet.json renamed to {}", migrated_path.display());
                }

                tracing::info!("Wallet migration complete: {}", db_path.display());
                return Ok(db);
            }
        }

        // No existing wallet — create fresh DB
        Self::open(db_path)
    }

    fn create_schema(&self) -> Result<(), WalletError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS wallet_keys (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                address     TEXT NOT NULL,
                public_key  BLOB NOT NULL,
                secret_key  BLOB NOT NULL,
                pk_hash     BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                note_data       BLOB NOT NULL,
                commitment      BLOB NOT NULL UNIQUE,
                position        INTEGER NOT NULL,
                height          INTEGER NOT NULL,
                is_spent        INTEGER NOT NULL DEFAULT 0,
                nullifier       BLOB,
                pq_randomness   BLOB,
                pq_commitment   BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_notes_unspent
                ON notes (is_spent) WHERE is_spent = 0;
            CREATE INDEX IF NOT EXISTS idx_notes_height
                ON notes (height);

            CREATE TABLE IF NOT EXISTS tx_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash       TEXT NOT NULL UNIQUE,
                direction     TEXT NOT NULL,
                amount        INTEGER NOT NULL,
                fee           INTEGER NOT NULL,
                counterparty  TEXT NOT NULL,
                height        INTEGER NOT NULL,
                timestamp     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_state (
                id                    INTEGER PRIMARY KEY CHECK (id = 1),
                last_scanned_height   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );
            INSERT OR IGNORE INTO schema_version VALUES (1);
            INSERT OR IGNORE INTO scan_state (id, last_scanned_height) VALUES (1, 0);"
        ).map_err(|e| WalletError::DbError(format!("Failed to create schema: {}", e)))?;

        // v2.3.5 schema v2: add network_name to scan_state so a wallet created
        // on an older testnet can be detected on open and its obsolete notes
        // archived. We use ALTER TABLE + default "" so existing DBs upgrade in
        // place without losing data; the caller (ShieldedWallet::open) then
        // decides what to do with a mismatch.
        let has_network_name: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM pragma_table_info('scan_state') WHERE name = 'network_name'",
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !has_network_name {
            self.conn
                .execute(
                    "ALTER TABLE scan_state ADD COLUMN network_name TEXT NOT NULL DEFAULT ''",
                    [],
                )
                .map_err(|e| WalletError::DbError(format!("Failed to add network_name column: {}", e)))?;
        }
        self.conn
            .execute("INSERT OR IGNORE INTO schema_version VALUES (2)", [])
            .map_err(|e| WalletError::DbError(format!("Failed to record schema v2: {}", e)))?;

        Ok(())
    }

    // ========================================================================
    // Key operations
    // ========================================================================

    /// Store wallet keys (exactly one row, id=1).
    pub fn store_keys(
        &self,
        address: &str,
        public_key: &[u8],
        secret_key: &[u8],
        pk_hash: &[u8; 32],
    ) -> Result<(), WalletError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wallet_keys (id, address, public_key, secret_key, pk_hash)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![address, public_key, secret_key, pk_hash.as_slice()],
        ).map_err(|e| WalletError::DbError(format!("Failed to store keys: {}", e)))?;
        Ok(())
    }

    /// Load wallet keys. Returns (address, public_key, secret_key, pk_hash).
    pub fn load_keys(&self) -> Result<Option<(String, Vec<u8>, Vec<u8>, [u8; 32])>, WalletError> {
        let result = self.conn.query_row(
            "SELECT address, public_key, secret_key, pk_hash FROM wallet_keys WHERE id = 1",
            [],
            |row| {
                let address: String = row.get(0)?;
                let public_key: Vec<u8> = row.get(1)?;
                let secret_key: Vec<u8> = row.get(2)?;
                let pk_hash_vec: Vec<u8> = row.get(3)?;
                Ok((address, public_key, secret_key, pk_hash_vec))
            },
        ).optional()
        .map_err(|e| WalletError::DbError(format!("Failed to load keys: {}", e)))?;

        match result {
            Some((address, pk, sk, pk_hash_vec)) => {
                if pk_hash_vec.len() != 32 {
                    return Err(WalletError::DbError("Invalid pk_hash length".into()));
                }
                let mut pk_hash = [0u8; 32];
                pk_hash.copy_from_slice(&pk_hash_vec);
                Ok(Some((address, pk, sk, pk_hash)))
            }
            None => Ok(None),
        }
    }

    /// Check if wallet keys exist in the database.
    pub fn has_keys(&self) -> bool {
        self.conn.query_row(
            "SELECT COUNT(*) FROM wallet_keys",
            [],
            |row| row.get::<_, i64>(0),
        ).unwrap_or(0) > 0
    }

    // ========================================================================
    // Note operations
    // ========================================================================

    /// Insert a note. Ignores duplicates (UNIQUE on commitment).
    pub fn insert_note(
        &self,
        note_data: &[u8],
        commitment: &[u8; 32],
        position: u64,
        height: u64,
        pq_randomness: Option<&[u8; 32]>,
        pq_commitment: Option<&[u8; 32]>,
    ) -> Result<bool, WalletError> {
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO notes (note_data, commitment, position, height, pq_randomness, pq_commitment)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                note_data,
                commitment.as_slice(),
                position as i64,
                height as i64,
                pq_randomness.map(|r| r.as_slice()),
                pq_commitment.map(|c| c.as_slice()),
            ],
        ).map_err(|e| WalletError::DbError(format!("Failed to insert note: {}", e)))?;
        Ok(rows > 0)
    }

    /// Insert multiple notes + update scan height in a single atomic transaction.
    pub fn insert_notes_batch(
        &self,
        notes: &[(Vec<u8>, [u8; 32], u64, u64, Option<[u8; 32]>, Option<[u8; 32]>)],
        new_height: u64,
    ) -> Result<usize, WalletError> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| WalletError::DbError(format!("Failed to start transaction: {}", e)))?;

        let mut inserted = 0;
        for (note_data, commitment, position, height, pq_rand, pq_cm) in notes {
            let rows = tx.execute(
                "INSERT OR IGNORE INTO notes (note_data, commitment, position, height, pq_randomness, pq_commitment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    note_data.as_slice(),
                    commitment.as_slice(),
                    *position as i64,
                    *height as i64,
                    pq_rand.as_ref().map(|r| r.as_slice()),
                    pq_cm.as_ref().map(|c| c.as_slice()),
                ],
            ).map_err(|e| WalletError::DbError(format!("Failed to insert note: {}", e)))?;
            inserted += rows;
        }

        tx.execute(
            "UPDATE scan_state SET last_scanned_height = MAX(last_scanned_height, ?1) WHERE id = 1",
            params![new_height as i64],
        ).map_err(|e| WalletError::DbError(format!("Failed to update scan height: {}", e)))?;

        tx.commit()
            .map_err(|e| WalletError::DbError(format!("Failed to commit batch: {}", e)))?;

        Ok(inserted)
    }

    /// Mark a note as spent by its commitment.
    pub fn mark_spent_by_commitment(&self, commitment: &[u8; 32]) -> Result<bool, WalletError> {
        let rows = self.conn.execute(
            "UPDATE notes SET is_spent = 1 WHERE commitment = ?1 AND is_spent = 0",
            params![commitment.as_slice()],
        ).map_err(|e| WalletError::DbError(format!("Failed to mark spent: {}", e)))?;
        Ok(rows > 0)
    }

    /// Mark a note as spent by its nullifier.
    pub fn mark_spent_by_nullifier(&self, nullifier: &[u8]) -> Result<bool, WalletError> {
        let rows = self.conn.execute(
            "UPDATE notes SET is_spent = 1 WHERE nullifier = ?1 AND is_spent = 0",
            params![nullifier],
        ).map_err(|e| WalletError::DbError(format!("Failed to mark spent by nullifier: {}", e)))?;
        Ok(rows > 0)
    }

    /// Store the computed nullifier for a note.
    pub fn set_nullifier(&self, commitment: &[u8; 32], nullifier: &[u8]) -> Result<(), WalletError> {
        self.conn.execute(
            "UPDATE notes SET nullifier = ?1 WHERE commitment = ?2",
            params![nullifier, commitment.as_slice()],
        ).map_err(|e| WalletError::DbError(format!("Failed to set nullifier: {}", e)))?;
        Ok(())
    }

    /// Get all unspent notes as raw data.
    /// Returns: (note_data, commitment, position, height, pq_randomness, pq_commitment)
    pub fn unspent_notes_raw(&self) -> Result<Vec<(Vec<u8>, [u8; 32], u64, u64, Option<[u8; 32]>, Option<[u8; 32]>)>, WalletError> {
        let mut stmt = self.conn.prepare(
            "SELECT note_data, commitment, position, height, pq_randomness, pq_commitment
             FROM notes WHERE is_spent = 0 ORDER BY height ASC"
        ).map_err(|e| WalletError::DbError(format!("Failed to prepare query: {}", e)))?;

        let rows = stmt.query_map([], |row| {
            let note_data: Vec<u8> = row.get(0)?;
            let cm_vec: Vec<u8> = row.get(1)?;
            let position: i64 = row.get(2)?;
            let height: i64 = row.get(3)?;
            let pq_rand: Option<Vec<u8>> = row.get(4)?;
            let pq_cm: Option<Vec<u8>> = row.get(5)?;
            Ok((note_data, cm_vec, position as u64, height as u64, pq_rand, pq_cm))
        }).map_err(|e| WalletError::DbError(format!("Failed to query notes: {}", e)))?;

        let mut result = Vec::new();
        for row in rows {
            let (note_data, cm_vec, position, height, pq_rand, pq_cm) = row
                .map_err(|e| WalletError::DbError(format!("Failed to read note row: {}", e)))?;

            if cm_vec.len() != 32 {
                continue; // skip corrupted entries
            }
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&cm_vec);

            let pq_randomness = pq_rand.and_then(|v| {
                if v.len() == 32 { let mut a = [0u8; 32]; a.copy_from_slice(&v); Some(a) } else { None }
            });
            let pq_commitment = pq_cm.and_then(|v| {
                if v.len() == 32 { let mut a = [0u8; 32]; a.copy_from_slice(&v); Some(a) } else { None }
            });

            result.push((note_data, commitment, position, height, pq_randomness, pq_commitment));
        }

        Ok(result)
    }

    /// Get all notes (spent and unspent) as raw data.
    pub fn all_notes_raw(&self) -> Result<Vec<(Vec<u8>, [u8; 32], u64, u64, bool, Option<[u8; 32]>, Option<[u8; 32]>)>, WalletError> {
        let mut stmt = self.conn.prepare(
            "SELECT note_data, commitment, position, height, is_spent, pq_randomness, pq_commitment
             FROM notes ORDER BY height ASC"
        ).map_err(|e| WalletError::DbError(format!("Failed to prepare query: {}", e)))?;

        let rows = stmt.query_map([], |row| {
            let note_data: Vec<u8> = row.get(0)?;
            let cm_vec: Vec<u8> = row.get(1)?;
            let position: i64 = row.get(2)?;
            let height: i64 = row.get(3)?;
            let is_spent: bool = row.get(4)?;
            let pq_rand: Option<Vec<u8>> = row.get(5)?;
            let pq_cm: Option<Vec<u8>> = row.get(6)?;
            Ok((note_data, cm_vec, position as u64, height as u64, is_spent, pq_rand, pq_cm))
        }).map_err(|e| WalletError::DbError(format!("Failed to query notes: {}", e)))?;

        let mut result = Vec::new();
        for row in rows {
            let (note_data, cm_vec, position, height, is_spent, pq_rand, pq_cm) = row
                .map_err(|e| WalletError::DbError(format!("Failed to read note row: {}", e)))?;

            if cm_vec.len() != 32 { continue; }
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&cm_vec);

            let pq_randomness = pq_rand.and_then(|v| {
                if v.len() == 32 { let mut a = [0u8; 32]; a.copy_from_slice(&v); Some(a) } else { None }
            });
            let pq_commitment = pq_cm.and_then(|v| {
                if v.len() == 32 { let mut a = [0u8; 32]; a.copy_from_slice(&v); Some(a) } else { None }
            });

            result.push((note_data, commitment, position, height, is_spent, pq_randomness, pq_commitment));
        }

        Ok(result)
    }

    /// Get total balance (sum of unspent note values).
    /// Note: this reads note_data to extract value, which is at bytes [0..8] (little-endian u64).
    pub fn balance(&self) -> Result<u64, WalletError> {
        let mut stmt = self.conn.prepare(
            "SELECT note_data FROM notes WHERE is_spent = 0"
        ).map_err(|e| WalletError::DbError(format!("Failed to prepare balance query: {}", e)))?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        }).map_err(|e| WalletError::DbError(format!("Failed to query balance: {}", e)))?;

        let mut total = 0u64;
        for row in rows {
            let data = row.map_err(|e| WalletError::DbError(format!("Failed to read row: {}", e)))?;
            if data.len() >= 8 {
                total += u64::from_le_bytes(data[0..8].try_into().unwrap());
            }
        }

        Ok(total)
    }

    /// Get count of unspent notes.
    pub fn unspent_count(&self) -> Result<usize, WalletError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM notes WHERE is_spent = 0",
            [],
            |row| row.get(0),
        ).map_err(|e| WalletError::DbError(format!("Failed to count notes: {}", e)))?;
        Ok(count as usize)
    }

    /// Get total note count (including spent).
    pub fn total_note_count(&self) -> Result<usize, WalletError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM notes",
            [],
            |row| row.get(0),
        ).map_err(|e| WalletError::DbError(format!("Failed to count notes: {}", e)))?;
        Ok(count as usize)
    }

    /// Clear all notes and reset scan height (for rescan).
    pub fn clear_notes(&self) -> Result<(), WalletError> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| WalletError::DbError(format!("Failed to start transaction: {}", e)))?;
        tx.execute("DELETE FROM notes", [])
            .map_err(|e| WalletError::DbError(format!("Failed to clear notes: {}", e)))?;
        tx.execute("UPDATE scan_state SET last_scanned_height = 0 WHERE id = 1", [])
            .map_err(|e| WalletError::DbError(format!("Failed to reset scan height: {}", e)))?;
        tx.commit()
            .map_err(|e| WalletError::DbError(format!("Failed to commit clear: {}", e)))?;
        Ok(())
    }

    // ========================================================================
    // Scan state
    // ========================================================================

    /// Get the last scanned block height.
    pub fn last_scanned_height(&self) -> Result<u64, WalletError> {
        let height: i64 = self.conn.query_row(
            "SELECT last_scanned_height FROM scan_state WHERE id = 1",
            [],
            |row| row.get(0),
        ).map_err(|e| WalletError::DbError(format!("Failed to get scan height: {}", e)))?;
        Ok(height as u64)
    }

    /// Set the last scanned block height.
    pub fn set_last_scanned_height(&self, height: u64) -> Result<(), WalletError> {
        self.conn.execute(
            "UPDATE scan_state SET last_scanned_height = ?1 WHERE id = 1",
            params![height as i64],
        ).map_err(|e| WalletError::DbError(format!("Failed to set scan height: {}", e)))?;
        Ok(())
    }

    /// v2.3.5: return the network this wallet was last synced against.
    /// Empty string for pre-v2.3.5 wallets that predate the network field.
    pub fn network_name(&self) -> Result<String, WalletError> {
        let name: String = self
            .conn
            .query_row(
                "SELECT network_name FROM scan_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| WalletError::DbError(format!("Failed to get network_name: {}", e)))?;
        Ok(name)
    }

    /// v2.3.5: record which network this wallet is synced against.
    pub fn set_network_name(&self, name: &str) -> Result<(), WalletError> {
        self.conn
            .execute(
                "UPDATE scan_state SET network_name = ?1 WHERE id = 1",
                params![name],
            )
            .map_err(|e| WalletError::DbError(format!("Failed to set network_name: {}", e)))?;
        Ok(())
    }

    /// v2.3.5: drop all notes and tx_history and reset the scan cursor. Keys
    /// are preserved. Called when the wallet's recorded network does not
    /// match the binary's current `config::NETWORK_NAME`: the old testnet's
    /// notes are unspendable on the new chain, so carrying them forward just
    /// produces confusing balances.
    pub fn archive_for_network_reset(&self, new_network: &str) -> Result<(), WalletError> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| WalletError::DbError(format!("Failed to begin archive tx: {}", e)))?;
        tx.execute("DELETE FROM notes", [])
            .map_err(|e| WalletError::DbError(format!("Failed to archive notes: {}", e)))?;
        tx.execute("DELETE FROM tx_history", [])
            .map_err(|e| WalletError::DbError(format!("Failed to archive tx_history: {}", e)))?;
        tx.execute(
            "UPDATE scan_state SET last_scanned_height = 0, network_name = ?1 WHERE id = 1",
            params![new_network],
        )
        .map_err(|e| WalletError::DbError(format!("Failed to reset scan_state: {}", e)))?;
        tx.commit()
            .map_err(|e| WalletError::DbError(format!("Failed to commit archive: {}", e)))?;
        Ok(())
    }

    // ========================================================================
    // Transaction history
    // ========================================================================

    /// Add a transaction record (ignores duplicates by tx_hash).
    pub fn add_tx(&self, record: &WalletTxRecord) -> Result<(), WalletError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO tx_history (tx_hash, direction, amount, fee, counterparty, height, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.tx_hash,
                record.direction,
                record.amount as i64,
                record.fee as i64,
                record.counterparty,
                record.height as i64,
                record.timestamp as i64,
            ],
        ).map_err(|e| WalletError::DbError(format!("Failed to add tx: {}", e)))?;
        Ok(())
    }

    /// Get transaction history, most recent first.
    pub fn tx_history(&self, limit: usize) -> Result<Vec<WalletTxRecord>, WalletError> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, direction, amount, fee, counterparty, height, timestamp
             FROM tx_history ORDER BY timestamp DESC LIMIT ?1"
        ).map_err(|e| WalletError::DbError(format!("Failed to prepare tx query: {}", e)))?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(WalletTxRecord {
                tx_hash: row.get(0)?,
                direction: row.get(1)?,
                amount: row.get::<_, i64>(2)? as u64,
                fee: row.get::<_, i64>(3)? as u64,
                counterparty: row.get(4)?,
                height: row.get::<_, i64>(5)? as u64,
                timestamp: row.get::<_, i64>(6)? as u64,
            })
        }).map_err(|e| WalletError::DbError(format!("Failed to query tx history: {}", e)))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| WalletError::DbError(format!("Failed to read tx row: {}", e)))?);
        }
        Ok(result)
    }

    // ========================================================================
    // Migration from JSON
    // ========================================================================

    /// Migrate wallet data from a legacy JSON file into this database.
    fn migrate_from_json(&self, json_path: &Path) -> Result<(), WalletError> {
        let data = std::fs::read_to_string(json_path).map_err(WalletError::IoError)?;
        let stored: StoredShieldedWallet =
            serde_json::from_str(&data).map_err(WalletError::ParseError)?;

        let public_key = hex::decode(&stored.public_key)
            .map_err(|_| WalletError::MigrationError("Invalid public_key hex".into()))?;
        let secret_key = hex::decode(&stored.secret_key)
            .map_err(|_| WalletError::MigrationError("Invalid secret_key hex".into()))?;
        let pk_hash_vec = hex::decode(&stored.pk_hash)
            .map_err(|_| WalletError::MigrationError("Invalid pk_hash hex".into()))?;

        if pk_hash_vec.len() != 32 {
            return Err(WalletError::MigrationError("pk_hash must be 32 bytes".into()));
        }
        let mut pk_hash = [0u8; 32];
        pk_hash.copy_from_slice(&pk_hash_vec);

        let tx = self.conn.unchecked_transaction()
            .map_err(|e| WalletError::DbError(format!("Migration transaction failed: {}", e)))?;

        // Store keys
        tx.execute(
            "INSERT OR REPLACE INTO wallet_keys (id, address, public_key, secret_key, pk_hash)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![stored.address, public_key, secret_key, pk_hash.as_slice()],
        ).map_err(|e| WalletError::DbError(format!("Failed to migrate keys: {}", e)))?;

        // Migrate notes
        for sn in &stored.notes {
            let note_data = hex::decode(&sn.note_data)
                .map_err(|_| WalletError::MigrationError("Invalid note_data hex".into()))?;
            let commitment = hex::decode(&sn.commitment)
                .map_err(|_| WalletError::MigrationError("Invalid commitment hex".into()))?;

            if commitment.len() != 32 {
                tracing::warn!("Skipping note with invalid commitment length: {}", commitment.len());
                continue;
            }

            let pq_rand = sn.pq_randomness.as_ref().and_then(|h| hex::decode(h).ok());
            let pq_cm = sn.pq_commitment.as_ref().and_then(|h| hex::decode(h).ok());

            tx.execute(
                "INSERT OR IGNORE INTO notes (note_data, commitment, position, height, is_spent, pq_randomness, pq_commitment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    note_data,
                    commitment,
                    sn.position as i64,
                    sn.height as i64,
                    sn.is_spent,
                    pq_rand.as_deref(),
                    pq_cm.as_deref(),
                ],
            ).map_err(|e| WalletError::DbError(format!("Failed to migrate note: {}", e)))?;
        }

        // Migrate scan state
        tx.execute(
            "UPDATE scan_state SET last_scanned_height = ?1 WHERE id = 1",
            params![stored.last_scanned_height as i64],
        ).map_err(|e| WalletError::DbError(format!("Failed to migrate scan state: {}", e)))?;

        // Migrate transaction history
        for record in &stored.tx_history {
            tx.execute(
                "INSERT OR IGNORE INTO tx_history (tx_hash, direction, amount, fee, counterparty, height, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.tx_hash,
                    record.direction,
                    record.amount as i64,
                    record.fee as i64,
                    record.counterparty,
                    record.height as i64,
                    record.timestamp as i64,
                ],
            ).map_err(|e| WalletError::DbError(format!("Failed to migrate tx: {}", e)))?;
        }

        tx.commit()
            .map_err(|e| WalletError::DbError(format!("Migration commit failed: {}", e)))?;

        let note_count = stored.notes.len();
        let tx_count = stored.tx_history.len();
        tracing::info!(
            "Migrated {} notes, {} transactions, scanned_height={}",
            note_count, tx_count, stored.last_scanned_height
        );

        Ok(())
    }

    /// Flush WAL to main database file (checkpoint).
    pub fn flush(&self) -> Result<(), WalletError> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| WalletError::DbError(format!("WAL checkpoint failed: {}", e)))?;
        Ok(())
    }

    /// Get the database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_schema() {
        let db = WalletDb::open_in_memory().unwrap();
        assert!(!db.has_keys());
        assert_eq!(db.last_scanned_height().unwrap(), 0);
        assert_eq!(db.unspent_count().unwrap(), 0);
        assert_eq!(db.balance().unwrap(), 0);
    }

    #[test]
    fn test_store_and_load_keys() {
        let db = WalletDb::open_in_memory().unwrap();
        let pk = vec![1u8; 64];
        let sk = vec![2u8; 128];
        let pk_hash = [3u8; 32];

        db.store_keys("tsn1abc...", &pk, &sk, &pk_hash).unwrap();
        assert!(db.has_keys());

        let (addr, loaded_pk, loaded_sk, loaded_hash) = db.load_keys().unwrap().unwrap();
        assert_eq!(addr, "tsn1abc...");
        assert_eq!(loaded_pk, pk);
        assert_eq!(loaded_sk, sk);
        assert_eq!(loaded_hash, pk_hash);
    }

    #[test]
    fn test_insert_and_query_notes() {
        let db = WalletDb::open_in_memory().unwrap();

        // note_data: value (8 bytes LE) + pk_hash (32 bytes) + randomness (32 bytes)
        let mut note_data = vec![0u8; 72];
        // value = 1000 in LE
        note_data[0..8].copy_from_slice(&1000u64.to_le_bytes());

        let commitment = [42u8; 32];
        db.insert_note(&note_data, &commitment, 0, 1, None, None).unwrap();

        assert_eq!(db.unspent_count().unwrap(), 1);
        assert_eq!(db.balance().unwrap(), 1000);

        let notes = db.unspent_notes_raw().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].1, commitment);
        assert_eq!(notes[0].2, 0); // position
        assert_eq!(notes[0].3, 1); // height
    }

    #[test]
    fn test_mark_spent() {
        let db = WalletDb::open_in_memory().unwrap();

        let mut note_data = vec![0u8; 72];
        note_data[0..8].copy_from_slice(&500u64.to_le_bytes());
        let commitment = [10u8; 32];

        db.insert_note(&note_data, &commitment, 0, 1, None, None).unwrap();
        assert_eq!(db.balance().unwrap(), 500);

        db.mark_spent_by_commitment(&commitment).unwrap();
        assert_eq!(db.balance().unwrap(), 0);
        assert_eq!(db.unspent_count().unwrap(), 0);
        assert_eq!(db.total_note_count().unwrap(), 1); // still in DB, just spent
    }

    #[test]
    fn test_duplicate_note_ignored() {
        let db = WalletDb::open_in_memory().unwrap();

        let mut note_data = vec![0u8; 72];
        note_data[0..8].copy_from_slice(&100u64.to_le_bytes());
        let commitment = [77u8; 32];

        let inserted1 = db.insert_note(&note_data, &commitment, 0, 1, None, None).unwrap();
        let inserted2 = db.insert_note(&note_data, &commitment, 0, 1, None, None).unwrap();

        assert!(inserted1);
        assert!(!inserted2);
        assert_eq!(db.balance().unwrap(), 100); // only one note
    }

    #[test]
    fn test_scan_height_tracking() {
        let db = WalletDb::open_in_memory().unwrap();

        assert_eq!(db.last_scanned_height().unwrap(), 0);
        db.set_last_scanned_height(42).unwrap();
        assert_eq!(db.last_scanned_height().unwrap(), 42);
        db.set_last_scanned_height(100).unwrap();
        assert_eq!(db.last_scanned_height().unwrap(), 100);
    }

    #[test]
    fn test_tx_history() {
        let db = WalletDb::open_in_memory().unwrap();

        let record = WalletTxRecord {
            tx_hash: "abc123".into(),
            direction: "sent".into(),
            amount: 1000,
            fee: 10,
            counterparty: "def456".into(),
            height: 5,
            timestamp: 1234567890,
        };

        db.add_tx(&record).unwrap();
        // Duplicate should be ignored
        db.add_tx(&record).unwrap();

        let history = db.tx_history(10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tx_hash, "abc123");
        assert_eq!(history[0].amount, 1000);
    }

    #[test]
    fn test_batch_insert() {
        let db = WalletDb::open_in_memory().unwrap();

        let notes: Vec<_> = (0..5).map(|i| {
            let mut data = vec![0u8; 72];
            data[0..8].copy_from_slice(&(100u64 * (i + 1)).to_le_bytes());
            let mut cm = [0u8; 32];
            cm[0] = i as u8;
            (data, cm, i as u64, 10u64, None, None)
        }).collect();

        let inserted = db.insert_notes_batch(&notes, 10).unwrap();
        assert_eq!(inserted, 5);
        assert_eq!(db.balance().unwrap(), 100 + 200 + 300 + 400 + 500);
        assert_eq!(db.last_scanned_height().unwrap(), 10);
    }

    #[test]
    fn test_clear_notes() {
        let db = WalletDb::open_in_memory().unwrap();

        let mut note_data = vec![0u8; 72];
        note_data[0..8].copy_from_slice(&999u64.to_le_bytes());
        db.insert_note(&note_data, &[1u8; 32], 0, 1, None, None).unwrap();
        db.set_last_scanned_height(50).unwrap();

        db.clear_notes().unwrap();
        assert_eq!(db.balance().unwrap(), 0);
        assert_eq!(db.unspent_count().unwrap(), 0);
        assert_eq!(db.last_scanned_height().unwrap(), 0);
    }

    #[test]
    fn test_pq_fields_preserved() {
        let db = WalletDb::open_in_memory().unwrap();

        let mut note_data = vec![0u8; 72];
        note_data[0..8].copy_from_slice(&250u64.to_le_bytes());
        let commitment = [5u8; 32];
        let pq_rand = [6u8; 32];
        let pq_cm = [7u8; 32];

        db.insert_note(&note_data, &commitment, 3, 7, Some(&pq_rand), Some(&pq_cm)).unwrap();

        let notes = db.unspent_notes_raw().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].4, Some(pq_rand));
        assert_eq!(notes[0].5, Some(pq_cm));
    }
}
