use anyhow::{Result, Context};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::core::{Block, Transaction, Account, Blockchain};
use crate::storage::Storage;
use crate::crypto::merkle_tree::MerkleTree;
use crate::network::mempool::Mempool;

/// Structure for the data d'affichage d'un bloc
#[derive(Debug)]
pub struct BlockDisplayData {
    pub height: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: u64,
    pub transaction_count: usize,
    pub difficulty: u64,
    pub nonce: u64,
    pub merkle_root: String,
    pub size_bytes: usize,
}

/// Structure for the data d'affichage d'une transaction
#[derive(Debug)]
pub struct TransactionDisplayData {
    pub hash: String,
    pub tx_type: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub timestamp: u64,
    pub size_bytes: usize,
    pub is_signature_valid: Option<bool>,
}

/// Structure for the data d'affichage d'un compte
#[derive(Debug)]
pub struct AccountDisplayData {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub created_at_block: u64,
    pub last_activity_block: u64,
    pub transaction_count: u64,
}

/// Structure for the statistics de the blockchain
#[derive(Debug)]
pub struct BlockchainStats {
    pub latest_height: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub avg_tx_per_block: f64,
}

pub struct BlockchainInspector {
    storage: Storage,
}

impl BlockchainInspector {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    /// Inspecte a bloc and returns the data structured
    pub async fn get_block_data(&self, block_height: u64) -> Result<BlockDisplayData> {
        let block = self.storage.get_block(block_height).await
            .context("Error lors de la retrieval du bloc")?
            .ok_or_else(|| anyhow::anyhow!("Bloc #{} non found", block_height))?;

        Ok(BlockDisplayData {
            height: block.height,
            hash: hex::encode(block.hash()),
            previous_hash: hex::encode(block.previous_hash),
            timestamp: block.timestamp,
            transaction_count: block.transactions.len(),
            difficulty: block.difficulty,
            nonce: block.nonce,
            merkle_root: hex::encode(block.merkle_root),
            size_bytes: self.calculate_block_size(&block),
        })
    }

    /// Inspecte a transaction and returns the data structured
    pub async fn get_transaction_data(&self, tx_hash: &str) -> Result<TransactionDisplayData> {
        let transaction = self.storage.get_transaction(tx_hash).await
            .context("Error lors de la retrieval de la transaction")?
            .ok_or_else(|| anyhow::anyhow!("Transaction {} non founde", tx_hash))?;

        let is_signature_valid = match transaction.verify_signature() {
            Ok(valid) => Some(valid),
            Err(_) => None,
        };

        Ok(TransactionDisplayData {
            hash: hex::encode(transaction.hash()),
            tx_type: transaction.tx_type().to_string(),
            from: transaction.from().to_string(),
            to: transaction.to().to_string(),
            amount: transaction.amount(),
            fee: transaction.fee(),
            nonce: transaction.nonce(),
            timestamp: transaction.timestamp(),
            size_bytes: self.calculate_transaction_size(&transaction),
            is_signature_valid,
        })
    }

    /// Inspecte a compte and returns the data structured
    pub async fn get_account_data(&self, address: &str) -> Result<AccountDisplayData> {
        let account = self.storage.get_account(address).await
            .context("Error lors de la retrieval du compte")?
            .ok_or_else(|| anyhow::anyhow!("Compte {} non found", address))?;

        Ok(AccountDisplayData {
            address: account.address().to_string(),
            balance: account.balance(),
            nonce: account.nonce(),
            created_at_block: account.created_at_block(),
            last_activity_block: account.last_activity_block(),
            transaction_count: account.transaction_count(),
        })
    }

    /// Retrieves the statistics de the blockchain
    pub async fn get_blockchain_stats(&self) -> Result<BlockchainStats> {
        let latest_height = self.storage.get_latest_block_height().await
            .context("Error lors de la retrieval de la hauteur")?;

        let total_transactions = self.storage.get_total_transaction_count().await
            .context("Error counting transactions")?;

        let total_accounts = self.storage.get_total_account_count().await
            .context("Error counting accounts")?;

        let avg_tx_per_block = if latest_height > 0 {
            total_transactions as f64 / latest_height as f64
        } else {
            0.0
        };

        Ok(BlockchainStats {
            latest_height,
            total_transactions,
            total_accounts,
            avg_tx_per_block,
        })
    }

    /// Commande d'inspection de bloc with affichage
    pub async fn inspect_block(&self, block_height: u64, verbose: bool) -> Result<()> {
        println!("🔍 Inspection du bloc #{}", block_height);

        let block_data = self.get_block_data(block_height).await?;
        self.print_block_info(&block_data, verbose);

        if verbose {
            let block = self.storage.get_block(block_height).await
                .context("Error lors de la retrieval du bloc")?
                .ok_or_else(|| anyhow::anyhow!("Bloc #{} non found", block_height))?;

            self.analyze_block_transactions(&block).await?;
            self.verify_block_integrity(&block).await?;
        }

        Ok(())
    }

    /// Commande d'inspection de transaction with affichage
    pub async fn inspect_transaction(&self, tx_hash: &str, verbose: bool) -> Result<()> {
        println!("🔍 Inspection de la transaction {}", &tx_hash[..16]);

        let tx_data = self.get_transaction_data(tx_hash).await?;
        self.print_transaction_info(&tx_data, verbose);

        if verbose {
            let transaction = self.storage.get_transaction(tx_hash).await
                .context("Error lors de la retrieval de la transaction")?
                .ok_or_else(|| anyhow::anyhow!("Transaction {} non founde", tx_hash))?;

            self.analyze_transaction_details(&transaction).await?;
        }

        Ok(())
    }

    /// Commande d'inspection de compte with affichage
    pub async fn inspect_account(&self, address: &str, verbose: bool) -> Result<()> {
        println!("🔍 Inspection du compte {}", &address[..16]);

        let account_data = self.get_account_data(address).await?;
        self.print_account_info(&account_data, verbose);

        if verbose {
            self.analyze_account_history(address).await?;
            
            let account = self.storage.get_account(address).await
                .context("Error lors de la retrieval du compte")?
                .ok_or_else(|| anyhow::anyhow!("Compte {} non found", address))?;
            
            self.check_account_state_consistency(&account).await?;
        }

        Ok(())
    }

    /// Commande d'inspection of statistics blockchain with affichage
    pub async fn inspect_blockchain_stats(&self) -> Result<()> {
        println!("📊 Statistiques de la blockchain");

        let stats = self.get_blockchain_stats().await?;
        self.print_blockchain_stats(&stats);

        // Analyser the derniers blocs
        self.analyze_recent_blocks(10).await?;

        Ok(())
    }

    // === METHODS D'AFFICHAGE (SEPARATE DE LA LOGIQUE) ===

    fn print_block_info(&self, data: &BlockDisplayData, verbose: bool) {
        println!("┌─────────────────────────────────────┐");
        println!("│            BLOC INFO                │");
        println!("├─────────────────────────────────────┤");
        println!("│ Height: {:>26} │", data.height);
        println!("│ Hash: {:>30} │", self.format_hash_display(&data.hash));
        println!("│ Hash previous: {:>18} │", self.format_hash_display(&data.previous_hash));
        println!("│ Timestamp: {:>24} │", data.timestamp);
        println!("│ Transactions: {:>20} │", data.transaction_count);
        println!("│ Difficulty: {:>22} │", data.difficulty);
        println!("│ Nonce: {:>29} │", data.nonce);
        
        if verbose {
            println!("│ Merkle Root: {:>21} │", self.format_hash_display(&data.merkle_root));
            println!("│ Size (bytes): {:>18} │", data.size_bytes);
        }
        
        println!("└─────────────────────────────────────┘");
    }

    fn print_transaction_info(&self, data: &TransactionDisplayData, verbose: bool) {
        println!("┌─────────────────────────────────────┐");
        println!("│         TRANSACTION INFO            │");
        println!("├─────────────────────────────────────┤");
        println!("│ Hash: {:>30} │", self.format_hash_display(&data.hash));
        println!("│ Type: {:>30} │", data.tx_type);
        println!("│ Sender:     {:>22} │", self.format_address_display(&data.from));
        println!("│ Destinataire: {:>20} │", self.format_address_display(&data.to));
        println!("│ Montant: {:>27} │", data.amount);
        println!("│ Frais: {:>29} │", data.fee);
        println!("│ Nonce: {:>29} │", data.nonce);
        println!("│ Timestamp: {:>24} │", data.timestamp);
        
        if verbose {
            let sig_status = match data.is_signature_valid {
                Some(true) => "✅ Valide",
                Some(false) => "❌ Invalid",
                None => "❓ Error verif",
            };
            println!("│ Signature: {:>25} │", sig_status);
            println!("│ Size (bytes): {:>18} │", data.size_bytes);
        }
        
        println!("└─────────────────────────────────────┘");
    }

    fn print_account_info(&self, data: &AccountDisplayData, verbose: bool) {
        println!("┌─────────────────────────────────────┐");
        println!("│           COMPTE INFO               │");
        println!("├─────────────────────────────────────┤");
        println!("│ Adresse: {:>26} │", self.format_address_display(&data.address));
        println!("│ Balance: {:>26} │", data.balance);
        println!("│ Nonce: {:>29} │", data.nonce);
        
        if verbose {
            println!("│ Created au bloc: {:>20} │", data.created_at_block);
            println!("│ Last activity: {:>15} │", data.last_activity_block);
            println!("│ Nb transactions: {:>17} │", data.transaction_count);
        }
        
        println!("└─────────────────────────────────────┘");
    }

    fn print_blockchain_stats(&self, stats: &BlockchainStats) {
        println!("┌─────────────────────────────────────┐");
        println!("│          BLOCKCHAIN STATS           │");
        println!("├─────────────────────────────────────┤");
        println!("│ Current height: {:>15} │", stats.latest_height);
        println!("│ Total transactions: {:>13} │", stats.total_transactions);
        println!("│ Total comptes: {:>18} │", stats.total_accounts);
        
        if stats.latest_height > 0 {
            println!("│ Moy. tx/bloc: {:>17.2} │", stats.avg_tx_per_block);
        }
        
        println!("└─────────────────────────────────────┘");
    }

    // === METHODS UTILITAIRES D'AFFICHAGE ===

    /// Formate a hash for l'affichage (firsts and last 4 characters)
    fn format_hash_display(&self, hash: &str) -> String {
        if hash.len() >= 8 {
            format!("{}...{}", &hash[..4], &hash[hash.len()-4..])
        } else {
            hash.to_string()
        }
    }

    /// Formate a adresse for l'affichage (firsts and last 4 characters)
    fn format_address_display(&self, address: &str) -> String {
        if address.len() >= 8 {
            format!("{}...{}", &address[..4], &address[address.len()-4..])
        } else {
            address.to_string()
        }
    }

    // === METHODS D'ANALYSE (LOGIQUE BUSINESS) ===

    async fn analyze_block_transactions(&self, block: &Block) -> Result<()> {
        println!("\n📋 Analyse des transactions du bloc:");
        
        let mut tx_types = HashMap::new();
        let mut total_amount = 0u64;
        let mut total_fees = 0u64;

        for tx in &block.transactions {
            *tx_types.entry(tx.tx_type().to_string()).or_insert(0) += 1;
            total_amount += tx.amount();
            total_fees += tx.fee();
        }

        println!("  💰 Volume total: {} TSN", total_amount);
        println!("  💸 Frais totaux: {} TSN", total_fees);
        println!("  📊 Types de transactions:");
        
        for (tx_type, count) in tx_types {
            println!("     {} : {} transactions", tx_type, count);
        }

        Ok(())
    }

    async fn verify_block_integrity(&self, block: &Block) -> Result<()> {
        println!("\n🔐 Verification de l'integrity du bloc:");

        // Verify the hash of the bloc
        let calculated_hash = block.calculate_hash();
        let stored_hash = block.hash();
        
        if calculated_hash == stored_hash {
            println!("  ✅ Hash du bloc valid");
        } else {
            println!("  ❌ Hash du bloc invalid!");
            println!("     Calculationated: {}", hex::encode(calculated_hash));
            println!("     Stored:  {}", hex::encode(stored_hash));
        }

        // Verify the merkle root
        let tx_hashes: Vec<[u8; 32]> = block.transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        
        if !tx_hashes.is_empty() {
            let merkle_tree = MerkleTree::new(tx_hashes);
            let calculated_root = merkle_tree.root();
            
            if calculated_root == block.merkle_root {
                println!("  ✅ Merkle root valid");
            } else {
                println!("  ❌ Merkle root invalid!");
            }
        }

        // Verify the difficulty
        let hash_value = u64::from_be_bytes(stored_hash[..8].try_into().unwrap());
        let target = u64::MAX >> block.difficulty;
        
        if hash_value <= target {
            println!("  ✅ Difficulty respected");
        } else {
            println!("  ❌ Difficulty non respected!");
        }

        Ok(())
    }

    async fn analyze_transaction_details(&self, transaction: &Transaction) -> Result<()> {
        println!("\n🔍 Analyse detailed de la transaction:");

        // Analyser the inputs/outputs if c'est a transaction complexe
        match transaction.tx_type() {
            "transfer" => {
                println!("  📤 Transfert simple");
                println!("     De: {}", self.format_address_display(&transaction.from().to_string()));
                println!("     Vers: {}", self.format_address_display(&transaction.to().to_string()));
                println!("     Montant: {} TSN", transaction.amount());
            }
            "mint" => {
                println!("  🏭 Creation de tokens");
                println!("     Destinataire: {}", self.format_address_display(&transaction.to().to_string()));
                println!("     Montant created: {} TSN", transaction.amount());
            }
            "burn" => {
                println!("  🔥 Destruction de tokens");
                println!("     Owner: {}", self.format_address_display(&transaction.from().to_string()));
                println!("     Montant destroyed: {} TSN", transaction.amount());
            }
            _ => {
                println!("  ❓ Type de transaction inconnu: {}", transaction.tx_type());
            }
        }

        Ok(())
    }

    async fn analyze_account_history(&self, address: &str) -> Result<()> {
        println!("\n📜 Historique du compte:");

        let transactions = self.storage.get_account_transactions(address, 10).await
            .context("Error lors de la retrieval de l'historique")?;

        if transactions.is_empty() {
            println!("  📭 Aucune transaction founde");
            return Ok(());
        }

        println!("  📊 Lasts {} transactions:", transactions.len());
        
        for (i, tx) in transactions.iter().enumerate() {
            let direction = if tx.from().to_string() == address { "📤" } else { "📥" };
            let tx_hash_display = self.format_hash_display(&hex::encode(tx.hash()));
            println!(
                "     {}. {} {} TSN - {} ({})",
                i + 1,
                direction,
                tx.amount(),
                tx_hash_display,
                tx.tx_type()
            );
        }

        Ok(())
    }

    async fn check_account_state_consistency(&self, account: &Account) -> Result<()> {
        println!("\n🔍 Verification de la consistency du compte:");

        // Recalculationate the balance to partir of transactions
        let calculated_balance = self.calculate_account_balance_from_history(account.address()).await?;
        
        if calculated_balance == account.balance() {
            println!("  ✅ Balance consistent avec l'historique");
        } else {
            println!("  ❌ Inconsistency de balance detectede!");
            println!("     Balance stored: {} TSN", account.balance());
            println!("     Balance calculationatede: {} TSN", calculated_balance);
        }

        Ok(())
    }

    async fn analyze_recent_blocks(&self, count: u64) -> Result<()> {
        println!("\n📈 Analyse des {} derniers blocs:", count);

        let latest_height = self.storage.get_latest_block_height().await
            .context("Error lors de la retrieval de la hauteur")?;

        let start_height = if latest_height >= count { latest_height - count + 1 } else { 0 };

        let mut total_transactions = 0;
        let mut total_size = 0;
        let mut difficulties = Vec::new();

        for height in start_height..=latest_height {
            if let Ok(Some(block)) = self.storage.get_block(height).await {
                total_transactions += block.transactions.len();
                total_size += self.calculate_block_size(&block);
                difficulties.push(block.difficulty);
            }
        }

        let blocks_analyzed = (latest_height - start_height + 1) as usize;
        
        if blocks_analyzed > 0 {
            println!("  📊 Moyennes sur {} blocs:", blocks_analyzed);
            println!("     Transactions/bloc: {:.1}", total_transactions as f64 / blocks_analyzed as f64);
            println!("     Size/bloc: {:.1} bytes", total_size as f64 / blocks_analyzed as f64);
            
            if !difficulties.is_empty() {
                let avg_difficulty = difficulties.iter().sum::<u64>() as f64 / difficulties.len() as f64;
                println!("     Difficulty moyenne: {:.1}", avg_difficulty);
            }
        }

        Ok(())
    }

    // === METHODS UTILITAIRES DE CALCUL ===

    fn calculate_block_size(&self, block: &Block) -> usize {
        // Estimation de the size of the bloc in bytes
        let mut size = 80; // Header approximatif
        for tx in &block.transactions {
            size += self.calculate_transaction_size(tx);
        }
        size
    }

    fn calculate_transaction_size(&self, transaction: &Transaction) -> usize {
        // Estimation de the size de the transaction in bytes
        // This estimation can be refined based on the exact format
        200 + transaction.tx_type().len() // Estimation basique
    }

    async fn calculate_account_balance_from_history(&self, address: &str) -> Result<u64> {
        let transactions = self.storage.get_account_transactions(address, u32::MAX).await
            .context("Error lors de la retrieval de l'historique complete")?;

        let mut balance = 0u64;
        
        for tx in transactions {
            if tx.to().to_string() == address {
                balance += tx.amount();
            }
            if tx.from().to_string() == address {
                balance = balance.saturating_sub(tx.amount() + tx.fee());
            }
        }

        Ok(balance)
    }
}

/// Structure for l'inspection of the mempool
pub struct MempoolInspector {
    mempool: Mempool,
}

impl MempoolInspector {
    pub fn new(mempool: Mempool) -> Self {
        Self { mempool }
    }

    pub async fn inspect_mempool(&self, verbose: bool, tx_type_filter: Option<String>) -> Result<()> {
        println!("🔍 Inspection du mempool");

        let pending_transactions = self.mempool.get_pending_transactions().await;
        
        let filtered_transactions: Vec<_> = if let Some(filter) = tx_type_filter {
            pending_transactions.into_iter()
                .filter(|tx| tx.tx_type() == filter)
                .collect()
        } else {
            pending_transactions
        };

        println!("┌─────────────────────────────────────┐");
        println!("│           MEMPOOL INFO              │");
        println!("├─────────────────────────────────────┤");
        println!("│ Transactions en attente: {:>10} │", filtered_transactions.len());
        
        if verbose && !filtered_transactions.is_empty() {
            println!("│                                     │");
            println!("│ Detail des transactions:            │");
            
            for (i, tx) in filtered_transactions.iter().take(10).enumerate() {
                let hash_display = if hex::encode(tx.hash()).len() >= 8 {
                    format!("{}...{}", &hex::encode(tx.hash())[..4], &hex::encode(tx.hash())[hex::encode(tx.hash()).len()-4..])
                } else {
                    hex::encode(tx.hash())
                };
                println!("│ {}. {} {:>6} TSN │", i + 1, hash_display, tx.amount());
            }
            
            if filtered_transactions.len() > 10 {
                println!("│ ... et {} autres                    │", filtered_transactions.len() - 10);
            }
        }
        
        println!("└─────────────────────────────────────┘");

        Ok(())
    }
}