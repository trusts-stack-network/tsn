use anyhow::{Result, Context};
use rand::{thread_rng, Rng};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use crate::core::{Block, Transaction, Account};
use crate::crypto::keys::KeyPair;
use crate::crypto::address::Address;
use crate::wallet::Wallet;

/// Generator of data de test for the development
pub struct TestDataGenerator {
    rng: rand::rngs::ThreadRng,
}

impl TestDataGenerator {
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
        }
    }

    /// Generates of transactions de test
    pub async fn generate_transactions(
        &mut self,
        count: u32,
        output_file: PathBuf,
        wallet_file: PathBuf,
        tx_type: String,
        amount_range: String,
    ) -> Result<()> {
        println!("🏭 Generation de {} transactions de test...", count);

        // Charger the wallet
        let wallet = self.load_or_create_wallet(&wallet_file).await?;
        
        // Parser the plage de montants
        let (min_amount, max_amount) = self.parse_amount_range(&amount_range)?;

        let mut transactions = Vec::new();

        for i in 0..count {
            let transaction = match tx_type.as_str() {
                "transfer" => self.generate_transfer_transaction(&wallet, min_amount, max_amount).await?,
                "mint" => self.generate_mint_transaction(&wallet, min_amount, max_amount).await?,
                "burn" => self.generate_burn_transaction(&wallet, min_amount, max_amount).await?,
                _ => return Err(anyhow::anyhow!("Type de transaction non supported: {}", tx_type)),
            };

            transactions.push(transaction);
            
            if (i + 1) % 10 == 0 {
                println!("  ✅ {} transactions generatedes", i + 1);
            }
        }

        // Save the transactions
        self.save_transactions_to_file(&transactions, &output_file).await?;
        
        println!("💾 {} transactions savedes dans {:?}", count, output_file);
        Ok(())
    }

    /// Generates of blocs de test
    pub async fn generate_blocks(
        &mut self,
        count: u32,
        output_dir: PathBuf,
        transactions_per_block: u32,
        starting_difficulty: u64,
    ) -> Result<()> {
        println!("🏭 Generation de {} blocs de test...", count);

        // Create the directory de sortie
        fs::create_dir_all(&output_dir)
            .context("Error lors de la creation du directory de sortie")?;

        let mut previous_hash = [0u8; 32]; // Genesis block hash
        let mut current_height = 0u64;
        let mut current_difficulty = starting_difficulty;

        for i in 0..count {
            // Generate the transactions for this bloc
            let mut transactions = Vec::new();
            for _ in 0..transactions_per_block {
                let tx = self.generate_random_transaction().await?;
                transactions.push(tx);
            }

            // Generate the bloc
            let block = self.generate_block(
                current_height,
                previous_hash,
                transactions,
                current_difficulty,
            ).await?;

            // Save the bloc
            let block_file = output_dir.join(format!("block_{:06}.json", current_height));
            self.save_block_to_file(&block, &block_file).await?;

            // Prepare for the bloc suivant
            previous_hash = block.hash();
            current_height += 1;
            
            // Ajuster the difficulty (simulation simple)
            if i % 10 == 9 {
                current_difficulty = current_difficulty.saturating_add(1);
            }

            if (i + 1) % 5 == 0 {
                println!("  ✅ {} blocs generateds", i + 1);
            }
        }

        println!("💾 {} blocs saveds dans {:?}", count, output_dir);
        Ok(())
    }

    /// Generates of wallets de test
    pub async fn generate_wallets(
        &mut self,
        count: u32,
        output_dir: PathBuf,
        prefund: bool,
        prefund_amount: u64,
    ) -> Result<()> {
        println!("🏭 Generation de {} wallets de test...", count);

        // Create the directory de sortie
        fs::create_dir_all(&output_dir)
            .context("Error lors de la creation du directory de sortie")?;

        let mut wallet_info = Vec::new();

        for i in 0..count {
            // Generate a new paire de keys
            let keypair = KeyPair::generate();
            let address = Address::from_public_key(&keypair.public_key());

            // Create the wallet
            let wallet = Wallet::new(keypair, address.clone());

            // Save the wallet
            let wallet_file = output_dir.join(format!("wallet_{:03}.json", i + 1));
            self.save_wallet_to_file(&wallet, &wallet_file).await?;

            // Collect the informations for the summary
            wallet_info.push(json!({
                "id": i + 1,
                "address": address.to_string(),
                "file": wallet_file.file_name().unwrap().to_string_lossy(),
                "prefunded": prefund,
                "prefund_amount": if prefund { prefund_amount } else { 0 }
            }));

            if (i + 1) % 5 == 0 {
                println!("  ✅ {} wallets generateds", i + 1);
            }
        }

        // Save the file de summary
        let summary_file = output_dir.join("wallets_summary.json");
        let summary = json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "total_wallets": count,
            "prefunded": prefund,
            "prefund_amount": prefund_amount,
            "wallets": wallet_info
        });

        fs::write(&summary_file, serde_json::to_string_pretty(&summary)?)
            .context("Error lors de la backup du summary")?;

        println!("💾 {} wallets saveds dans {:?}", count, output_dir);
        println!("📋 Summary available dans {:?}", summary_file);

        if prefund {
            println!("💰 Note: Les wallets sont marked comme pre-funded avec {} TSN", prefund_amount);
            println!("    Vous devez manuellement transfer les fonds depuis un wallet existant.");
        }

        Ok(())
    }

    // === METHODS PRIVATE DE GENERATION ===

    async fn load_or_create_wallet(&mut self, wallet_file: &PathBuf) -> Result<Wallet> {
        if wallet_file.exists() {
            // Charger the wallet existant
            let wallet_data = fs::read_to_string(wallet_file)
                .context("Error during la lecture du file wallet")?;
            
            let wallet: Wallet = serde_json::from_str(&wallet_data)
                .context("Error lors du parsing du wallet")?;
            
            Ok(wallet)
        } else {
            // Create a nouveau wallet
            println!("  📝 Creation d'un nouveau wallet: {:?}", wallet_file);
            
            let keypair = KeyPair::generate();
            let address = Address::from_public_key(&keypair.public_key());
            let wallet = Wallet::new(keypair, address);
            
            // Save the nouveau wallet
            self.save_wallet_to_file(&wallet, wallet_file).await?;
            
            Ok(wallet)
        }
    }

    fn parse_amount_range(&self, range_str: &str) -> Result<(u64, u64)> {
        let parts: Vec<&str> = range_str.split(',').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Format de plage invalid. Utilisez 'min,max'"));
        }

        let min = parts[0].trim().parse::<u64>()
            .context("Montant minimum invalid")?;
        let max = parts[1].trim().parse::<u64>()
            .context("Montant maximum invalid")?;

        if min > max {
            return Err(anyhow::anyhow!("Le montant minimum ne peut pas be higher au maximum"));
        }

        Ok((min, max))
    }

    async fn generate_transfer_transaction(&mut self, wallet: &Wallet, min_amount: u64, max_amount: u64) -> Result<Transaction> {
        // Generate a adresse de destination random
        let dest_keypair = KeyPair::generate();
        let dest_address = Address::from_public_key(&dest_keypair.public_key());
        
        let amount = self.rng.gen_range(min_amount..=max_amount);
        let fee = self.rng.gen_range(1..=10); // Frais random entre 1 et 10
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_transfer(
            wallet.address().clone(),
            dest_address,
            amount,
            fee,
            nonce,
        );

        // Signer the transaction
        let signed_transaction = wallet.sign_transaction(transaction)?;
        
        Ok(signed_transaction)
    }

    async fn generate_mint_transaction(&mut self, wallet: &Wallet, min_amount: u64, max_amount: u64) -> Result<Transaction> {
        let amount = self.rng.gen_range(min_amount..=max_amount);
        let fee = self.rng.gen_range(1..=5);
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_mint(
            wallet.address().clone(),
            amount,
            fee,
            nonce,
        );

        let signed_transaction = wallet.sign_transaction(transaction)?;
        
        Ok(signed_transaction)
    }

    async fn generate_burn_transaction(&mut self, wallet: &Wallet, min_amount: u64, max_amount: u64) -> Result<Transaction> {
        let amount = self.rng.gen_range(min_amount..=max_amount);
        let fee = self.rng.gen_range(1..=5);
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_burn(
            wallet.address().clone(),
            amount,
            fee,
            nonce,
        );

        let signed_transaction = wallet.sign_transaction(transaction)?;
        
        Ok(signed_transaction)
    }

    async fn generate_random_transaction(&mut self) -> Result<Transaction> {
        // Generate of addresses random
        let from_keypair = KeyPair::generate();
        let from_address = Address::from_public_key(&from_keypair.public_key());
        
        let to_keypair = KeyPair::generate();
        let to_address = Address::from_public_key(&to_keypair.public_key());

        let amount = self.rng.gen_range(1..=1000);
        let fee = self.rng.gen_range(1..=10);
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_transfer(
            from_address,
            to_address,
            amount,
            fee,
            nonce,
        );

        // For random transactions, we cannot sign them
        // car on n'a pas access to the key private in a vrai contexte
        // On returns the transaction non signed for the tests
        Ok(transaction)
    }

    async fn generate_block(
        &mut self,
        height: u64,
        previous_hash: [u8; 32],
        transactions: Vec<Transaction>,
        difficulty: u64,
    ) -> Result<Block> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let nonce = self.rng.gen::<u64>();

        let block = Block::new(
            height,
            previous_hash,
            transactions,
            timestamp,
            difficulty,
            nonce,
        );

        Ok(block)
    }

    // === METHODS DE SAUVEGARDE ===

    async fn save_transactions_to_file(&self, transactions: &[Transaction], file_path: &PathBuf) -> Result<()> {
        let transactions_json: Vec<Value> = transactions
            .iter()
            .map(|tx| self.transaction_to_json(tx))
            .collect();

        let output = json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "count": transactions.len(),
            "transactions": transactions_json
        });

        fs::write(file_path, serde_json::to_string_pretty(&output)?)
            .context("Error during la sauvegarde des transactions")?;

        Ok(())
    }

    async fn save_block_to_file(&self, block: &Block, file_path: &PathBuf) -> Result<()> {
        let block_json = self.block_to_json(block);

        fs::write(file_path, serde_json::to_string_pretty(&block_json)?)
            .context("Error during la sauvegarde du bloc")?;

        Ok(())
    }

    async fn save_wallet_to_file(&self, wallet: &Wallet, file_path: &PathBuf) -> Result<()> {
        let wallet_json = self.wallet_to_json(wallet);

        fs::write(file_path, serde_json::to_string_pretty(&wallet_json)?)
            .context("Error during la sauvegarde du wallet")?;

        Ok(())
    }

    // === METHODS DE SERIALIZATION JSON ===

    fn transaction_to_json(&self, transaction: &Transaction) -> Value {
        json!({
            "hash": hex::encode(transaction.hash()),
            "type": transaction.tx_type(),
            "from": transaction.from().to_string(),
            "to": transaction.to().to_string(),
            "amount": transaction.amount(),
            "fee": transaction.fee(),
            "nonce": transaction.nonce(),
            "timestamp": transaction.timestamp(),
            "signature": hex::encode(transaction.signature()),
        })
    }

    fn block_to_json(&self, block: &Block) -> Value {
        let transactions_json: Vec<Value> = block.transactions
            .iter()
            .map(|tx| self.transaction_to_json(tx))
            .collect();

        json!({
            "height": block.height,
            "hash": hex::encode(block.hash()),
            "previous_hash": hex::encode(block.previous_hash),
            "merkle_root": hex::encode(block.merkle_root),
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "nonce": block.nonce,
            "transaction_count": block.transactions.len(),
            "transactions": transactions_json
        })
    }

    fn wallet_to_json(&self, wallet: &Wallet) -> Value {
        json!({
            "address": wallet.address().to_string(),
            "public_key": hex::encode(wallet.public_key().as_bytes()),
            // Note: On not backup jamais the key private in clair in a vrai contexte
            // Ici c'est for the tests de development only
            "private_key_encrypted": "ENCRYPTED_FOR_DEV_ONLY",
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": "1.0.0"
        })
    }
}

/// Generator of data de performance for the benchmarks
pub struct PerformanceDataGenerator {
    rng: rand::rngs::ThreadRng,
}

impl PerformanceDataGenerator {
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
        }
    }

    /// Generates a dataset for the tests de performance
    pub async fn generate_performance_dataset(
        &mut self,
        transaction_count: u32,
        block_count: u32,
        output_dir: PathBuf,
    ) -> Result<()> {
        println!("🚀 Generation d'un dataset de performance...");
        println!("   {} transactions, {} blocs", transaction_count, block_count);

        fs::create_dir_all(&output_dir)
            .context("Error lors de la creation du directory")?;

        // Generate the transactions
        let mut test_generator = TestDataGenerator::new();
        let tx_file = output_dir.join("performance_transactions.json");
        
        test_generator.generate_transactions(
            transaction_count,
            tx_file,
            output_dir.join("temp_wallet.json"),
            "transfer".to_string(),
            "1,1000".to_string(),
        ).await?;

        // Generate the blocs
        let blocks_dir = output_dir.join("performance_blocks");
        test_generator.generate_blocks(
            block_count,
            blocks_dir,
            transaction_count / block_count,
            16,
        ).await?;

        // Generate the file de configuration for the benchmarks
        let config = json!({
            "dataset_type": "performance",
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "transaction_count": transaction_count,
            "block_count": block_count,
            "files": {
                "transactions": "performance_transactions.json",
                "blocks_directory": "performance_blocks"
            },
            "benchmark_scenarios": [
                {
                    "name": "transaction_validation",
                    "description": "Validation de transactions en lot"
                },
                {
                    "name": "block_mining",
                    "description": "Simulation de minage de blocs"
                },
                {
                    "name": "merkle_tree_construction",
                    "description": "Construction d'arbres de Merkle"
                }
            ]
        });

        let config_file = output_dir.join("benchmark_config.json");
        fs::write(&config_file, serde_json::to_string_pretty(&config)?)
            .context("Error during la sauvegarde de la configuration")?;

        println!("✅ Dataset de performance generated dans {:?}", output_dir);
        println!("📋 Configuration available dans {:?}", config_file);

        Ok(())
    }
}