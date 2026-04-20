use clap::{Parser, Subcommand, ValueEnum};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tsn::config::{self, GENESIS_DIFFICULTY};
use tsn::consensus::{MiningPool, SimdMode};
use tsn::core::{ShieldedBlock, ShieldedBlockchain};
use tsn::network::{create_router, Mempool, peer_id};
use tsn::node::NodeRole;
use tsn::wallet::{ShieldedWallet, WalletLock, WalletService};

#[derive(Parser)]
#[command(name = "tsn", version)]
#[command(about = "TSN - Trust Stack Network: A privacy-preserving post-quantum cryptocurrency", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // ---- Top-level flags (for default node mode) ----

    /// Number of mining threads (default: 1)
    #[arg(short, long, global = false)]
    threads: Option<usize>,

    /// Wallet file (default: auto-detect wallet.json next to binary)
    #[arg(short, long, global = false)]
    wallet: Option<String>,

    /// Port to listen on (default: 9333)
    #[arg(short, long, global = false)]
    port: Option<u16>,

    /// Additional peer nodes
    #[arg(long, global = false)]
    peer: Vec<String>,

    /// Data directory (default: ./data)
    #[arg(short, long, global = false)]
    data_dir: Option<String>,

    /// Public URL to announce to peers
    #[arg(long, global = false)]
    public_url: Option<String>,

    /// Disable connecting to seed nodes
    #[arg(long, global = false)]
    no_seeds: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SimdArg {
    Neon,
}

impl From<SimdArg> for SimdMode {
    fn from(value: SimdArg) -> Self {
        match value {
            SimdArg::Neon => SimdMode::Neon,
        }
    }
}

fn require_simd_support(simd: Option<SimdMode>) -> Option<SimdMode> {
    if let Some(mode) = simd {
        if !mode.is_supported() {
            eprintln!("SIMD mode {:?} requires ARMv8 NEON+SHA2 support.", mode);
            std::process::exit(1);
        }
    }
    simd
}

/// Expected SHA256 checksums for verification keys (for integrity verification)
const SPEND_VKEY_SHA256: &str = "a1ff15d0968e066b6d8285993580f57065d67fb7ce5625ed7966fd13a8952e27";
const OUTPUT_VKEY_SHA256: &str = "c97a5eb20c85009a2abd2f85b1bece88c054e913a24423e1973e0629537ff038";

/// Find verification keys, checking committed keys first, then build directory.
/// Also verifies checksums for committed keys to ensure integrity.
fn find_verification_keys() -> anyhow::Result<(String, String)> {
    use sha2::{Sha256, Digest};
    use std::path::{Path, PathBuf};

    // Build list of directories to search (CWD, next to binary, parent of binary)
    let mut search_dirs: Vec<PathBuf> = vec![PathBuf::from(".")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            search_dirs.push(parent.to_path_buf());
            // Also check parent of parent (for target/release/tsn → project root)
            if let Some(grandparent) = parent.parent() {
                search_dirs.push(grandparent.to_path_buf());
                if let Some(ggp) = grandparent.parent() {
                    search_dirs.push(ggp.to_path_buf());
                }
            }
        }
    }

    for base in &search_dirs {
        let committed_spend = base.join("circuits/keys/spend_vkey.json");
        let committed_output = base.join("circuits/keys/output_vkey.json");
        if committed_spend.exists() && committed_output.exists() {
            // Read and normalize line endings (strip \r) so checksums match
            // regardless of platform (Windows CRLF vs Unix LF)
            let spend_data: Vec<u8> = std::fs::read(&committed_spend)?
                .into_iter().filter(|&b| b != b'\r').collect();
            let output_data: Vec<u8> = std::fs::read(&committed_output)?
                .into_iter().filter(|&b| b != b'\r').collect();
            let spend_hash = hex::encode(Sha256::digest(&spend_data));
            let output_hash = hex::encode(Sha256::digest(&output_data));
            if spend_hash != SPEND_VKEY_SHA256 {
                return Err(anyhow::anyhow!(
                    "Spend verification key checksum mismatch!\n  Expected: {}\n  Got: {}",
                    SPEND_VKEY_SHA256, spend_hash
                ));
            }
            if output_hash != OUTPUT_VKEY_SHA256 {
                return Err(anyhow::anyhow!(
                    "Output verification key checksum mismatch!\n  Expected: {}\n  Got: {}",
                    OUTPUT_VKEY_SHA256, output_hash
                ));
            }
            println!("  Using committed verification keys (checksums verified)");
            return Ok((committed_spend.to_string_lossy().to_string(), committed_output.to_string_lossy().to_string()));
        }
    }

    for base in &search_dirs {
        let build_spend = base.join("circuits/build/spend_vkey.json");
        let build_output = base.join("circuits/build/output_vkey.json");
        if build_spend.exists() && build_output.exists() {
            println!("  Using local build verification keys (development mode)");
            return Ok((build_spend.to_string_lossy().to_string(), build_output.to_string_lossy().to_string()));
        }
    }

    // Legacy: check relative paths (backward compat)
    let committed_spend = "circuits/keys/spend_vkey.json";
    let committed_output = "circuits/keys/output_vkey.json";
    let build_spend = "circuits/build/spend_vkey.json";
    let build_output = "circuits/build/output_vkey.json";

    if Path::new(committed_spend).exists() && Path::new(committed_output).exists() {
        // Verify checksums for committed keys (normalize CRLF for cross-platform)
        let spend_data: Vec<u8> = std::fs::read(committed_spend)?
            .into_iter().filter(|&b| b != b'\r').collect();
        let output_data: Vec<u8> = std::fs::read(committed_output)?
            .into_iter().filter(|&b| b != b'\r').collect();

        let spend_hash = hex::encode(Sha256::digest(&spend_data));
        let output_hash = hex::encode(Sha256::digest(&output_data));

        if spend_hash != SPEND_VKEY_SHA256 {
            return Err(anyhow::anyhow!(
                "Spend verification key checksum mismatch!\n  Expected: {}\n  Got: {}\n  File may be corrupted or tampered with.",
                SPEND_VKEY_SHA256, spend_hash
            ));
        }
        if output_hash != OUTPUT_VKEY_SHA256 {
            return Err(anyhow::anyhow!(
                "Output verification key checksum mismatch!\n  Expected: {}\n  Got: {}\n  File may be corrupted or tampered with.",
                OUTPUT_VKEY_SHA256, output_hash
            ));
        }

        println!("  Using committed verification keys (checksums verified)");
        return Ok((committed_spend.to_string(), committed_output.to_string()));
    }

    // Fall back to build directory (local development)
    if Path::new(build_spend).exists() && Path::new(build_output).exists() {
        println!("  Using local build verification keys (development mode)");
        return Ok((build_spend.to_string(), build_output.to_string()));
    }

    Err(anyhow::anyhow!(
        "Verification keys not found.\n\
         For production: Ensure circuits/keys/ directory is present (from git).\n\
         For development: Run 'npm run compile:all && npm run setup:spend && npm run setup:output' in circuits/"
    ))
}

#[derive(Clone, Copy)]
enum MiningMode {
    Mine,
    Benchmark,
}

#[derive(serde::Deserialize)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
}

async fn fetch_peer_chain_info(
    client: &reqwest::Client,
    peer_url: &str,
) -> Option<PeerChainInfo> {
    if !tsn::network::is_contactable_peer(peer_url) {
        return None;
    }
    let info_url = format!("{}/chain/info", peer_url);
    let response = client.get(&info_url)
        .timeout(std::time::Duration::from_secs(3))
        .send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<PeerChainInfo>().await.ok()
}

async fn wait_for_initial_sync(
    state: Arc<tsn::network::AppState>,
    max_wait_secs: u64,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);

    loop {
        let peers = { state.peers.read().unwrap().clone() };
        let (local_height, local_hash) = {
            let chain = state.blockchain.read().unwrap();
            (chain.height(), hex::encode(chain.latest_hash()))
        };

        // Allow solo mining when no peers are available (single-node deployment)
        if peers.is_empty() {
            println!("No peers configured. Starting solo mining at height {}...", local_height);
            return Ok(());
        }

        let mut best_peer: Option<(String, PeerChainInfo)> = None;
        for peer in &peers {
            if let Some(info) = fetch_peer_chain_info(&client, peer).await {
                let take = match &best_peer {
                    None => true,
                    Some((_, best_info)) => info.height > best_info.height,
                };
                if take {
                    best_peer = Some((peer.clone(), info));
                }
            }
        }

        if let Some((peer_url, info)) = best_peer {
            // Accept if we're within 5 blocks AND our tip hash matches the peer's chain
            let gap = if info.height > local_height { info.height - local_height } else { local_height - info.height };
            if gap <= 5 {
                // Verify we're on the same chain, not a fork
                let on_same_chain = if info.height == local_height {
                    info.latest_hash == local_hash
                } else {
                    // Check peer's block at our height
                    let check_url = format!("{}/block/height/{}", peer_url, local_height);
                    match client.get(&check_url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.json::<serde_json::Value>().await {
                                Ok(block) => block["hash"].as_str() == Some(&local_hash),
                                Err(_) => true, // assume OK if can't parse
                            }
                        }
                        _ => true, // assume OK if can't reach
                    }
                };
                if on_same_chain {
                    println!(
                        "Local chain synced with network at height {}.",
                        local_height
                    );
                    return Ok(());
                } else {
                    println!(
                        "Fork detected at height {}. Force re-sync from network (wiping local chain)...",
                        local_height
                    );
                    // v1.4.1: Do NOT wipe chain. Just attempt normal sync — the peer
                    // may have a heavier chain and sync_from_peer will handle fork resolution.
                    // Wiping was the cause of catastrophic chain loss.
                    let _ = tsn::network::sync_from_peer(state.clone(), &peer_url).await;
                }
            } else if local_height > info.height + 5 {
                // We're ahead of peers — just start mining, the network will catch up
                println!(
                    "Local chain ahead of peers (local: {}, peer: {}). Starting mining.",
                    local_height, info.height
                );
                return Ok(());
            } else {
                println!(
                    "Waiting for sync... local height={}, peer height={} (gap: {})",
                    local_height, info.height, gap
                );
                let _ = tsn::network::sync_from_peer(state.clone(), &peer_url).await;
            }
        } else {
            println!("Waiting for sync... no peer info available yet.");
        }

        if Instant::now() >= deadline {
            // Don't fail — just start mining anyway if we have any blocks
            let height = state.blockchain.read().unwrap().height();
            if height > 0 {
                println!("Sync timeout but chain at height {}. Starting mining.", height);
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "Timed out waiting for sync; local tip does not match any peer."
            ));
        }

        sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive wallet menu
    Wallet {
        /// Wallet file (default: auto-detect)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Node URL (default: auto-detect)
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Generate a new shielded wallet
    NewWallet {
        /// Output file for the wallet (default: wallet.json)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
    },
    /// Restore a wallet from a 24-word seed phrase
    #[command(name = "restore-wallet")]
    RestoreWallet {
        /// The 24-word seed phrase (quoted string)
        #[arg(long)]
        seed: String,
        /// Output file for the wallet (default: wallet.json)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
    },
    /// Show wallet balance (scans blockchain for owned notes)
    Balance {
        /// Wallet file (default: auto-detect)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Node URL to query (default: auto-detect from port)
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Run a miner node (shortcut for: node --role miner)
    Miner {
        /// Number of mining threads
        #[arg(short, long)]
        threads: Option<usize>,
        /// Port (default: auto-detect free port from 9333)
        #[arg(short, long)]
        port: Option<u16>,
        /// Wallet file (default: auto-detect or auto-create)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Data directory (default: ./data-miner)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Additional peer nodes
        #[arg(long)]
        peer: Vec<String>,
        /// Public URL to announce to peers
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
    /// Run a relay node (shortcut for: node --role relay)
    Relay {
        /// Port (default: auto-detect free port from 9333)
        #[arg(short, long)]
        port: Option<u16>,
        /// Wallet file (for receiving relay rewards)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Data directory (default: ./data-relay)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Additional peer nodes
        #[arg(long)]
        peer: Vec<String>,
        /// Public URL to announce to peers
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
    /// Run a light client node (shortcut for: node --role light)
    Light {
        /// Port (default: auto-detect free port from 9333)
        #[arg(short, long)]
        port: Option<u16>,
        /// Wallet file (for balance checking and sending transactions)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Data directory (default: ./data-light)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Additional peer nodes
        #[arg(long)]
        peer: Vec<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
    /// Show transaction history from the explorer
    History {
        /// Node URL to query (default: auto-detect)
        #[arg(short, long)]
        node: Option<String>,
        /// Number of recent transactions to show (default: 20)
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Send TSN to an address
    Send {
        /// Recipient address (pk_hash hex, 64 chars)
        #[arg(long)]
        to: String,
        /// Amount to send in TSN
        #[arg(long)]
        amount: f64,
        /// Transaction fee in TSN (default: 0.001)
        #[arg(long, default_value = "0.001")]
        fee: f64,
        /// Wallet file (default: auto-detect)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Node URL to submit transaction (default: auto-detect)
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Start mining blocks
    Mine {
        /// Wallet file (mining rewards go to this wallet)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Number of blocks to mine (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "16")]
        difficulty: u64,
        /// Number of mining threads to use
        #[arg(short = 't', long = "threads", default_value = "1")]
        jobs: usize,
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
    },
    /// Run a mining benchmark (mines N blocks and prints avg hashrate)
    Benchmark {
        /// Wallet file (mining rewards go to this wallet)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Number of blocks to mine
        #[arg(short, long, default_value = "20")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "20")]
        difficulty: u64,
        /// Number of mining threads to use
        #[arg(short = 't', long = "threads", default_value = "1")]
        jobs: usize,
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
    },
    /// Run a full node
    Node {
        /// Node role: miner, relay, light (default: miner)
        #[arg(long, default_value = "miner")]
        role: String,
        /// Port to listen on (or set TSN_PORT env var)
        #[arg(short, long)]
        port: Option<u16>,
        /// Peer nodes to connect to (in addition to seed nodes)
        #[arg(long)]
        peer: Vec<String>,
        /// Data directory (or set TSN_DATA_DIR env var)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Enable mining
        #[arg(long)]
        mine: bool,
        /// Number of mining threads to use
        #[arg(short = 't', long = "threads", default_value = "1")]
        jobs: usize,
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
        /// Public URL to announce to peers (e.g. https://example.com)
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
        /// Disable assume-valid and verify all ZK proofs from genesis
        #[arg(long)]
        full_verify: bool,
        /// Allow mining without peer sync verification (for solo/testing)
        #[arg(long)]
        force_mine: bool,
        /// Wallet file for faucet (enables faucet if provided)
        #[arg(long)]
        faucet_wallet: Option<String>,
        /// Override daily faucet limit in TSN (default: 50)
        #[arg(long)]
        faucet_daily_limit: Option<u64>,
    },
    /// Restore chain state from a verified snapshot (requires signed manifest)
    #[command(name = "restore-snapshot")]
    RestoreSnapshot {
        /// Path to the compressed snapshot file (.json.gz)
        #[arg(long)]
        snapshot: String,
        /// Path to the signed manifest file (.json) — REQUIRED for verification
        #[arg(long)]
        manifest: String,
        /// Data directory (default: ./data)
        #[arg(short, long)]
        data_dir: Option<String>,
    },
    /// Check for updates and install the latest version
    Update,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Suppress logs for simple commands (balance, new-wallet)
    let is_quiet_cmd = matches!(cli.command, Some(Commands::Wallet { .. }) | Some(Commands::Balance { .. }) | Some(Commands::NewWallet { .. }) | Some(Commands::RestoreWallet { .. }) | Some(Commands::Send { .. }) | Some(Commands::History { .. }) | Some(Commands::Update));
    let log_level = if is_quiet_cmd {
        "error".to_string()
    } else {
        "info,yamux=error,libp2p_swarm=warn,libp2p_gossipsub=error".to_string()
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .init();

    match cli.command {
        Some(Commands::Wallet { wallet, node }) => {
            let wallet = wallet.or_else(auto_detect_wallet).unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_wallet_menu(&wallet, &node).await?;
        }
        Some(Commands::NewWallet { output }) => {
            cmd_new_wallet(&output)?;
        }
        Some(Commands::RestoreWallet { seed, output }) => {
            let words: Vec<&str> = seed.trim().split_whitespace().collect();
            if words.len() != 24 {
                eprintln!("Error: seed phrase must be exactly 24 words (got {})", words.len());
                std::process::exit(1);
            }
            let seed_bytes = seed_phrase_to_bytes(&seed);
            let wallet = ShieldedWallet::from_seed(&seed_bytes);
            wallet.save(&output).expect("Failed to save wallet");
            println!();
            println!("  Wallet restored from seed phrase.");
            println!("  Address: {}", hex::encode(wallet.pk_hash()));
            println!("  Saved to: {}", output);
            println!();
            println!("  Run './tsn balance' to scan the blockchain for your notes.");
        }
        Some(Commands::Balance { wallet, node }) => {
            let wallet = wallet.or_else(auto_detect_wallet).unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                // Try common ports to find running node (use 127.0.0.1, not localhost which may resolve to IPv6)
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_balance(&wallet, &node).await?;
        }
        Some(Commands::History { node, limit }) => {
            let wallet_path = auto_detect_wallet().unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_history(&wallet_path, &node, limit).await?;
        }
        Some(Commands::Send { to, amount, fee, wallet, node }) => {
            let wallet = wallet.or_else(auto_detect_wallet).unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_send(&wallet, &node, &to, amount, fee).await?;
        }
        Some(Commands::RestoreSnapshot { snapshot, manifest, data_dir }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data".to_string());
            println!("=== TSN Snapshot Restore (Verified) ===");
            println!("Snapshot: {}", snapshot);
            println!("Manifest: {}", manifest);
            println!("Data dir: {}", data_dir);
            println!();

            // Read snapshot file
            let compressed = std::fs::read(&snapshot)
                .map_err(|e| anyhow::anyhow!("Failed to read snapshot file: {}", e))?;
            println!("Compressed size: {} bytes", compressed.len());

            // Parse manifest (REQUIRED — no unsigned imports allowed)
            let manifest_data = std::fs::read_to_string(&manifest)
                .map_err(|e| anyhow::anyhow!("Failed to read manifest: {}", e))?;
            let m: tsn::network::snapshot_manifest::SnapshotManifest = serde_json::from_str(&manifest_data)
                .map_err(|e| anyhow::anyhow!("Failed to parse manifest: {}", e))?;

            println!("\n--- Verification (all 3 checks must pass) ---");

            // Check 1: Producer signature
            if m.verify_producer_signature() {
                println!("  [PASS] 1/3 Producer signature valid");
                println!("         Producer: {} (PK: {}...)", m.producer.seed_name, &m.producer.public_key[..16]);
            } else {
                println!("  [FAIL] 1/3 Producer signature INVALID");
                return Err(anyhow::anyhow!("REJECTED: Producer signature invalid — snapshot cannot be trusted"));
            }

            // Check 2: At least 2 seed confirmations
            let valid_confs = m.valid_confirmation_count();
            if valid_confs >= 2 {
                println!("  [PASS] 2/3 {} seed confirmations valid (minimum: 2)", valid_confs);
                for c in &m.confirmations {
                    if c.verify() {
                        println!("         {} (PK: {}...)", c.seed_name, &c.public_key[..16]);
                    }
                }
            } else {
                println!("  [FAIL] 2/3 Only {} valid confirmations (minimum: 2)", valid_confs);
                return Err(anyhow::anyhow!("REJECTED: Insufficient seed confirmations ({}/2)", valid_confs));
            }

            // Check 3: SHA256
            let computed_sha = {
                use sha2::Digest;
                hex::encode(sha2::Sha256::digest(&compressed))
            };
            if computed_sha == m.snapshot_sha256 {
                println!("  [PASS] 3/3 SHA256 match ({}...)", &computed_sha[..16]);
            } else {
                println!("  [FAIL] 3/3 SHA256 MISMATCH");
                return Err(anyhow::anyhow!("REJECTED: SHA256 mismatch — file corrupted or tampered"));
            }

            println!("\n  All pre-import checks passed.");
            println!("  Height: {}, Block: {}...", m.height, &m.block_hash[..24]);

            // Decompress
            println!("\nDecompressing...");
            let json_data = {
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                let mut buf = Vec::new();
                decoder.read_to_end(&mut buf)
                    .map_err(|e| anyhow::anyhow!("Decompression failed: {}", e))?;
                buf
            };
            println!("Decompressed: {} bytes", json_data.len());

            let snapshot_state: tsn::core::StateSnapshotPQ = serde_json::from_slice(&json_data)
                .map_err(|e| anyhow::anyhow!("Failed to parse snapshot state: {}", e))?;

            // Initialize blockchain
            println!("Opening blockchain in {}/blockchain...", data_dir);
            std::fs::create_dir_all(&data_dir).ok();
            let db_path = format!("{}/blockchain", data_dir);
            let mut blockchain = ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY)?;

            // Import
            let mut block_hash = [0u8; 32];
            if let Ok(bytes) = hex::decode(&m.block_hash) {
                if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
            }
            blockchain.import_snapshot_at_height(
                snapshot_state, m.height, block_hash,
                1000, 1000, 0,
            );

            // Check 4: State root post-import
            let computed_root = hex::encode(blockchain.state_root());
            println!("\n--- Post-import verification ---");
            if computed_root == m.state_root {
                println!("  [PASS] 4/4 State root MATCH ({}...)", &computed_root[..16]);
            } else {
                println!("  [WARN] 4/4 State root MISMATCH: computed={}..., manifest={}...", &computed_root[..16], &m.state_root[..16]);
                println!("         Chain may self-correct during sync.");
            }

            println!("\n=== Restore complete ===");
            println!("Chain restored to height {}.", m.height);
            println!("Start your node to sync remaining blocks from the network.");
        }
        Some(Commands::Update) => {
            tsn::network::auto_update::cmd_update().await.map_err(|e| anyhow::anyhow!(e))?;
        }
        Some(Commands::Miner { threads, port, wallet, data_dir, peer, public_url, no_seeds }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data-miner".to_string());
            let port = port.unwrap_or_else(|| find_free_port(config::get_port()));
            let wallet_path = wallet.unwrap_or_else(|| auto_wallet_for_mining(&data_dir));
            let jobs = threads.unwrap_or(1);
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);
            cmd_node(port, peers, &data_dir, Some(wallet_path), jobs, None, public_url, false, None, None, true, NodeRole::Miner).await?;
        }
        Some(Commands::Relay { port, wallet, data_dir, peer, public_url, no_seeds }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data-relay".to_string());
            let port = port.unwrap_or_else(|| find_free_port(config::get_port()));
            let wallet_path = wallet.or_else(auto_detect_wallet);
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);
            cmd_node(port, peers, &data_dir, wallet_path, 1, None, public_url, false, None, None, true, NodeRole::Relay).await?;
        }
        Some(Commands::Light { port, wallet, data_dir, peer, no_seeds }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data-light".to_string());
            let port = port.unwrap_or_else(|| find_free_port(config::get_port()));
            let wallet_path = wallet.or_else(auto_detect_wallet);
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);
            cmd_node(port, peers, &data_dir, wallet_path, 1, None, None, false, None, None, true, NodeRole::LightClient).await?;
        }
        Some(Commands::Mine {
            wallet,
            blocks,
            difficulty,
            jobs,
            simd,
        }) => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                simd.map(Into::into),
                MiningMode::Mine,
            )?;
        }
        Some(Commands::Benchmark {
            wallet,
            blocks,
            difficulty,
            jobs,
            simd,
        }) => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                simd.map(Into::into),
                MiningMode::Benchmark,
            )?;
        }
        Some(Commands::Node {
            role,
            port,
            peer,
            data_dir,
            mine,
            jobs,
            simd,
            public_url,
            no_seeds,
            full_verify,
            force_mine,
            faucet_wallet,
            faucet_daily_limit,
        }) => {
            // Legacy `node` subcommand — still supported
            let node_role = NodeRole::from_str(&role).unwrap_or_else(|| {
                eprintln!("Unknown node role '{}'. Valid roles: miner, relay, light", role);
                std::process::exit(1);
            });
            let port = port.unwrap_or_else(config::get_port);
            let data_dir = data_dir.unwrap_or_else(config::get_data_dir);
            if full_verify {
                std::env::set_var("TSN_FULL_VERIFY", "1");
            }
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);

            // If --mine flag is set, auto-detect or auto-create wallet
            let mine_wallet = if mine {
                let w = auto_detect_wallet();
                match w {
                    Some(w) => Some(w),
                    None => Some(auto_wallet_for_mining(&data_dir)),
                }
            } else {
                None
            };

            cmd_node(
                port, peers, &data_dir,
                mine_wallet, jobs, simd.map(Into::into), public_url,
                force_mine, faucet_wallet, faucet_daily_limit,
                true, // fast_sync always on
                node_role,
            ).await?;
        }
        None => {
            // ---- DEFAULT MODE: auto-detect everything and run as miner ----
            let node_role = auto_detect_role();
            let data_dir = cli.data_dir.unwrap_or_else(|| {
                match node_role {
                    NodeRole::Miner => "data-miner".to_string(),
                    NodeRole::Relay => "data-relay".to_string(),
                    NodeRole::LightClient => "data-light".to_string(),
                }
            });
            let port = cli.port.unwrap_or_else(|| find_free_port(config::get_port()));
            let jobs = cli.threads.unwrap_or(1);

            // Auto-detect or auto-create wallet (same behavior as `tsn miner`)
            let wallet = cli.wallet.or_else(auto_detect_wallet);
            let wallet = match wallet {
                Some(w) => Some(w),
                None if matches!(node_role, NodeRole::Miner) => {
                    // Auto-create wallet for mining, just like `tsn miner` does
                    Some(auto_wallet_for_mining(&data_dir))
                }
                None => None,
            };

            let mut peers = if cli.no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(cli.peer);
            dedup_peers(&mut peers);

            cmd_node(
                port, peers, &data_dir,
                wallet, jobs, None, cli.public_url,
                false, None, None,
                true, // fast_sync always on
                node_role,
            ).await?;
        }
    }

    Ok(())
}

/// Find a free port starting from `start`.
/// Tries start, start+1, start+2, ... up to start+100.
fn find_free_port(start: u16) -> u16 {
    for port in start..start.saturating_add(100) {
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() {
            return port;
        }
    }
    start // fallback
}

/// Auto-detect or auto-create wallet for mining.
/// 1. Check wallet.json next to binary / in cwd
/// 2. Check data_dir/wallet.json
/// 3. Create a new wallet in data_dir/wallet.json
/// BIP39-like word list (2048 words, simplified — first 256 common English words)
const SEED_WORDS: &[&str] = &[
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","act","action","actor","actress","actual",
    "adapt","add","addict","address","adjust","admit","adult","advance",
    "advice","aerobic","affair","afford","afraid","again","age","agent",
    "agree","ahead","aim","air","airport","aisle","alarm","album",
    "alcohol","alert","alien","all","alley","allow","almost","alone",
    "alpha","already","also","alter","always","amateur","amazing","among",
    "amount","amused","analyst","anchor","ancient","anger","angle","angry",
    "animal","ankle","announce","annual","another","answer","antenna","antique",
    "anxiety","any","apart","apology","appear","apple","approve","april",
    "arch","arctic","area","arena","argue","arm","armed","armor",
    "army","around","arrange","arrest","arrive","arrow","art","artefact",
    "artist","artwork","ask","aspect","assault","asset","assist","assume",
    "asthma","athlete","atom","attack","attend","attitude","attract","auction",
    "audit","august","aunt","author","auto","autumn","average","avocado",
    "avoid","awake","aware","awesome","awful","awkward","axis","baby",
    "bachelor","bacon","badge","bag","balance","balcony","ball","bamboo",
    "banana","banner","bar","barely","bargain","barrel","base","basic",
    "basket","battle","beach","bean","beauty","because","become","beef",
    "before","begin","behave","behind","believe","below","belt","bench",
    "benefit","best","betray","better","between","beyond","bicycle","bid",
    "bike","bind","biology","bird","birth","bitter","black","blade",
    "blame","blanket","blast","bleak","bless","blind","blood","blossom",
    "blow","blue","blur","blush","board","boat","body","boil",
    "bomb","bone","bonus","book","boost","border","boring","borrow",
    "boss","bottom","bounce","box","boy","bracket","brain","brand",
    "brass","brave","bread","breeze","brick","bridge","brief","bright",
    "bring","brisk","broccoli","broken","bronze","broom","brother","brown",
    "brush","bubble","buddy","budget","buffalo","build","bulb","bulk",
    "bullet","bundle","bunny","burden","burger","burst","bus","business",
];

fn generate_seed_phrase() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut entropy = [0u8; 32]; // 256 bits
    rng.fill_bytes(&mut entropy);

    // Convert 256 bits of entropy to 24 words (each word = ~10.7 bits)
    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let byte_idx = i * 32 / 24;
        let combined = if byte_idx + 1 < 32 {
            ((entropy[byte_idx] as u16) << 8) | (entropy[byte_idx + 1] as u16)
        } else {
            (entropy[byte_idx] as u16) << 8
        };
        let word_idx = (combined as usize + i * 7) % SEED_WORDS.len();
        words.push(SEED_WORDS[word_idx]);
    }
    words.join(" ")
}

fn auto_wallet_for_mining(data_dir: &str) -> String {
    // Check common locations first
    if let Some(w) = auto_detect_wallet() {
        println!("Wallet found: {}", w);
        return w;
    }
    // Check in data dir (SQLite first, then JSON)
    let data_dir_path = std::path::PathBuf::from(data_dir);
    let data_wallet_db = data_dir_path.join("wallet.db");
    let data_wallet_json = data_dir_path.join("wallet.json");
    if data_wallet_db.exists() {
        // Return the .json path — open() handles .json → .db resolution
        let p = data_wallet_json.to_string_lossy().to_string();
        println!("Wallet found: {}", p);
        return p;
    }
    if data_wallet_json.exists() {
        let p = data_wallet_json.to_string_lossy().to_string();
        println!("Wallet found: {}", p);
        return p;
    }

    // Auto-create with seed phrase
    let yellow = "\x1b[1;33m";
    let green = "\x1b[1;32m";
    let red = "\x1b[1;31m";
    let reset = "\x1b[0m";

    println!();
    println!("{}========================================{}", yellow, reset);
    println!("{}  NEW WALLET CREATION{}", yellow, reset);
    println!("{}========================================{}", yellow, reset);
    println!();

    let seed_phrase = generate_seed_phrase();

    println!("  Your recovery seed phrase (24 words):");
    println!();
    println!("  {}{}{}",green, seed_phrase, reset);
    println!();
    println!("  {}WARNING: Write these words down and store them safely!{}", red, reset);
    println!("  {}Without this phrase, your coins are LOST FOREVER.{}", red, reset);
    println!("  This is the ONLY time this phrase will be shown.");
    println!();

    // Wait for user confirmation
    print!("  Have you saved your seed phrase? Type YES to continue: ");
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();

    if input.trim().to_uppercase() != "YES" {
        println!();
        println!("  Aborted. Please run again and save your seed phrase.");
        std::process::exit(0);
    }

    println!();
    std::fs::create_dir_all(data_dir).ok();

    // Derive wallet deterministically from seed phrase via PBKDF2
    let seed_bytes = seed_phrase_to_bytes(&seed_phrase);
    let wallet = ShieldedWallet::from_seed(&seed_bytes);
    let path = data_wallet_json.to_string_lossy().to_string();
    wallet.save(&path).expect("Failed to create wallet");
    println!("  Wallet created: {}", path);
    println!("  Address: {}", hex::encode(wallet.pk_hash()));
    println!();
    path
}

/// Convert a BIP39-style seed phrase to a 32-byte seed using PBKDF2-SHA256.
/// Same phrase always produces the same 32-byte seed.
fn seed_phrase_to_bytes(phrase: &str) -> [u8; 32] {
    use sha2::Sha256;
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    let mut seed = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        phrase.as_bytes(),
        b"tsn-wallet-seed-v1",
        210_000, // OWASP recommended minimum for PBKDF2-SHA256
        &mut seed,
    ).expect("PBKDF2 should not fail");
    seed
}

/// Auto-detect node role from parent directory name
fn auto_detect_role() -> NodeRole {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dir_name = parent.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            if dir_name.contains("relay") { return NodeRole::from_str("relay").unwrap(); }
            if dir_name.contains("light") { return NodeRole::from_str("light").unwrap(); }
        }
    }
    // Also check current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let dir_name = cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if dir_name.contains("relay") { return NodeRole::from_str("relay").unwrap(); }
        if dir_name.contains("light") { return NodeRole::from_str("light").unwrap(); }
    }
    // Default: miner
    NodeRole::from_str("miner").unwrap()
}

/// Auto-detect wallet.json next to binary or in current dir
fn auto_detect_wallet() -> Option<String> {
    // Helper: check if wallet exists at a given base path (try .db first, then .json)
    let check_wallet = |dir: &std::path::Path, name: &str| -> Option<String> {
        let db_path = dir.join(format!("{}.db", name));
        if db_path.exists() {
            return Some(db_path.with_extension("json").to_string_lossy().to_string());
        }
        let json_path = dir.join(format!("{}.json", name));
        if json_path.exists() {
            return Some(json_path.to_string_lossy().to_string());
        }
        None
    };

    // Check next to binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(w) = check_wallet(parent, "wallet") {
                return Some(w);
            }
            // Check data* subdirectories next to binary
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("data") && entry.path().is_dir() {
                        if let Some(w) = check_wallet(&entry.path(), "wallet") {
                            return Some(w);
                        }
                    }
                }
            }
        }
    }
    // Check current directory
    if let Some(w) = check_wallet(std::path::Path::new("."), "wallet") {
        return Some(w);
    }
    // Check data* subdirectories in current directory
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("data") && entry.path().is_dir() {
                if let Some(w) = check_wallet(&entry.path(), "wallet") {
                    return Some(w);
                }
            }
        }
    }
    None
}

/// Deduplicate peer URLs
fn dedup_peers(peers: &mut Vec<String>) {
    for p in peers.iter_mut() {
        while p.ends_with('/') { p.pop(); }
    }
    let mut seen = std::collections::HashSet::new();
    peers.retain(|p| seen.insert(p.clone()));
}

fn cmd_new_wallet(output: &str) -> anyhow::Result<()> {
    let red = "\x1b[1;31m";
    let green = "\x1b[1;32m";
    let yellow = "\x1b[1;33m";
    let reset = "\x1b[0m";

    println!();
    println!("{}========================================{}", yellow, reset);
    println!("{}  NEW WALLET CREATION{}", yellow, reset);
    println!("{}========================================{}", yellow, reset);
    println!();

    let seed_phrase = generate_seed_phrase();

    println!("  Your recovery seed phrase (24 words):");
    println!();
    println!("  {}{}{}", green, seed_phrase, reset);
    println!();
    println!("  {}WARNING: Write these words down and store them safely!{}", red, reset);
    println!("  {}Without this phrase, your coins are LOST FOREVER.{}", red, reset);
    println!("  This is the ONLY time this phrase will be shown.");
    println!();
    println!("  To restore later: ./tsn restore-wallet --seed \"word1 word2 ... word24\"");
    println!();

    print!("  Have you saved your seed phrase? Type YES to continue: ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    if input.trim().to_uppercase() != "YES" {
        println!("\n  Aborted. Please run again and save your seed phrase.");
        std::process::exit(0);
    }

    // Derive wallet deterministically from the seed phrase
    let seed_bytes = seed_phrase_to_bytes(&seed_phrase);
    let wallet = ShieldedWallet::from_seed(&seed_bytes);
    wallet.save(output)?;

    println!();
    println!("  Wallet saved to: {}", output);
    println!("  Address: {}", hex::encode(wallet.pk_hash()));
    println!();
    println!("  Post-quantum signatures: ML-DSA-65 (FIPS 204)");
    println!("  Privacy: Shielded transactions with ZK proofs");
    println!();
    Ok(())
}

async fn cmd_wallet_menu(wallet_path: &str, node_url: &str) -> anyhow::Result<()> {
    use std::io::{self, Write};

    let green = "\x1b[1;32m";
    let cyan = "\x1b[1;36m";
    let yellow = "\x1b[1;33m";
    let reset = "\x1b[0m";

    loop {
        // Load wallet for display (try SQLite first, fallback to JSON)
        let wallet = ShieldedWallet::open(wallet_path)
            .or_else(|_| ShieldedWallet::load(wallet_path));
        let pk_hash_hex = wallet.as_ref()
            .map(|w| hex::encode(w.pk_hash()))
            .unwrap_or_else(|_| "???".to_string());

        println!();
        println!("  {}╔══════════════════════════════════════════════════════════════════════╗{}", cyan, reset);
        println!("  {}║  TSN Wallet v{}                                                     ║{}", cyan, env!("CARGO_PKG_VERSION"), reset);
        println!("  {}╚══════════════════════════════════════════════════════════════════════╝{}", cyan, reset);
        println!("  Your address (share this to receive TSN):");
        println!("  {}{}{}", green, pk_hash_hex, reset);
        println!();
        println!("  {}1{} — Balance", yellow, reset);
        println!("  {}2{} — Transaction history", yellow, reset);
        println!("  {}3{} — Send TSN", yellow, reset);
        println!("  {}4{} — Rescan wallet", yellow, reset);
        println!("  {}0{} — Quit", yellow, reset);
        println!();
        print!("  Choice: ");
        io::stdout().flush().ok();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => {
                cmd_balance(wallet_path, node_url).await?;
            }
            "2" => {
                cmd_history(wallet_path, node_url, 20).await?;
            }
            "3" => {
                print!("  Recipient address: ");
                io::stdout().flush().ok();
                let mut to = String::new();
                io::stdin().read_line(&mut to)?;
                let to = to.trim();
                if to.len() != 64 {
                    println!("  {}Invalid address (must be 64 hex chars){}", "\x1b[1;31m", reset);
                    continue;
                }

                print!("  Amount (TSN): ");
                io::stdout().flush().ok();
                let mut amt = String::new();
                io::stdin().read_line(&mut amt)?;
                let amount: f64 = match amt.trim().parse() {
                    Ok(a) if a > 0.0 => a,
                    _ => {
                        println!("  {}Invalid amount{}", "\x1b[1;31m", reset);
                        continue;
                    }
                };

                if let Err(e) = cmd_send(wallet_path, node_url, to, amount, 0.001).await {
                    println!("  {}Error: {}{}", "\x1b[1;31m", e, reset);
                }
            }
            "4" => {
                println!("  Rescanning wallet from height 0...");
                // v2.3.7 — capture pre-rescan totals so we can surface what actually
                // changed (new notes, stale notes removed, net balance delta).
                // A rescan can DECREASE the visible balance when the previous
                // incremental scan missed nullifiers and the wallet was counting
                // already-spent notes as unspent — the full replay corrects that.
                let pre_balance_raw: u64;
                let pre_notes_count: usize;
                {
                    let w = ShieldedWallet::open(wallet_path)
                        .or_else(|_| ShieldedWallet::load(wallet_path))?;
                    pre_balance_raw = w.balance();
                    pre_notes_count = w.note_count();
                }
                {
                    let _lock = WalletLock::acquire(wallet_path)?;
                    if let Ok(mut w) = ShieldedWallet::open(wallet_path)
                        .or_else(|_| ShieldedWallet::load(wallet_path)) {
                        w.clear_notes();
                        if let Err(e) = w.save(wallet_path) {
                            tracing::error!("Failed to save wallet after rescan: {}", e);
                        }
                    }
                }
                cmd_balance(wallet_path, node_url).await?;
                // Report delta vs previous snapshot.
                let (post_balance_raw, post_notes_count) = {
                    let w = ShieldedWallet::open(wallet_path)
                        .or_else(|_| ShieldedWallet::load(wallet_path))?;
                    (w.balance(), w.note_count())
                };
                let divisor = 10u64.pow(config::COIN_DECIMALS) as f64;
                let notes_delta = post_notes_count as i64 - pre_notes_count as i64;
                let bal_delta = post_balance_raw as i128 - pre_balance_raw as i128;
                let bal_delta_coins = bal_delta as f64 / divisor as f64;
                let yellow = "\x1b[1;33m";
                let reset = "\x1b[0m";
                if notes_delta != 0 || bal_delta != 0 {
                    println!();
                    println!("  {}Rescan delta vs previous state:{}", yellow, reset);
                    if notes_delta >= 0 {
                        println!("    +{} notes", notes_delta);
                    } else {
                        println!("    {} notes removed (were counted as unspent but are actually spent on-chain)", notes_delta);
                    }
                    if bal_delta >= 0 {
                        println!("    +{:.4} TSN", bal_delta_coins);
                    } else {
                        println!("    {:.4} TSN (the rescan corrected stale unspent accounting)", bal_delta_coins);
                    }
                }
            }
            "0" | "q" | "quit" | "exit" => {
                println!("  Bye!");
                break;
            }
            _ => {
                println!("  Invalid choice");
            }
        }
    }
    Ok(())
}

async fn cmd_history(wallet_path: &str, _node_url: &str, limit: usize) -> anyhow::Result<()> {
    let green = "\x1b[1;32m";
    let red = "\x1b[1;31m";
    let cyan = "\x1b[1;36m";
    let reset = "\x1b[0m";

    let coin_decimals = config::COIN_DECIMALS;
    let divisor = 10u64.pow(coin_decimals) as f64;

    // Read TX history from wallet
    let wallet = ShieldedWallet::open(wallet_path)
        .or_else(|_| ShieldedWallet::load(wallet_path))?;
    let history = wallet.tx_history();

    if history.is_empty() {
        println!("  No transactions yet.");
        println!();
        println!("  Transactions will appear here after you send or receive TSN.");
        println!("  Explorer: https://explorer.tsnchain.com/");
        return Ok(());
    }

    println!();
    println!("  Transaction History ({}):", history.len());
    println!();

    for (i, tx) in history.iter().rev().take(limit).enumerate() {
        let arrow = if tx.direction == "sent" {
            format!("{}SENT{}", red, reset)
        } else {
            format!("{}RECEIVED{}", green, reset)
        };

        let amount_display = tx.amount as f64 / divisor;
        let fee_display = tx.fee as f64 / divisor;

        let counterparty_short = if tx.counterparty.len() > 16 {
            format!("{}…{}", &tx.counterparty[..8], &tx.counterparty[tx.counterparty.len()-8..])
        } else {
            tx.counterparty.clone()
        };

        let time_str = if tx.timestamp > 0 {
            let secs_ago = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(tx.timestamp);
            if secs_ago < 60 { format!("{}s ago", secs_ago) }
            else if secs_ago < 3600 { format!("{}m ago", secs_ago / 60) }
            else if secs_ago < 86400 { format!("{}h ago", secs_ago / 3600) }
            else { format!("{}d ago", secs_ago / 86400) }
        } else {
            "unknown".to_string()
        };

        println!("  {} #{}", arrow, i + 1);
        println!("    {}{:.4} TSN{}  →  {}  |  Fee: {:.4} TSN  |  {}",
            cyan, amount_display, reset, counterparty_short, fee_display, time_str);
        println!("    Hash: {}{}{}", green, tx.tx_hash, reset);
        println!();
    }

    println!("  Explorer: https://explorer.tsnchain.com/");
    Ok(())
}

async fn cmd_balance(wallet_path: &str, node_url: &str) -> anyhow::Result<()> {
    // Acquire exclusive lock to prevent race with mining process
    let _lock = WalletLock::acquire(wallet_path)?;
    let mut wallet = ShieldedWallet::open(wallet_path)
        .or_else(|_| ShieldedWallet::load(wallet_path))?;
    let coin_decimals = config::COIN_DECIMALS;
    let divisor = 10u64.pow(coin_decimals);
    let scanned_height = wallet.last_scanned_height();

    // Try to scan new blocks via running node API, then fallback to local DB
    let (api_ok, api_notes) = try_scan_via_api(&mut wallet, node_url, wallet_path).await;

    let mut new_notes = api_notes;
    let mut scan_source = if api_ok { "node API" } else { "" };

    if !api_ok {
        // Fallback: try local blockchain DB
        let data_dirs = ["data-miner", "data", "./data-miner", "./data"];
        for dir in &data_dirs {
            let db_path = format!("{}/blockchain", dir);
            if !std::path::Path::new(&db_path).exists() { continue; }
            if let Ok(chain) = ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY) {
                let chain_height = chain.height();
                if chain_height > wallet.last_scanned_height() {
                    // Calculate starting position from commitment count
                    let mut pos = chain.fast_sync_commitment_offset();
                    // Count outputs from fast_sync_base to scan start
                    let scan_start = wallet.last_scanned_height() + 1;
                    let fs_base = chain.fast_sync_base_height();
                    if fs_base > 0 && scan_start > fs_base {
                        for h in (fs_base + 1)..scan_start {
                            if let Some(b) = chain.get_block_by_height(h) {
                                for tx in &b.transactions { pos += tx.outputs.len() as u64; }
                                for tx in &b.transactions_v2 { pos += tx.outputs.len() as u64; }
                                pos += 1; // coinbase
                            }
                        }
                    }
                    for h in scan_start..=chain_height {
                        if let Some(block) = chain.get_block_by_height(h) {
                            new_notes += wallet.scan_block(&block, pos);
                            for tx in &block.transactions { pos += tx.outputs.len() as u64; }
                            for tx in &block.transactions_v2 { pos += tx.outputs.len() as u64; }
                            pos += 1; // coinbase
                        }
                    }
                    if let Err(e) = wallet.save(wallet_path) {
                        tracing::error!("Failed to save wallet after local scan: {}", e);
                    }
                    scan_source = dir;
                }
                break;
            }
        }
    }

    // Display result — clean and simple
    let balance_raw = wallet.balance();
    let balance_coins = balance_raw as f64 / divisor as f64;
    let green = "\x1b[1;32m";
    let cyan = "\x1b[1;36m";
    let yellow = "\x1b[1;33m";
    let reset = "\x1b[0m";

    // v2.3.4: pre-validate unspent note witnesses against the node's Merkle
    // tree so orphan (reorg'd-out) notes are surfaced here as Stuck instead
    // of only being discovered at send-time. Best-effort: if the node is
    // unreachable we fall back to the legacy single-line display.
    let orphan_positions = if api_ok {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        // cmd_balance is nice-to-have; bail early on repeated 429.
        pre_validate_orphan_positions(&wallet, node_url, &client, true).await
    } else {
        std::collections::HashSet::new()
    };

    let (stuck_raw, spendable_raw) = if orphan_positions.is_empty() {
        (0u64, balance_raw)
    } else {
        let stuck: u64 = wallet
            .notes()
            .iter()
            .filter(|n| !n.is_spent && orphan_positions.contains(&n.position))
            .map(|n| n.note.value)
            .sum();
        (stuck, balance_raw.saturating_sub(stuck))
    };

    println!();
    println!("  Address:   {}", hex::encode(wallet.pk_hash()));
    if balance_raw > 0 {
        let total_coins = balance_coins;
        let spendable_coins = spendable_raw as f64 / divisor as f64;
        let stuck_coins = stuck_raw as f64 / divisor as f64;
        println!("  Total:     {}{:.4} TSN{} ({} notes)", green, total_coins, reset, wallet.note_count());
        if stuck_raw > 0 {
            println!("  Spendable: {}{:.4} TSN{}", green, spendable_coins, reset);
            println!("  Stuck:     {}{:.4} TSN{} ({} orphan note(s) from chain reorg)", yellow, stuck_coins, reset, orphan_positions.len());
        }
    } else {
        println!("  Balance:   0 TSN");
    }
    println!("  Scanned:   height {}", wallet.last_scanned_height());

    if new_notes > 0 {
        println!("  {}+{} new notes found{} (from {})", cyan, new_notes, reset, scan_source);
    }

    if wallet.last_scanned_height() == 0 && balance_raw == 0 {
        println!();
        println!("  Tip: Run your node to sync the blockchain first.");
    }
    println!();

    Ok(())
}

/// Try to scan wallet via a running node's API.
/// Uses /blocks/since/:height which returns full ShieldedBlock structs.
/// Returns (success, notes_found).
/// v2.3.0 wallet fix: resolve the PQ commitment of a wallet note when building
/// a spend witness. If the wallet stored a value, use it directly. Otherwise
/// fall back to the `leaf` field of the server's witness response — the node
/// already exposes the actual tree leaf at the requested position. The fallback
/// is equivalent in trust to the merkle path we already consume from the same
/// response: a lying node only fails the spend downstream, it cannot alter
/// funds.
/// Marker substring used in the error message so callers can detect an orphan
/// note mismatch via `err.to_string().contains(ORPHANED_NOTE_MARKER)` and skip
/// the note instead of aborting the whole send.
const ORPHANED_NOTE_MARKER: &str = "ORPHANED_NOTE";

fn resolve_pq_commitment(
    stored: Option<[u8; 32]>,
    server_leaf_hex: Option<&str>,
    position: u64,
) -> anyhow::Result<[u8; 32]> {
    // v2.3.1: resolve the commitment used for Merkle witness construction AND
    // for the STARK circuit's spend check. Both sides must agree on the same
    // value — stored in the wallet AND recorded on-chain at this position.
    //
    // Truth table:
    //   stored  server-leaf        → outcome
    //   --------------------------------
    //   None    None               → bail (nothing to use)
    //   None    placeholder (00..) → bail (no usable value)
    //   None    real               → Ok(leaf)           legacy/migrated wallet
    //   Some(s) None               → Ok(s)              server has no leaf path (rare)
    //   Some(s) placeholder (00..) → Ok(s)              fast-sync blind zone, trust wallet
    //   Some(s) real, s == leaf    → Ok(s)              normal happy path
    //   Some(s) real, s != leaf    → bail ORPHANED_NOTE the block that minted this note
    //                                                   was reorg'd out; wallet still
    //                                                   holds stale metadata. Caller is
    //                                                   expected to skip this note.
    let server_leaf = match server_leaf_hex {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                let bytes = hex::decode(trimmed).map_err(|_| {
                    anyhow::anyhow!("Invalid leaf hex from node for position {}", position)
                })?;
                if bytes.len() != 32 {
                    anyhow::bail!(
                        "Leaf from node has wrong length {} for position {}",
                        bytes.len(),
                        position
                    );
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            }
        }
        None => None,
    };

    let server_is_placeholder = matches!(server_leaf, Some(l) if l == [0u8; 32]);

    match (stored, server_leaf) {
        // Explicit orphan: wallet and chain disagree on a real leaf.
        (Some(s), Some(leaf)) if !server_is_placeholder && s != leaf => {
            anyhow::bail!(
                "{}: note at position {} has stored commitment {}... but server leaf {}... — \
                 the block that produced this note was reorg'd out. Skip this note and rescan.",
                ORPHANED_NOTE_MARKER,
                position,
                hex::encode(&s[..8]),
                hex::encode(&leaf[..8])
            );
        }
        // Happy path or fast-sync blind zone or missing server leaf: trust stored.
        (Some(s), _) => Ok(s),
        // Legacy wallet with no stored commitment: use server's real leaf.
        (None, Some(leaf)) if !server_is_placeholder => Ok(leaf),
        // Nothing usable.
        (None, _) => anyhow::bail!(
            "Note at position {} has no pq_commitment and the node did not return \
             a usable leaf. Please upgrade the node binary or rescan the wallet.",
            position
        ),
    }
}

/// v2.3.0 auto-consolidation: maximum number of spends per transaction that
/// the STARK prover can handle (mirrors MAX_SPENDS in circuit_pq.rs). The
/// consolidation loop uses MAX_SPENDS_PER_TX - 1 as batch size to keep one
/// slot free for flexibility at the final tx.
pub const MAX_SPENDS_PER_TX: usize = 10;
pub const CONSOLIDATION_BATCH: usize = MAX_SPENDS_PER_TX - 1;

/// v2.3.1: GET with exponential backoff on HTTP 429 (Too Many Requests).
/// Delay doubles each retry: 1s, 2s, 4s, 8s, 16s, 32s, then bails.
/// All other HTTP statuses (including 5xx) are returned to the caller as-is.
async fn get_with_429_backoff(
    client: &reqwest::Client,
    url: &str,
    label: &str,
) -> anyhow::Result<reqwest::Response> {
    let mut delay_ms: u64 = 1000;
    loop {
        let resp = client.get(url).send().await?;
        if resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Ok(resp);
        }
        if delay_ms > 32000 {
            anyhow::bail!("{}: HTTP 429 rate limit, gave up after backoff cap (~63s)", label);
        }
        eprintln!("    ⏳ {}: 429 rate limit, backoff {}ms...", label, delay_ms);
        tracing::warn!("{}: HTTP 429 backoff {}ms", label, delay_ms);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        delay_ms *= 2;
    }
}

/// v2.3.1: POST JSON with exponential backoff on HTTP 429. Same schedule as
/// `get_with_429_backoff`. The body is serialized once and cloned (as JSON)
/// for each retry.
async fn post_json_with_429_backoff<B: serde::Serialize + ?Sized>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
    label: &str,
) -> anyhow::Result<reqwest::Response> {
    let mut delay_ms: u64 = 1000;
    loop {
        let resp = client.post(url).json(body).send().await?;
        if resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Ok(resp);
        }
        if delay_ms > 32000 {
            anyhow::bail!("{}: HTTP 429 rate limit, gave up after backoff cap (~63s)", label);
        }
        eprintln!("    ⏳ {}: 429 rate limit, backoff {}ms...", label, delay_ms);
        tracing::warn!("{}: HTTP 429 backoff {}ms", label, delay_ms);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        delay_ms *= 2;
    }
}

/// v2.3.1: parse an `ORPHANED_NOTE_POSITIONS=p1,p2,p3:...` marker out of an
/// error message. Returns the list of positions, or empty if the error is
/// not an orphan-note error.
fn parse_orphan_positions(err_msg: &str) -> Vec<u64> {
    let needle = "ORPHANED_NOTE_POSITIONS=";
    let Some(start) = err_msg.find(needle) else { return Vec::new() };
    let after = &err_msg[start + needle.len()..];
    let end = after.find(':').unwrap_or(after.len());
    after[..end]
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .collect()
}

/// Build, prove, sign and submit one ShieldedTransactionV2. Reused by both
/// the final cmd_send tx and each auto-consolidation round. Returns the
/// tx hash and the list of nullifier hex strings, so the caller can poll
/// /nullifiers/check to detect mining confirmation.
async fn send_single_tx(
    selected_notes: &[tsn::wallet::WalletNote],
    amount_base: u64,
    fee_base: u64,
    recipient_pk_hash: [u8; 32],
    wallet: &tsn::wallet::ShieldedWallet,
    node_url: &str,
    client: &reqwest::Client,
) -> anyhow::Result<(String, Vec<String>)> {
    use tsn::crypto::pq::commitment_pq::NoteCommitmentPQ;
    use tsn::crypto::pq::proof_pq::{SpendWitnessPQ, OutputWitnessPQ, TransactionProver};
    use tsn::crypto::note::encrypt_note_pq;
    use tsn::core::{SpendDescriptionV2, OutputDescriptionV2, ShieldedTransactionV2};
    use rand::RngCore;

    let selected_total: u64 = selected_notes.iter().map(|n| n.note.value).sum();
    let total_needed = amount_base + fee_base;
    if selected_total < total_needed {
        anyhow::bail!(
            "Insufficient selected notes: have {}, need {}",
            selected_total, total_needed
        );
    }
    let change = selected_total - total_needed;

    let nullifier_key = wallet.nullifier_key_bytes();
    let pk_hash = wallet.pk_hash();
    let keypair = wallet.keypair();

    // Fetch Merkle witnesses from the node (one per selected note).
    // v2.3.1: collect orphan positions from resolve_pq_commitment and bail
    // once at the end with a machine-parseable list. The caller retries with
    // these positions excluded.
    let mut spend_witnesses = Vec::new();
    let mut orphan_positions: Vec<u64> = Vec::new();
    for note in selected_notes {
        let pos = note.position;
        let url = format!("{}/witness/v2/position/{}", node_url, pos);
        let resp = get_with_429_backoff(
            client, &url, &format!("witness pos {}", pos)
        ).await?;
        if !resp.status().is_success() {
            anyhow::bail!("Failed to get witness for position {}: HTTP {}", pos, resp.status());
        }
        let v: serde_json::Value = resp.json().await?;
        let root_hex = v["root"].as_str().unwrap_or("");
        let mut root = [0u8; 32];
        if let Ok(bytes) = hex::decode(root_hex) {
            if bytes.len() == 32 { root.copy_from_slice(&bytes); }
        }
        let empty = vec![];
        let path_arr = v["path"].as_array().unwrap_or(&empty);
        let indices_arr = v["indices"].as_array().unwrap_or(&empty);
        let siblings: Vec<[u8; 32]> = path_arr.iter().filter_map(|s| {
            let h = s.as_str()?;
            let b = hex::decode(h).ok()?;
            if b.len() == 32 { let mut a = [0u8;32]; a.copy_from_slice(&b); Some(a) } else { None }
        }).collect();
        let indices: Vec<u8> = indices_arr.iter().filter_map(|i| i.as_u64().map(|n| n as u8)).collect();

        let witness = tsn::crypto::pq::merkle_pq::MerkleWitnessPQ {
            path: tsn::crypto::pq::merkle_pq::MerklePathPQ { siblings, indices },
            position: pos,
            root,
        };

        let randomness = match note.pq_randomness {
            Some(r) => r,
            None => {
                let mut r = [0u8; 32];
                use ark_serialize::CanonicalSerialize;
                note.note.randomness.serialize_compressed(&mut r[..]).ok();
                r
            }
        };

        // v2.3.1: resolve commitment from wallet + server. Orphans are
        // collected and reported together; happy-path notes go straight into
        // the spend witness list.
        let server_leaf_hex = v["leaf"].as_str();
        let stored_pq_cm = match resolve_pq_commitment(note.pq_commitment, server_leaf_hex, pos) {
            Ok(c) => c,
            Err(e) if e.to_string().contains(ORPHANED_NOTE_MARKER) => {
                orphan_positions.push(pos);
                continue;
            }
            Err(e) => return Err(e),
        };
        if !witness.verify(&NoteCommitmentPQ(stored_pq_cm)) {
            anyhow::bail!(
                "Merkle witness verification failed for note at position {}. \
                 The commitment in your wallet does not match the merkle tree. \
                 Try rescanning your wallet.",
                pos
            );
        }

        spend_witnesses.push(SpendWitnessPQ {
            value: note.note.value,
            recipient_pk_hash: note.note.recipient_pk_hash,
            randomness,
            nullifier_key,
            position: pos,
            merkle_witness: witness,
        });
    }

    // v2.3.1: if any selected notes turned out to be orphans, bail with a
    // structured error. The caller parses the positions and retries with a
    // fresh selection that excludes them.
    if !orphan_positions.is_empty() {
        let csv = orphan_positions.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        anyhow::bail!(
            "{}_POSITIONS={}: selection contains {} orphan note(s); retry with a different selection",
            ORPHANED_NOTE_MARKER,
            csv,
            orphan_positions.len()
        );
    }

    // Build output witnesses (recipient + optional change)
    let mut rng = rand::thread_rng();
    let mut output_witnesses = Vec::new();
    let mut recipient_randomness = [0u8; 32];
    rng.fill_bytes(&mut recipient_randomness);
    output_witnesses.push(OutputWitnessPQ {
        value: amount_base,
        recipient_pk_hash,
        randomness: recipient_randomness,
    });
    let mut change_randomness = None;
    if change > 0 {
        let mut cr = [0u8; 32];
        rng.fill_bytes(&mut cr);
        output_witnesses.push(OutputWitnessPQ {
            value: change,
            recipient_pk_hash: pk_hash,
            randomness: cr,
        });
        change_randomness = Some(cr);
    }

    // Generate STARK proof
    let prover = TransactionProver::new();
    let proof = prover.prove(&spend_witnesses, &output_witnesses, fee_base)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;

    // Build spend descriptions (sign each nullifier with ML-DSA-65)
    let mut spends = Vec::new();
    let mut nullifiers_hex = Vec::new();
    for sw in &spend_witnesses {
        let nullifier = sw.nullifier();
        nullifiers_hex.push(hex::encode(nullifier));
        let anchor = sw.merkle_witness.root;
        let signature = tsn::crypto::sign(&nullifier, keypair);
        spends.push(SpendDescriptionV2 {
            anchor,
            nullifier,
            signature,
            public_key: keypair.public_key_bytes().to_vec(),
        });
    }

    // Build output descriptions
    let mut outputs = Vec::new();
    let rc = NoteCommitmentPQ::commit(amount_base, &recipient_pk_hash, &recipient_randomness);
    let re = encrypt_note_pq(amount_base, &recipient_pk_hash, &recipient_randomness);
    outputs.push(OutputDescriptionV2 {
        note_commitment: rc.to_bytes(),
        encrypted_note: re,
    });
    if let Some(cr) = change_randomness {
        let cc = NoteCommitmentPQ::commit(change, &pk_hash, &cr);
        let ce = encrypt_note_pq(change, &pk_hash, &cr);
        outputs.push(OutputDescriptionV2 {
            note_commitment: cc.to_bytes(),
            encrypted_note: ce,
        });
    }

    // Assemble + submit
    let tx = ShieldedTransactionV2::new(spends, outputs, fee_base, proof);
    let tx_hash = hex::encode(tx.hash());
    let submit_body = serde_json::json!({ "transaction": tx });
    let resp = post_json_with_429_backoff(
        client,
        &format!("{}/tx/v2", node_url),
        &submit_body,
        &format!("submit tx {}", &tx_hash[..16]),
    ).await?;
    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("Transaction rejected: {}", err);
    }

    // Relay directly to seeds for faster propagation
    let seeds = config::get_seed_nodes();
    let tx_json = serde_json::json!({ "transaction": tx });
    for seed in &seeds {
        let url = format!("{}/tx/v2", seed);
        let _ = client.post(&url).json(&tx_json).send().await;
    }

    Ok((tx_hash, nullifiers_hex))
}

/// v2.3.3: pre-validate the wallet's unspent notes against the node's Merkle
/// tree. Returns the positions of notes whose stored `pq_commitment` no longer
/// matches the server's leaf at that position — i.e. notes that were
/// orphaned by a chain reorg since the last wallet scan.
///
/// Called at the top of `cmd_send` to seed the `bad_positions` set, so
/// auto-consolidation and the final send both skip orphan notes from their
/// first batch instead of wasting a full proof attempt discovering them.
///
/// `best_effort` controls behaviour when the node pushes back with 429 rate
/// limiting: when true, the function bails after two consecutive 429 and
/// returns whatever orphans it has detected so far (used by `cmd_balance`
/// where an exact answer is nice-to-have, not correctness-critical). When
/// false, every note is validated even if the node makes us back off for
/// minutes (used by `cmd_send` where skipping an orphan would cost a full
/// proof round-trip).
///
/// A 100ms pacing delay is inserted between requests to respect the node's
/// sync rate limiter (200 rps / burst 400 in `api.rs`).
async fn pre_validate_orphan_positions(
    wallet: &tsn::wallet::ShieldedWallet,
    node_url: &str,
    client: &reqwest::Client,
    best_effort: bool,
) -> std::collections::HashSet<u64> {
    let placeholder = "0".repeat(64);
    let candidates: Vec<(u64, [u8; 32])> = wallet
        .notes()
        .iter()
        .filter(|n| !n.is_spent)
        .filter_map(|n| n.pq_commitment.map(|c| (n.position, c)))
        .collect();

    if candidates.is_empty() {
        return std::collections::HashSet::new();
    }

    eprint!("  Validating {} note witness(es)... ", candidates.len());
    let mut orphans = std::collections::HashSet::new();
    let mut checked = 0usize;
    let mut consecutive_429: u32 = 0;
    let mut bailed_best_effort = false;
    for (pos, stored) in candidates {
        // v2.3.5: pace requests so we never trip the server's sync rate
        // limiter (200 rps / burst 400 in `api.rs`). 100ms per request caps
        // the effective rate at 10 rps from a single wallet, well under the
        // threshold even if other peers are also polling.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("{}/witness/v2/position/{}", node_url, pos);
        let resp = match get_with_429_backoff(
            client,
            &url,
            &format!("validate pos {}", pos),
        ).await {
            Ok(r) => r,
            Err(e) => {
                // v2.3.5: when the node keeps pushing back with 429, short-
                // circuit best-effort callers (cmd_balance) instead of
                // burning their time. cmd_send stays strict.
                let is_429 = format!("{}", e).contains("429");
                if is_429 {
                    consecutive_429 += 1;
                } else {
                    consecutive_429 = 0;
                }
                if best_effort && consecutive_429 >= 2 {
                    bailed_best_effort = true;
                    break;
                }
                continue;
            }
        };
        consecutive_429 = 0;
        if !resp.status().is_success() {
            continue;
        }
        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let leaf_hex = match body["leaf"].as_str() {
            Some(s) => s.trim().to_string(),
            None => continue,
        };
        if leaf_hex.is_empty() || leaf_hex == placeholder {
            // Placeholder leaf (fast-sync blind zone) — trust the wallet's
            // stored value, not an orphan.
            continue;
        }
        let leaf_bytes = match hex::decode(&leaf_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut leaf_arr = [0u8; 32];
        leaf_arr.copy_from_slice(&leaf_bytes);
        if leaf_arr != stored {
            orphans.insert(pos);
        }
        checked += 1;
    }

    if bailed_best_effort {
        eprintln!(
            "partial ({} checked, {} orphan(s) so far; node rate-limited, stopping early)",
            checked, orphans.len()
        );
    } else if orphans.is_empty() {
        eprintln!("done ({} checked, all valid)", checked);
    } else {
        eprintln!(
            "done ({} checked, {} orphan(s) detected)",
            checked, orphans.len()
        );
    }
    orphans
}

/// Poll /nullifiers/check until all given nullifiers appear as spent on the
/// chain's nullifier_set (= tx has been mined into a block). Blocks up to
/// `timeout`. Errors on timeout.
async fn wait_nullifiers_mined(
    nullifiers_hex: &[String],
    node_url: &str,
    client: &reqwest::Client,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let check_url = format!("{}/nullifiers/check", node_url);
    let deadline = std::time::Instant::now() + timeout;
    let nf_set: std::collections::HashSet<&str> =
        nullifiers_hex.iter().map(|s| s.as_str()).collect();
    while std::time::Instant::now() < deadline {
        let resp = client.post(&check_url)
            .json(&serde_json::json!({"nullifiers": nullifiers_hex}))
            .timeout(std::time::Duration::from_secs(10))
            .send().await;
        if let Ok(resp) = resp {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(spent_arr) = body["spent"].as_array() {
                        let spent: std::collections::HashSet<&str> = spent_arr.iter()
                            .filter_map(|s| s.as_str())
                            .collect();
                        if nf_set.iter().all(|n| spent.contains(n)) {
                            return Ok(());
                        }
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    anyhow::bail!("Timeout waiting for tx confirmation ({}s)", timeout.as_secs())
}

/// Auto-consolidate small notes into larger ones until the greedy selection
/// for `total_needed` fits within CONSOLIDATION_BATCH (9) spends. Each round
/// is a self-send that takes the 9 smallest unspent notes and folds them into
/// one bigger note. Waits for confirmation and rescans between rounds.
async fn auto_consolidate(
    wallet: &mut tsn::wallet::ShieldedWallet,
    wallet_path: &str,
    node_url: &str,
    fee_base: u64,
    total_needed: u64,
    client: &reqwest::Client,
    initial_bad_positions: std::collections::HashSet<u64>,
) -> anyhow::Result<usize> {
    let cyan = "\x1b[1;36m";
    let reset = "\x1b[0m";
    let multiplier = 10u64.pow(config::COIN_DECIMALS);
    let self_pk = wallet.pk_hash();
    let max_rounds = 200usize;
    let mut round = 0usize;
    // v2.3.1: positions of orphan notes discovered during a send attempt.
    // These notes are filtered out of all subsequent batch selections.
    // v2.3.3: seed with positions flagged by pre_validate_orphan_positions
    // so the very first batch already excludes them.
    let mut bad_positions: std::collections::HashSet<u64> = initial_bad_positions;

    loop {
        // Count notes needed for the final send (greedy), excluding orphans.
        let (count, _) = {
            let unspent = wallet.unspent_notes();
            let mut sorted: Vec<&tsn::wallet::WalletNote> = unspent.iter()
                .copied()
                .filter(|n| !bad_positions.contains(&n.position))
                .collect();
            sorted.sort_by(|a, b| b.note.value.cmp(&a.note.value));
            let mut acc = 0u64;
            let mut c = 0usize;
            for n in &sorted {
                if acc >= total_needed { break; }
                acc += n.note.value;
                c += 1;
            }
            (c, acc)
        };
        if count <= CONSOLIDATION_BATCH {
            return Ok(round);
        }

        // Take the CONSOLIDATION_BATCH smallest unspent notes, excluding orphans.
        let batch: Vec<tsn::wallet::WalletNote> = {
            let unspent = wallet.unspent_notes();
            let mut sorted: Vec<tsn::wallet::WalletNote> = unspent.iter()
                .filter(|n| !bad_positions.contains(&n.position))
                .map(|n| (*n).clone())
                .collect();
            sorted.sort_by(|a, b| a.note.value.cmp(&b.note.value));
            sorted.into_iter().take(CONSOLIDATION_BATCH).collect()
        };
        if batch.len() < 2 {
            anyhow::bail!("Not enough unspent notes to consolidate (have {}, need ≥ 2).", batch.len());
        }
        let batch_sum: u64 = batch.iter().map(|n| n.note.value).sum();
        if batch_sum <= fee_base {
            anyhow::bail!(
                "Consolidation batch value {} is not larger than fee {}.",
                batch_sum, fee_base
            );
        }
        let consolidation_amount = batch_sum - fee_base;

        println!(
            "  {}Consolidation {}{}: {} notes ({:.4} TSN) → 1 note ({:.4} TSN)",
            cyan, round + 1, reset, batch.len(),
            batch_sum as f64 / multiplier as f64,
            consolidation_amount as f64 / multiplier as f64,
        );
        eprint!("    proving + submitting... ");
        let (tx_hash, nullifiers) = match send_single_tx(
            &batch, consolidation_amount, fee_base, self_pk, wallet, node_url, client,
        ).await {
            Ok(r) => r,
            Err(e) => {
                let orphans = parse_orphan_positions(&e.to_string());
                if !orphans.is_empty() {
                    eprintln!("orphan notes detected, retrying without them");
                    for p in &orphans {
                        bad_positions.insert(*p);
                        eprintln!("    ⚠ excluding orphan note at position {}", p);
                    }
                    continue;
                }
                return Err(e);
            }
        };
        eprintln!("tx {} submitted", &tx_hash[..16]);
        eprint!("    waiting for mining... ");
        wait_nullifiers_mined(
            &nullifiers, node_url, client,
            std::time::Duration::from_secs(180),
        ).await?;
        eprintln!("confirmed");

        // Rescan to ingest the new big note (and mark consumed notes as spent).
        try_scan_via_api(wallet, node_url, wallet_path).await;

        round += 1;
        if round >= max_rounds {
            anyhow::bail!("Too many consolidation rounds ({}); aborting to avoid loop.", round);
        }
    }
}

async fn cmd_send(wallet_path: &str, node_url: &str, to: &str, amount: f64, fee: f64) -> anyhow::Result<()> {
    let green = "\x1b[1;32m";
    let cyan = "\x1b[1;36m";
    let reset = "\x1b[0m";

    // Validate recipient
    if to.len() != 64 || hex::decode(to).is_err() {
        anyhow::bail!("Invalid recipient address. Must be 64 hex characters (pk_hash).");
    }
    let mut recipient_pk_hash = [0u8; 32];
    hex::decode_to_slice(to, &mut recipient_pk_hash)?;

    // Convert amounts to base units (1 TSN = 10^9)
    let decimals = config::COIN_DECIMALS;
    let multiplier = 10u64.pow(decimals);
    let amount_base = (amount * multiplier as f64) as u64;
    let fee_base = (fee * multiplier as f64) as u64;
    let total_needed = amount_base + fee_base;

    // Load and scan wallet (exclusive lock vs mining). v2.3.2: switch to
    // non-blocking try_acquire so the user gets an actionable error instead
    // of a process that silently waits forever when their own miner is
    // currently holding the lock.
    let _lock = match WalletLock::try_acquire(wallet_path)? {
        Some(l) => l,
        None => anyhow::bail!(
            "Wallet is locked by another process (typically a running miner on the \
             same wallet file). Either stop that process, or run the miner against \
             a dedicated wallet — e.g. `./tsn new-wallet --output miner-wallet.json` \
             and start the miner with `--wallet miner-wallet.json`, keeping the \
             current wallet for sends only."
        ),
    };
    let mut wallet = ShieldedWallet::open(wallet_path)
        .or_else(|_| ShieldedWallet::load(wallet_path))?;
    try_scan_via_api(&mut wallet, node_url, wallet_path).await;

    let balance = wallet.balance();
    println!();
    println!("  Wallet:    {}", wallet_path);
    println!("  Balance:   {}{:.4} TSN{}", green, balance as f64 / multiplier as f64, reset);
    println!("  Sending:   {}{:.4} TSN{} to {}...{}", cyan, amount, reset, &to[..8], &to[56..]);
    println!("  Fee:       {:.4} TSN", fee);
    if balance < total_needed {
        anyhow::bail!("Insufficient balance: have {:.4} TSN, need {:.4} TSN",
            balance as f64 / multiplier as f64,
            total_needed as f64 / multiplier as f64
        );
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // Filter already-spent notes by checking nullifiers against the node
    {
        let nk_bytes = wallet.nullifier_key_bytes();
        let mut nullifier_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut nullifier_hexes: Vec<String> = Vec::new();
        let notes = wallet.notes_mut();
        for (i, note) in notes.iter().enumerate() {
            if !note.is_spent {
                if let Some(pq_cm) = note.pq_commitment {
                    let nf = tsn::crypto::pq::commitment_pq::derive_nullifier_pq(
                        &nk_bytes, &pq_cm, note.position
                    );
                    let nf_hex = hex::encode(nf);
                    nullifier_map.insert(nf_hex.clone(), i);
                    nullifier_hexes.push(nf_hex);
                }
            }
        }
        if !nullifier_hexes.is_empty() {
            let check_url = format!("{}/nullifiers/check", node_url);
            if let Ok(resp) = client.post(&check_url)
                .json(&serde_json::json!({"nullifiers": nullifier_hexes}))
                .send().await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(spent_arr) = body["spent"].as_array() {
                        let notes = wallet.notes_mut();
                        let mut count = 0;
                        for s in spent_arr {
                            if let Some(h) = s.as_str() {
                                if let Some(&idx) = nullifier_map.get(h) {
                                    notes[idx].is_spent = true;
                                    count += 1;
                                }
                            }
                        }
                        if count > 0 {
                            eprintln!("  ({} spent notes filtered)", count);
                            if let Err(e) = wallet.save(wallet_path) {
                                tracing::error!("Failed to save wallet after nullifier check: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    // v2.3.3: pre-validate unspent note witnesses against the node. Flags
    // notes that were orphaned by chain reorgs since the last scan, so both
    // auto_consolidate and the final send skip them from their first batch
    // instead of wasting a proof attempt discovering them round by round.
    // cmd_send needs every orphan caught up-front, so best_effort = false.
    let pre_orphan_positions = pre_validate_orphan_positions(&wallet, node_url, &client, false).await;

    // Spendable balance check, after subtracting pre-detected orphans. This
    // is informational; the actual selection re-checks in both auto_consolidate
    // and the final send loop.
    if !pre_orphan_positions.is_empty() {
        let orphan_value: u64 = wallet.notes().iter()
            .filter(|n| !n.is_spent && pre_orphan_positions.contains(&n.position))
            .map(|n| n.note.value)
            .sum();
        let spendable = balance.saturating_sub(orphan_value);
        println!(
            "  Spendable: {}{:.4} TSN{} ({} orphan note(s) excluded, {:.4} TSN stuck)",
            green,
            spendable as f64 / multiplier as f64,
            reset,
            pre_orphan_positions.len(),
            orphan_value as f64 / multiplier as f64,
        );
        if spendable < total_needed {
            anyhow::bail!(
                "Insufficient spendable balance after excluding {} orphan note(s): \
                 have {:.4} TSN, need {:.4} TSN. Run `./tsn` menu 4 (Rescan wallet) \
                 to refresh the wallet state.",
                pre_orphan_positions.len(),
                spendable as f64 / multiplier as f64,
                total_needed as f64 / multiplier as f64,
            );
        }
    }

    // Count notes required for the final send, excluding pre-detected orphans.
    // If > CONSOLIDATION_BATCH, auto-consolidate first so the user only sees
    // one recipient-facing tx.
    let needed_count: usize = {
        let unspent = wallet.unspent_notes();
        let mut sorted: Vec<&tsn::wallet::WalletNote> = unspent.iter()
            .copied()
            .filter(|n| !pre_orphan_positions.contains(&n.position))
            .collect();
        sorted.sort_by(|a, b| b.note.value.cmp(&a.note.value));
        let mut acc = 0u64;
        let mut c = 0usize;
        for n in &sorted {
            if acc >= total_needed { break; }
            acc += n.note.value;
            c += 1;
        }
        c
    };

    if needed_count > CONSOLIDATION_BATCH {
        println!();
        println!(
            "  {}Auto-consolidation required{}: {} notes needed, max {} per tx.",
            cyan, reset, needed_count, CONSOLIDATION_BATCH
        );
        let rounds = auto_consolidate(
            &mut wallet, wallet_path, node_url, fee_base, total_needed, &client,
            pre_orphan_positions.clone(),
        ).await?;
        println!("  Consolidation complete ({} rounds).", rounds);
        println!();
    }

    // Final greedy-select after any consolidation. v2.3.1: retry loop that
    // excludes orphan notes discovered mid-proof if the final selection still
    // happens to contain one. v2.3.3: seed the exclusion set with positions
    // already flagged by pre_validate_orphan_positions above.
    let mut final_bad_positions: std::collections::HashSet<u64> = pre_orphan_positions;
    let max_final_retries = 20usize;
    let mut final_attempt = 0usize;
    let (tx_hash, _nullifiers, selected_total) = loop {
        final_attempt += 1;
        if final_attempt > max_final_retries {
            anyhow::bail!(
                "Final send aborted after {} retries with orphan notes — \
                 wallet state is deeply inconsistent, please rescan.",
                max_final_retries
            );
        }

        let selected: Vec<tsn::wallet::WalletNote> = {
            let unspent = wallet.unspent_notes();
            let mut sorted: Vec<&tsn::wallet::WalletNote> = unspent.iter()
                .copied()
                .filter(|n| !final_bad_positions.contains(&n.position))
                .collect();
            sorted.sort_by(|a, b| b.note.value.cmp(&a.note.value));
            let mut out: Vec<tsn::wallet::WalletNote> = Vec::new();
            let mut acc = 0u64;
            for n in &sorted {
                if acc >= total_needed { break; }
                out.push((*n).clone());
                acc += n.note.value;
            }
            out
        };
        if selected.len() > CONSOLIDATION_BATCH {
            anyhow::bail!(
                "After consolidation, still need {} notes (max {}). Unexpected.",
                selected.len(), CONSOLIDATION_BATCH
            );
        }
        let selected_total: u64 = selected.iter().map(|n| n.note.value).sum();
        if selected_total < total_needed {
            anyhow::bail!(
                "Insufficient spendable notes after excluding orphans: have {} TSN, need {} TSN",
                selected_total as f64 / multiplier as f64,
                total_needed as f64 / multiplier as f64
            );
        }
        let change = selected_total - total_needed;
        if final_attempt == 1 {
            println!(
                "  Notes:     {} selected ({:.4} TSN, change: {:.4} TSN)",
                selected.len(),
                selected_total as f64 / multiplier as f64,
                change as f64 / multiplier as f64
            );
        } else {
            println!(
                "  Notes:     {} re-selected attempt {} ({:.4} TSN, change: {:.4} TSN)",
                selected.len(), final_attempt,
                selected_total as f64 / multiplier as f64,
                change as f64 / multiplier as f64
            );
        }

        eprint!("  Proof:     generating... ");
        match send_single_tx(
            &selected, amount_base, fee_base, recipient_pk_hash, &wallet, node_url, &client,
        ).await {
            Ok((tx_hash, nullifiers)) => {
                break (tx_hash, nullifiers, selected_total);
            }
            Err(e) => {
                let orphans = parse_orphan_positions(&e.to_string());
                if !orphans.is_empty() {
                    eprintln!("orphan notes detected, retrying without them");
                    for p in &orphans {
                        final_bad_positions.insert(*p);
                        eprintln!("  ⚠ excluding orphan note at position {}", p);
                    }
                    continue;
                }
                return Err(e);
            }
        }
    };
    let _ = selected_total;
    eprintln!("done");
    let seeds_n = config::get_seed_nodes().len();
    eprintln!(
        "  Submit:    {}confirmed!{} (relayed to {} seeds)",
        green, reset, seeds_n
    );
    println!();
    println!("  {}TX: {}{}", green, tx_hash, reset);
    println!();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    wallet.add_tx(tsn::wallet::WalletTxRecord {
        tx_hash: tx_hash.clone(),
        direction: "sent".to_string(),
        amount: amount_base,
        fee: fee_base,
        counterparty: to.to_string(),
        height: 0,
        timestamp: now,
    });
    if let Err(e) = wallet.save(wallet_path) {
        tracing::error!("Failed to save wallet after send: {}", e);
    }

    Ok(())
}

async fn try_scan_via_api(wallet: &mut ShieldedWallet, node_url: &str, wallet_path: &str) -> (bool, usize) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (false, 0),
    };

    // Check node is reachable and get chain height
    let info_url = format!("{}/chain/info", node_url);
    let chain_height: u64 = match client.get(&info_url).send().await {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(v) => v["height"].as_u64().unwrap_or(0),
                Err(_) => return (false, 0),
            }
        }
        _ => return (false, 0),
    };

    let scanned_height = wallet.last_scanned_height();
    if chain_height <= scanned_height {
        return (true, 0); // already up to date
    }

    let blocks_to_scan = chain_height - scanned_height;
    if blocks_to_scan > 50 {
        eprint!("  Scanning {} blocks via outputs API...", blocks_to_scan);
    }

    // Use /outputs/since/ API — returns each output with its CORRECT position
    // from the server's merkle tree. This avoids position mismatch after fast-sync.
    let url = format!("{}/outputs/since/{}", node_url, scanned_height);
    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(_) => return (false, 0),
            }
        }
        _ => return (false, 0),
    };

    let outputs = match resp["outputs"].as_array() {
        Some(arr) => arr,
        None => return (false, 0),
    };

    let mut new_notes = 0usize;
    let mut max_height = scanned_height;

    for output in outputs {
        let position = output["position"].as_u64().unwrap_or(0);
        let block_height = output["block_height"].as_u64().unwrap_or(0);
        let note_commitment = output["note_commitment"].as_str().unwrap_or("");
        let note_commitment_pq = output["note_commitment_pq"].as_str().unwrap_or("");
        let ephemeral_pk_hex = output["ephemeral_pk"].as_str().unwrap_or("");
        let ciphertext_hex = output["ciphertext"].as_str().unwrap_or("");

        // Reconstruct EncryptedNote from hex data
        let ephemeral_pk = match hex::decode(ephemeral_pk_hex) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ciphertext = match hex::decode(ciphertext_hex) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let encrypted_note = tsn::crypto::note::EncryptedNote {
            ciphertext,
            ephemeral_pk,
        };

        if wallet.scan_encrypted_output(
            &encrypted_note,
            note_commitment,
            note_commitment_pq,
            position,
            block_height,
        ) {
            new_notes += 1;

            // Detect received TX (not mining reward)
            // Mining rewards are exactly miner_reward or dev_fee amounts
            let miner_rwd = config::miner_reward(config::BLOCK_REWARD);
            let dev_rwd = config::dev_fee(config::BLOCK_REWARD);
            let last_note = wallet.notes().last();
            if let Some(note) = last_note {
                let val = note.note.value;
                if val != miner_rwd && val != dev_rwd && val > 0 {
                    // This is a received transfer, not a mining reward
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    wallet.add_tx(tsn::wallet::WalletTxRecord {
                        tx_hash: format!("received-at-height-{}", block_height),
                        direction: "received".to_string(),
                        amount: val,
                        fee: 0,
                        counterparty: "unknown".to_string(),
                        height: block_height,
                        timestamp: now,
                    });
                }
            }
        }

        if block_height > max_height {
            max_height = block_height;
        }
    }

    // Update scanned height to the chain height (we scanned all available outputs)
    wallet.set_last_scanned_height(chain_height);

    // Check PQ nullifiers to mark spent notes
    {
        let nk_bytes = wallet.nullifier_key_bytes();
        let mut nullifier_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut nullifier_hexes: Vec<String> = Vec::new();
        let notes = wallet.notes_mut();
        for (i, note) in notes.iter().enumerate() {
            if !note.is_spent {
                if let Some(pq_cm) = note.pq_commitment {
                    let nf = tsn::crypto::pq::commitment_pq::derive_nullifier_pq(
                        &nk_bytes, &pq_cm, note.position
                    );
                    let nf_hex = hex::encode(nf);
                    nullifier_map.insert(nf_hex.clone(), i);
                    nullifier_hexes.push(nf_hex);
                }
            }
        }
        if !nullifier_hexes.is_empty() {
            let check_url = format!("{}/nullifiers/check", node_url);
            if let Ok(resp) = client.post(&check_url)
                .json(&serde_json::json!({"nullifiers": nullifier_hexes}))
                .send().await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(spent_arr) = body["spent"].as_array() {
                        let notes = wallet.notes_mut();
                        for s in spent_arr {
                            if let Some(h) = s.as_str() {
                                if let Some(&idx) = nullifier_map.get(h) {
                                    notes[idx].is_spent = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if blocks_to_scan > 50 {
        eprintln!(" done ({} new notes).", new_notes);
    }

    if chain_height > scanned_height {
        if let Err(e) = wallet.save(wallet_path) {
            tracing::error!("Failed to save wallet after API scan: {}", e);
        }
    }
    (true, new_notes)
}

fn cmd_mine(
    wallet_path: &str,
    blocks: u64,
    difficulty: u64,
    jobs: usize,
    simd: Option<SimdMode>,
    mode: MiningMode,
) -> anyhow::Result<()> {
    let jobs = jobs.max(1);
    let simd = require_simd_support(simd);
    // Open wallet (SQLite or migrate from JSON) for mining rewards
    let wallet = ShieldedWallet::open(wallet_path)?;
    let miner_pk_hash = wallet.pk_hash();
    let viewing_key = wallet.viewing_key().clone();

    match mode {
        MiningMode::Mine => println!("Starting standalone miner..."),
        MiningMode::Benchmark => println!("Starting mining benchmark..."),
    }
    println!("Miner wallet: {}", wallet_path);
    println!("Miner pk_hash: {}", hex::encode(miner_pk_hash));
    println!("Difficulty: {} leading zero bits", difficulty);
    println!("Threads: {}", jobs);
    if let Some(simd) = simd {
        println!("SIMD mode: {:?}", simd);
    }
    let pool = MiningPool::new_with_simd(jobs, simd);
    let mut blockchain = ShieldedBlockchain::with_miner(difficulty, miner_pk_hash, &viewing_key);
    let mut blocks_mined = 0u64;
    let mut total_attempts = 0u64;
    let mut total_elapsed = std::time::Duration::ZERO;

    loop {
        let mempool_txs = vec![]; // Standalone miner has no mempool
        let mut block = blockchain.create_block_template(miner_pk_hash, &viewing_key, mempool_txs);

        println!(
            "\nMining block {} (prev: {}...)",
            blockchain.height() + 1,
            &hex::encode(&block.header.prev_hash)[..16]
        );

        let start = std::time::Instant::now();
        let attempts = pool.mine_block(&mut block);
        let elapsed = start.elapsed();
        total_attempts = total_attempts.saturating_add(attempts);
        total_elapsed += elapsed;

        println!(
            "Block mined! Hash: {}...",
            &block.hash_hex()[..16]
        );
        println!(
            "  {} attempts in {:.2}s ({:.0} H/s)",
            attempts,
            elapsed.as_secs_f64(),
            attempts as f64 / elapsed.as_secs_f64()
        );

        blockchain.add_block(block)?;

        blocks_mined += 1;
        println!(
            "  Chain height: {}, Commitments: {}",
            blockchain.height(),
            blockchain.state().commitment_count()
        );

        if blocks > 0 && blocks_mined >= blocks {
            println!("\nMined {} blocks, stopping.", blocks_mined);
            if total_elapsed.as_secs_f64() > 0.0 {
                let avg_hashrate = total_attempts as f64 / total_elapsed.as_secs_f64();
                let label = match mode {
                    MiningMode::Mine => "Summary",
                    MiningMode::Benchmark => "Benchmark summary",
                };
                println!("{}:", label);
                println!(
                    "  Total attempts: {} in {:.2}s",
                    total_attempts,
                    total_elapsed.as_secs_f64()
                );
                println!("  Avg hashrate: {:.0} H/s", avg_hashrate);
            }
            break;
        }
    }

    Ok(())
}

/// Automatic snapshot export — triggered when a new block-based interval becomes finalized.
/// Exports the snapshot, signs the manifest, and requests cross-confirmations from seeds.
/// Runs as a fire-and-forget background task.
/// v2.3.0 Phase 2.1 — shared snapshot auto-trigger.
/// Called from both the P2P NewBlock handler and the local miner path after a
/// block is successfully added to the chain. Exports a signed snapshot when a
/// new multiple of SNAPSHOT_MANIFEST_INTERVAL just became finalized
/// (tip >= multiple + MAX_REORG_DEPTH).
///
/// Single-fire guarantee: the AtomicU64 `last_snapshot_auto_trigger` CAS ensures
/// at most one export is spawned per interval-crossing, even if both paths race
/// on the same tip or a reorg brings us back to the crossing height.
fn check_snapshot_auto_trigger(state: &std::sync::Arc<tsn::network::AppState>, tip_h: u64) {
    use std::sync::atomic::Ordering;
    let interval = tsn::config::SNAPSHOT_MANIFEST_INTERVAL;
    let max_reorg = tsn::config::MAX_REORG_DEPTH;
    // v2.3.6 — fix: was `<=` which caused the first interval (tip=max_reorg+interval,
    // e.g. 1100) to return early. Also removed the `prev_eligible` crossing check:
    // it only fired exactly at the tip transition, so a node that restarted above
    // the interval (or caught up via fast-sync) never triggered its first snapshot
    // until the NEXT interval. The atomic `last_snapshot_auto_trigger` below is the
    // correct single-fire guard on its own.
    if tip_h < max_reorg + interval {
        return;
    }
    let finalized = tip_h - max_reorg;
    let latest_eligible = (finalized / interval) * interval;
    if latest_eligible == 0 {
        return;
    }
    let last = state.last_snapshot_auto_trigger.load(Ordering::Relaxed);
    if latest_eligible <= last {
        return;
    }
    if state
        .last_snapshot_auto_trigger
        .compare_exchange(last, latest_eligible, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    // v2.3.7 — persist the trigger height to disk so we don't re-trigger on restart.
    // Previously the atomic was reset to 0 at boot, causing every restart to fire
    // a snapshot at the current (non-aligned) tip, polluting tsn-snapshots with
    // dozens of near-duplicate releases.
    let data_dir = tsn::config::get_data_dir();
    let trigger_file = std::path::PathBuf::from(&data_dir).join(".last_snapshot_trigger");
    let _ = std::fs::write(&trigger_file, latest_eligible.to_string());

    tracing::info!(
        "Snapshot auto-trigger: height {} finalized interval {}",
        latest_eligible, interval
    );
    let snap_state = state.clone();
    let export_height = latest_eligible;
    tokio::spawn(async move {
        auto_snapshot_export(snap_state, export_height).await;
    });
}

/// v2.3.7 — Load the last-triggered snapshot height from disk so we don't re-fire
/// a snapshot at the same interval after a restart.
fn load_last_snapshot_trigger(data_dir: &str) -> u64 {
    let path = std::path::PathBuf::from(data_dir).join(".last_snapshot_trigger");
    match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    }
}

async fn auto_snapshot_export(state: std::sync::Arc<tsn::network::AppState>, tag_height: u64) {
    use tracing::{info, warn};

    // Only export if we have a signing key (seed nodes only)
    let signing_key = match &state.seed_signing_key {
        Some(k) => k,
        None => return, // miners without signing key skip snapshot export
    };

    // Export snapshot
    let (data, height, block_hash, state_root, peer_id_str) = {
        let chain = state.blockchain.read().unwrap_or_else(|e| e.into_inner());
        let tip = chain.height();
        if tip <= tsn::config::MAX_REORG_DEPTH + 100 {
            return;
        }
        let snapshot = match chain.export_snapshot() {
            Some(s) => s,
            None => return,
        };
        let state_root = hex::encode(chain.state_root());
        let p2p_id = state.p2p_peer_id.read().unwrap().clone().unwrap_or_default();
        (snapshot.0, snapshot.1, snapshot.2, state_root, p2p_id)
    };

    // Compress
    let compressed = {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        if encoder.write_all(&data).is_err() { return; }
        match encoder.finish() {
            Ok(c) => c,
            Err(_) => return,
        }
    };

    // SHA256
    let snapshot_sha256 = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&compressed))
    };

    // Build and sign manifest
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let mut manifest = tsn::network::snapshot_manifest::SnapshotManifest {
        version: 1,
        chain_id: tsn::config::NETWORK_NAME.to_string(),
        height,
        block_hash,
        state_root,
        snapshot_sha256,
        snapshot_size_bytes: compressed.len() as u64,
        format: "json-gzip".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        producer: tsn::network::snapshot_manifest::SeedIdentity {
            seed_name: state.public_url.clone().unwrap_or_else(|| "unknown".to_string()),
            peer_id: peer_id_str,
            public_key: public_key_hex,
        },
        signature: String::new(),
        confirmations: Vec::new(),
    };

    let payload = manifest.signing_payload();
    manifest.signature = tsn::network::snapshot_manifest::sign_ed25519(signing_key, &payload);

    info!(
        "Auto snapshot exported: height={}, sha256={}, size={}KB",
        manifest.height, &manifest.snapshot_sha256[..16], manifest.snapshot_size_bytes / 1024
    );

    // v2.3.4: Persist snapshot + manifest to disk so they survive process restarts.
    // Retention: 24h (~2880 blocks @ 30s). Older snapshots are pruned by mtime.
    {
        let data_dir = std::path::PathBuf::from(tsn::config::get_data_dir());
        persist_snapshot_to_disk(&data_dir, height, &compressed, &manifest).await;
    }

    // v2.3.5: publish the signed snapshot to the public tsn-snapshots GitHub
    // repo so community light clients and miners can fast-sync from a durable
    // mirror (seeds may be NAT'd, behind rate limits, or offline). The token
    // is read from env TSN_SNAPSHOT_GH_TOKEN; if absent, publishing is
    // skipped silently (not every seed is configured as a publisher).
    {
        let client = state.http_client.clone();
        let compressed_for_gh = compressed.clone();
        let manifest_for_gh = manifest.clone();
        // v2.3.7 — tag by interval-multiple (e.g. "snapshot-2000") rather than by
        // exact chain height. This makes the tag deterministic across seeds that
        // race to publish the same interval, so GitHub's idempotent tag check
        // actually hits (422 → skip) instead of creating near-duplicate releases
        // like snapshot-1582, snapshot-1585, snapshot-1587, snapshot-1592.
        let gh_tag_height = tag_height;
        tokio::spawn(async move {
            publish_snapshot_to_github(&client, &manifest_for_gh, &compressed_for_gh, gh_tag_height).await;
        });
    }

    // Store in snapshot cache for coherent /snapshot/download
    {
        let cache_hash = manifest.block_hash.clone();
        let mut cache = state.snapshot_cache.write().await;
        *cache = Some(tsn::network::api::CachedSnapshot {
            compressed,
            height,
            hash: cache_hash,
            raw_size: data.len(),
        });
    }

    // Store manifest
    {
        let mut manifests = state.snapshot_manifests.write().unwrap();
        if let Some(pos) = manifests.iter().position(|m| m.height == manifest.height) {
            manifests[pos] = manifest.clone();
        } else {
            manifests.push(manifest.clone());
            if manifests.len() > 10 { manifests.remove(0); }
        }
    }

    // Request cross-confirmations from seeds (async)
    let client = &state.http_client;
    let confirm_body = match serde_json::to_string(&manifest) {
        Ok(b) => b,
        Err(_) => return,
    };

    for seed_url in tsn::config::SEED_NODES.iter() {
        if let Some(ref our_url) = state.public_url {
            if seed_url.contains(our_url.split("://").last().unwrap_or("")) {
                continue;
            }
        }
        let url = format!("{}/snapshot/confirm", seed_url);
        match client.post(&url)
            .header("Content-Type", "application/json")
            .body(confirm_body.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(confirmation) = resp.json::<tsn::network::snapshot_manifest::SeedConfirmation>().await {
                    if confirmation.verify() {
                        info!("Auto snapshot: confirmation from {} for height {}", confirmation.seed_name, manifest.height);
                        let mut manifests = state.snapshot_manifests.write().unwrap();
                        if let Some(m) = manifests.iter_mut().find(|m| m.height == manifest.height) {
                            if !m.confirmations.iter().any(|c| c.seed_name == confirmation.seed_name) {
                                m.confirmations.push(confirmation);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let final_confs = state.snapshot_manifests.read().unwrap()
        .iter().find(|m| m.height == manifest.height)
        .map(|m| m.valid_confirmation_count()).unwrap_or(0);
    info!("Auto snapshot complete: height={}, {} confirmations", manifest.height, final_confs);
}

/// Persist a signed snapshot and its manifest to `<data_dir>/snapshots/`.
/// Applies a 24h retention policy by mtime. Errors are logged but non-fatal
/// (cache in RAM remains authoritative for `/snapshot/download`).
async fn persist_snapshot_to_disk(
    data_dir: &std::path::Path,
    height: u64,
    compressed: &[u8],
    manifest: &tsn::network::snapshot_manifest::SnapshotManifest,
) {
    use tracing::{info, warn};
    let dir = data_dir.join("snapshots");
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        warn!("Snapshot persistence: failed to create {:?}: {}", dir, e);
        return;
    }

    let snap_path = dir.join(format!("snapshot-{}.json.gz", height));
    let manifest_path = dir.join(format!("snapshot-{}.manifest.json", height));

    if let Err(e) = tokio::fs::write(&snap_path, compressed).await {
        warn!("Snapshot persistence: failed to write {:?}: {}", snap_path, e);
        return;
    }
    let manifest_bytes = match serde_json::to_vec_pretty(manifest) {
        Ok(b) => b,
        Err(e) => {
            warn!("Snapshot persistence: failed to serialize manifest for height {}: {}", height, e);
            return;
        }
    };
    if let Err(e) = tokio::fs::write(&manifest_path, &manifest_bytes).await {
        warn!("Snapshot persistence: failed to write {:?}: {}", manifest_path, e);
        return;
    }
    info!(
        "Snapshot persisted: height={}, path={}, size={}KB",
        height, snap_path.display(), compressed.len() / 1024
    );

    // Retention: prune files older than 24h (by mtime).
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(86400));
    let cutoff = match cutoff {
        Some(c) => c,
        None => return,
    };
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(e) => e,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("snapshot-") {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if modified < cutoff {
            if let Err(e) = tokio::fs::remove_file(&path).await {
                warn!("Snapshot retention: failed to delete {:?}: {}", path, e);
            } else {
                info!("Snapshot retention: pruned {}", name);
            }
        }
    }
}

/// v2.3.5: publish a signed snapshot to the public tsn-snapshots GitHub repo.
/// Requires the `TSN_SNAPSHOT_GH_TOKEN` env var to be set on the seed running
/// this binary; without it, publishing is a silent no-op (non-publisher seeds
/// keep running normally). Errors at any HTTP step are logged at WARN and the
/// function returns — the local snapshot cache is still authoritative for
/// `/snapshot/download`, so failure to publish does not block chain operation.
///
/// Release naming: `snapshot-<height>`. Tag the release with `snapshot-<height>`
/// so consumers can download `https://github.com/trusts-stack-network/tsn-snapshots/releases/download/snapshot-<height>/snapshot.tar.gz`.
/// Retention: the function prunes releases older than the 10 most recent so the
/// repo does not grow unbounded.
async fn publish_snapshot_to_github(
    client: &reqwest::Client,
    manifest: &tsn::network::snapshot_manifest::SnapshotManifest,
    compressed: &[u8],
    tag_height: u64,
) {
    use tracing::{info, warn};
    let token = match std::env::var("TSN_SNAPSHOT_GH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return,
    };

    let owner_repo = "trusts-stack-network/tsn-snapshots";
    // v2.3.7 — tag by interval-multiple (passed in), not manifest.height. This
    // makes the tag deterministic so concurrent publishers collide and only one
    // succeeds.
    let tag = format!("snapshot-{}", tag_height);

    // v2.3.7 — HEAD probe before POST to catch the race window where two seeds
    // both see a missing tag and fire create-release. GitHub's POST handler does
    // return 422 for duplicate tags but the check is not strictly atomic; a HEAD
    // first removes most of the window.
    let head_url = format!(
        "https://api.github.com/repos/{}/releases/tags/{}",
        owner_repo, tag
    );
    if let Ok(resp) = client
        .get(&head_url)
        .bearer_auth(&token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
    {
        if resp.status().is_success() {
            info!("Snapshot GitHub publish: tag {} already exists (HEAD 200), skipping", tag);
            return;
        }
    }

    let create_url = format!("https://api.github.com/repos/{}/releases", owner_repo);
    let body = serde_json::json!({
        "tag_name": tag,
        "name": format!("Snapshot height={} ({})", manifest.height, manifest.chain_id),
        "body": format!(
            "Signed snapshot for chain {} at height {}.\n\n\
             - block_hash: `{}`\n\
             - state_root: `{}`\n\
             - snapshot_sha256: `{}`\n\
             - size: {} bytes (compressed)\n\
             - producer: `{}`\n\
             - confirmations: {}\n\n\
             Verify with the public release signing key (see auto_update.rs \
             `RELEASE_SIGNING_PUBKEY`) against `snapshot.tar.gz`'s sha256 and \
             `manifest.json`'s `signature` field.",
            manifest.chain_id,
            manifest.height,
            manifest.block_hash,
            manifest.state_root,
            manifest.snapshot_sha256,
            manifest.snapshot_size_bytes,
            manifest.producer.seed_name,
            manifest.confirmations.len(),
        ),
        "draft": false,
        "prerelease": false,
    });

    let resp = match client
        .post(&create_url)
        .bearer_auth(&token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Snapshot GitHub publish: create release failed: {}", e);
            return;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        // 422 = tag already exists — treat as idempotent success, don't spam warns.
        if status.as_u16() == 422 {
            info!("Snapshot GitHub publish: tag {} already exists, skipping upload", tag);
            return;
        }
        warn!(
            "Snapshot GitHub publish: create release returned {} — {}",
            status,
            text.chars().take(200).collect::<String>()
        );
        return;
    }

    let release: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("Snapshot GitHub publish: parse create response failed: {}", e);
            return;
        }
    };

    let upload_url_template = match release["upload_url"].as_str() {
        Some(s) => s.to_string(),
        None => {
            warn!("Snapshot GitHub publish: no upload_url in response");
            return;
        }
    };
    // upload_url template looks like "...{?name,label}" — strip the suffix.
    let upload_base = upload_url_template
        .split_once('{')
        .map(|(head, _)| head.to_string())
        .unwrap_or(upload_url_template);

    // Upload the compressed snapshot as `snapshot.tar.gz`.
    let snap_url = format!("{}?name=snapshot.tar.gz", upload_base);
    match client
        .post(&snap_url)
        .bearer_auth(&token)
        .header("Content-Type", "application/gzip")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
        .body(compressed.to_vec())
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            warn!(
                "Snapshot GitHub publish: asset upload returned {}",
                r.status()
            );
            return;
        }
        Err(e) => {
            warn!("Snapshot GitHub publish: asset upload failed: {}", e);
            return;
        }
    }

    // Upload the signed manifest as `manifest.json`.
    let manifest_json = match serde_json::to_vec_pretty(manifest) {
        Ok(b) => b,
        Err(_) => return,
    };
    let manifest_url = format!("{}?name=manifest.json", upload_base);
    if let Err(e) = client
        .post(&manifest_url)
        .bearer_auth(&token)
        .header("Content-Type", "application/json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
        .body(manifest_json)
        .send()
        .await
    {
        warn!("Snapshot GitHub publish: manifest upload failed: {}", e);
        return;
    }

    info!(
        "Snapshot GitHub publish: tag={}, size={}KB",
        tag, compressed.len() / 1024
    );

    // Retention: prune releases older than the 10 most recent.
    prune_github_snapshot_releases(client, &token, owner_repo, 10).await;
}

/// Keep only the `keep` most recent snapshot- releases on the tsn-snapshots
/// repo. Older releases are deleted along with their git tags. Silent on
/// errors — retention is best-effort.
async fn prune_github_snapshot_releases(
    client: &reqwest::Client,
    token: &str,
    owner_repo: &str,
    keep: usize,
) {
    use tracing::{info, warn};
    let list_url = format!("https://api.github.com/repos/{}/releases?per_page=100", owner_repo);
    let resp = match client
        .get(&list_url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Snapshot retention: list releases failed: {}", e);
            return;
        }
    };
    if !resp.status().is_success() {
        return;
    }
    let releases: Vec<serde_json::Value> = match resp.json().await {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut snapshots: Vec<(i64, u64, String)> = releases
        .iter()
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?.to_string();
            if !tag.starts_with("snapshot-") {
                return None;
            }
            let height: u64 = tag.trim_start_matches("snapshot-").parse().ok()?;
            let id = r["id"].as_i64()?;
            Some((id, height, tag))
        })
        .collect();
    // Sort descending by height, keep the first `keep`.
    snapshots.sort_by(|a, b| b.1.cmp(&a.1));
    if snapshots.len() <= keep {
        return;
    }
    for (id, height, tag) in snapshots.into_iter().skip(keep) {
        let rel_url = format!("https://api.github.com/repos/{}/releases/{}", owner_repo, id);
        let _ = client
            .delete(&rel_url)
            .bearer_auth(token)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
            .send()
            .await;
        let tag_url = format!("https://api.github.com/repos/{}/git/refs/tags/{}", owner_repo, tag);
        let _ = client
            .delete(&tag_url)
            .bearer_auth(token)
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, format!("tsn-snapshot-publisher/{}", env!("CARGO_PKG_VERSION")))
            .send()
            .await;
        info!("Snapshot retention: pruned GitHub release {} (height {})", tag, height);
    }
}

async fn cmd_node(
    port: u16,
    peers: Vec<String>,
    data_dir: &str,
    mine_wallet: Option<String>,
    jobs: usize,
    simd: Option<SimdMode>,
    public_url: Option<String>,
    force_mine: bool,
    faucet_wallet: Option<String>,
    faucet_daily_limit: Option<u64>,
    fast_sync: bool,
    node_role: NodeRole,
) -> anyhow::Result<()> {
    use tsn::network::{AppState, MinerStats, sync_from_peer, sync_loop, broadcast_block, discovery_loop};
    use tsn::crypto::proof::CircomVerifyingParams;
    use tsn::faucet::FaucetService;
    use tsn::storage::Database;
    use std::sync::RwLock;
    use tokio::sync::RwLock as TokioRwLock;

    let simd = require_simd_support(simd);

    // Create data directory if needed
    std::fs::create_dir_all(data_dir)?;

    // Open wallet (SQLite or migrate from JSON) for any role
    let miner_info = if let Some(wallet_path) = &mine_wallet {
        let wallet = ShieldedWallet::open(wallet_path)?;
        let pk_hash = wallet.pk_hash();
        let viewing_key = wallet.viewing_key().clone();
        Some((pk_hash, viewing_key))
    } else {
        None
    };

    let role_icon = match node_role {
        NodeRole::Miner => "⛏️",
        NodeRole::Relay => "🔄",
        NodeRole::LightClient => "💡",
    };

    let version_str = env!("CARGO_PKG_VERSION");
    let banner_line = format!("║     TSN Shielded Node v{:<19}║", version_str);
    println!();
    println!("╔═══════════════════════════════════════════╗");
    println!("{}", banner_line);
    println!("╚═══════════════════════════════════════════╝");
    println!();
    // ANSI color codes
    let green = "\x1b[1;32m";   // bold green
    let cyan = "\x1b[1;36m";    // bold cyan
    let yellow = "\x1b[1;33m";  // bold yellow
    let reset = "\x1b[0m";

    println!("  {} Role:        {}{} ({}){}", role_icon, green, node_role, node_role.description(), reset);
    println!("  Network:      {}", config::NETWORK_NAME);
    println!("  Port:         {}", port);
    println!("  Data:         {}", data_dir);
    if node_role.stores_full_chain() {
        println!("  Explorer:     https://explorer.tsnchain.com");
    }
    if let Some((ref pk_hash, _)) = miner_info {
        println!();
        match node_role {
            NodeRole::Miner => {
                println!("  {}⛏️  MINING ACTIVE{}", yellow, reset);
                println!("  Threads:      {}{}{}", cyan, jobs, reset);
                println!("  Address:      {}", hex::encode(pk_hash));
                println!("  Reward split: 92% miner / 5% dev fees / 3% relay pool");
            }
            NodeRole::Relay => {
                println!("  {}🔄 RELAY WALLET{}", yellow, reset);
                println!("  Address:      {}", hex::encode(pk_hash));
                println!("  Reward:       3% relay pool");
            }
            NodeRole::LightClient => {
                println!("  {}💡 WALLET ACTIVE{}", yellow, reset);
                println!("  Address:      {}", hex::encode(pk_hash));
            }
        }
    } else {
        match node_role {
            NodeRole::Miner => {
                println!();
                println!("  Mining:       INACTIVE (no wallet provided)");
            }
            NodeRole::Relay => {}
            NodeRole::LightClient => {}
        }
    }
    if !peers.is_empty() {
        println!("  Seed peers:   {}", peers.len());
    }
    println!();

    // Initialize blockchain with persistence
    let db_path = format!("{}/blockchain", data_dir);

    // v2.3.5: auto-wipe obsolete chain data on testnet reset. When the on-disk
    // genesis does not match EXPECTED_GENESIS_HASH (because we bumped the
    // network name / coinbase tag), the previous data is from an older testnet
    // and must be discarded. The blockchain DB itself refuses to open with a
    // mismatched genesis; catch that one specific error, wipe blockchain +
    // snapshots, and retry. Wallet DB is left alone — the wallet code handles
    // its own obsolescence via a network_name field.
    let mut blockchain = match ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY) {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("Genesis hash mismatch") {
                tracing::warn!(
                    "v2.3.5 auto-wipe: obsolete chain data detected ({}). Wiping {} and {}/snapshots to boot on the current testnet.",
                    msg, db_path, data_dir
                );
                let snap_path = format!("{}/snapshots", data_dir);
                let _ = std::fs::remove_dir_all(&db_path);
                let _ = std::fs::remove_dir_all(&snap_path);
                ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY)?
            } else {
                return Err(e.into());
            }
        }
    };

    // NOTE: Startup fork detection was removed in v1.3.4 — it caused false positives
    // when deploying to multiple nodes simultaneously (peers not yet ready → cumulative_work
    // mismatch → incorrectly wiped the chain). The post-mining fork check (comparing
    // cumulative_work after each mined block, see fork check section below) is sufficient
    // and doesn't have this race condition.

    // Fast sync: paginated block download from peers
    // Works for fresh nodes (height=0) AND nodes that are behind
    if fast_sync && !peers.is_empty() {
        let local_height = blockchain.height();
        // Check if any peer is ahead of us
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // v1.4.0: Select sync peer by cumulative_work (heaviest chain), not just height.
        // Query /chain/info for work from each peer. Keep peers within 5% of max work.
        // v1.6.1: Select peers by HEIGHT only, not cumulative_work
        let mut eligible_peers: Vec<(String, u64)> = Vec::new(); // (url, height)
        let mut max_height = 0u64;
        for peer_url in &peers {
            let info_url = format!("{}/chain/info", peer_url);
            if let Ok(resp) = client.get(&info_url)
                .timeout(std::time::Duration::from_secs(10))
                .send().await
            {
                if let Ok(info) = resp.json::<serde_json::Value>().await {
                    let peer_height = info["height"].as_u64().unwrap_or(0);
                    if peer_height > local_height + 10 {
                        if peer_height > max_height {
                            max_height = peer_height;
                        }
                        eligible_peers.push((peer_url.clone(), peer_height));
                    }
                }
            }
        }
        // Keep only peers within 2 blocks of the highest
        eligible_peers.retain(|(_, h)| *h >= max_height.saturating_sub(2));
        // Random selection to distribute load across seeds
        use rand::seq::SliceRandom;
        let best_peer = eligible_peers.choose(&mut rand::thread_rng())
            .map(|(url, h)| (url.clone(), *h));

        if let Some((peer_url, peer_height)) = best_peer {
            // v2.3.5: verify the peer is on the same testnet before syncing
            // from them. testnet-v5 seeds advertise a specific genesis hash;
            // a peer claiming a different one (or still running the v2.3.4
            // "tsn-mainnet" chain_id) is on an incompatible network, and
            // importing its snapshot would re-adopt the obsolete chain the
            // reset was meant to leave behind.
            {
                let info_url = format!("{}/chain/info", peer_url);
                let peer_genesis = client
                    .get(&info_url)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                    .ok()
                    .and_then(|r| r.error_for_status().ok())
                    .map(|r| async move { r.json::<serde_json::Value>().await.ok() });
                let peer_genesis = match peer_genesis {
                    Some(fut) => fut.await,
                    None => None,
                };
                if let Some(info) = peer_genesis {
                    let their_genesis = info["genesis_hash"].as_str().unwrap_or("");
                    let expected = tsn::config::EXPECTED_GENESIS_HASH;
                    let placeholder = "0".repeat(64);
                    if !expected.is_empty()
                        && !their_genesis.is_empty()
                        && their_genesis != placeholder
                        && their_genesis != expected
                    {
                        tracing::warn!(
                            "Fast sync: peer {} advertises genesis {} (expected {}) — different testnet, skipping",
                            peer_url, their_genesis, expected
                        );
                        return Ok(());
                    }
                }
            }

            let behind = peer_height - local_height;
            let start_time = std::time::Instant::now();

            // Strategy: if far behind (>100 blocks), use snapshot-based sync (instant)
            // Otherwise, use block-by-block trusted sync
            if behind > 50 {
                // ===== SNAPSHOT SYNC (instant) =====
                println!("Fast sync: {} blocks behind — downloading state snapshot...", behind);

                let snapshot_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(600))
                    .build()?;

                // Get snapshot info
                let info_url = format!("{}/snapshot/info", peer_url);
                let mut snapshot_ok = false;

                if let Ok(resp) = snapshot_client.get(&info_url).send().await {
                    if let Ok(info) = resp.json::<serde_json::Value>().await {
                        if info["available"].as_bool() == Some(true) {
                            let snap_height = info["height"].as_u64().unwrap_or(0);
                            let snap_hash_str = info["block_hash"].as_str().unwrap_or("");
                            let snap_size = info["size_bytes"].as_u64().unwrap_or(0);
                            println!("  Snapshot available: height={}, size={}KB", snap_height, snap_size / 1024);

                            // Download compressed snapshot
                            let dl_url = format!("{}/snapshot/download", peer_url);
                            if let Ok(resp) = snapshot_client.get(&dl_url).send().await {
                                if resp.status().is_success() {
                                    // v2.1.3 FIX: Use actual snapshot height from download headers,
                                    // not from /info which may be newer (cache staleness).
                                    // The download serves a cached snapshot that can be up to 99
                                    // blocks behind the live state reported by /info.
                                    let snap_height = resp.headers()
                                        .get("x-snapshot-height")
                                        .and_then(|v| v.to_str().ok())
                                        .and_then(|s| s.parse::<u64>().ok())
                                        .unwrap_or(snap_height);
                                    let snap_hash_str = resp.headers()
                                        .get("x-snapshot-hash")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or(snap_hash_str)
                                        .to_string();
                                    let snap_hash_str = snap_hash_str.as_str();

                                    let compressed = resp.bytes().await?;
                                    println!("  Downloaded {}KB compressed", compressed.len() / 1024);

                                    // Decompress
                                    use std::io::Read;
                                    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                    let mut json_data = Vec::new();
                                    if decoder.read_to_end(&mut json_data).is_ok() {
                                        // Parse snapshot
                                        if let Ok(snapshot) = serde_json::from_slice::<tsn::core::StateSnapshotPQ>(&json_data) {
                                            // Parse block hash
                                            let mut block_hash = [0u8; 32];
                                            if let Ok(hash_bytes) = hex::decode(snap_hash_str) {
                                                if hash_bytes.len() == 32 {
                                                    block_hash.copy_from_slice(&hash_bytes);
                                                }
                                            }

                                            // Get difficulty, next_difficulty AND cumulative_work from peer
                                            let (difficulty, next_diff, peer_work) = if let Ok(resp) = client.get(&format!("{}/chain/info", peer_url)).send().await {
                                                let info = resp.json::<serde_json::Value>().await.ok();
                                                let d = info.as_ref().and_then(|i| i["difficulty"].as_u64()).unwrap_or(GENESIS_DIFFICULTY);
                                                let nd = info.as_ref().and_then(|i| i["next_difficulty"].as_u64()).unwrap_or(d);
                                                let w = info.as_ref().and_then(|i| i["cumulative_work"].as_u64()).unwrap_or(0);
                                                (d, nd, w as u128)
                                            } else {
                                                (GENESIS_DIFFICULTY, GENESIS_DIFFICULTY, 0u128)
                                            };

                                            // v2.3.9 — seed LWMA headers before taking the blockchain lock
                                            // so the freshly fast-synced node can compute next_difficulty()
                                            // the same way full-sync validators do. Empty on peer error; in
                                            // that case we simply fall back to the legacy behaviour.
                                            let lwma_seed = tsn::network::sync::fetch_pre_snapshot_lwma_headers(&client, &peer_url, snap_height).await;

                                            // Import snapshot — sets chain state instantly
                                            blockchain.import_snapshot_at_height(snapshot, snap_height, block_hash, difficulty, next_diff, peer_work);
                                            if !lwma_seed.is_empty() {
                                                tracing::info!("pre_snapshot_lwma: seeded {} headers from {}", lwma_seed.len(), peer_url);
                                                blockchain.set_pre_snapshot_lwma(lwma_seed);
                                            }

                                            // Now sync only recent blocks (from snapshot height onward)
                                            println!("  Syncing recent blocks...");
                                            let mut synced = 0u64;
                                            let mut current = snap_height;
                                            loop {
                                                let url = format!("{}/blocks/since/{}", peer_url, current);
                                                match client.get(&url).send().await {
                                                    Ok(resp) if resp.status().is_success() => {
                                                        match resp.json::<Vec<serde_json::Value>>().await {
                                                            Ok(blocks) if !blocks.is_empty() => {
                                                                let count = blocks.len() as u64;
                                                                for bv in &blocks {
                                                                    if let Ok(block) = serde_json::from_value::<tsn::core::ShieldedBlock>(bv.clone()) {
                                                                        let _ = blockchain.add_block_trusted(block);
                                                                    }
                                                                }
                                                                current = blockchain.height();
                                                                synced += count;
                                                                if count < 50 { break; }
                                                            }
                                                            _ => break,
                                                        }
                                                    }
                                                    _ => break,
                                                }
                                            }

                                            let elapsed = start_time.elapsed().as_secs_f64();
                                            println!("  ✓ State restored at height {} + {} recent blocks in {:.1}s",
                                                snap_height, synced, elapsed);
                                            snapshot_ok = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !snapshot_ok {
                    println!("  Snapshot unavailable — falling back to block sync...");
                }

                // Fall through to block sync if snapshot failed
                if !snapshot_ok {
                    println!("  Block-by-block sync (trusted)...");
                    let mut current_height = local_height;
                    let mut total = 0u64;
                    loop {
                        let prev_height = current_height;
                        let url = format!("{}/blocks/since/{}", peer_url, current_height);
                        match client.get(&url).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.json::<Vec<serde_json::Value>>().await {
                                    Ok(blocks) if !blocks.is_empty() => {
                                        let n = blocks.len() as u64;
                                        for bv in &blocks {
                                            if let Ok(block) = serde_json::from_value::<tsn::core::ShieldedBlock>(bv.clone()) {
                                                let _ = blockchain.add_block_trusted(block);
                                            }
                                        }
                                        current_height = blockchain.height();
                                        total += n;
                                        if total % 500 == 0 || n < 50 {
                                            let e = start_time.elapsed().as_secs_f64();
                                            println!("  {} blocks — height: {} / {} — {:.0} b/s", total, current_height, peer_height, total as f64 / e);
                                        }
                                        // Break if no progress (prevents infinite loop)
                                        if current_height == prev_height { break; }
                                        if n < 50 { break; }
                                    }
                                    _ => break,
                                }
                            }
                            _ => break,
                        }
                    }
                    let elapsed = start_time.elapsed().as_secs_f64();
                    println!("  Fallback sync: {} blocks in {:.1}s", total, elapsed);
                }
            } else if behind > 10 {
                // ===== SMALL GAP: block-by-block trusted sync =====
                println!("Syncing {} blocks from {} (trusted)...", behind, peer_id(&peer_url));
                let mut current_height = local_height;
                let mut total = 0u64;
                loop {
                    let prev_height = current_height;
                    let url = format!("{}/blocks/since/{}", peer_url, current_height);
                    match client.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.json::<Vec<serde_json::Value>>().await {
                                Ok(blocks) if !blocks.is_empty() => {
                                    let n = blocks.len() as u64;
                                    for bv in &blocks {
                                        if let Ok(block) = serde_json::from_value::<tsn::core::ShieldedBlock>(bv.clone()) {
                                            let _ = blockchain.add_block_trusted(block);
                                        }
                                    }
                                    current_height = blockchain.height();
                                    total += n;
                                    if total % 500 == 0 || n < 50 {
                                        let e = start_time.elapsed().as_secs_f64();
                                        println!("  {} blocks — height: {} / {} — {:.0} b/s", total, current_height, peer_height, total as f64 / e);
                                    }
                                    if current_height == prev_height { break; }
                                    if n < 50 { break; }
                                }
                                _ => break,
                            }
                        }
                        _ => break,
                    }
                }
                let elapsed = start_time.elapsed().as_secs_f64();
                println!("  Synced {} blocks in {:.1}s", total, elapsed);
            }
        } else {
            println!("Node synced (height: {})", local_height);
        }
    }

    let mempool = Mempool::new();

    // Load Circom verification keys for proof verification (optional — mining works without them)
    println!();
    match find_verification_keys() {
        Ok((spend_vkey_path, output_vkey_path)) => {
            println!("Loading Circom verification keys...");
            println!("  Loading {}...", spend_vkey_path);
            println!("  Loading {}...", output_vkey_path);
            match CircomVerifyingParams::from_files(&spend_vkey_path, &output_vkey_path) {
                Ok(verifying_params) => {
                    blockchain.set_verifying_params(Arc::new(verifying_params));
                    println!("  ZK proof verification ENABLED (Circom/snarkjs)");
                }
                Err(e) => {
                    println!("  ZK proof verification DISABLED (failed to load keys: {})", e);
                }
            }
        }
        Err(_) => {
            println!("  ZK proof verification DISABLED (verification keys not found)");
            println!("  Mining and relay functions work normally without ZK keys.");
        }
    }

    // Show assume-valid checkpoint status
    let assume_valid_height = blockchain.assume_valid_height();
    if assume_valid_height > 0 {
        println!("  Assume-valid checkpoint: height {} (proofs skipped during sync)", assume_valid_height);
    } else {
        println!("  Assume-valid: DISABLED (full proof verification from genesis)");
    }
    println!();

    // Initialize faucet if wallet provided
    let faucet_service = if let Some(faucet_path) = &faucet_wallet {
        let faucet_wlt = ShieldedWallet::load(faucet_path)?;
        let pk_hash = faucet_wlt.pk_hash();
        let faucet_pk_hash_hex = hex::encode(pk_hash);
        println!("Faucet enabled: {} (pk_hash)", &faucet_pk_hash_hex[..16]);

        // Extract keypair for signing
        let keypair = faucet_wlt.keypair().clone();

        // Open database for faucet claims
        let db = Arc::new(Database::open(&format!("{}/faucet", data_dir))?);

        let service = if let Some(limit) = faucet_daily_limit {
            let limit_base = limit * 1_000_000_000; // Convert TSN to base units
            println!("  Daily limit: {} TSN", limit);
            FaucetService::with_limits(keypair, pk_hash, db, limit_base, 86400)
        } else {
            println!("  Daily limit: 50 TSN (default)");
            FaucetService::new(keypair, pk_hash, db)
        };

        Some(TokioRwLock::new(service))
    } else {
        None
    };

    // Shared HTTP client for all outbound requests — prevents FD leaks from per-request clients
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // Initialize wallet service (SQLite backend) before AppState
    let wallet_service: Option<Arc<WalletService>> = if let Some(wallet_path) = &mine_wallet {
        match ShieldedWallet::open(wallet_path) {
            Ok(wallet) => {
                tracing::info!("Wallet service initialized (SQLite): {}", wallet_path);
                Some(Arc::new(WalletService::new(wallet)))
            }
            Err(e) => {
                tracing::warn!("Could not initialize wallet service: {} — falling back to legacy mode", e);
                None
            }
        }
    } else {
        None
    };

    let state = Arc::new(AppState {
        blockchain: RwLock::new(blockchain),
        mempool: RwLock::new(mempool),
        peers: RwLock::new(peers.clone()),
        miner_stats: RwLock::new(MinerStats::default()),
        faucet: faucet_service,
        sync_gate: tsn::network::SyncGate::new(),
        public_url: public_url.clone(),
        p2p_broadcast: RwLock::new(None),
        p2p_peer_id: RwLock::new(None),
        p2p_shared_peers: RwLock::new(None),
        node_role: format!("{}", node_role),
        mining_cancel: RwLock::new(None),
        http_client,
        last_reorg_height: std::sync::atomic::AtomicU64::new(0),
        snapshot_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(3)),
        snapshot_cache: tokio::sync::RwLock::new(None),
        orphan_count: std::sync::atomic::AtomicU64::new(0),
        reorg_count: std::sync::atomic::AtomicU64::new(0),
        reorg_lock: tokio::sync::RwLock::new(()),
        banned_peers: std::sync::RwLock::new(std::collections::HashMap::new()),
        peer_info: std::sync::RwLock::new(std::collections::HashMap::new()),
        error_log: std::sync::RwLock::new(Vec::new()),
        auto_heal_mode: std::sync::RwLock::new("automatic".to_string()),
        removed_peers: std::sync::Mutex::new(std::collections::HashSet::new()),
        metric_empty_batches: std::sync::atomic::AtomicU64::new(0),
        metric_stale_blocks: std::sync::atomic::AtomicU64::new(0),
        metric_fork_recoveries: std::sync::atomic::AtomicU64::new(0),
        metric_recovery_time_ms: std::sync::atomic::AtomicU64::new(0),
        metric_commitment_mismatches: std::sync::atomic::AtomicU64::new(0),
        seed_signing_key: {
            let key_path = std::path::Path::new(&data_dir).join("seed_key.bin");
            Some(tsn::network::snapshot_manifest::load_or_generate_seed_key(&key_path))
        },
        snapshot_manifests: std::sync::RwLock::new(Vec::new()),
        mining_address: miner_info.as_ref().map(|(pk, _)| hex::encode(pk)),
        wallet_service: wallet_service.clone(),
        seen_tips: std::sync::Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(tsn::network::api::TIP_DEDUP_CAPACITY).unwrap(),
        )),
        seen_blocks: std::sync::Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(tsn::network::api::BLOCK_DEDUP_CAPACITY).unwrap(),
        )),
        fork_recovery_cooldown: std::sync::Mutex::new(std::collections::HashMap::new()),
        last_snapshot_auto_trigger: std::sync::atomic::AtomicU64::new(
            // v2.3.7 — load persisted trigger height so restart does not re-fire
            // a snapshot at an interval we already published.
            load_last_snapshot_trigger(&data_dir)
        ),
        version_bans: std::sync::RwLock::new(std::collections::HashMap::new()),
    });

    // ========================================================================
    // CHECKPOINT VALIDATION AT STARTUP
    // If our chain doesn't match hardcoded checkpoints, rollback and re-sync.
    // ========================================================================
    {
        let chain = state.blockchain.read().unwrap();
        let local_height = chain.height();
        let mut violations = Vec::new();
        for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
            if cp_height <= local_height {
                if let Some(actual_hash) = chain.get_hash_at_height(cp_height) {
                    let actual_hex = hex::encode(actual_hash);
                    // Skip placeholder hashes (fast-synced blocks before base)
                    if actual_hex != "0".repeat(64) && actual_hex != cp_hash {
                        violations.push((cp_height, cp_hash.to_string(), actual_hex));
                    }
                }
            }
        }
        if !violations.is_empty() {
            drop(chain);
            let lowest = violations.iter().map(|(h, _, _)| *h).min().unwrap();
            for (h, expected, actual) in &violations {
                tracing::error!(
                    "CHECKPOINT MISMATCH at height {}: expected {}, got {}",
                    h, &expected[..16], &actual[..16]
                );
            }
            tracing::warn!(
                "Chain is on a fork! Rolling back to height {} to re-sync from peers.",
                lowest.saturating_sub(1)
            );
            let rollback_target = lowest.saturating_sub(1);
            let mut chain = state.blockchain.write().unwrap();
            // Bypass MAX_REORG_DEPTH for checkpoint-forced rollback
            if local_height - rollback_target <= ShieldedBlockchain::MAX_REORG_DEPTH {
                let _ = chain.rollback_to_height(rollback_target);
            } else {
                // Too deep to rollback — wipe data and force fresh fast-sync
                tracing::error!(
                    "Checkpoint violation too deep ({} blocks). Wiping chain for fresh sync.",
                    local_height - rollback_target
                );
                drop(chain);
                let db_path = format!("{}/blockchain", data_dir);
                let _ = std::fs::remove_dir_all(&db_path);
                // Re-open empty blockchain
                let fresh = ShieldedBlockchain::open(&db_path, 1_500_000)
                    .expect("Failed to create fresh blockchain");
                *state.blockchain.write().unwrap() = fresh;
            }
        }
    }

    // Create router with API (wallet and explorer are served from static React app)
    let app = create_router(state.clone());

    // Build our own URL for peer announcements
    let our_url = public_url.unwrap_or_else(|| format!("http://localhost:{}", port));
    println!("Announcing as:  {}", our_url);

    // Start HTTP API server FIRST (non-blocking — explorer and wallet need this immediately)
    let api_port = port;
    let api_app = app;
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", api_port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("FATAL: Cannot bind port {}: {}", api_port, e);
                std::process::exit(1);
            }
        };
        tracing::info!("HTTP API listening on port {}", api_port);
        if let Err(e) = axum::serve(listener, api_app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await {
            eprintln!("HTTP server error: {}", e);
        }
    });

    // Start Prometheus metrics server. v2.3.2: auto-fallback 9090..=9099 so
    // running a miner and a relay on the same host (common for local testing)
    // no longer fails noisily on "Address already in use". Metrics is a
    // side-channel — if all ports are taken, skip silently with a warn instead
    // of crashing or spamming an error on every startup.
    {
        let mut started = false;
        for port in 9090u16..=9099 {
            let config = tsn::metrics::http_endpoint::MetricsServerConfig {
                port,
                bind_address: "0.0.0.0".to_string(),
                enable_cors: true,
            };
            match tsn::metrics::http_endpoint::start_metrics_server(config).await {
                Ok(_handle) => {
                    println!("Metrics server:  http://0.0.0.0:{}/metrics", port);
                    started = true;
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Address already in use") || msg.contains("address in use") {
                        // Port taken — try the next one silently.
                        continue;
                    }
                    tracing::error!("Failed to start metrics server on port {}: {}", port, e);
                    break;
                }
            }
        }
        if !started {
            tracing::warn!("Metrics server disabled: no free port in 9090..=9099");
        }
    }

    // Start version checker — blocks mining if node is outdated
    tokio::spawn(async {
        tsn::network::version_check::version_check_loop().await;
    });

    // Start auto-update loop — checks for new versions and self-updates
    tokio::spawn(async {
        tsn::network::auto_update::auto_update_loop().await;
    });

    // ========================================================================
    // SELF-HEALING WATCHDOG — monitors node health and auto-repeers
    // ========================================================================
    {
        let watchdog_state = state.clone();
        tokio::spawn(async move {
            let mut last_height: u64 = 0;
            let mut stuck_since: Option<std::time::Instant> = None;
            let mut resync_count: u32 = 0;
            let mut resync_window_start = std::time::Instant::now();
            let mut error_count: u32 = 0;
            // v2.3.8 — smart auto-wipe state
            let mut last_wipe_at: Option<std::time::Instant> = None;
            let mut wipe_history_24h: std::collections::VecDeque<std::time::Instant> =
                std::collections::VecDeque::new();
            const WIPE_COOLDOWN_SECS: u64 = 3600;    // 1 hour between wipes
            const WIPE_MAX_PER_24H: usize = 3;       // kill switch
            const SOLO_FORK_THRESHOLD: u64 = 5;      // blocks ahead of consensus. Smart guards (≥3 peers agree, cooldown 1h, max 3 wipes/24h) make this safe at low threshold.
            const MIN_PEERS_AGREE: usize = 3;        // peers agreeing on consensus

            // Returns Some(consensus_height) iff ≥MIN_PEERS_AGREE peers share the
            // same tip height (majority), otherwise None. Used to gate auto-wipe.
            let compute_consensus = |peer_heights: &[u64]| -> Option<u64> {
                if peer_heights.len() < MIN_PEERS_AGREE {
                    return None;
                }
                let mut by_h: std::collections::HashMap<u64, usize> =
                    std::collections::HashMap::new();
                for h in peer_heights {
                    *by_h.entry(*h).or_insert(0) += 1;
                }
                let mut entries: Vec<(u64, usize)> = by_h.into_iter().collect();
                entries.sort_by(|a, b| b.1.cmp(&a.1));
                if let Some((h, count)) = entries.first() {
                    if *count >= MIN_PEERS_AGREE {
                        return Some(*h);
                    }
                    // Allow ±2 block cluster around majority
                    let cluster: usize = entries.iter()
                        .filter(|(eh, _)| eh.abs_diff(*h) <= 2)
                        .map(|(_, c)| *c).sum();
                    if cluster >= MIN_PEERS_AGREE {
                        return Some(*h);
                    }
                }
                None
            };

            // v2.3.8 — decide whether a wipe is safe right now.
            // Returns (allow: bool, reason: String)
            let check_wipe_allowed = |now: std::time::Instant,
                                      last: Option<std::time::Instant>,
                                      history: &std::collections::VecDeque<std::time::Instant>|
             -> (bool, String) {
                if let Some(t) = last {
                    let since = now.duration_since(t).as_secs();
                    if since < WIPE_COOLDOWN_SECS {
                        return (false, format!("cooldown ({}s since last wipe, need {}s)", since, WIPE_COOLDOWN_SECS));
                    }
                }
                if history.len() >= WIPE_MAX_PER_24H {
                    return (false, format!("kill switch ({} wipes in last 24h, max {})", history.len(), WIPE_MAX_PER_24H));
                }
                (true, String::new())
            };

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                let current_height = {
                    let chain = watchdog_state.blockchain.read().unwrap();
                    chain.height()
                };

                // Reset resync counter every 5 minutes
                if resync_window_start.elapsed() > std::time::Duration::from_secs(300) {
                    resync_count = 0;
                    resync_window_start = std::time::Instant::now();
                }

                // Check auto_heal_mode
                let is_auto = *watchdog_state.auto_heal_mode.read().unwrap() == "automatic";

                // Check 1: All peers banned → clear bans (always auto, even in validation mode)
                {
                    let peers = watchdog_state.peers.read().unwrap();
                    let bans = watchdog_state.banned_peers.read().unwrap();
                    let now = std::time::Instant::now();
                    let active_bans = bans.values().filter(|t| now < **t).count();
                    if !peers.is_empty() && active_bans >= peers.len() {
                        drop(bans);
                        drop(peers);
                        tracing::warn!("\x1b[36mWATCHDOG:\x1b[0m All peers banned! Clearing ban list.");
                        tsn::network::log_node_error(&watchdog_state, "all_peers_banned", "All peers were banned, clearing ban list");
                        let mut bans = watchdog_state.banned_peers.write().unwrap();
                        bans.clear();
                    }
                }

                // Check 2: Height stagnant for 5+ minutes while peers exist
                if current_height > last_height {
                    last_height = current_height;
                    stuck_since = None;
                    error_count = 0;
                } else {
                    let peers_exist = !watchdog_state.peers.read().unwrap().is_empty();
                    if peers_exist {
                        if stuck_since.is_none() {
                            stuck_since = Some(std::time::Instant::now());
                        }
                        if let Some(since) = stuck_since {
                            if since.elapsed() > std::time::Duration::from_secs(300) {
                                let msg = format!("Height stuck at {} for 5+ min", current_height);
                                // v2.3.6 — Never auto-wipe. A stuck height is almost always
                                // either a valid temporary stall (peers catching up, reorg)
                                // or a real consensus bug that requires manual investigation.
                                // Wiping silently destroys data and re-imports whatever vintage
                                // snapshot a peer happens to serve. Log only; operator decides.
                                tracing::warn!(
                                    "\x1b[36mWATCHDOG:\x1b[0m {}. Auto-wipe DISABLED (v2.3.6). Use /admin/force-resync if needed.",
                                    msg
                                );
                                tsn::network::log_node_error(&watchdog_state, "stuck_height", &msg);
                                let _ = is_auto; // kept for future reintroduction
                                stuck_since = None;
                                resync_count += 1;
                                last_height = current_height;
                            }
                        }
                    }
                }

                // Check 2b: Fork divergence — peers are far ahead and we can't catch up
                // v2.0.9: Only use HTTP-verified heights (not P2P which can be 0 at startup).
                // Requires is_auto mode, reorg_lock, and verifies tip hash from at least 2 peers.
                {
                    let sync_client = &watchdog_state.http_client;
                    let peers_list = watchdog_state.peers.read().unwrap().clone();
                    let mut verified_heights: Vec<(u64, String)> = Vec::new(); // (height, tip_hash)
                    for peer in &peers_list {
                        if !tsn::network::is_contactable_peer(peer) { continue; }
                        let url = format!("{}/tip", peer);
                        if let Ok(resp) = sync_client.get(&url).timeout(std::time::Duration::from_secs(2)).send().await {
                            if let Ok(tip) = resp.json::<serde_json::Value>().await {
                                let h = tip["height"].as_u64().unwrap_or(0);
                                let hash = tip["hash"].as_str().unwrap_or("").to_string();
                                if h > 0 && !hash.is_empty() {
                                    verified_heights.push((h, hash));
                                }
                            }
                        }
                    }
                    // v2.0.9: Require at least 2 HTTP-verified peers agreeing on tip height
                    // Do NOT use P2P heights (often 0 at startup, caused infinite reset loops in v2.0.8)
                    let max_peer_h = verified_heights.iter().map(|(h, _)| *h).max().unwrap_or(0);
                    let peers_at_max = verified_heights.iter().filter(|(h, _)| *h >= max_peer_h.saturating_sub(5)).count();
                    let gap = max_peer_h.saturating_sub(current_height);
                    if gap > 100 && max_peer_h > 100 && current_height > 0 && peers_at_max >= 2 {
                        // v2.3.6 — Never auto-wipe. A "gap" can be caused by a transient
                        // P2P sync pause, a peer serving a stale snapshot, or a real fork.
                        // In each case, blind auto-wipe is worse than waiting: it destroys
                        // the canonical chain and re-imports from an arbitrary peer.
                        tracing::warn!(
                            "\x1b[36mWATCHDOG:\x1b[0m Peers far ahead — {} peers at ~{} but local at {} (gap={}). Auto-wipe DISABLED (v2.3.6). Investigate manually.",
                            peers_at_max, max_peer_h, current_height, gap
                        );
                        let _ = is_auto;
                    }
                }

                // Check 2c: Solo ahead — local node is far AHEAD of all peers (on a solo fork)
                // v2.1.0: If we're >100 blocks ahead of all verified peers, we're on a fork.
                // This catches nodes that mined solo without connecting to seeds.
                {
                    let sync_client = &watchdog_state.http_client;
                    let peers_list = watchdog_state.peers.read().unwrap().clone();
                    let mut verified_peer_heights: Vec<u64> = Vec::new();
                    for peer in &peers_list {
                        if !tsn::network::is_contactable_peer(peer) { continue; }
                        let url = format!("{}/tip", peer);
                        if let Ok(resp) = sync_client.get(&url).timeout(std::time::Duration::from_secs(2)).send().await {
                            if let Ok(tip) = resp.json::<serde_json::Value>().await {
                                let h = tip["height"].as_u64().unwrap_or(0);
                                if h > 0 { verified_peer_heights.push(h); }
                            }
                        }
                    }
                    // v2.3.8 — smart auto-wipe for solo-fork:
                    // only triggered when MULTIPLE guards are satisfied simultaneously.
                    if verified_peer_heights.len() >= MIN_PEERS_AGREE && current_height > 100 {
                        let consensus_opt = compute_consensus(&verified_peer_heights);
                        let ahead_gap = consensus_opt
                            .map(|c| current_height.saturating_sub(c))
                            .unwrap_or(0);
                        if ahead_gap > SOLO_FORK_THRESHOLD {
                            let consensus_h = consensus_opt.unwrap();
                            let now = std::time::Instant::now();
                            // Trim wipe_history_24h
                            while let Some(front) = wipe_history_24h.front() {
                                if now.duration_since(*front).as_secs() > 86400 {
                                    wipe_history_24h.pop_front();
                                } else { break; }
                            }
                            let (allowed, reason) = check_wipe_allowed(now, last_wipe_at, &wipe_history_24h);
                            let status_msg = if allowed {
                                "ALLOWED".to_string()
                            } else {
                                format!("DENIED: {}", reason)
                            };
                            tracing::warn!(
                                "\x1b[36mWATCHDOG:\x1b[0m SOLO FORK confirmed — local={} consensus={} gap={} ({} peers agree). Auto-wipe {}.",
                                current_height, consensus_h, ahead_gap, verified_peer_heights.len(),
                                status_msg
                            );
                            if allowed && is_auto {
                                tracing::warn!("\x1b[36mWATCHDOG:\x1b[0m Executing smart auto-wipe (conditions satisfied).");
                                let _reorg_guard = watchdog_state.reorg_lock.write().await;
                                let mut chain = watchdog_state.blockchain.write().unwrap();
                                chain.reset_for_snapshot_resync();
                                drop(chain);
                                drop(_reorg_guard);
                                last_wipe_at = Some(now);
                                wipe_history_24h.push_back(now);
                                stuck_since = None;
                                last_height = 0;
                                continue;
                            }
                            // v2.3.8 — If validation mode OR wipe denied by guards,
                            // surface to operator without touching data.
                            if !is_auto {
                                tracing::info!("\x1b[36mWATCHDOG:\x1b[0m Mode validation — solo fork detected (gap={}), action proposed via /admin/force-resync", ahead_gap);
                            }
                        }
                    }
                }

                // Check 3: Too many resyncs in short window → wipe completely
                if resync_count >= 3 {
                    let msg = format!("{} resyncs in 5 min — chain is unstable", resync_count);
                    tracing::error!("\x1b[36mWATCHDOG:\x1b[0m {}. Auto-wipe DISABLED (v2.3.6). Investigate manually.", msg);
                    tsn::network::log_node_error(&watchdog_state, "resync_loop", &msg);
                    if false { // v2.3.6: dead-branch, full wipe disabled
                        tracing::warn!("\x1b[36mWATCHDOG:\x1b[0m Auto mode — full wipe + fresh sync.");
                        // v2.0.9: Take reorg_lock to prevent race with miner
                        let _reorg_guard = watchdog_state.reorg_lock.write().await;
                        let mut chain = watchdog_state.blockchain.write().unwrap();
                        chain.reset_for_snapshot_resync();
                        drop(chain);
                        drop(_reorg_guard);
                        let mut bans = watchdog_state.banned_peers.write().unwrap();
                        bans.clear();
                    } else {
                        tracing::warn!("\x1b[36mWATCHDOG:\x1b[0m Validation mode — action required: POST /admin/force-resync");
                    }
                    resync_count = 0;
                    last_height = 0;
                    stuck_since = None;
                }

                // Check 4: Verify checkpoints periodically (every 5 min)
                // v2.0.9: Collect violation info first, drop read guard, then act
                let checkpoint_violated = {
                    let chain = watchdog_state.blockchain.read().unwrap();
                    let mut violated = false;
                    for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
                        if cp_height <= chain.height() {
                            if let Some(actual) = chain.get_hash_at_height(cp_height) {
                                let actual_hex = hex::encode(actual);
                                if actual_hex != "0".repeat(64) && actual_hex != cp_hash {
                                    let msg = format!("Checkpoint violation at height {}", cp_height);
                                    tracing::error!("\x1b[36mWATCHDOG:\x1b[0m {}! Re-syncing.", msg);
                                    tsn::network::log_node_error(&watchdog_state, "checkpoint_violation", &msg);
                                    violated = true;
                                    break;
                                }
                            }
                        }
                    }
                    violated
                }; // read guard dropped here
                if checkpoint_violated {
                    // Always auto for checkpoint violations — chain is on wrong fork
                    // v2.0.9: Take reorg_lock to prevent race with miner
                    let _reorg_guard = watchdog_state.reorg_lock.write().await;
                    let mut chain_w = watchdog_state.blockchain.write().unwrap();
                    chain_w.reset_for_snapshot_resync();
                    drop(chain_w);
                    drop(_reorg_guard);
                    let mut bans = watchdog_state.banned_peers.write().unwrap();
                    bans.clear();
                    last_height = 0;
                    stuck_since = None;
                }
            }
        });
    }

    // Sync from peers in background (non-blocking — API is already running)
    if !peers.is_empty() {
        println!("Peers: [{}]", peers.iter().map(|p| peer_id(p)).collect::<Vec<_>>().join(", "));

        let sync_state_init = state.clone();
        let sync_peers_init = peers.clone();
        let sync_our_url = our_url.clone();
        tokio::spawn(async move {
            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default();

            for peer in &sync_peers_init {
                let announce_url = format!("{}/peers", peer.trim_end_matches('/'));
                let _ = http_client.post(&announce_url)
                    .json(&serde_json::json!({ "url": sync_our_url }))
                    .send()
                    .await;

                match sync_from_peer(sync_state_init.clone(), peer).await {
                    Ok(n) if n > 0 => tracing::info!("Synced {} blocks from {}", n, peer_id(peer)),
                    Ok(_) => {}
                    Err(e) => tracing::debug!("Sync from {} failed: {}", peer_id(peer), e),
                }
            }
        });

        // Start background sync loop (HTTP fallback — checks every 30 seconds)
        let sync_state = state.clone();
        let sync_peers = state.peers.read().unwrap().clone();
        tokio::spawn(async move {
            sync_loop(sync_state, sync_peers, 10).await;
        });

        // Start peer discovery loop (checks every 60 seconds)
        let discovery_state = state.clone();
        tokio::spawn(async move {
            discovery_loop(discovery_state).await;
        });

        // Start libp2p P2P layer — PRIMARY block/tx propagation
        // GossipSub pushes blocks instantly to all connected peers (including NAT)
        // HTTP sync loop kept as temporary fallback for non-upgraded nodes
        {
            use tsn::network::p2p::{P2pConfig, P2pNode, P2pEvent, seeds_to_bootstrap};
            use tracing::{info, warn, debug};

            let p2p_port = port + 1; // P2P on next port (e.g. 9334 if HTTP is 9333)
            let seed_urls = state.peers.read().unwrap().clone();

            // Convert HTTP seed URLs to P2P multiaddrs (IP:p2p_port)
            let dial_seeds = seeds_to_bootstrap(&seed_urls, p2p_port);
            info!("P2P: dialing {} seed nodes on port {}", dial_seeds.len(), p2p_port);

            // v2.3.0 Phase 2.3: startup-time height hint for the Identify
            // agent_version field. Peers parse this as "h=<number>" and seed
            // their peer-height cache without an HTTP /chain/info call.
            // The hint is frozen at startup; live updates continue via the
            // existing tip broadcast loop.
            let startup_height = state.blockchain.read().unwrap().height();
            let p2p_config = P2pConfig {
                listen_port: p2p_port,
                bootstrap_peers: Vec::new(),
                dial_seeds,
                relay_server: node_role == NodeRole::Miner,
                // Use actual mining status for protocol role (not node_role which defaults to miner)
                protocol_version: format!("tsn/{}/{}", env!("CARGO_PKG_VERSION"),
                    if miner_info.is_some() && node_role == NodeRole::Miner { "miner" }
                    else if node_role == NodeRole::LightClient { "light" }
                    else { "relay" }),
                agent_version: format!("h={}", startup_height),
            };

            let p2p = P2pNode::start(p2p_config).await
                .expect("FATAL: P2P layer failed to start — node cannot propagate blocks");

            // v2.1.1: Peer ID displayed prominently in color — users need this
            let magenta = "\x1b[1;35m"; // bold magenta
            let cyan = "\x1b[1;36m";
            let reset_color = "\x1b[0m";
            println!();
            println!("  {}YOUR NODE ID:{}", magenta, reset_color);
            println!("  {}{}{}", cyan, p2p.peer_id, reset_color);
            println!("  P2P port: {}", p2p_port);
            println!("  API:      http://localhost:{}/node/info", port);

            // Store PeerID and shared peer list in AppState
            {
                let mut pid = state.p2p_peer_id.write().unwrap();
                *pid = Some(p2p.peer_id.to_string());
            }
            {
                let mut sp = state.p2p_shared_peers.write().unwrap();
                *sp = Some(p2p.shared_peers.clone());
            }

            let p2p_peer_id = p2p.peer_id;
            let p2p_command_tx = p2p.command_tx.clone();

            // Store P2P command sender in AppState for use by miner and API
            // (used to broadcast mined blocks and submitted transactions)
            {
                let mut p2p_tx = state.p2p_broadcast.write().unwrap();
                *p2p_tx = Some(p2p.command_tx.clone());
            }

            // Shared cancel signal: P2P handler sets this when a new block arrives,
            // causing the miner to immediately abort and restart on the new tip.
            let mining_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            {
                let mut mc = state.mining_cancel.write().unwrap();
                *mc = Some(Arc::clone(&mining_cancel));
            }

            // Spawn task to handle incoming P2P events
            let p2p_blockchain = state.clone();
            let p2p_cancel = Arc::clone(&mining_cancel);
            let mut p2p_events = p2p.event_rx;
            tokio::spawn(async move {
                // Throttle orphan sync: at most one sync task every 10 seconds
                let orphan_sync_lock = Arc::new(tokio::sync::Mutex::new(()));
                let last_orphan_sync = Arc::new(std::sync::atomic::AtomicU64::new(0));
                // v2.1.3: Ghost peer blacklist is stored in AppState.removed_peers

                while let Some(event) = p2p_events.recv().await {
                    match event {
                        P2pEvent::NewBlock(data) => {
                            match serde_json::from_slice::<tsn::core::ShieldedBlock>(&data) {
                                Ok(block) => {
                                    let height = block.coinbase.height;
                                    // v2.3.0 Phase 1: dedup same block within BLOCK_DEDUP_SECS (60s).
                                    // GossipSub can redeliver blocks (mesh heal / orphans) and HTTP may
                                    // have already accepted this block — skip before taking reorg_lock.
                                    let block_hash = block.hash_hex();
                                    let now_secs = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    {
                                        let mut cache = p2p_blockchain.seen_blocks.lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        if let Some(&seen_at) = cache.get(&block_hash) {
                                            if now_secs.saturating_sub(seen_at) < tsn::network::api::BLOCK_DEDUP_SECS {
                                                tracing::debug!("dedup: P2P block #{} {} already seen ({}s ago)",
                                                    height, &block_hash[..16], now_secs - seen_at);
                                                continue;
                                            }
                                        }
                                        cache.put(block_hash.clone(), now_secs);
                                    }
                                    // v2.3.4: capture confirmed tx hashes + nullifiers BEFORE
                                    // the block is moved into try_add_block, so we can clean
                                    // the mempool when the block is accepted. Previously the
                                    // P2P path never cleaned the mempool (only HTTP and the
                                    // local miner did), which caused miners to keep re-picking
                                    // already-confirmed V2 txs into block templates and hitting
                                    // "Nullifier already spent" on every subsequent mine attempt.
                                    let mut confirmed_tx_hashes: Vec<[u8; 32]> =
                                        block.transactions.iter().map(|tx| tx.hash()).collect();
                                    confirmed_tx_hashes.extend(
                                        block.transactions_v2.iter().map(|tx| tx.hash())
                                    );
                                    let mut confirmed_nullifiers: Vec<[u8; 32]> =
                                        block.nullifiers().iter().map(|n| n.0).collect();
                                    confirmed_nullifiers.extend(
                                        block.transactions_v2.iter()
                                            .flat_map(|tx| tx.spends.iter().map(|s| s.nullifier))
                                    );
                                    let result = {
                                        // v2.0.9: Take reorg_lock to prevent race with miner
                                        let _reorg_guard = p2p_blockchain.reorg_lock.read().await;
                                        let mut chain = p2p_blockchain.blockchain.write().unwrap();
                                        chain.try_add_block(block)
                                    };
                                    match result {
                                        Ok(true) => {
                                            info!("P2P: new block #{} accepted", height);
                                            // v2.3.5: clean mempool on a spawned task so the P2P
                                            // event loop returns to receive the next gossip event
                                            // immediately, and skip the expensive revalidate+
                                            // blockchain.read() path entirely when the mempool is
                                            // empty (common case on seeds). Holding mempool.write()
                                            // + blockchain.read() on the hot path in v2.3.4 was
                                            // contending with /tip readers and caused axum accept-
                                            // queue starvation under external polling load.
                                            let cleanup_state = p2p_blockchain.clone();
                                            let cleanup_hashes = confirmed_tx_hashes.clone();
                                            let cleanup_nullifiers = confirmed_nullifiers.clone();
                                            let cleanup_height = height;
                                            tokio::task::spawn_blocking(move || {
                                                let mut mempool = cleanup_state.mempool
                                                    .write().unwrap_or_else(|e| e.into_inner());
                                                mempool.remove_confirmed(&cleanup_hashes);
                                                mempool.remove_spent_nullifiers(&cleanup_nullifiers);
                                                if mempool.is_empty() {
                                                    return;
                                                }
                                                let chain_ro = cleanup_state.blockchain.read()
                                                    .unwrap_or_else(|e| e.into_inner());
                                                let removed = mempool.revalidate(chain_ro.state());
                                                if removed > 0 {
                                                    info!(
                                                        "P2P: removed {} invalid transactions from mempool after block #{}",
                                                        removed, cleanup_height
                                                    );
                                                }
                                            });
                                            // Signal miner to cancel and restart on new tip
                                            p2p_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                                            // v2.1.3: Broadcast tip immediately after accepting a block.
                                            // This keeps P2P peer heights fresh without waiting for
                                            // the periodic 10s tip broadcast cycle.
                                            {
                                                let chain = p2p_blockchain.blockchain.read().unwrap();
                                                let tip_h = chain.height();
                                                let tip_hash = hex::encode(chain.latest_hash());
                                                let tx = p2p_blockchain.p2p_broadcast.read().unwrap().clone();
                                                if let Some(tx) = tx {
                                                    tokio::spawn(async move {
                                                        let _ = tx.send(tsn::network::p2p::P2pCommand::BroadcastTip(tip_h, tip_hash)).await;
                                                    });
                                                }
                                            }
                                            // v2.3.0 Phase 2.1: block-based snapshot auto-trigger.
                                            // Shared with the miner-local path via check_snapshot_auto_trigger.
                                            {
                                                let tip_h = p2p_blockchain.blockchain.read().unwrap().height();
                                                check_snapshot_auto_trigger(&p2p_blockchain, tip_h);
                                            }
                                        }
                                        Ok(false) => {
                                            // Stored as orphan — request missing blocks via P2P
                                            let local_height = p2p_blockchain.blockchain.read().unwrap().height();
                                            let now_secs = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default().as_secs();
                                            let last = last_orphan_sync.load(std::sync::atomic::Ordering::Relaxed);
                                            if now_secs - last < 5 {
                                                tracing::debug!("P2P: block #{} orphan — request throttled", height);
                                            } else {
                                                last_orphan_sync.store(now_secs, std::sync::atomic::Ordering::Relaxed);
                                                let gap = height.saturating_sub(local_height);
                                                if gap > 0 && gap <= 50 {
                                                    // Request missing blocks via P2P first
                                                    tracing::info!("P2P: block #{} orphan (local: {}), requesting {} blocks via P2P + HTTP fallback", height, local_height, gap);
                                                    let tx = p2p_blockchain.p2p_broadcast.read().unwrap().clone();
                                                    if let Some(tx) = tx {
                                                        let _ = tx.send(tsn::network::p2p::P2pCommand::RequestBlocks(local_height + 1, height)).await;
                                                    }
                                                    // v2.1.3: HTTP fallback — P2P RequestBlocks is unreliable
                                                    // (broadcast, not unicast; mesh may not include the source)
                                                    let fb_state = p2p_blockchain.clone();
                                                    let fb_lock = orphan_sync_lock.clone();
                                                    let fb_height = local_height;
                                                    tokio::spawn(async move {
                                                        // Give P2P 3s to fill the gap first
                                                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                                        let cur_h = fb_state.blockchain.read().unwrap().height();
                                                        if cur_h <= fb_height {
                                                            // P2P didn't fill the gap — use HTTP
                                                            let _guard = fb_lock.lock().await;
                                                            let peers = fb_state.peers.read().unwrap().clone();
                                                            for peer in &peers {
                                                                if !tsn::network::is_contactable_peer(peer) { continue; }
                                                                match tsn::network::sync_from_peer(fb_state.clone(), peer).await {
                                                                    Ok(n) if n > 0 => {
                                                                        tracing::info!("HTTP orphan fallback: synced {} blocks from {}", n, tsn::network::peer_id(peer));
                                                                        break;
                                                                    }
                                                                    _ => {}
                                                                }
                                                            }
                                                        }
                                                    });
                                                } else if gap > 50 {
                                                    // Too far behind — try HTTP sync as fallback
                                                    tracing::info!("P2P: block #{} orphan (local: {}, gap={}), falling back to HTTP sync", height, local_height, gap);
                                                    let sync_state = p2p_blockchain.clone();
                                                    let sync_peers = p2p_blockchain.peers.read().unwrap().clone();
                                                    let lock = orphan_sync_lock.clone();
                                                    tokio::spawn(async move {
                                                        let _guard = lock.lock().await;
                                                        for peer in &sync_peers {
                                                            if !tsn::network::is_contactable_peer(peer) { continue; }
                                                            match tsn::network::sync_from_peer(sync_state.clone(), peer).await {
                                                                Ok(n) if n > 0 => {
                                                                    tracing::info!("HTTP sync: got {} blocks from {}", n, tsn::network::peer_id(peer));
                                                                    break;
                                                                }
                                                                _ => {}
                                                            }
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                        Err(e) => tracing::debug!("P2P: block #{} rejected: {}", height, e),
                                    }
                                }
                                Err(e) => tracing::debug!("P2P: invalid block data: {}", e),
                            }
                        }
                        P2pEvent::NewTransaction(data) => {
                            // Add received transaction to mempool
                            if let Ok(tx) = serde_json::from_slice::<tsn::core::ShieldedTransactionV2>(&data) {
                                let mut mempool = p2p_blockchain.mempool.write().unwrap();
                                let wrapped = tsn::core::Transaction::V2(tx);
                                mempool.add_v2(wrapped);
                            }
                        }
                        P2pEvent::PeerConnected(peer) => {
                            debug!("P2P: peer {} connected", peer);
                        }
                        P2pEvent::PeerDisconnected(peer) => {
                            debug!("P2P: peer {} disconnected", peer);
                        }
                        P2pEvent::NatStatus(status) => {
                            info!("P2P: NAT status = {}", status);
                        }
                        P2pEvent::PeerHttpAddr(url) => {
                            // v2.1.3: Don't re-add peers that were removed by ghost cleanup.
                            // Ghost peers get removed after 5 sync failures, but P2P Identify
                            // keeps rediscovering them via Kademlia → infinite add/remove loop.
                            if !p2p_blockchain.removed_peers.lock().unwrap().contains(&url) {
                                let mut peers = p2p_blockchain.peers.write().unwrap();
                                if !peers.contains(&url) {
                                    debug!("P2P: discovered HTTP peer {}", tsn::network::peer_id(&url));
                                    peers.push(url);
                                }
                            }
                        }
                        P2pEvent::BlockRequest(from, to) => {
                            // A peer needs blocks from us — serve them via P2P
                            let blocks_data = {
                                let chain = p2p_blockchain.blockchain.read().unwrap();
                                let local_h = chain.height();
                                if from <= local_h && to <= local_h {
                                    let mut bd: Vec<Vec<u8>> = Vec::new();
                                    for h in from..=to {
                                        if let Some(block) = chain.get_block_by_height(h) {
                                            if let Ok(data) = serde_json::to_vec(&block) {
                                                bd.push(data);
                                            }
                                        }
                                    }
                                    bd
                                } else {
                                    Vec::new()
                                }
                            };
                            if !blocks_data.is_empty() {
                                tracing::info!("P2P: serving {} blocks ({} → {})", blocks_data.len(), from, to);
                                let tx = p2p_blockchain.p2p_broadcast.read().unwrap().clone();
                                if let Some(tx) = tx {
                                    let _ = tx.send(tsn::network::p2p::P2pCommand::SendBlocks(blocks_data)).await;
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // Start tip broadcast loop (announces local tip to peers every 10 seconds)
    // v2.1.3: reduced from 30s to 10s to match block time — keeps P2P peer heights fresh
    {
        let tip_state = state.clone();
        let tip_our_url = our_url.clone();
        let tip_local_url = format!("http://localhost:{}", port);
        let tip_local_ip_url = format!("http://127.0.0.1:{}", port);
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                let (height, hash) = {
                    let chain = tip_state.blockchain.read().unwrap();
                    (chain.height(), hex::encode(chain.latest_hash()))
                };

                // P2P tip broadcast: announce height+hash to all GossipSub peers
                {
                    let p2p_tx = tip_state.p2p_broadcast.read().unwrap().clone();
                    if let Some(tx) = p2p_tx {
                        use tsn::network::p2p::P2pCommand;
                        tx.send(P2pCommand::BroadcastTip(height, hash.clone())).await.ok();
                    }
                }

                let mut peers = tip_state.peers.read().unwrap().clone();
                peers.retain(|p| p != &tip_our_url && p != &tip_local_url && p != &tip_local_ip_url);

                for peer in &peers {
                    let url = format!("{}/tip", peer);
                    let body = serde_json::json!({ "height": height, "hash": hash });
                    match client.post(&url)
                        .header("X-TSN-Version", env!("CARGO_PKG_VERSION"))
                        .header("X-TSN-Network", tsn::config::NETWORK_NAME)
                        .header("X-TSN-Genesis", tsn::config::EXPECTED_GENESIS_HASH)
                        .json(&body).send().await {
                        Ok(resp) => {
                            if let Ok(tip_resp) = resp.json::<serde_json::Value>().await {
                                // Update sync gate with peer's tip
                                if let (Some(peer_height), Some(peer_hash)) = (
                                    tip_resp.get("height").and_then(|v| v.as_u64()),
                                    tip_resp.get("hash").and_then(|v| v.as_str()),
                                ) {
                                    if let Ok(hash_bytes) = hex::decode(peer_hash) {
                                        if hash_bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&hash_bytes);
                                            tip_state.sync_gate.update_tip(peer, peer_height, arr);
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {} // Peer unreachable, skip silently
                    }
                }
            }
        });
    }

    // Scan blockchain for faucet notes if enabled
    if state.faucet.is_some() {
        println!("Scanning blockchain for faucet notes...");

        // Do initial scan in a blocking task to avoid blocking the async runtime
        let scan_state = state.clone();
        let (new_notes, balance) = tokio::task::spawn_blocking(move || {
            let blockchain = scan_state.blockchain.read().unwrap();
            let current_height = blockchain.height();

            // Collect blocks into a vec to avoid borrowing issues
            let blocks: Vec<_> = (0..=current_height)
                .filter_map(|h| blockchain.get_block_by_height(h))
                .collect();
            drop(blockchain);

            if let Some(ref faucet) = scan_state.faucet {
                let mut faucet_guard = faucet.blocking_write();

                let get_block = |height: u64| -> Option<ShieldedBlock> {
                    blocks.get(height as usize).cloned()
                };

                let new_notes = faucet_guard.scan_blockchain(get_block, current_height);
                let balance = faucet_guard.balance();
                (new_notes, balance)
            } else {
                (0, 0)
            }
        }).await.unwrap_or((0, 0));

        if new_notes > 0 {
            println!("  Found {} faucet notes, balance: {} TSN", new_notes, balance / 1_000_000_000);
        } else {
            println!("  No faucet notes found (balance: {} TSN)", balance / 1_000_000_000);
        }

        // Start background faucet scanning task (every 30 seconds)
        let faucet_scan_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                let scan_state = faucet_scan_state.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Some(ref faucet) = scan_state.faucet {
                        let blockchain = scan_state.blockchain.read().unwrap();
                        let current_height = blockchain.height();

                        let mut faucet_guard = faucet.blocking_write();
                        let last_scanned = faucet_guard.last_scanned_height();

                        // Only scan if there are new blocks
                        if current_height > last_scanned {
                            // Collect only new blocks
                            let blocks: Vec<_> = ((last_scanned + 1)..=current_height)
                                .filter_map(|h| blockchain.get_block_by_height(h))
                                .collect();
                            drop(blockchain);

                            let get_block = |height: u64| -> Option<ShieldedBlock> {
                                let idx = height.saturating_sub(last_scanned + 1) as usize;
                                blocks.get(idx).cloned()
                            };

                            let _new_notes = faucet_guard.scan_blockchain(get_block, current_height);
                        }
                    }
                }).await;
            }
        });
    }

    // Role-specific behavior summary
    let mining_active = miner_info.is_some();
    match node_role {
        NodeRole::LightClient => {
            tracing::info!("Light client mode: syncing headers only, skipping full block storage");
            println!("Mode: LIGHT CLIENT — header-only sync, minimal storage");
        }
        NodeRole::Relay => {
            tracing::info!("Relay mode: storing and relaying full blocks, mining disabled");
            println!("Mode: RELAY — full block relay, no mining");
        }
        NodeRole::Miner => {
            if !mining_active {
                tracing::info!("Miner mode: full node (no --mine wallet provided, mining inactive)");
            } else {
                tracing::info!("Miner mode: full node with active mining");
            }
        }
    }

    // Start integrated miner (ONLY for miner role — relay/light have wallets but don't mine)
    let mining_wallet = if node_role.can_mine() { miner_info } else { None };
    if let Some((miner_pk_hash, viewing_key)) = mining_wallet {
        if force_mine {
            println!("Force mining enabled - skipping sync verification");
        } else {
            println!("Waiting for initial sync before mining...");
            wait_for_initial_sync(state.clone(), 300).await?;
        }

        let jobs = jobs.max(1);
        let mine_state = state.clone();
        let mine_wallet_path = mine_wallet.clone();
        let announce_url = our_url.clone();
        let local_url = format!("http://localhost:{}", port);
        let local_ip_url = format!("http://127.0.0.1:{}", port);
        if let Some(simd) = simd {
            println!("SIMD mode: {:?}", simd);
        }
        let pool = Arc::new(MiningPool::new_with_simd(jobs, simd));

        tokio::spawn(async move {
            let client = mine_state.http_client.clone();

            // v2.1.3: Wait for P2P mesh formation before mining.
            // After fast-sync, GossipSub needs time to form mesh connections.
            // Mining immediately causes blocks to be lost (no mesh peers yet).
            println!("Waiting 15s for P2P mesh formation...");
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;

            println!("Starting integrated miner...");
            println!("Mining threads: {}", jobs);
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut stats = mine_state.miner_stats.write().unwrap();
                stats.is_mining = true;
                stats.last_updated = now;
            }

            let mut unaccepted_count: u32 = 0;
            let mut resync_attempts: u32 = 0;
            let mut last_resync_height: u64 = 0;
            // Auto-resync stuck detection
            let mut stuck_last_height: u64 = 0;
            let mut stuck_consecutive: u32 = 0;

            loop {
                // Post-reorg cooldown: wait once for network to stabilize before mining
                {
                    let last_reorg = mine_state.last_reorg_height.load(std::sync::atomic::Ordering::Relaxed);
                    if last_reorg > 0 {
                        tracing::info!("Post-reorg cooldown: waiting 3s after reorg at height {}", last_reorg);
                        // Reset immediately so we only wait ONCE per reorg
                        mine_state.last_reorg_height.store(0, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                }

                // Version gate: refuse to mine if node is outdated
                if !tsn::network::version_check::is_version_ok() {
                    tracing::warn!(
                        "Mining PAUSED — node version {} is below network minimum. Please upgrade!",
                        tsn::network::version_check::LOCAL_VERSION
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }

                // NOTE: Solo fork detection DISABLED in mining loop.
                // P2P shared_peers heights are unreliable (often 0 at startup).
                // The watchdog handles fork detection with proper HTTP verification.

                // Sync gate: pause mining if too far behind VERIFIED peers
                // v1.3.3: only consider peers whose height we can verify via HTTP /tip
                // (gossip tips can come from fork chains and are unreliable)
                if !force_mine {
                    let local_height = mine_state.blockchain.read().unwrap().height();
                    let sync_client = mine_state.http_client.clone();
                    let peers_list = mine_state.peers.read().unwrap().clone();

                    // Query ACTUAL peer heights via HTTP (concurrent, 1s timeout)
                    let mut tip_handles = Vec::new();
                    for peer in &peers_list {
                        if !tsn::network::is_contactable_peer(peer) { continue; }
                        let tip_url = format!("{}/tip", peer);
                        let c = sync_client.clone();
                        tip_handles.push(tokio::spawn(async move {
                            if let Ok(resp) = c.get(&tip_url)
                                .timeout(std::time::Duration::from_secs(1))
                                .send().await
                            {
                                if let Ok(tip) = resp.json::<serde_json::Value>().await {
                                    return tip["height"].as_u64().unwrap_or(0);
                                }
                            }
                            0u64
                        }));
                    }
                    let mut verified_max_height: u64 = 0;
                    for h in tip_handles {
                        if let Ok(height) = h.await {
                            if height > 0 && height > verified_max_height {
                                verified_max_height = height;
                            }
                        }
                    }

                    // Fix 3: only pause if verified peers are actually ahead
                    // (gossip network_tip is ignored — it can be from fork chains)
                    let gap = verified_max_height.saturating_sub(local_height);
                    if verified_max_height == 0 || gap <= 2 {
                        // Synced or no peers — reset backoff for next time
                        if resync_attempts > 0 {
                            resync_attempts = 0;
                            last_resync_height = 0;
                        }
                    } else if gap > 2 {
                        tracing::info!(
                            "Behind verified peers (local: {}, verified tip: {}, gap: {}). Waiting for sync...",
                            local_height, verified_max_height, gap
                        );

                        // Fix 2: fast backoff (5s base, up to 30s) — let sync catch up quickly
                        let backoff_secs = std::cmp::min(5u64 * 2u64.pow(resync_attempts.min(3)), 30);
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

                        let fresh_height = mine_state.blockchain.read().unwrap().height();
                        let fresh_gap = verified_max_height.saturating_sub(fresh_height);

                        if fresh_height > local_height {
                            // Sync is making progress — reset backoff
                            resync_attempts = 0;
                        } else if fresh_gap > 2 {
                            resync_attempts += 1;

                            // Fix 1: only re-sync via snapshot if we haven't tried at same height
                            if fresh_height != last_resync_height && resync_attempts <= 3 {
                                last_resync_height = fresh_height;
                                tracing::warn!(
                                    "Still behind (local: {}, tip: {}). Attempting snapshot sync (attempt #{})...",
                                    fresh_height, verified_max_height, resync_attempts
                                );

                                // v1.4.0: Find best VERIFIED peer by cumulative_work.
                                // Require at least 2 peers agreeing (within 5% of max work) before resyncing.
                                let mut peer_infos: Vec<(String, u64, u128)> = Vec::new(); // (url, height, work)
                                for peer in &peers_list {
                                    if !tsn::network::is_contactable_peer(peer) { continue; }
                                    let info_url = format!("{}/chain/info", peer);
                                    if let Ok(resp) = sync_client.get(&info_url)
                                        .timeout(std::time::Duration::from_secs(2))
                                        .send().await
                                    {
                                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                                            let h = info["height"].as_u64().unwrap_or(0);
                                            let w = info["cumulative_work"].as_u64().unwrap_or(0) as u128;
                                            if h > fresh_height {
                                                peer_infos.push((peer.clone(), h, w));
                                            }
                                        }
                                    }
                                }
                                // v1.6.1: Select peer by HEIGHT only, not work
                                let max_h = peer_infos.iter().map(|(_, h, _)| *h).max().unwrap_or(0);
                                let agreeing: Vec<_> = peer_infos.iter()
                                    .filter(|(_, h, _)| *h >= max_h.saturating_sub(2))
                                    .collect();
                                let best: Option<(String, u64)> = if agreeing.len() >= 2 || (peer_infos.len() == 1 && !peer_infos.is_empty()) {
                                    agreeing.iter()
                                        .max_by_key(|(_, h, _)| *h)
                                        .map(|(url, h, _)| (url.clone(), *h))
                                } else {
                                    tracing::warn!(
                                        "Auto-resync: only {}/{} peers at max height — skipping resync",
                                        agreeing.len(), peer_infos.len()
                                    );
                                    None
                                };

                                if let Some((peer_url, _)) = best {
                                    let info_url = format!("{}/snapshot/info", peer_url);
                                    if let Ok(resp) = sync_client.get(&info_url).send().await {
                                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                                            if info["available"].as_bool() == Some(true) {
                                                let snap_height = info["height"].as_u64().unwrap_or(0);
                                                // Fix 1: don't import snapshot at same or lower height
                                                // v1.3.3: also reject snapshots below highest hardcoded checkpoint
                                                let highest_cp = crate::config::HARDCODED_CHECKPOINTS.iter()
                                                    .map(|(h, _)| *h).max().unwrap_or(0);
                                                if snap_height > fresh_height && snap_height >= highest_cp {
                                                    let mut snap_hash_str = info["block_hash"].as_str().unwrap_or("").to_string();
                                                    let dl_url = format!("{}/snapshot/download", peer_url);
                                                    if let Ok(resp) = sync_client.get(&dl_url).send().await {
                                                        // v2.1.3 FIX: use actual snapshot height/hash from download headers
                                                        let snap_height = resp.headers()
                                                            .get("x-snapshot-height")
                                                            .and_then(|v| v.to_str().ok())
                                                            .and_then(|s| s.parse::<u64>().ok())
                                                            .unwrap_or(snap_height);
                                                        if let Some(h) = resp.headers().get("x-snapshot-hash").and_then(|v| v.to_str().ok()) {
                                                            snap_hash_str = h.to_string();
                                                        }
                                                        if let Ok(compressed) = resp.bytes().await {
                                                            use std::io::Read;
                                                            let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                                            let mut json_data = Vec::new();
                                                            if decoder.read_to_end(&mut json_data).is_ok() {
                                                                if let Ok(snapshot) = serde_json::from_slice::<tsn::core::StateSnapshotPQ>(&json_data) {
                                                                    let mut block_hash = [0u8; 32];
                                                                    if let Ok(bytes) = hex::decode(&snap_hash_str) {
                                                                        if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
                                                                    }
                                                                    let ci_url = format!("{}/chain/info", peer_url);
                                                                    let (diff, next_diff, peer_work) = if let Ok(r) = sync_client.get(&ci_url).send().await {
                                                                        let i = r.json::<serde_json::Value>().await.ok();
                                                                        let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
                                                                        let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
                                                                        let w = i.as_ref().and_then(|v| v["cumulative_work"].as_u64()).unwrap_or(0);
                                                                        (d, nd, w as u128)
                                                                    } else { (1000, 1000, 0u128) };

                                                                    // v2.3.9 — fetch LWMA seed headers before taking the lock.
                                                                    let lwma_seed = tsn::network::sync::fetch_pre_snapshot_lwma_headers(&sync_client, &peer_url, snap_height).await;
                                                                    let mut chain = mine_state.blockchain.write().unwrap();
                                                                    chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, peer_work);
                                                                    if !lwma_seed.is_empty() {
                                                                        tracing::info!("pre_snapshot_lwma: seeded {} headers from {}", lwma_seed.len(), peer_url);
                                                                        chain.set_pre_snapshot_lwma(lwma_seed);
                                                                    }
                                                                    println!("Re-synced to height {} from network.", snap_height);
                                                                    resync_attempts = 0;
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    tracing::info!("Snapshot height {} <= local {}, skipping", snap_height, fresh_height);
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if resync_attempts > 3 {
                                // After 3 failed attempts, give up re-syncing and mine anyway
                                tracing::warn!(
                                    "Re-sync stuck after {} attempts at height {}. Mining anyway.",
                                    resync_attempts, fresh_height
                                );
                                // Don't reset — will keep mining until sync catches up naturally
                            }
                            continue;
                        }
                    }
                }

                // Auto-resync: detect stuck node and trigger full wipe+resync
                if !force_mine {
                    let current_height = mine_state.blockchain.read().unwrap().height();
                    let sync_client = mine_state.http_client.clone();
                    let peers_list = mine_state.peers.read().unwrap().clone();

                    // v1.4.0: Compare cumulative_work for stuck detection (not just height)
                    if current_height > stuck_last_height {
                        // Node is making progress — reset stuck counter
                        stuck_consecutive = 0;
                        stuck_last_height = current_height;
                    } else if current_height == stuck_last_height {
                        // Same height as last check (including height 0) — query verified peers via /chain/info
                        let mut verified_max_height: u64 = 0;
                        let mut best_peer: Option<String> = None;
                        let mut _peer_max_work: u128 = 0;
                        let _local_work = mine_state.blockchain.read().unwrap().cumulative_work();
                        for peer in &peers_list {
                            let info_url = format!("{}/chain/info", peer);
                            if let Ok(resp) = sync_client.get(&info_url)
                                .timeout(std::time::Duration::from_secs(5))
                                .send().await
                            {
                                if let Ok(info) = resp.json::<serde_json::Value>().await {
                                    let h = info["height"].as_u64().unwrap_or(0);
                                    // v1.6.1: Select peer by height only
                                    if h > verified_max_height {
                                        verified_max_height = h;
                                        best_peer = Some(peer.clone());
                                    }
                                }
                            }
                        }

                        let gap = verified_max_height.saturating_sub(current_height);
                        if verified_max_height > 0 && gap > 50 {
                            stuck_consecutive += 1;
                            tracing::warn!(
                                "Stuck check #{}: node at height {}, peers at {} (gap {})",
                                stuck_consecutive, current_height, verified_max_height, gap
                            );

                            if stuck_consecutive >= 3 {
                                tracing::warn!(
                                    "Node stuck at height {} for {} checks, peers at {}. Auto-resyncing...",
                                    current_height, stuck_consecutive, verified_max_height
                                );

                                // v1.4.1: Do NOT wipe chain. Attempt snapshot sync WITHOUT wiping first.
                                // If snapshot is at a higher height with more work, import it on top.
                                // Wiping was the cause of catastrophic chain loss.
                                tracing::info!("Attempting snapshot sync without chain wipe...");

                                // Attempt snapshot sync from best peer
                                if let Some(peer_url) = best_peer {
                                    let info_url = format!("{}/snapshot/info", peer_url);
                                    if let Ok(resp) = sync_client.get(&info_url).send().await {
                                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                                            if info["available"].as_bool() == Some(true) {
                                                let snap_height = info["height"].as_u64().unwrap_or(0);
                                                let highest_cp = crate::config::HARDCODED_CHECKPOINTS.iter()
                                                    .map(|(h, _)| *h).max().unwrap_or(0);
                                                if snap_height > 0 && snap_height >= highest_cp {
                                                    let mut snap_hash_str = info["block_hash"].as_str().unwrap_or("").to_string();
                                                    let dl_url = format!("{}/snapshot/download", peer_url);
                                                    if let Ok(resp) = sync_client.get(&dl_url).send().await {
                                                        // v2.1.3 FIX: use actual snapshot height/hash from download headers
                                                        let snap_height = resp.headers()
                                                            .get("x-snapshot-height")
                                                            .and_then(|v| v.to_str().ok())
                                                            .and_then(|s| s.parse::<u64>().ok())
                                                            .unwrap_or(snap_height);
                                                        if let Some(h) = resp.headers().get("x-snapshot-hash").and_then(|v| v.to_str().ok()) {
                                                            snap_hash_str = h.to_string();
                                                        }
                                                        if let Ok(compressed) = resp.bytes().await {
                                                            use std::io::Read;
                                                            let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                                            let mut json_data = Vec::new();
                                                            if decoder.read_to_end(&mut json_data).is_ok() {
                                                                if let Ok(snapshot) = serde_json::from_slice::<tsn::core::StateSnapshotPQ>(&json_data) {
                                                                    let mut block_hash = [0u8; 32];
                                                                    if let Ok(bytes) = hex::decode(&snap_hash_str) {
                                                                        if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
                                                                    }
                                                                    let ci_url = format!("{}/chain/info", peer_url);
                                                                    let (diff, next_diff, peer_work) = if let Ok(r) = sync_client.get(&ci_url).send().await {
                                                                        let i = r.json::<serde_json::Value>().await.ok();
                                                                        let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
                                                                        let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
                                                                        let w = i.as_ref().and_then(|v| v["cumulative_work"].as_u64()).unwrap_or(0);
                                                                        (d, nd, w as u128)
                                                                    } else { (1000, 1000, 0u128) };

                                                                    // v2.3.9 — fetch LWMA seed headers before taking the lock.
                                                                    let lwma_seed = tsn::network::sync::fetch_pre_snapshot_lwma_headers(&sync_client, &peer_url, snap_height).await;
                                                                    let mut chain = mine_state.blockchain.write().unwrap();
                                                                    chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, peer_work);
                                                                    if !lwma_seed.is_empty() {
                                                                        tracing::info!("pre_snapshot_lwma: seeded {} headers from {}", lwma_seed.len(), peer_id(&peer_url));
                                                                        chain.set_pre_snapshot_lwma(lwma_seed);
                                                                    }
                                                                    tracing::info!("Auto-resync complete: jumped to height {} from peer {}", snap_height, peer_id(&peer_url));
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Reset stuck tracking after resync attempt
                                stuck_consecutive = 0;
                                stuck_last_height = 0;
                                resync_attempts = 0;
                                last_resync_height = 0;
                                continue;
                            }
                        } else {
                            // Gap is small or no peers — not stuck
                            stuck_consecutive = 0;
                        }
                    } else {
                        // First check or height 0 — initialize tracking
                        stuck_last_height = current_height;
                    }
                }

                // Get mempool transactions (both V1 and V2)
                let (mempool_txs, mempool_txs_v2) = {
                    let mempool = mine_state.mempool.read().unwrap();
                    let v1 = mempool.get_transactions(100);
                    let all_v2 = mempool.get_shielded_v2_transactions(100);
                    drop(mempool);

                    // Filter V2 transactions: only include those with valid anchors
                    // This prevents invalid TX anchors from blocking mining
                    let chain = mine_state.blockchain.read().unwrap();
                    let v2: Vec<_> = all_v2.into_iter().filter(|tx| {
                        tx.spends.iter().all(|spend| chain.state().is_valid_anchor_pq(&spend.anchor))
                    }).collect();
                    drop(chain);

                    if !v2.is_empty() {
                        println!("  Including {} V2 transactions in block template", v2.len());
                    }
                    (v1, v2)
                };

                // Minimum block interval: wait until enough time has passed since last block.
                // This is critical: ensures ~8-10s between blocks regardless of hashrate.
                // Without this, fast miners find blocks in <1s and fork before propagation.
                let block_wait_secs = {
                    let min_interval = crate::config::MIN_BLOCK_INTERVAL_SECS;
                    let wait_secs = {
                        let chain = mine_state.blockchain.read().unwrap();
                        let tip_height = chain.height();
                        if tip_height > 0 {
                            if let Some(prev_block) = chain.get_block_by_height(tip_height) {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                let earliest = prev_block.header.timestamp + min_interval;
                                if now < earliest { earliest - now } else { 0 }
                            } else { 0 }
                        } else { 0 }
                    };
                    if wait_secs > 0 {
                        tracing::info!("Waiting {}s for minimum block interval ({}s required)", wait_secs, min_interval);
                        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
                    }
                    wait_secs
                };

                // Acquire reorg READ lock — blocks if a rollback is in progress
                let _reorg_read = mine_state.reorg_lock.read().await;

                // Create block template with both V1 and V2 transactions
                let mut block = {
                    let chain = mine_state.blockchain.read().unwrap();
                    chain.create_block_template_with_v2(miner_pk_hash, &viewing_key, mempool_txs, mempool_txs_v2)
                };
                // Save the prev_hash to detect stale blocks after PoW
                let template_prev_hash = block.header.prev_hash;

                // Drop reorg lock during PoW (cancel signal handles abort)
                drop(_reorg_read);

                let (height, difficulty) = {
                    let chain = mine_state.blockchain.read().unwrap();
                    (chain.height() + 1, block.header.difficulty)
                };

                let v2_count = block.transactions_v2.len();
                if v2_count > 0 {
                    println!("Mining block {} (difficulty: {}, V2 txs: {})...", height, difficulty, v2_count);
                } else {
                    println!("Mining block {} (difficulty: {})...", height, difficulty);
                }

                // Get or create the mining cancel signal
                let cancel_signal = {
                    let mc = mine_state.mining_cancel.read().unwrap();
                    mc.clone().unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
                };
                // Reset cancel before starting mining
                if cancel_signal.load(std::sync::atomic::Ordering::Relaxed) {
                    tracing::debug!("MINING_CANCEL=false reason=mining_cycle_start");
                }
                cancel_signal.store(false, std::sync::atomic::Ordering::Relaxed);

                // Mine in a blocking task to not block the async runtime
                let mine_state_for_stats = mine_state.clone();
                let pool = Arc::clone(&pool);
                let cancel_for_mine = Arc::clone(&cancel_signal);
                let wait_secs_for_log = block_wait_secs;
                let mined_block = tokio::task::spawn_blocking(move || {
                    let start = std::time::Instant::now();
                    let attempts = pool.mine_block_cancellable(&mut block, Some(cancel_for_mine));
                    let elapsed = start.elapsed();

                    if attempts == 0 {
                        // Cancelled by P2P new block — return None
                        return None;
                    }

                    let hashrate = if elapsed.as_secs_f64() > 0.0 {
                        (attempts as f64 / elapsed.as_secs_f64()) as u64
                    } else {
                        0
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    {
                        let mut stats = mine_state_for_stats.miner_stats.write().unwrap();
                        stats.hashrate_hps = hashrate;
                        stats.last_attempts = attempts;
                        stats.last_elapsed_ms = elapsed.as_millis() as u64;
                        stats.last_updated = now;
                    }

                    // Display mining metrics — raw hashrate, PoW time, wait time
                    fn fmt_hashrate(h: u64) -> String {
                        if h > 1_000_000 { format!("{:.2} MH/s", h as f64 / 1_000_000.0) }
                        else if h > 1_000 { format!("{:.2} KH/s", h as f64 / 1_000.0) }
                        else { format!("{} H/s", h) }
                    }
                    let pow_secs = elapsed.as_secs_f64();
                    let cycle_secs = pow_secs + wait_secs_for_log as f64;
                    if wait_secs_for_log > 0 {
                        eprintln!("  ⛏ {} | PoW {:.1}s + wait {}s = cycle {:.1}s | {} attempts",
                            fmt_hashrate(hashrate), pow_secs, wait_secs_for_log, cycle_secs, attempts);
                    } else {
                        eprintln!("  ⛏ {} | PoW {:.1}s | {} attempts",
                            fmt_hashrate(hashrate), pow_secs, attempts);
                    }

                    Some(block)
                }).await.unwrap_or_else(|e| {
                    tracing::warn!("Mining task cancelled ({}), restarting cycle", e);
                    None
                });

                // If cancelled, restart on new tip (with cooldown after reorg)
                let mined_block = match mined_block {
                    Some(b) => b,
                    None => {
                        tracing::debug!("Mining cancelled — restarting on new tip");
                        continue;
                    }
                };

                // Re-acquire reorg lock before adding block — ensures no reorg in progress
                let _reorg_read_post = mine_state.reorg_lock.read().await;

                // Check if tip changed during PoW (reorg happened while mining)
                {
                    let chain = mine_state.blockchain.read().unwrap();
                    let current_tip = chain.latest_hash();
                    if template_prev_hash != current_tip {
                        mine_state.metric_stale_blocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(
                            "Mined block discarded (tip changed during PoW)"
                        );
                        drop(_reorg_read_post);
                        continue;
                    }
                }

                // Add to local chain
                {
                    let mut chain = mine_state.blockchain.write().unwrap();
                    match chain.add_block(mined_block.clone()) {
                        Ok(()) => {
                            println!(
                                "\x1b[1;33m🧱 Potential mined block #{} (hash: {})\x1b[0m",
                                chain.height(),
                                mined_block.hash_hex()
                            );

                            // Save mined coinbase note to wallet (so balance updates immediately)
                            // Use the correct global position in the commitment tree
                            if let Some(ref wp) = mine_wallet_path {
                                // Acquire exclusive lock to prevent race with ./tsn wallet
                                let _lock = match WalletLock::acquire(wp) {
                                    Ok(l) => l,
                                    Err(e) => {
                                        tracing::error!("Failed to lock wallet for mining: {}", e);
                                        continue;
                                    }
                                };
                                if let Ok(mut wallet) = ShieldedWallet::open(wp) {
                                    // The miner reward commitment was just added to the tree.
                                    // Its position = tree_size_before_this_block's commitments
                                    // = current_tree_size - N (where N = commitments in this block)
                                    let tree_size = chain.state().commitment_count() as u64;
                                    // This block added: 1 (miner) + optionally 1 (dev fee) = 1-2 commitments
                                    let coinbase_commitments = if mined_block.coinbase.has_dev_fee() { 2u64 } else { 1u64 };
                                    let tx_commitments: u64 = mined_block.transactions.iter().map(|t| t.outputs.len() as u64).sum::<u64>()
                                        + mined_block.transactions_v2.iter().map(|t| t.outputs.len() as u64).sum::<u64>();
                                    let block_start_pos = tree_size - coinbase_commitments - tx_commitments;

                                    let new_notes = wallet.scan_block(&mined_block, block_start_pos);
                                    if new_notes > 0 {
                                        if let Err(e) = wallet.save(wp) {
                                            tracing::error!("Failed to save wallet after mining: {}", e);
                                        }
                                    }
                                }
                                // _lock dropped here — releases flock
                            }

                            // Remove mined transactions from mempool (both V1 and V2)
                            let mut tx_hashes: Vec<[u8; 32]> = mined_block
                                .transactions
                                .iter()
                                .map(|tx| tx.hash())
                                .collect();
                            tx_hashes.extend(mined_block.transactions_v2.iter().map(|tx| tx.hash()));

                            let mut mempool = mine_state.mempool.write().unwrap();
                            mempool.remove_confirmed(&tx_hashes);

                            // Remove transactions with spent nullifiers (both V1 and V2)
                            let mut nullifiers: Vec<[u8; 32]> = mined_block.nullifiers().iter().map(|n| n.0).collect();
                            nullifiers.extend(mined_block.transactions_v2.iter().flat_map(|tx| tx.spends.iter().map(|s| s.nullifier)));
                            mempool.remove_spent_nullifiers(&nullifiers);

                            // Re-validate remaining mempool transactions
                            let removed = mempool.revalidate(chain.state());
                            if removed > 0 {
                                println!("  Removed {} invalid transactions from mempool", removed);
                            }
                        }
                        Err(e) => {
                            println!("Failed to add mined block: {}", e);
                            mine_state.orphan_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue;
                        }
                    }
                }

                // v2.3.0 Phase 2.1: snapshot auto-trigger from the miner path.
                // Must run outside the blockchain write-lock (just released above).
                // check_snapshot_auto_trigger is a no-op unless the new tip crosses an
                // interval boundary and the CAS claims the exported interval first.
                {
                    let tip_h = mine_state.blockchain.read().unwrap().height();
                    check_snapshot_auto_trigger(&mine_state, tip_h);
                }

                // Broadcast via P2P GossipSub (primary — instant push to all peers)
                {
                    let p2p_tx = mine_state.p2p_broadcast.read().unwrap().clone();
                    if let Some(tx) = p2p_tx {
                        if let Ok(block_data) = serde_json::to_vec(&mined_block) {
                            let _ = tx.send(tsn::network::p2p::P2pCommand::BroadcastBlock(block_data)).await;
                        }
                    }
                }

                // Broadcast via HTTP (fallback for non-upgraded nodes)
                let mut current_peers = mine_state.peers.read().unwrap().clone();
                current_peers.retain(|peer| {
                    tsn::network::is_contactable_peer(peer) && peer != &announce_url && peer != &local_url && peer != &local_ip_url
                });
                if !current_peers.is_empty() {
                    let local_pid = mine_state.p2p_peer_id.read().unwrap().clone();
                    tsn::network::broadcast_block_with_id(&mined_block, &current_peers, &client, local_pid).await;
                }

                // v1.6.1: Fork check by HEIGHT + HASH, never by cumulative_work.
                // Peer-reported work is unreliable (different fast-sync estimates).
                if let Some(peer) = current_peers.first() {
                    let height = mined_block.coinbase.height;
                    let ci_url = format!("{}/chain/info", peer);
                    if let Ok(resp) = client.get(&ci_url).timeout(std::time::Duration::from_secs(1)).send().await {
                        if let Ok(peer_info) = resp.json::<serde_json::Value>().await {
                            let peer_height = peer_info.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                            let peer_hash = peer_info.get("latest_hash").and_then(|v| v.as_str()).unwrap_or("");

                            let local_hash_hex = {
                                let chain = mine_state.blockchain.read().unwrap();
                                hex::encode(chain.latest_hash())
                            };

                            if peer_hash == local_hash_hex {
                                // Same tip — no fork. Verify confirmation after short delay.
                                let confirm_height = height;
                                let confirm_hash = local_hash_hex.clone();
                                let confirm_state = mine_state.clone();
                                let confirm_peers = current_peers.clone();
                                tokio::spawn(async move {
                                    // Wait for next block cycle to check if our block survived
                                    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                                    let local_hash_at_h = {
                                        let chain = confirm_state.blockchain.read().unwrap();
                                        chain.get_hash_at_height(confirm_height)
                                            .map(|h| hex::encode(h))
                                            .unwrap_or_default()
                                    };
                                    if local_hash_at_h == confirm_hash {
                                        // Our block is still canonical locally, verify with a seed
                                        let client = reqwest::Client::new();
                                        let mut confirmed = false;
                                        for peer in &confirm_peers {
                                            let url = format!("{}/block/height/{}", peer, confirm_height);
                                            if let Ok(resp) = client.get(&url)
                                                .timeout(std::time::Duration::from_secs(3))
                                                .send().await
                                            {
                                                if let Ok(info) = resp.json::<serde_json::Value>().await {
                                                    if info.get("hash").and_then(|v| v.as_str()) == Some(&confirm_hash) {
                                                        confirmed = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if confirmed {
                                            println!("\x1b[1;32m💎 Block #{} CONFIRMED by network (hash: {})\x1b[0m", confirm_height, confirm_hash);
                                        } else {
                                            println!("\x1b[1;31m✗ Block #{} ORPHANED — replaced by another miner\x1b[0m", confirm_height);
                                        }
                                    } else {
                                        println!("\x1b[1;31m✗ Block #{} ORPHANED — replaced by another miner\x1b[0m", confirm_height);
                                    }
                                });
                                tracing::info!("Block #{} mined, synced with peers at height {}", height, peer_height);
                                unaccepted_count = 0;
                            } else if peer_height > height {
                                // Peer is ahead by height — we might be on a fork
                                unaccepted_count += 1;
                                tracing::warn!(
                                    "FORK: peer ahead (peer h={}, local h={}, strike {}/2)",
                                    peer_height, height, unaccepted_count
                                );
                                if unaccepted_count >= 2 {
                                    tracing::error!("FORK CONFIRMED: peer is ahead. Re-syncing...");
                                    mine_state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    let _ = tsn::network::sync_from_peer(mine_state.clone(), peer).await;
                                    // BUG FIX: Do NOT set mining_cancel here.
                                    // sync_from_peer already cancels mining during reorg internally.
                                    // Setting cancel=true AFTER sync returns kills the next mining
                                    // cycle before it starts, creating a deadlock:
                                    //   cancel=true → mine returns None → sync gate sees gap → waits
                                    //   → nobody mines → gap never closes → mining stalled forever.
                                    unaccepted_count = 0;
                                }
                            } else {
                                // We're at same height or ahead — peer will sync to us
                                tracing::info!("Block #{} mined, at or ahead of peers (local h={}, peer h={})", height, height, peer_height);
                                unaccepted_count = 0;
                            }
                        }
                    }
                }
            }
        });
    }

    let chain_height = state.blockchain.read().unwrap().height();
    let node_id = state.p2p_peer_id.read().unwrap().clone().unwrap_or_default();
    println!();
    println!("Chain height: {}", chain_height);
    println!("Node is running. Type \x1b[1;35mhelp\x1b[0m for commands, Ctrl+C to stop.");
    if !node_id.is_empty() {
        println!("Your Node ID: \x1b[1;36m{}\x1b[0m", node_id);
    }
    println!();

    // Interactive console — reads stdin commands, displays in violet
    let console_state = state.clone();
    let console_start = std::time::Instant::now();
    tokio::spawn(async move {
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        use tokio::io::AsyncBufReadExt;
        let mut lines = stdin.lines();
        let violet = "\x1b[1;35m";
        let cyan = "\x1b[1;36m";
        let reset = "\x1b[0m";

        while let Ok(Some(line)) = lines.next_line().await {
            let cmd = line.trim().to_lowercase();
            match cmd.as_str() {
                "id" => {
                    let pid = console_state.p2p_peer_id.read().unwrap().clone().unwrap_or_default();
                    println!("{violet}> {cyan}{pid}{reset}");
                }
                "address" | "addr" => {
                    match &console_state.mining_address {
                        Some(addr) => println!("{violet}> {cyan}{addr}{reset}"),
                        None => println!("{violet}> No wallet loaded{reset}"),
                    }
                }
                "status" => {
                    let chain = console_state.blockchain.read().unwrap();
                    let h = chain.height();
                    let diff = chain.info().difficulty;
                    let work = chain.cumulative_work();
                    drop(chain);
                    let peers = console_state.peers.read().unwrap().len();
                    let p2p_count = console_state.p2p_shared_peers.read().unwrap()
                        .as_ref().map(|sp| sp.read().unwrap().len()).unwrap_or(0);
                    println!("{violet}> Height:     {reset}{h}");
                    println!("{violet}  Peers:      {reset}{peers} HTTP, {p2p_count} P2P");
                    println!("{violet}  Difficulty:  {reset}{diff}");
                    println!("{violet}  Work:       {reset}{work}");
                    println!("{violet}  Version:    {reset}{}", env!("CARGO_PKG_VERSION"));
                }
                "peers" => {
                    let peers = console_state.p2p_shared_peers.read().unwrap()
                        .as_ref().map(|sp| sp.read().unwrap().clone()).unwrap_or_default();
                    println!("{violet}> {} P2P peers:{reset}", peers.len());
                    for p in &peers {
                        let h = p.height.map(|h| format!("{h}")).unwrap_or_else(|| "?".to_string());
                        println!("{violet}  {reset}{} h={} {}", &p.peer_id[..20], h, p.protocol);
                    }
                }
                "version" => {
                    println!("{violet}> TSN v{}{reset}", env!("CARGO_PKG_VERSION"));
                }
                "difficulty" => {
                    let chain = console_state.blockchain.read().unwrap();
                    let diff = chain.info().difficulty;
                    let next = chain.info().next_difficulty;
                    println!("{violet}> Current:    {reset}{diff}");
                    println!("{violet}  Next:       {reset}{next}");
                }
                "uptime" => {
                    let elapsed = console_start.elapsed();
                    let hours = elapsed.as_secs() / 3600;
                    let mins = (elapsed.as_secs() % 3600) / 60;
                    let secs = elapsed.as_secs() % 60;
                    println!("{violet}> {reset}{hours}h {mins}m {secs}s");
                }
                "clear" => {
                    print!("\x1b[2J\x1b[H");
                }
                "help" | "?" => {
                    println!("{violet}> Commands:{reset}");
                    println!("{violet}  id         {reset}Show your Node ID (PeerID)");
                    println!("{violet}  address    {reset}Show your mining/wallet address");
                    println!("{violet}  status     {reset}Height, peers, difficulty, version");
                    println!("{violet}  peers      {reset}List connected P2P peers");
                    println!("{violet}  version    {reset}Show node version");
                    println!("{violet}  difficulty {reset}Current and next difficulty");
                    println!("{violet}  uptime     {reset}Time since node started");
                    println!("{violet}  clear      {reset}Clear screen");
                    println!("{violet}  help       {reset}This message");
                }
                "" => {} // ignore empty lines
                _ => {
                    println!("{violet}> Unknown command: {reset}{cmd}{violet}. Type help for commands.{reset}");
                }
            }
        }
    });

    // Keep the main task alive
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");

    // Graceful wallet shutdown — flush SQLite WAL
    if let Some(ref ws) = wallet_service {
        match ws.flush().await {
            Ok(()) => println!("Wallet flushed."),
            Err(e) => eprintln!("Warning: wallet flush failed: {}", e),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_pq_commitment_returns_stored_when_server_agrees() {
        // Happy path: stored and server report the same real commitment.
        let shared = [7u8; 32];
        let got = resolve_pq_commitment(Some(shared), Some(&hex::encode(shared)), 42)
            .expect("agreeing values should succeed");
        assert_eq!(got, shared);
    }

    #[test]
    fn resolve_pq_commitment_bails_orphan_when_stored_and_server_differ() {
        // v2.3.1 orphan detection: wallet and chain disagree on a real leaf
        // at this position. The wallet's note is stale (the block that minted
        // it was reorg'd out). Callers must detect ORPHANED_NOTE in the error
        // string and skip the note from their spend selection.
        let stored = [7u8; 32];
        let server_leaf = [0xffu8; 32];
        let err = resolve_pq_commitment(Some(stored), Some(&hex::encode(server_leaf)), 2956)
            .expect_err("mismatch must bail as orphan");
        let msg = format!("{}", err);
        assert!(msg.contains(ORPHANED_NOTE_MARKER), "error must carry the orphan marker: {msg}");
        assert!(msg.contains("position 2956"), "error must identify the position: {msg}");
    }

    #[test]
    fn resolve_pq_commitment_trusts_stored_when_server_returns_placeholder() {
        // v2.3.1: fast-sync blind zone returns an all-zeros placeholder. Trust
        // the wallet's stored value — the STARK circuit will cross-check that
        // the note data actually hashes to it at spend time.
        let stored = [7u8; 32];
        let placeholder = "0".repeat(64);
        let got = resolve_pq_commitment(Some(stored), Some(&placeholder), 42)
            .expect("stored should be used when server leaf is placeholder");
        assert_eq!(got, stored);
    }

    #[test]
    fn resolve_pq_commitment_trusts_stored_when_server_has_no_leaf() {
        // Old node binary that does not return a "leaf" field at all. Trust
        // the wallet's stored value.
        let stored = [0xabu8; 32];
        let got = resolve_pq_commitment(Some(stored), None, 7)
            .expect("stored should be used when server leaf is absent");
        assert_eq!(got, stored);
    }

    #[test]
    fn resolve_pq_commitment_bails_when_both_placeholder_and_stored_missing() {
        // If the server leaf is a placeholder and the wallet has no stored
        // value, there is nothing usable to build the witness — bail.
        let placeholder = "0".repeat(64);
        let err = resolve_pq_commitment(None, Some(&placeholder), 99)
            .expect_err("placeholder + no stored must bail");
        let msg = format!("{}", err);
        assert!(msg.contains("position 99"));
    }

    #[test]
    fn resolve_pq_commitment_falls_back_to_server_leaf() {
        let leaf_bytes = [3u8; 32];
        let leaf_hex = hex::encode(leaf_bytes);
        let got = resolve_pq_commitment(None, Some(&leaf_hex), 100)
            .expect("fallback should succeed");
        assert_eq!(got, leaf_bytes);
    }

    #[test]
    fn resolve_pq_commitment_bails_on_missing_leaf() {
        let err = resolve_pq_commitment(None, None, 7)
            .expect_err("missing leaf must bail");
        let msg = format!("{}", err);
        assert!(msg.contains("position 7"));
        assert!(msg.contains("upgrade the node"));
    }

    #[test]
    fn resolve_pq_commitment_bails_on_empty_leaf_string() {
        let err = resolve_pq_commitment(None, Some(""), 11)
            .expect_err("empty leaf must bail");
        assert!(format!("{}", err).contains("position 11"));
    }

    #[test]
    fn resolve_pq_commitment_trims_whitespace() {
        let leaf_bytes = [0xabu8; 32];
        let padded = format!("  {}  ", hex::encode(leaf_bytes));
        let got = resolve_pq_commitment(None, Some(&padded), 1)
            .expect("whitespace-padded hex should parse");
        assert_eq!(got, leaf_bytes);
    }

    #[test]
    fn resolve_pq_commitment_rejects_invalid_hex() {
        let err = resolve_pq_commitment(None, Some("zzz"), 1)
            .expect_err("bad hex must bail");
        assert!(format!("{}", err).contains("Invalid leaf hex"));
    }

    #[test]
    fn resolve_pq_commitment_rejects_wrong_length() {
        let err = resolve_pq_commitment(None, Some("aabb"), 1)
            .expect_err("short hex must bail");
        assert!(format!("{}", err).contains("wrong length"));
    }

    /// v2.3.5 — print the genesis hash produced by this binary so the release
    /// engineer can paste it into `EXPECTED_GENESIS_HASH`. Run with:
    ///   cargo test --release --bin tsn print_genesis_hash -- --nocapture --ignored
    /// Marked #[ignore] so it never runs as part of the normal suite.
    #[test]
    #[ignore]
    fn print_genesis_hash() {
        use tsn::core::{CoinbaseTransaction, ShieldedBlock};
        use tsn::crypto::{NoteCommitment, EncryptedNote};

        let genesis_coinbase = CoinbaseTransaction::new(
            NoteCommitment([0u8; 32]),
            [0u8; 32],
            EncryptedNote {
                ciphertext: vec![0; 64],
                ephemeral_pk: vec![0; 32],
            },
            tsn::config::BLOCK_REWARD,
            0,
        );

        let genesis = ShieldedBlock::genesis(
            tsn::config::GENESIS_DIFFICULTY,
            genesis_coinbase,
        );
        let hash = hex::encode(genesis.hash());
        println!("NETWORK_NAME        = {}", tsn::config::NETWORK_NAME);
        println!("GENESIS_DIFFICULTY  = {}", tsn::config::GENESIS_DIFFICULTY);
        println!("BLOCK_REWARD        = {}", tsn::config::BLOCK_REWARD);
        println!("EXPECTED_GENESIS_HASH = {}", hash);
    }

    /// v2.3.4 — `persist_snapshot_to_disk` must write both the compressed
    /// snapshot and a signed manifest into `<data_dir>/snapshots/` and the
    /// manifest on disk must round-trip back to an equal object.
    fn sample_manifest(height: u64) -> tsn::network::snapshot_manifest::SnapshotManifest {
        tsn::network::snapshot_manifest::SnapshotManifest {
            version: 1,
            chain_id: "tsn-mainnet".to_string(),
            height,
            block_hash: "aa".repeat(32),
            state_root: "bb".repeat(32),
            snapshot_sha256: "cc".repeat(32),
            snapshot_size_bytes: 0,
            format: "json-gzip".to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            producer: tsn::network::snapshot_manifest::SeedIdentity {
                seed_name: "unit-test".to_string(),
                peer_id: "peer".to_string(),
                public_key: "dd".repeat(32),
            },
            signature: "deadbeef".to_string(),
            confirmations: Vec::new(),
        }
    }

    /// v2.3.4 — `persist_snapshot_to_disk` must write both the compressed
    /// snapshot and a signed manifest into `<data_dir>/snapshots/` and the
    /// manifest on disk must round-trip back to an equal object.
    #[tokio::test]
    async fn persist_snapshot_to_disk_writes_files_and_round_trips_manifest() {
        let tmp = tempfile::tempdir().expect("create temp data dir");
        let compressed = b"fake-compressed-snapshot-payload".to_vec();
        let manifest = sample_manifest(12345);

        persist_snapshot_to_disk(tmp.path(), 12345, &compressed, &manifest).await;

        let snap_path = tmp.path().join("snapshots").join("snapshot-12345.json.gz");
        let manifest_path = tmp.path().join("snapshots").join("snapshot-12345.manifest.json");
        assert!(snap_path.exists(), "snapshot file must be written");
        assert!(manifest_path.exists(), "manifest file must be written");

        let snap_bytes = tokio::fs::read(&snap_path).await.expect("read snapshot");
        assert_eq!(snap_bytes, compressed, "snapshot bytes must match input");

        let manifest_bytes = tokio::fs::read(&manifest_path).await.expect("read manifest");
        let loaded: tsn::network::snapshot_manifest::SnapshotManifest =
            serde_json::from_slice(&manifest_bytes).expect("manifest must deserialize");
        assert_eq!(loaded.height, manifest.height);
        assert_eq!(loaded.block_hash, manifest.block_hash);
        assert_eq!(loaded.signature, manifest.signature);
        assert_eq!(loaded.producer.public_key, manifest.producer.public_key);
    }

    /// v2.3.4 — writing multiple snapshots keeps them all (retention by mtime,
    /// not count, so freshly-written files must survive).
    #[tokio::test]
    async fn persist_snapshot_to_disk_keeps_recent_files_under_retention() {
        let tmp = tempfile::tempdir().expect("create temp data dir");
        let compressed = vec![1u8, 2, 3, 4];
        let manifest = sample_manifest(1);

        persist_snapshot_to_disk(tmp.path(), 1, &compressed, &manifest).await;
        persist_snapshot_to_disk(tmp.path(), 2, &compressed, &manifest).await;

        let snap_dir = tmp.path().join("snapshots");
        let mut names: Vec<String> = Vec::new();
        let mut entries = tokio::fs::read_dir(&snap_dir).await.expect("read_dir");
        while let Ok(Some(e)) = entries.next_entry().await {
            if let Some(n) = e.file_name().to_str() {
                names.push(n.to_string());
            }
        }
        assert!(names.iter().any(|n| n == "snapshot-1.json.gz"));
        assert!(names.iter().any(|n| n == "snapshot-2.json.gz"));
        assert!(names.iter().any(|n| n == "snapshot-1.manifest.json"));
        assert!(names.iter().any(|n| n == "snapshot-2.manifest.json"));
    }
}
