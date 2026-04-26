//! v2.6.0 — Auto-fetch signed snapshots from GitHub.
//!
//! When the rollback guard (`core::blockchain::reorganize_to_block`) refuses a
//! rollback because the fast-sync base has pruned older blocks, it used to halt
//! and leave the node silently stuck until an operator ran `restore-snapshot`
//! manually. This module closes that loop: on the next startup, if a marker
//! file signals a prior guard fire, the node fetches the latest producer-signed
//! snapshot from the public `tsn-snapshots` GitHub repo, verifies SHA-256 +
//! producer Ed25519 signature, imports it, and clears the marker.
//!
//! The GitHub releases API is unauthenticated (60 req/h/IP public rate limit)
//! and only queried at startup after a guard fire, so we stay far below any
//! cap. All verification is done locally; no trust is placed in GitHub itself.

use super::snapshot_manifest::SnapshotManifest;

const RELEASES_API: &str =
    "https://api.github.com/repos/trusts-stack-network/tsn-snapshots/releases";
const RELEASES_DL: &str =
    "https://github.com/trusts-stack-network/tsn-snapshots/releases/download";

/// Filename written under the data dir when the rollback guard refuses a
/// rollback. Presence on next startup triggers `auto_restore_if_marker_present`.
pub const MARKER_FILENAME: &str = "AUTO_RESTORE_NEEDED";

/// Place the marker that signals "next startup, please auto-restore".
pub fn set_marker(data_dir: &std::path::Path, reason: &str) {
    let p = data_dir.join(MARKER_FILENAME);
    if let Err(e) = std::fs::write(&p, format!("{}\n{}\n", chrono::Utc::now().to_rfc3339(), reason))
    {
        tracing::warn!("auto-restore marker write failed at {:?}: {}", p, e);
    } else {
        tracing::warn!("auto-restore marker written at {:?} — next startup will self-heal", p);
    }
}

/// Remove the marker after a successful auto-restore.
pub fn clear_marker(data_dir: &std::path::Path) {
    let p = data_dir.join(MARKER_FILENAME);
    let _ = std::fs::remove_file(p);
}

pub fn marker_exists(data_dir: &std::path::Path) -> bool {
    data_dir.join(MARKER_FILENAME).exists()
}

#[derive(Debug)]
pub struct FetchedSnapshot {
    pub manifest: SnapshotManifest,
    pub compressed: Vec<u8>,
    pub tag: String,
}

/// Fetch the latest signed snapshot from GitHub. Highest-height release wins;
/// signature + SHA-256 are verified against the manifest before returning. The
/// seed confirmations check is deliberately relaxed to producer-only, mirroring
/// `restore-snapshot --force-producer-only` — auto-healing already only runs
/// after a fatal guard fire, so requiring 2-of-N co-signers would turn transient
/// publishing gaps into hard deadlocks.
pub async fn fetch_latest_snapshot() -> Result<FetchedSnapshot, String> {
    // Build a client with a sane user-agent — GitHub API rejects unauth'd
    // requests with no UA as "abuse detection".
    let client = reqwest::Client::builder()
        .user_agent(concat!("tsn-auto-restore/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client build: {}", e))?;

    let resp = client
        .get(RELEASES_API)
        .send()
        .await
        .map_err(|e| format!("GitHub releases list: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("GitHub releases list returned HTTP {}", resp.status()));
    }
    let releases: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("GitHub releases JSON parse: {}", e))?;

    // Releases are returned newest-first by GitHub, but tag name convention
    // `snapshot-<height>` lets us pick deterministically by height. Be
    // defensive — a release with no matching tag or missing assets is skipped.
    let mut best: Option<(u64, String)> = None;
    for r in releases.as_array().ok_or("GitHub releases: expected array")? {
        let tag = r.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
        let Some(rest) = tag.strip_prefix("snapshot-") else {
            continue;
        };
        let Ok(h) = rest.parse::<u64>() else { continue };
        let has_assets = r.get("assets").and_then(|a| a.as_array()).map_or(0, |a| a.len()) >= 2;
        if !has_assets {
            continue;
        }
        if best.as_ref().map_or(true, |(bh, _)| h > *bh) {
            best = Some((h, tag.to_string()));
        }
    }
    let (height, tag) =
        best.ok_or_else(|| "no usable snapshot-* release found in tsn-snapshots".to_string())?;
    tracing::info!("auto-restore: selected {} (height {})", tag, height);

    // Download manifest first (tiny, cheap) — if the tag is broken we bail
    // before pulling the compressed snapshot.
    let manifest_url = format!("{}/{}/manifest.json", RELEASES_DL, tag);
    let manifest_bytes = client
        .get(&manifest_url)
        .send()
        .await
        .map_err(|e| format!("fetch manifest {}: {}", manifest_url, e))?
        .bytes()
        .await
        .map_err(|e| format!("read manifest bytes: {}", e))?;
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("parse manifest: {}", e))?;

    // Producer signature MUST verify before we waste bandwidth on the payload.
    if !manifest.verify_producer_signature() {
        return Err(format!("manifest {} producer signature invalid", tag));
    }

    // Now pull the compressed snapshot.
    let snapshot_url = format!("{}/{}/snapshot.tar.gz", RELEASES_DL, tag);
    let compressed = client
        .get(&snapshot_url)
        .send()
        .await
        .map_err(|e| format!("fetch snapshot {}: {}", snapshot_url, e))?
        .bytes()
        .await
        .map_err(|e| format!("read snapshot bytes: {}", e))?
        .to_vec();

    // SHA-256 must match the manifest — defends against GitHub-side tampering
    // or a half-written upload.
    let computed = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&compressed))
    };
    if computed != manifest.snapshot_sha256 {
        return Err(format!(
            "snapshot {} SHA-256 mismatch: computed={}..., manifest={}...",
            tag,
            &computed[..16],
            &manifest.snapshot_sha256[..16]
        ));
    }

    Ok(FetchedSnapshot { manifest, compressed, tag })
}

/// If the marker file is present in the data dir, fetch + import the latest
/// signed snapshot, then clear the marker. This is called from the node startup
/// path before the blockchain is opened for regular operation.
///
/// Returns Ok(true) if a restore happened, Ok(false) if no marker, Err on any
/// failure (caller must decide whether to proceed or halt).
pub async fn auto_restore_if_marker_present(data_dir: &std::path::Path) -> Result<bool, String> {
    if !marker_exists(data_dir) {
        return Ok(false);
    }
    tracing::warn!(
        "AUTO_RESTORE_NEEDED marker present at {:?} — fetching latest signed snapshot",
        data_dir
    );

    let fetched = fetch_latest_snapshot().await?;

    // v2.6.0 hotfix (Phase 1.9) — the snapshot manifest carries the chain_id
    // of the network it was produced on. Refuse to import a snapshot from a
    // different network than the one this binary is compiled for. Without
    // this guard, a testnet reset (NETWORK_NAME bump) combined with a stale
    // AUTO_RESTORE_NEEDED marker would pull down the last pre-reset snapshot
    // and hydrate this node onto the dead chain. The symptom was observed in
    // the field on 2026-04-24: after the v11→v12 reset, auto-restored nodes
    // broadcast h=7100 from the v11 chain while their canonical chain had
    // moved to v12 h=1800, appearing as "solo forks" in the explorer even
    // though internal /chain/info read correct.
    if fetched.manifest.chain_id != crate::config::NETWORK_NAME {
        return Err(format!(
            "snapshot {} is for chain_id={}, but this node is on {}. \
             The latest published snapshot predates the current testnet reset. \
             Leaving the marker in place; operator intervention required to \
             republish a post-reset snapshot or manually restore from a trusted peer.",
            fetched.tag,
            fetched.manifest.chain_id,
            crate::config::NETWORK_NAME
        ));
    }

    tracing::info!(
        "auto-restore: fetched {} ({} bytes, height {}, chain_id={}) — importing",
        fetched.tag,
        fetched.compressed.len(),
        fetched.manifest.height,
        fetched.manifest.chain_id
    );

    // Decompress
    let json_data = {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(&fetched.compressed[..]);
        let mut buf = Vec::new();
        decoder
            .read_to_end(&mut buf)
            .map_err(|e| format!("decompression: {}", e))?;
        buf
    };
    let snapshot_state: crate::core::StateSnapshotPQ =
        serde_json::from_slice(&json_data).map_err(|e| format!("parse snapshot state: {}", e))?;

    // Before importing, backup the current blockchain dir (never wipe without
    // a trace — the user rule is: keep past state recoverable).
    let bc_path = data_dir.join("blockchain");
    if bc_path.exists() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = data_dir.join(format!("blockchain.pre-auto-restore-{}", ts));
        std::fs::rename(&bc_path, &backup)
            .map_err(|e| format!("backup blockchain: {}", e))?;
        tracing::info!("auto-restore: moved {:?} -> {:?}", bc_path, backup);
    }

    // Import into a fresh blockchain
    let db_path = bc_path.to_string_lossy().to_string();
    let mut blockchain = crate::core::ShieldedBlockchain::open(&db_path, crate::config::GENESIS_DIFFICULTY)
        .map_err(|e| format!("open fresh blockchain: {}", e))?;

    let mut block_hash = [0u8; 32];
    if let Ok(bytes) = hex::decode(&fetched.manifest.block_hash) {
        if bytes.len() == 32 {
            block_hash.copy_from_slice(&bytes);
        }
    }
    blockchain.import_snapshot_at_height(snapshot_state, fetched.manifest.height, block_hash, 1000, 1000, 0);

    // Post-import verification — state root must match
    let computed_root = hex::encode(blockchain.state_root());
    if computed_root != fetched.manifest.state_root {
        return Err(format!(
            "state root mismatch after import: computed={}..., manifest={}...",
            &computed_root[..16],
            &fetched.manifest.state_root[..16]
        ));
    }

    // Success — clear the marker
    clear_marker(data_dir);
    tracing::info!(
        "auto-restore: complete — chain restored to height {} ({}), marker cleared",
        fetched.manifest.height,
        &fetched.manifest.block_hash[..16]
    );
    Ok(true)
}
