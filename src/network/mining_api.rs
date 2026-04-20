//! Mining API (v2.4.0, Phase 6) — template/submit endpoints for external miners.
//!
//! This module lets GPU miners and third-party pool servers mine against a
//! TSN node without running a full node themselves: they fetch a block
//! template, run their hash kernel over the nonce space, and post a winning
//! nonce back. The node reconstitutes the block from the server-side cache,
//! validates PoW + block contents, and broadcasts as if it had mined locally.
//!
//! Design choices:
//!   * The template exposes the FULL header layout including `min_v2_count`
//!     (Phase 2) and the coinbase commit (hash of the pre-built coinbase,
//!     which carries `miner_pk_hash` from Phase 1). A miner that changes
//!     any of these bytes invalidates the PoW, so the template can be
//!     trusted server-side once cached.
//!   * The server-side cache is keyed by `template_id` (Blake2s hash of the
//!     204-byte prefix), NOT by height — that way two miners racing on the
//!     same height see the same template_id and don't thrash the cache.
//!   * Templates expire after `TEMPLATE_TTL_SECS` (90 s). Tip changes also
//!     evict stale templates via `evict_stale_on_tip`.
//!
//! This module is pure data + pure logic; the axum handlers that wire it
//! into the API router live in `network::api`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Byte range 0..148 of the header is fixed (version+roots+timestamp+difficulty+min_v2_count
/// = 4+32+32+32+32+8+8+2 = 150 bytes). Then 64 bytes of nonce. The `nonce_prefix`
/// returned in the template is the first 56 bytes of that nonce; the miner
/// fills the last 8 bytes (the counter) and submits the full 64-byte nonce.
pub const NONCE_PREFIX_BYTES: usize = 56;
pub const NONCE_COUNTER_BYTES: usize = 8;
pub const NONCE_TOTAL_BYTES: usize = NONCE_PREFIX_BYTES + NONCE_COUNTER_BYTES;

/// Time-to-live for a cached template before it is dropped.
pub const TEMPLATE_TTL_SECS: u64 = 90;

// ============================================================================
// Template response
// ============================================================================

/// Response to `GET /mining/template`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateResponse {
    /// Template identifier — Blake2s hash of the canonical header bytes with
    /// nonce cleared. Miners echo this back in submit to pick the cached
    /// template unambiguously (vs. relying on height, which collides on
    /// simultaneous builds).
    pub template_id: String,

    /// Block height this template is for (= chain.height() + 1).
    pub height: u64,

    /// Block header version (currently 3).
    pub version: u32,

    /// Hex-encoded 32-byte hash of the parent block.
    pub prev_hash: String,

    /// Hex-encoded 32-byte merkle root over the transactions + coinbase.
    pub merkle_root: String,

    /// Hex-encoded 32-byte commitment root after applying this block.
    pub commitment_root: String,

    /// Hex-encoded 32-byte nullifier root after applying this block.
    pub nullifier_root: String,

    /// Hex-encoded 32-byte post-block state root.
    pub state_root: String,

    /// Unix timestamp baked into the header at template-build time.
    pub timestamp: u64,

    /// Numeric difficulty target. `hash_prefix < u64::MAX / difficulty` wins.
    pub difficulty: u64,

    /// Miner's engagement on the V2 transactions count (Phase 2/3). Bound
    /// into the PoW hash — the miner cannot rewrite it without redoing work.
    pub min_v2_count: u16,

    /// Hex-encoded 32-byte hash of the coinbase transaction the server
    /// pre-built and cached. Included so the miner can audit that the
    /// coinbase it will be credited for corresponds to its own pk_hash.
    pub coinbase_hash: String,

    /// Hex-encoded 56 bytes of random nonce prefix allocated to this
    /// submission slot. The miner owns bytes 56..64 (counter) and MUST
    /// keep these 56 bytes verbatim.
    pub nonce_prefix_hex: String,

    /// Server wall-clock epoch at which this template was produced (ms).
    /// Useful for clients that want to quantify freshness.
    pub produced_at_ms: u64,
}

// ============================================================================
// Submit request / response
// ============================================================================

/// Body of `POST /mining/submit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRequest {
    /// The `template_id` echoed from the template the miner worked against.
    pub template_id: String,
    /// 64 bytes of nonce hex. The first 56 bytes MUST match the template's
    /// `nonce_prefix_hex`; the last 8 bytes are the winning counter.
    pub nonce_hex: String,
}

impl SubmitRequest {
    /// Parse the nonce field as [u8; 64], returning `None` on malformed hex
    /// or wrong length.
    pub fn parsed_nonce(&self) -> Option<[u8; NONCE_TOTAL_BYTES]> {
        let bytes = hex::decode(&self.nonce_hex).ok()?;
        if bytes.len() != NONCE_TOTAL_BYTES {
            return None;
        }
        let mut out = [0u8; NONCE_TOTAL_BYTES];
        out.copy_from_slice(&bytes);
        Some(out)
    }
}

/// Response body for `POST /mining/submit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub accepted: bool,
    /// Hex-encoded block hash when `accepted == true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Block height when `accepted == true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    /// Human-readable rejection reason when `accepted == false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SubmitResponse {
    pub fn ok(hash: [u8; 32], height: u64) -> Self {
        Self {
            accepted: true,
            hash: Some(hex::encode(hash)),
            height: Some(height),
            reason: None,
        }
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            hash: None,
            height: None,
            reason: Some(reason.into()),
        }
    }
}

/// Reasons the server can return when rejecting a submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitReject {
    UnknownTemplate,
    TemplateExpired,
    WrongNoncePrefix,
    InsufficientPow,
    StaleTip,
    InvalidBlock(String),
}

impl SubmitReject {
    pub fn reason(&self) -> String {
        match self {
            Self::UnknownTemplate => "unknown template_id".into(),
            Self::TemplateExpired => "template expired".into(),
            Self::WrongNoncePrefix => "nonce prefix does not match template".into(),
            Self::InsufficientPow => "nonce does not meet difficulty".into(),
            Self::StaleTip => "template parent is no longer tip".into(),
            Self::InvalidBlock(s) => format!("block validation failed: {}", s),
        }
    }
}

// ============================================================================
// Template cache
// ============================================================================

/// Server-side entry for a template that has been handed out. Carries the
/// opaque `material` the caller needs to reconstitute the block at submit
/// time (a `ShieldedBlock` in prod; a `Vec<u8>` in tests).
#[derive(Debug, Clone)]
pub struct TemplateEntry<Material: Clone> {
    pub template_id: [u8; 32],
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub difficulty: u64,
    pub min_v2_count: u16,
    pub nonce_prefix: [u8; NONCE_PREFIX_BYTES],
    pub coinbase_hash: [u8; 32],
    /// Block material needed to rebuild the full block from the winning nonce.
    pub material: Material,
    /// Unix seconds at which this template was created.
    pub created_at_secs: u64,
}

impl<Material: Clone> TemplateEntry<Material> {
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.created_at_secs) > TEMPLATE_TTL_SECS
    }
}

/// Cache of active templates, keyed by `template_id`. Not thread-safe by
/// itself — wrap in a `Mutex`/`RwLock` for concurrent access.
#[derive(Debug)]
pub struct MiningTemplateCache<Material: Clone> {
    entries: HashMap<[u8; 32], TemplateEntry<Material>>,
}

impl<Material: Clone> Default for MiningTemplateCache<Material> {
    fn default() -> Self {
        Self { entries: HashMap::new() }
    }
}

impl<Material: Clone> MiningTemplateCache<Material> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached templates.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert a new template and return the entry's `template_id`.
    pub fn insert(&mut self, entry: TemplateEntry<Material>) -> [u8; 32] {
        let id = entry.template_id;
        self.entries.insert(id, entry);
        id
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&TemplateEntry<Material>> {
        self.entries.get(id)
    }

    /// Drop entries that have lived past `TEMPLATE_TTL_SECS`, evaluated
    /// against `now_secs`. Returns the number of evictions.
    pub fn evict_expired(&mut self, now_secs: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired(now_secs));
        before - self.entries.len()
    }

    /// Drop every entry whose `parent_hash` differs from `current_tip`.
    /// Called on every new block accepted so miners stop working on stale
    /// tips (the server would reject the submit anyway, but pruning saves
    /// memory and gossip-induced retries).
    pub fn evict_stale_on_tip(&mut self, current_tip: &[u8; 32]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| &e.parent_hash == current_tip);
        before - self.entries.len()
    }
}

// ============================================================================
// Template ID derivation
// ============================================================================

/// Compute the `template_id` for a set of header fields. Uses Blake2s-256.
/// This is a commitment to the fixed part of the header (everything except
/// the nonce) — two templates that share all fixed fields MUST share id.
pub fn derive_template_id(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    commitment_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    timestamp: u64,
    difficulty: u64,
    min_v2_count: u16,
    coinbase_hash: &[u8; 32],
) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(&version.to_le_bytes());
    h.update(prev_hash);
    h.update(merkle_root);
    h.update(commitment_root);
    h.update(nullifier_root);
    h.update(&timestamp.to_le_bytes());
    h.update(&difficulty.to_le_bytes());
    h.update(&min_v2_count.to_le_bytes());
    h.update(coinbase_hash);
    h.finalize().into()
}

/// Current unix timestamp in seconds. Separated so tests can swap it.
pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ============================================================================
// Submit validation (pure)
// ============================================================================

/// Pure-function validation of a submit against its template. Returns either
/// the reconstructed `[u8; 64]` nonce (ready to fill into a BlockHeader) or a
/// typed rejection. Does NOT do the block-level validation (that's the caller's
/// job once the block is rebuilt).
pub fn validate_submit<Material: Clone>(
    req: &SubmitRequest,
    cache: &MiningTemplateCache<Material>,
    now: u64,
    current_tip: &[u8; 32],
) -> Result<([u8; NONCE_TOTAL_BYTES], TemplateEntry<Material>), SubmitReject> {
    // Parse nonce.
    let nonce = req.parsed_nonce().ok_or_else(|| {
        SubmitReject::InvalidBlock(format!("malformed nonce_hex ({} bytes)", req.nonce_hex.len() / 2))
    })?;

    // Look up template.
    let id_bytes = hex::decode(&req.template_id)
        .map_err(|_| SubmitReject::UnknownTemplate)?;
    if id_bytes.len() != 32 {
        return Err(SubmitReject::UnknownTemplate);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_bytes);

    let entry = cache.get(&id).ok_or(SubmitReject::UnknownTemplate)?;

    // Freshness checks.
    if entry.is_expired(now) {
        return Err(SubmitReject::TemplateExpired);
    }
    if &entry.parent_hash != current_tip {
        return Err(SubmitReject::StaleTip);
    }

    // Nonce prefix MUST match what the server allocated — this binds a
    // submission to its template, prevents silent mix-and-match.
    if &nonce[..NONCE_PREFIX_BYTES] != &entry.nonce_prefix[..] {
        return Err(SubmitReject::WrongNoncePrefix);
    }

    Ok((nonce, entry.clone()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hash32(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn sample_entry(id_byte: u8, parent_byte: u8, created_at: u64) -> TemplateEntry<Vec<u8>> {
        TemplateEntry {
            template_id: hash32(id_byte),
            height: 1000,
            parent_hash: hash32(parent_byte),
            difficulty: 10_000,
            min_v2_count: 3,
            nonce_prefix: [0x11; NONCE_PREFIX_BYTES],
            coinbase_hash: hash32(99),
            material: vec![1, 2, 3],
            created_at_secs: created_at,
        }
    }

    // ---- Template response / submit serde ----

    #[test]
    fn template_response_round_trip() {
        let t = TemplateResponse {
            template_id: "abcd".into(),
            height: 100,
            version: 3,
            prev_hash: "00".into(),
            merkle_root: "11".into(),
            commitment_root: "22".into(),
            nullifier_root: "33".into(),
            state_root: "44".into(),
            timestamp: 1_700_000_000,
            difficulty: 12345,
            min_v2_count: 3,
            coinbase_hash: "cc".into(),
            nonce_prefix_hex: "ff".repeat(NONCE_PREFIX_BYTES),
            produced_at_ms: 1_700_000_000_000,
        };
        let s = serde_json::to_string(&t).unwrap();
        let back: TemplateResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn submit_request_parses_nonce() {
        let req = SubmitRequest {
            template_id: hex::encode([0u8; 32]),
            nonce_hex: hex::encode([0xAB; NONCE_TOTAL_BYTES]),
        };
        let nonce = req.parsed_nonce().unwrap();
        assert_eq!(nonce, [0xAB; NONCE_TOTAL_BYTES]);
    }

    #[test]
    fn submit_request_rejects_short_nonce() {
        let req = SubmitRequest {
            template_id: hex::encode([0u8; 32]),
            nonce_hex: hex::encode([0u8; NONCE_TOTAL_BYTES - 1]),
        };
        assert!(req.parsed_nonce().is_none());
    }

    #[test]
    fn submit_request_rejects_malformed_hex() {
        let req = SubmitRequest {
            template_id: "not-hex".into(),
            nonce_hex: "zz".repeat(64),
        };
        assert!(req.parsed_nonce().is_none());
    }

    #[test]
    fn submit_response_ok_and_reject() {
        let ok = SubmitResponse::ok([7u8; 32], 42);
        assert!(ok.accepted);
        assert_eq!(ok.height, Some(42));
        assert!(ok.reason.is_none());

        let bad = SubmitResponse::reject("nope");
        assert!(!bad.accepted);
        assert!(bad.hash.is_none());
        assert_eq!(bad.reason.as_deref(), Some("nope"));
    }

    // ---- Template ID derivation ----

    #[test]
    fn template_id_is_deterministic() {
        let a = derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(9));
        let b = derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(9));
        assert_eq!(a, b);
    }

    #[test]
    fn template_id_flips_on_any_field_change() {
        let base = derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(9));

        // Flip each field individually; every one must alter the hash.
        assert_ne!(base, derive_template_id(4, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(9), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(9), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(2), &hash32(9), &hash32(4), 1000, 500, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(9), 1000, 500, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1001, 500, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 501, 3, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 4, &hash32(9)));
        assert_ne!(base, derive_template_id(3, &hash32(1), &hash32(2), &hash32(3), &hash32(4), 1000, 500, 3, &hash32(8)));
    }

    // ---- Cache ----

    #[test]
    fn cache_insert_get() {
        let mut cache = MiningTemplateCache::new();
        assert!(cache.is_empty());
        let entry = sample_entry(1, 2, 1000);
        let id = cache.insert(entry.clone());
        assert_eq!(cache.len(), 1);
        let got = cache.get(&id).unwrap();
        assert_eq!(got.height, entry.height);
        assert_eq!(got.difficulty, entry.difficulty);
    }

    #[test]
    fn cache_get_missing_returns_none() {
        let cache: MiningTemplateCache<Vec<u8>> = MiningTemplateCache::new();
        assert!(cache.get(&[0u8; 32]).is_none());
    }

    #[test]
    fn cache_evict_expired_drops_only_expired() {
        let mut cache = MiningTemplateCache::new();
        cache.insert(sample_entry(1, 0, 1000));              // fresh
        cache.insert(sample_entry(2, 0, 1000 - TEMPLATE_TTL_SECS - 10)); // stale
        let evicted = cache.evict_expired(1000);
        assert_eq!(evicted, 1);
        assert!(cache.get(&hash32(1)).is_some());
        assert!(cache.get(&hash32(2)).is_none());
    }

    #[test]
    fn cache_evict_stale_on_tip_prunes_wrong_parent() {
        let mut cache = MiningTemplateCache::new();
        cache.insert(sample_entry(1, 7, now_secs())); // parent_hash = [7; 32]
        cache.insert(sample_entry(2, 8, now_secs())); // parent_hash = [8; 32]
        let evicted = cache.evict_stale_on_tip(&hash32(7));
        assert_eq!(evicted, 1);
        assert!(cache.get(&hash32(1)).is_some());
        assert!(cache.get(&hash32(2)).is_none());
    }

    // ---- Submit validation ----

    #[test]
    fn validate_submit_happy_path() {
        let mut cache = MiningTemplateCache::new();
        let tip = hash32(7);
        let entry = TemplateEntry {
            parent_hash: tip,
            ..sample_entry(11, 7, 1000)
        };
        cache.insert(entry.clone());

        let mut nonce = [0u8; NONCE_TOTAL_BYTES];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&entry.nonce_prefix);
        nonce[NONCE_PREFIX_BYTES..].copy_from_slice(&[0xAA; NONCE_COUNTER_BYTES]);

        let req = SubmitRequest {
            template_id: hex::encode(entry.template_id),
            nonce_hex: hex::encode(nonce),
        };

        let (parsed, e) = validate_submit(&req, &cache, 1000, &tip).unwrap();
        assert_eq!(parsed, nonce);
        assert_eq!(e.height, entry.height);
    }

    #[test]
    fn validate_submit_unknown_template() {
        let cache: MiningTemplateCache<Vec<u8>> = MiningTemplateCache::new();
        let req = SubmitRequest {
            template_id: hex::encode([0u8; 32]),
            nonce_hex: hex::encode([0u8; NONCE_TOTAL_BYTES]),
        };
        let err = validate_submit(&req, &cache, 1000, &hash32(0)).unwrap_err();
        assert_eq!(err, SubmitReject::UnknownTemplate);
    }

    #[test]
    fn validate_submit_expired_template() {
        let mut cache = MiningTemplateCache::new();
        let entry = sample_entry(1, 0, 100); // stale
        cache.insert(entry.clone());
        let mut nonce = [0u8; NONCE_TOTAL_BYTES];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&entry.nonce_prefix);
        let req = SubmitRequest {
            template_id: hex::encode(entry.template_id),
            nonce_hex: hex::encode(nonce),
        };
        let err = validate_submit(&req, &cache, 100 + TEMPLATE_TTL_SECS + 1, &entry.parent_hash).unwrap_err();
        assert_eq!(err, SubmitReject::TemplateExpired);
    }

    #[test]
    fn validate_submit_stale_tip() {
        let mut cache = MiningTemplateCache::new();
        let entry = sample_entry(1, 7, 1000);
        cache.insert(entry.clone());
        let mut nonce = [0u8; NONCE_TOTAL_BYTES];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&entry.nonce_prefix);
        let req = SubmitRequest {
            template_id: hex::encode(entry.template_id),
            nonce_hex: hex::encode(nonce),
        };
        let err = validate_submit(&req, &cache, 1000, &hash32(99)).unwrap_err();
        assert_eq!(err, SubmitReject::StaleTip);
    }

    #[test]
    fn validate_submit_wrong_prefix() {
        let mut cache = MiningTemplateCache::new();
        let entry = sample_entry(1, 7, 1000);
        cache.insert(entry.clone());

        // Wrong prefix bytes.
        let mut nonce = [0u8; NONCE_TOTAL_BYTES];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&[0x22; NONCE_PREFIX_BYTES]);
        let req = SubmitRequest {
            template_id: hex::encode(entry.template_id),
            nonce_hex: hex::encode(nonce),
        };
        let err = validate_submit(&req, &cache, 1000, &entry.parent_hash).unwrap_err();
        assert_eq!(err, SubmitReject::WrongNoncePrefix);
    }

    #[test]
    fn submit_reject_reason_strings() {
        assert_eq!(SubmitReject::UnknownTemplate.reason(), "unknown template_id");
        assert_eq!(SubmitReject::TemplateExpired.reason(), "template expired");
        assert_eq!(SubmitReject::WrongNoncePrefix.reason(),
            "nonce prefix does not match template");
        assert_eq!(SubmitReject::InsufficientPow.reason(),
            "nonce does not meet difficulty");
        assert_eq!(SubmitReject::StaleTip.reason(), "template parent is no longer tip");
        assert_eq!(
            SubmitReject::InvalidBlock("bad merkle".into()).reason(),
            "block validation failed: bad merkle"
        );
    }
}
