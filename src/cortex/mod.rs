//! TSN Cortex — service-layer node type for dApp modules.
//!
//! Phase 1 (this release, v2.5.0): the node follows the chain like a relay, exposes a local
//! WASM runtime, and can load signed modules from disk. No on-chain registry yet, no job
//! scheduling, no rewards. The plumbing is here so dApp developers and operators can start
//! exercising the runtime ahead of the consensus-level integration in later phases.
//!
//! Phase 2 (future hard fork): on-chain `CortexRegister` / `CortexHeartbeat` / `CortexModulePublish`
//! tx types + state-bound registry + module publication via signed tx. Nodes auto-download
//! the bytecode when a new module appears on-chain.
//!
//! Phase 3 (future hard fork): job scheduling, results verification, slashing, rewards distributed
//! from the relay pool residue + dApp fees.

pub mod wasm_runtime;

/// Capabilities a Cortex node advertises to the explorer / future registry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CortexCapabilities {
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub disk_gb: u32,
    /// WASM module names this node has loaded and can serve.
    pub loaded_modules: Vec<String>,
}

impl CortexCapabilities {
    /// Auto-detect CPU/RAM/disk from the host system. Disk is best-effort (data_dir partition).
    pub fn auto_detect(data_dir: &std::path::Path) -> Self {
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);
        let ram_gb = Self::detect_ram_gb();
        let disk_gb = Self::detect_disk_gb(data_dir);
        Self {
            cpu_cores,
            ram_gb,
            disk_gb,
            loaded_modules: Vec::new(),
        }
    }

    fn detect_ram_gb() -> u32 {
        // /proc/meminfo MemTotal, Linux only; 0 if unreadable.
        let meminfo = match std::fs::read_to_string("/proc/meminfo") {
            Ok(s) => s,
            Err(_) => return 0,
        };
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: u64 = rest.split_whitespace().next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return (kb / 1024 / 1024) as u32;
            }
        }
        0
    }

    fn detect_disk_gb(path: &std::path::Path) -> u32 {
        // statvfs via nix-less shim: shell out to `df`. Lightweight enough for startup.
        let output = std::process::Command::new("df")
            .arg("-BG")
            .arg("--output=avail")
            .arg(path)
            .output();
        let text = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return 0,
        };
        text.lines()
            .nth(1)
            .and_then(|l| l.trim().trim_end_matches('G').parse().ok())
            .unwrap_or(0)
    }
}
