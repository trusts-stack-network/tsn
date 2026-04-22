//! WASM sandbox for Cortex service modules.
//!
//! Phase 1 design goals:
//!   * Deterministic execution (no threads, no wall-clock side-effects, no filesystem)
//!   * Fuel metering so a misbehaving module can't DoS the node
//!   * Signed bytecode (ML-DSA-65) verified before load
//!   * Single entry point per module: `extern "C" fn run(input_ptr: i32, input_len: i32) -> i64`
//!     where the return value packs (output_ptr << 32) | output_len into 64 bits
//!
//! This file keeps the surface small on purpose. Registry wiring, module distribution,
//! and job scheduling come in later phases.

use std::sync::{Arc, RwLock};
use wasmtime::{Engine, Module, Store, Linker, Config};

/// Default fuel budget per job execution. One fuel unit corresponds to roughly one
/// WASM bytecode operation, so 100M covers O(1-10) second jobs on commodity CPU.
/// Operators can override per-module via `ModuleRecord::fuel_budget`.
pub const DEFAULT_FUEL_BUDGET: u64 = 100_000_000;

/// Maximum module bytecode size accepted on load (2 MB). Well above any realistic
/// service module and well below anything that would take minutes to verify.
pub const MAX_MODULE_BYTES: usize = 2 * 1024 * 1024;

#[derive(thiserror::Error, Debug)]
pub enum CortexError {
    #[error("wasmtime init: {0}")]
    WasmInit(String),
    #[error("module load: {0}")]
    ModuleLoad(String),
    #[error("module too large: {0} bytes (max {})", MAX_MODULE_BYTES)]
    ModuleTooLarge(usize),
    #[error("invalid module signature")]
    InvalidSignature,
    #[error("module name not registered: {0}")]
    UnknownModule(String),
    #[error("execution: {0}")]
    ExecutionFailed(String),
    #[error("out of fuel after {0} units")]
    OutOfFuel(u64),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A module loaded in memory, ready to be invoked.
struct LoadedModule {
    module: Module,
    fuel_budget: u64,
}

/// The per-node WASM runtime. Owns a shared wasmtime Engine (thread-safe JIT cache) and
/// a map of loaded modules. Cheap to clone via Arc — hand one clone to the CLI, another
/// to the HTTP API, etc.
#[derive(Clone)]
pub struct CortexRuntime {
    engine: Arc<Engine>,
    modules: Arc<RwLock<std::collections::HashMap<String, LoadedModule>>>,
}

impl CortexRuntime {
    /// Build a runtime with deterministic, fuel-metered configuration.
    pub fn new() -> Result<Self, CortexError> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        // Deterministic: disable anything non-deterministic that wasmtime exposes.
        // wasmtime 24 turns SIMD/multi-memory/relaxed-simd off by default for Config::new().
        // We flip bulk_memory on (Rust→WASM builds need it) and canonicalize NaN so
        // two Cortex nodes executing the same float-heavy module agree on the result.
        cfg.wasm_multi_memory(false);
        cfg.wasm_relaxed_simd(false);
        cfg.wasm_bulk_memory(true);
        cfg.cranelift_nan_canonicalization(true);
        let engine = Engine::new(&cfg).map_err(|e| CortexError::WasmInit(e.to_string()))?;
        Ok(Self {
            engine: Arc::new(engine),
            modules: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Load a module from bytecode. Signature check is caller's responsibility (see
    /// `load_signed_module` for the wrapped version). `name` is how the CLI / API will
    /// address it when running a job.
    pub fn load_raw_module(
        &self,
        name: &str,
        wasm_bytes: &[u8],
        fuel_budget: u64,
    ) -> Result<(), CortexError> {
        if wasm_bytes.len() > MAX_MODULE_BYTES {
            return Err(CortexError::ModuleTooLarge(wasm_bytes.len()));
        }
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| CortexError::ModuleLoad(e.to_string()))?;
        let mut store = self.modules.write().unwrap_or_else(|e| e.into_inner());
        store.insert(name.to_string(), LoadedModule { module, fuel_budget });
        Ok(())
    }

    /// Load a module whose bytecode was signed by a trusted TSN dev-team public key.
    ///
    /// The on-chain registry layer (Phase 2) will supply the expected signer via
    /// consensus. For Phase 1 we hand over a pinned ML-DSA-65 public key — typically
    /// baked into the binary or distributed via the same mechanism as the release
    /// manifest (`latest.json`). That stays honest for Phase 1 because every Cortex
    /// operator has to install `tsn` from a known build.
    pub fn load_signed_module(
        &self,
        name: &str,
        wasm_bytes: &[u8],
        signature: &[u8],
        signer_pk: &[u8],
        fuel_budget: u64,
    ) -> Result<(), CortexError> {
        use fips204::ml_dsa_65;
        use fips204::traits::{SerDes, Verifier};
        const PK_LEN: usize = ml_dsa_65::PK_LEN;
        const SIG_LEN: usize = ml_dsa_65::SIG_LEN;
        let pk_arr: [u8; PK_LEN] = signer_pk
            .try_into()
            .map_err(|_| CortexError::InvalidSignature)?;
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
            .map_err(|_| CortexError::InvalidSignature)?;
        let sig_arr: [u8; SIG_LEN] = signature
            .try_into()
            .map_err(|_| CortexError::InvalidSignature)?;
        let ok = pk.verify(wasm_bytes, &sig_arr, &[]);
        if !ok {
            return Err(CortexError::InvalidSignature);
        }
        self.load_raw_module(name, wasm_bytes, fuel_budget)
    }

    /// Number of currently loaded modules (for /cortex/info).
    pub fn loaded_names(&self) -> Vec<String> {
        let store = self.modules.read().unwrap_or_else(|e| e.into_inner());
        store.keys().cloned().collect()
    }

    /// Remove a loaded module by name. No-op if the name isn't known.
    pub fn unload(&self, name: &str) {
        let mut store = self.modules.write().unwrap_or_else(|e| e.into_inner());
        store.remove(name);
    }

    /// Execute a loaded module with the given input bytes and return the output bytes.
    /// Module contract: exports `run(input_ptr: i32, input_len: i32) -> i64` where the
    /// return value is `(output_ptr << 32) | output_len`.
    pub fn execute(&self, name: &str, input: &[u8]) -> Result<Vec<u8>, CortexError> {
        let store_guard = self.modules.read().unwrap_or_else(|e| e.into_inner());
        let loaded = store_guard
            .get(name)
            .ok_or_else(|| CortexError::UnknownModule(name.to_string()))?;
        let module = loaded.module.clone();
        let fuel_budget = loaded.fuel_budget;
        drop(store_guard);

        let mut store = Store::new(&self.engine, ());
        store.set_fuel(fuel_budget).map_err(|e| CortexError::WasmInit(e.to_string()))?;
        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| CortexError::ExecutionFailed(format!("instantiate: {}", e)))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| CortexError::ExecutionFailed("module has no exported memory".into()))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| CortexError::ExecutionFailed(format!("missing alloc(): {}", e)))?;
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "run")
            .map_err(|e| CortexError::ExecutionFailed(format!("missing run(): {}", e)))?;

        // Copy the input into the module's memory
        let input_len = input.len() as i32;
        let input_ptr = alloc
            .call(&mut store, input_len)
            .map_err(|e| CortexError::ExecutionFailed(format!("alloc: {}", e)))?;
        memory
            .data_mut(&mut store)
            .get_mut(input_ptr as usize..(input_ptr as usize + input.len()))
            .ok_or_else(|| CortexError::ExecutionFailed("alloc returned out-of-bounds pointer".into()))?
            .copy_from_slice(input);

        let packed = run
            .call(&mut store, (input_ptr, input_len))
            .map_err(|e| {
                // Out-of-fuel surfaces as an Err from run() in wasmtime
                let fuel_used = fuel_budget.saturating_sub(store.get_fuel().unwrap_or(0));
                let msg = format!("{}", e);
                if msg.contains("fuel") {
                    CortexError::OutOfFuel(fuel_used)
                } else {
                    CortexError::ExecutionFailed(msg)
                }
            })?;

        // Unpack (ptr << 32) | len
        let output_ptr = ((packed as u64) >> 32) as i32;
        let output_len = ((packed as u64) & 0xFFFF_FFFF) as i32;
        if output_len < 0 {
            return Err(CortexError::ExecutionFailed(format!(
                "run() returned negative length: {}", output_len
            )));
        }
        let start = output_ptr as usize;
        let end = start + output_len as usize;
        let data = memory
            .data(&store)
            .get(start..end)
            .ok_or_else(|| CortexError::ExecutionFailed(
                "run() returned out-of-bounds pointer".into()
            ))?;
        Ok(data.to_vec())
    }
}

impl Default for CortexRuntime {
    fn default() -> Self {
        Self::new().expect("CortexRuntime default-init failed — wasmtime Config invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal WAT source that exports `alloc` (bump allocator) + `run` (echoes input).
    /// Mirrors the contract every TSN Cortex module follows.
    const ECHO_WAT: &str = r#"
(module
    (memory (export "memory") 1)
    (global $heap_next (mut i32) (i32.const 1024))
    (func (export "alloc") (param $size i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $heap_next))
        (global.set $heap_next (i32.add (local.get $ptr) (local.get $size)))
        (local.get $ptr))
    (func (export "run") (param $in_ptr i32) (param $in_len i32) (result i64)
        ;; Echo: return the input pointer/length unchanged as (ptr<<32)|len
        (i64.or
            (i64.shl (i64.extend_i32_u (local.get $in_ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $in_len))))
)
    "#;

    fn compile_wat(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("WAT parse")
    }

    #[test]
    fn runtime_roundtrip_echo_module() {
        let rt = CortexRuntime::new().expect("runtime");
        let wasm = compile_wat(ECHO_WAT);
        rt.load_raw_module("echo", &wasm, DEFAULT_FUEL_BUDGET).expect("load");
        let out = rt.execute("echo", b"hello tsn").expect("exec");
        assert_eq!(out, b"hello tsn");
    }

    #[test]
    fn runtime_rejects_oversized_module() {
        let rt = CortexRuntime::new().expect("runtime");
        let huge = vec![0u8; MAX_MODULE_BYTES + 1];
        let err = rt.load_raw_module("too_big", &huge, DEFAULT_FUEL_BUDGET).unwrap_err();
        assert!(matches!(err, CortexError::ModuleTooLarge(_)));
    }

    #[test]
    fn runtime_reports_loaded_names() {
        let rt = CortexRuntime::new().expect("runtime");
        let wasm = compile_wat(ECHO_WAT);
        rt.load_raw_module("a", &wasm, DEFAULT_FUEL_BUDGET).expect("a");
        rt.load_raw_module("b", &wasm, DEFAULT_FUEL_BUDGET).expect("b");
        let mut names = rt.loaded_names();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
}
