# Benchmarks TSN — SLH-DSA vs ML-DSA

Ce directory contains les benchmarks comparatifs de performance pour les deux signatures post-quantiques de TSN :

- **SLH-DSA** (SPHINCS+) — FIPS 205, signature de reference
- **ML-DSA-65** — FIPS 204, kept for legacy compatibility

## Metrics measureds

| Benchmark | Metrics |
|-----------|-----------|
| `throughput_bench.rs` | Throughput (tx/s), latence moyenne |
| `latency_bench.rs` | p50, p95, p99 (percentiles) |
| `memory_bench.rs` | Utilisation memory (heap) |
| `parallel_bench.rs` | Parallel acceleration (batch verification) |
| `workload_bench.rs` | Charge real (1000–10000 tx/bloc) |

## Usage

```bash
# Lancer tous les benchmarks
cargo bench

# Lancer un benchmark specific
cargo bench --bench throughput_bench

# Generate un rapport HTML (avec criterion)
cargo bench -- --output-file bench_report.json
```

## Rapport de performance attendu

| Operation | SLH-DSA (µs) | ML-DSA-65 (µs) | Ratio SLH/ML |
|-----------|--------------|----------------|--------------|
| Sign (p50) | ~1500 | ~500 | 3.0x |
| Verify (p50) | ~800 | ~200 | 4.0x |
| Keygen (p50) | ~2000 | ~600 | 3.3x |
| Memory (sign) | ~8 KB | ~2 KB | 4.0x |

## Recommandations

- **Production** : SLH-DSA (security proven, NIST standard)
- **Legacy** : ML-DSA-65 (compatibility avec v1)
- **Optimisation** : Usesr batch verification pour les hauts throughputs

## CI Integration

Les benchmarks sont integrateds to la CI GitHub Actions :

```yaml
- name: Run benchmarks
  run: cargo bench -- --output-file bench_results.json
- name: Check performance regressions
  run: cargo run --bin bench_diff -- bench_results.json
```

## Scripts associateds

- `scripts/bench_report.sh` — Generates un rapport HTML to partir des results
- `scripts/bench_compare.sh` — Compare deux jeux de benchmarks
