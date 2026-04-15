# Manual Audit Guide - Rust Crypto Code

## Audit commands

### 1. Static analysis

### 2. Timing tests (requires valgrind/perf)

### 3. Continuous fuzzing

## Dangerous patterns to detect

### DANGER: Comparison directe

### DANGER: Branch on secret

### DANGER: Manual nonce

## Dependency verification

## PR Review - Questions to Ask
1. Does this function take external data? → Fuzz target added?
2. Is there a new secret comparison? → CT test added?
3. New crypto primitive? → Property tests added?
4. Keys in memory? → Zeroize implemented?