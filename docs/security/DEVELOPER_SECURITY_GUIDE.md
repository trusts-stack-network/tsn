# TSN Developer Security Guide

## Rules Criticals

### 1. Interdiction of the `unwrap()` and `expect()` in the code network/consensus

**❌ INTERDIT:**
```rust
// Dans handlers network, consensus, or validation
let value = result.unwrap();
let value = result.expect("should never fail");
```

**✅ OBLIGATOIRE:**
```rust
// Utiliser ? pour propager les errors
let value = result?;

// Ou manage explicitement
match result {
    Ok(v) => v,
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(e.into());
    }
}
```

### 2. Verification of the bornes systematic

**❌ INTERDIT:**
```rust
let first = vec[0]; // Panic si vide
let slice = &data[start..end]; // Panic si out of bounds
```

**✅ OBLIGATOIRE:**
```rust
let first = vec.first()?; // Option
let first = vec.get(0).ok_or(Error::Empty)?; // Result

// Verify les bornes
if end > data.len() {
    return Err(Error::OutOfBounds);
}
let slice = &data[start..end];
```

### 3. Arithmetic verifiede

**❌ INTERDIT:**
```rust
let sum = a + b; // Peut overflow
let product = a * b;
```

**✅ OBLIGATOIRE:**
```rust
let sum = a.checked_add(b).ok_or(Error::Overflow)?;
let product = a.checked_mul(b).ok_or(Error::Overflow)?;
```

### 4. Parsing secure

**❌ INTERDIT:**
```rust
let num: u64 = s.parse().unwrap();
```

**✅ OBLIGATOIRE:**
```rust
let num: u64 = s.parse().map_err(|e| Error::ParseError(e))?;
```

## Checklist of Review

Before each commit in the modules criticals:

- [ ] None `unwrap()`/`expect()` non justified
- [ ] Every indexations utilisent `get()` or are verifieds
- [ ] Arithmetic with `checked_*` in les hot paths
- [ ] Parsing with gestion d'errors explicite
- [ ] Tests de resilience added

## Modules Criticals

The modules followings requiresnt une attention particular:

1. **src/crypto/** - Toute panic = compromiseddeddsion possible
2. **src/consensus/** - Panic = fork potential
3. **src/network/** - Panic = DoS vector
4. **src/core/validation.rs** - Panic = blockk invalid accepted

## Outils de Verification

```bash
# Audit of the unwraps/expects
grep -rn "\.unwrap()" src/crypto src/consensus src/network
grep -rn "\.expect(" src/crypto src/consensus src/network

# Verification with clippy
cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used

# Tests de resilience
cargo test --test panic_regression_test
cargo test --test error_handling_integration
```

## Example de Code Secure

```rust
/// Valide a transaction without never paniquer
pub fn validate_transaction(tx: &Transaction) -> Result<ValidationResult, ValidationError> {
    // Verify la size
    if tx.encoded_len() > MAX_TX_SIZE {
        return Err(ValidationError::Oversized);
    }
    
    // Verify les inputs
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs);
    }
    
    // Verify les montants with arithmetic securee
    let total_input = tx.inputs
        .iter()
        .try_fold(0u64, |acc, input| {
            acc.checked_add(input.amount)
                .ok_or(ValidationError::AmountOverflow)
        })?;
    
    // Verify the signatures
    for (i, input) in tx.inputs.iter().enumerate() {
        let sig = tx.signatures.get(i)
            .ok_or(ValidationError::MissingSignature(i))?;
        
        if !verify_signature(sig, &input.pubkey, &tx.hash)? {
            return Err(ValidationError::InvalidSignature(i));
        }
    }
    
    Ok(ValidationResult::Valid)
}
```

## Contact

Security questions: security@tsn.network
