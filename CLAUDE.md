# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mozambigue** is a pure Rust library for JWT validation with JWKS caching, extracted from the `atlas-identity-proxy` repository. It is specifically designed for Kubernetes service account token validation but works with any OpenID Connect JWT provider.

**Design Philosophy:**
- Pure library with no HTTP framework dependencies (Axum, Actix, etc.)
- HTTP error mapping should be done by consuming applications
- Kubernetes-specific subject extraction (service account + namespace)
- Thread-safe JWKS caching to minimize network overhead

## Build and Test Commands

**Before committing changes, ALWAYS run these commands:**

```bash
# Format code
cargo fmt

# Run clippy on all targets and features
cargo clippy --all-targets --all-features

# Run tests
cargo test

# Build the library
cargo build
```

Additional commands:

```bash
# Build with release optimizations
cargo build --release

# Run library tests only
cargo test --lib

# Generate and view documentation
cargo doc --no-deps --open

# Run the example
cargo run --example basic_usage

# Check for compilation errors without building
cargo check
```

## Architecture

### Core Components

The library consists of five main modules:

1. **verifier.rs** - Main entry point
   - `JwtVerifier`: The primary struct that orchestrates JWT validation
   - `VerifyJwt` trait: Async trait defining the verification interface
   - Two-phase validation: First parses token unsafely to extract issuer, then performs full signature verification

2. **jwks_cache.rs** - JWKS caching layer
   - `JwksCache`: Thread-safe cache using `Arc<RwLock<HashMap>>`
   - Fetches JWKS from `{issuer}/.well-known/openid-configuration`
   - Configurable TTL (default: 1 hour)
   - Cache key: issuer URL
   - Automatic expiration checking on read

3. **claims.rs** - JWT claims parsing
   - `Claims`: Internal struct for JWT claims with Kubernetes-specific fields
   - `Subject`: Public struct containing `service_account` and `namespace`
   - Extraction logic: Tries `kubernetes.io` claim first, falls back to parsing `sub` field as `system:serviceaccount:<namespace>:<service_account>`

4. **config.rs** - Configuration
   - `JwtVerifierConfig`: Builder-pattern configuration
   - Allows custom HTTP client and cache TTL

5. **error.rs** - Error types
   - Pure error types with no HTTP framework dependencies
   - Comprehensive validation error variants

### Verification Flow

```
Token → parse_token_data() → get_jwks() → validate_jwt() → get_subject_from_claims() → Subject
         (unsafe decode)      (with cache)  (full verify)   (K8s extraction)
```

1. **Parse without validation** (`verifier.rs:45-50`): Uses `dangerous::insecure_decode()` to extract issuer and audiences from claims
2. **Fetch JWKS** (`jwks_cache.rs:53-74`): Gets JWKS from cache or network, using issuer from step 1
3. **Full validation** (`verifier.rs:53-68`): Verifies signature, issuer, expiration, and audience
4. **Subject extraction** (`claims.rs:67-77`): Extracts Kubernetes service account and namespace from validated claims

### Key Design Decisions

**Why two-phase parsing?**
- Need to extract issuer before knowing which JWKS to fetch
- Safe because full validation happens before returning any data to caller

**Why RwLock instead of Mutex?**
- Multiple concurrent reads are common (verifying many tokens)
- Writes are rare (only on cache miss/expiration)
- RwLock optimizes for the read-heavy workload

**Why clone JwkSet from cache?**
- Allows releasing the read lock immediately
- JwkSet is relatively small and cheap to clone
- Prevents holding locks during expensive crypto operations

## Code Style

### Encapsulation

**Always make struct fields private** (or `pub(crate)` at most) to enforce invariants:

```rust
// BAD - public fields allow bypassing validation
pub struct JwtVerifierConfig {
    pub expected_issuer: String,
    pub expected_audiences: Vec<String>,  // User could set this to empty!
}

// GOOD - private fields with public constructors
pub struct JwtVerifierConfig {
    pub(crate) expected_issuer: String,
    pub(crate) expected_audiences: Vec<String>,
}

impl JwtVerifierConfig {
    // Force users to go through safe constructors
    pub fn new(issuer: String, audience: String) -> Self { /* ... */ }

    // Note: No getters needed - config is consumed immediately by JwtVerifier::new()
}
```

**Why:** Private fields prevent users from bypassing validation logic and creating invalid states. Users MUST use constructors which enforce all invariants.

### Error Handling

**NEVER panic in library code!** Always return proper errors:

- ❌ `panic!("error message")` - Never use in library code
- ❌ `.unwrap()` - Never use in library code (except in tests)
- ❌ `.expect()` - Never use in library code (except in tests)
- ✅ `return Err(Error::SomeVariant)` - Always return errors

Library users need to be able to handle errors gracefully. Panics cannot be caught and will crash the application. This is especially critical in production environments.

**Example:**
```rust
// BAD - panics!
pub fn new_with_audiences(audiences: Vec<String>) -> Self {
    if audiences.is_empty() {
        panic!("At least one audience must be provided");
    }
    // ...
}

// GOOD - returns error
pub fn new_with_audiences(audiences: Vec<String>) -> Result<Self> {
    if audiences.is_empty() {
        return Err(Error::NoAudiencesConfigured);
    }
    Ok(Self { /* ... */ })
}
```

### Import Organization

Imports must be unmerged and organized in the following order:

1. Standard library imports (`std::`)
2. Blank line
3. External crate imports (alphabetically)
4. Blank line
5. Internal crate imports (`crate::`)

Example:
```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::{Error, Result};
use crate::jwks_cache::JwksCache;
```

Do not merge imports like `use std::{collections::HashMap, sync::Arc}`. Each import should be on its own line.

## Public API

The library exports only these types:
- `JwtVerifier` - Main verifier struct
- `VerifyJwt` - Trait for verification
- `JwtVerifierConfig` - Configuration builder
- `Subject` - Result type with service_account and namespace
- `Error` - All error variants
- `Result<T>` - Type alias for `Result<T, Error>`

## Security: Audience Validation

**IMPORTANT:** The library validates token audiences against **configured expected audiences**, not the token's own audience claim.

**Why this matters:**
- Without proper audience validation, any valid token from the correct issuer could be used, regardless of which service it was intended for
- This prevents token reuse across services (a token meant for Service A cannot be used for Service B)

**Defense in Depth:**
1. **Compile-time:** `JwtVerifierConfig::new()` requires at least one audience parameter
2. **Runtime:** `get_decoding_key_and_validation()` returns `Error::NoAudiencesConfigured` if audiences is empty

**Configuration:**
```rust
// Single audience with default cache (1 hour)
let config = JwtVerifierConfig::new("https://issuer.example.com", "my-service");

// Single audience with custom cache TTL
let config = JwtVerifierConfig::new("https://issuer.example.com", "my-service")
    .with_cache_ttl(Duration::from_secs(1800)); // 30 minutes

// Multiple audiences with custom cache
let config = JwtVerifierConfig::new_with_audiences(
    "https://issuer.example.com",
    vec!["service-a".to_string(), "service-b".to_string()]
)?
.with_cache_ttl(Duration::from_secs(3600)); // 1 hour

// Convenience method
let verifier = JwtVerifier::with_issuer("https://issuer.example.com", "my-service").await?;

// Add additional audiences incrementally
let config = JwtVerifierConfig::new("https://issuer", "primary")
    .with_audience("secondary")
    .with_cache_ttl(Duration::from_secs(1800));
```

**Breaking Change from Original:** The TODO in `atlas-identity-proxy` has been resolved. The original validated against the token's own audiences (circular validation). This library now properly validates against configured expected audiences.

## Integration Notes

When integrating this library into applications (like `atlas-identity-proxy`):

1. Add as dependency: `mozambique = { path = "../mozambique" }`
2. Wrap errors in application-specific error types with HTTP response mappings
3. Create thin adapter implementing `From<mozambique::Error>` for your error type
4. Use `VerifyJwt` trait for testing/mocking

Example error mapping:
```rust
impl From<mozambique::Error> for YourHttpError {
    fn from(e: mozambique::Error) -> Self {
        match e {
            mozambique::Error::TokenExpired(_) => YourHttpError::Unauthorized(...),
            mozambique::Error::WrongIssuer(_) => YourHttpError::BadRequest(...),
            // ... map other variants
        }
    }
}
```

## Future Extensibility

The library is currently Kubernetes-specific. To support other JWT formats in the future, consider implementing a trait-based subject extraction pattern without breaking existing users.
