# Mozambigue

A Rust library for JWT (JSON Web Token) validation with JWKS (JSON Web Key Set) caching support.

**This library is designed for validating Kubernetes service account tokens.** While it uses standard OpenID Connect mechanisms (JWKS, JWT validation), the subject extraction is currently hardcoded for Kubernetes-specific claims.

## Features

- ✅ JWT signature verification using RSA and Octet keys
- ✅ Automatic JWKS fetching from OpenID configuration endpoints (standard OIDC)
- ✅ Configurable JWKS caching with TTL
- ✅ Issuer and expiration validation
- ✅ **Secure audience validation** - validates against configured expected audiences, not the token's own claims
- ✅ **Kubernetes-specific claims extraction** (service account and namespace from `kubernetes.io` claim)

**Note:** This library currently only supports Kubernetes service account tokens. Generic OpenID Connect token support is not yet implemented.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
mozambigue = "0.1.0"
```

## Usage

### Basic Usage

```rust
use mozambigue::{JwtVerifier, VerifyJwt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a verifier - requires issuer and at least one audience
    let verifier = JwtVerifier::with_issuer(
        "https://kubernetes.default.svc.cluster.local",
        "my-service"  // Expected audience
    ).await?;

    // Verify a token
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
    let subject = verifier.verify(token).await?;

    println!("Service Account: {}", subject.service_account);
    println!("Namespace: {}", subject.namespace);

    Ok(())
}
```

### Custom Configuration

```rust
use mozambique::{JwtVerifier, JwtVerifierConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a verifier with custom cache TTL
    let config = JwtVerifierConfig::new(
        "https://your-issuer.example.com",
        "my-service"  // Expected audience (required)
    )
    .with_cache_ttl(Duration::from_secs(1800)); // 30 minutes cache

    let verifier = JwtVerifier::new(config).await?;

    let token = "your-jwt-token";
    let subject = verifier.verify(token).await?;

    println!("Service Account: {}", subject.service_account);
    println!("Namespace: {}", subject.namespace);

    Ok(())
}
```

### Multiple Audiences

```rust
use mozambigue::{JwtVerifier, JwtVerifierConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Accept tokens for multiple services
    let config = JwtVerifierConfig::new_with_audiences(
        "https://your-issuer.example.com",
        vec!["service-a".to_string(), "service-b".to_string()]
    )?
    .with_cache_ttl(Duration::from_secs(3600));

    let verifier = JwtVerifier::new(config).await?;

    let token = "your-jwt-token";
    let subject = verifier.verify(token).await?;

    Ok(())
}
```

### With Custom HTTP Client

```rust
use mozambique::{JwtVerifier, JwtVerifierConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a custom HTTP client with specific settings
    let custom_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let config = JwtVerifierConfig::new(
        "https://your-issuer.example.com",
        "my-service"
    )
    .with_cache_ttl(Duration::from_secs(3600))
    .with_http_client(custom_client);

    let verifier = JwtVerifier::new(config).await?;

    let token = "your-jwt-token";
    let subject = verifier.verify(token).await?;

    Ok(())
}
```

## How It Works

1. **Token Parsing**: The library first parses the JWT token without validation to extract the issuer from the claims.

2. **JWKS Fetching**: It fetches the JWKS from the issuer's OpenID configuration endpoint (`{issuer}/.well-known/openid-configuration`) and caches it according to the configured TTL.

3. **Signature Verification**: The token signature is verified using the appropriate key from the JWKS based on the `kid` (key ID) in the JWT header.

4. **Claims Validation**: The library validates:
   - Token signature
   - Issuer matches the expected issuer
   - Token has not expired
   - **Audience matches at least one expected audience** (validated against configuration, not token's own claims)

5. **Subject Extraction** (Kubernetes-specific): The library extracts Kubernetes service account information:
   - First, it checks for the `kubernetes.io` claim containing service account and namespace
   - If not present, it falls back to parsing the `sub` claim expecting the format: `system:serviceaccount:<namespace>:<service_account>`
   - **Tokens from non-Kubernetes OIDC providers will fail at this step** with `ServiceAccountNotPresentInSubject` error

## Security: Audience Validation

**Important:** This library implements proper audience validation to prevent token reuse across services.

- ✅ Tokens are validated against **configured expected audiences**, not the token's own audience claim
- ✅ At least one audience is **required** at configuration time
- ✅ Runtime checks ensure audiences are never empty
- ✅ Prevents security issues where any token from the correct issuer could be used for any service

## JWKS Caching

The library implements efficient JWKS caching:

- JWKS are cached with a configurable TTL (default: 1 hour)
- Automatic cache expiration and refresh
- Reduces network calls to the issuer's JWKS endpoint

## Limitations

- **Kubernetes-only**: The library currently only supports Kubernetes service account tokens
- **Subject extraction**: Hardcoded to extract `service_account` and `namespace` from Kubernetes-specific claims
- **Not generic OIDC**: Tokens from Auth0, Okta, Google, or other standard OIDC providers will fail subject extraction

If you need generic OIDC token validation, this library is not suitable in its current form. Consider using a generic JWT validation library like `jsonwebtoken` directly.

## Examples

See the [examples](examples/) directory for more usage examples:

- `basic_usage.rs`: Simple JWT verification examples

Run an example:

```bash
cargo run --example basic_usage
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
