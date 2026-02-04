# Mozambigue

A generic, extensible Rust library for JWT (JSON Web Token) validation with JWKS (JSON Web Key Set) caching support.

**Designed for flexibility:** Mozambigue provides a trait-based architecture that makes it easy to add support for different JWT providers while maintaining type safety and zero serialization overhead.

## Features

- ✅ **Generic architecture** - Trait-based system supporting multiple JWT providers
- ✅ **Zero serialization overhead** - Direct field access via `StandardClaims` trait
- ✅ JWT signature verification (RSA and Octet keys)
- ✅ Automatic JWKS fetching from OpenID configuration endpoints
- ✅ Configurable JWKS caching with TTL
- ✅ **Secure audience validation** - Validates against configured expected audiences
- ✅ Issuer and expiration validation

### Currently Supported Providers

- **Kubernetes** - Service account token validation with namespace and service account extraction

### Ready to Add

The architecture is ready for additional providers:
- Standard OIDC (email, name, profile)
- Auth0 (roles, permissions, metadata)
- Google Sign-In
- Azure AD / Entra ID
- Keycloak (realm roles, client roles)
- Any custom OIDC provider

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
mozambigue = "0.1"
```

## Quick Start

### Kubernetes Service Account Tokens

```rust
use mozambigue::{KubernetesJwtVerifier, VerifyJwt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simple usage - one line setup
    let verifier = KubernetesJwtVerifier::with_issuer(
        "https://kubernetes.default.svc.cluster.local",
        "my-service"
    ).await?;

    // Verify a token
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
    let identity = verifier.verify(token).await?;

    println!("Service Account: {}", identity.service_account);
    println!("Namespace: {}", identity.namespace);

    Ok(())
}
```

### Generic Usage (Custom Provider)

```rust
use mozambigue::{
    JwtVerifier,
    JwtVerifierConfig,
    IdentityExtractor,
    StandardClaims,
};
use serde::Deserialize;

// 1. Define your claims structure
#[derive(Deserialize)]
struct MyClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: i64,
    custom_field: String,
}

// 2. Implement StandardClaims
impl StandardClaims for MyClaims {
    fn iss(&self) -> &str { &self.iss }
    fn sub(&self) -> &str { &self.sub }
    fn aud(&self) -> &[String] { &self.aud }
    fn exp(&self) -> i64 { self.exp }
}

// 3. Define your identity type
struct MyIdentity {
    user_id: String,
    custom_data: String,
}

// 4. Create your extractor
struct MyExtractor;

impl IdentityExtractor for MyExtractor {
    type Claims = MyClaims;
    type Identity = MyIdentity;

    fn extract_identity(&self, claims: &Self::Claims)
        -> mozambigue::Result<Self::Identity>
    {
        Ok(MyIdentity {
            user_id: claims.sub.clone(),
            custom_data: claims.custom_field.clone(),
        })
    }
}

// 5. Use it!
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = JwtVerifierConfig::new(
        "https://my-issuer.example.com",
        "my-audience"
    );

    let verifier = JwtVerifier::new(config, MyExtractor).await?;
    let identity = verifier.verify("token").await?;

    println!("User: {}", identity.user_id);
    Ok(())
}
```

## Architecture

### Provider-Based Structure

```
mozambigue/
├── Generic Infrastructure
│   ├── JwtVerifier<E>       - Generic verifier
│   ├── IdentityExtractor    - Trait for extractors
│   ├── StandardClaims       - Trait for claims access
│   └── VerifyJwt            - Verification trait
│
└── providers/
    └── kubernetes/          - Kubernetes implementation
        ├── KubernetesClaims
        ├── KubernetesIdentity
        ├── KubernetesExtractor
        └── KubernetesJwtVerifier
```

### How It Works

1. **Token Parsing**: Parse JWT to extract issuer (without validation)
2. **JWKS Fetching**: Fetch JWKS from `{issuer}/.well-known/openid-configuration` (cached)
3. **Signature Verification**: Verify signature using key from JWKS
4. **Claims Validation**: Validate issuer, expiration, and audience
5. **Identity Extraction**: Provider-specific extraction via `IdentityExtractor` trait

## Examples

### Kubernetes: Custom Configuration

```rust
use mozambigue::{KubernetesJwtVerifier, JwtVerifierConfig, KubernetesExtractor};
use std::time::Duration;

let config = JwtVerifierConfig::new(
    "https://kubernetes.default.svc.cluster.local",
    "my-service"
)
.with_cache_ttl(Duration::from_secs(1800)); // 30 minutes

let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;
let identity = verifier.verify(token).await?;
```

### Multiple Audiences

```rust
use mozambigue::JwtVerifierConfig;

let config = JwtVerifierConfig::new_with_audiences(
    "https://your-issuer.example.com",
    vec!["service-a".to_string(), "service-b".to_string()]
)?
.with_cache_ttl(Duration::from_secs(3600));

let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;
```

### Custom HTTP Client

```rust
let custom_client = reqwest::Client::builder()
    .timeout(Duration::from_secs(10))
    .build()?;

let config = JwtVerifierConfig::new(
    "https://your-issuer.example.com",
    "my-service"
)
.with_http_client(custom_client);

let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;
```

### Using Explicit Provider Path

```rust
use mozambigue::JwtVerifier;
use mozambigue::providers::kubernetes::{
    KubernetesExtractor,
    KubernetesIdentity,
};

let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;
let identity: KubernetesIdentity = verifier.verify(token).await?;
```

## JWKS Caching

Efficient caching reduces network calls:

- Configurable TTL (default: 1 hour)
- Automatic cache expiration
- Thread-safe with `Arc<RwLock<HashMap>>`
- Per-issuer caching

## Implementing Custom Providers

Want to add support for Auth0, Google, or your custom OIDC provider? It's easy:

1. **Define your claims structure** with provider-specific fields
2. **Implement `StandardClaims`** for standard field access
3. **Define your identity type** with extracted information
4. **Implement `IdentityExtractor`** with your extraction logic

See the [Kubernetes provider](src/providers/kubernetes.rs) for a complete example.

## Examples

See the [examples](examples/) directory:

```bash
cargo run --example basic_usage
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
