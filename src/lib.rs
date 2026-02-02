//! # Mozambigue
//!
//! A Rust library for JWT (JSON Web Token) validation with JWKS (JSON Web Key Set) caching support.
//!
//! This library is designed for validating JWTs issued by Kubernetes or other OpenID Connect providers,
//! with built-in support for Kubernetes service account token validation.
//!
//! ## Features
//!
//! - JWT signature verification using RSA and Octet keys
//! - Automatic JWKS fetching from OpenID configuration endpoints
//! - Configurable JWKS caching with TTL (Time-To-Live)
//! - Issuer, audience and expiration validation
//! - Kubernetes-specific claims extraction (service account and namespace)
//!
//! ## Example
//!
//! ```rust,no_run
//! use mozambigue::{JwtVerifier, JwtVerifierConfig, KubernetesExtractor, VerifyJwt};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Simple usage with convenience method
//!     let verifier = JwtVerifier::with_issuer(
//!         "https://kubernetes.default.svc.cluster.local",
//!         "my-service"
//!     ).await?;
//!
//!     // Or create with custom configuration
//!     let config = JwtVerifierConfig::new(
//!         "https://kubernetes.default.svc.cluster.local",
//!         "my-service"
//!     ).with_cache_ttl(Duration::from_secs(1800)); // 30 minutes
//!
//!     let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;
//!
//!     // Verify a token
//!     let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
//!     let identity = verifier.verify(token).await?;
//!
//!     println!("Service Account: {}", identity.service_account);
//!     println!("Namespace: {}", identity.namespace);
//!
//!     Ok(())
//! }
//! ```

mod claims;
mod config;
mod error;
mod extractor;
mod jwks_cache;
mod verifier;

// Re-exports for public API
pub use claims::KubernetesClaims;
pub use claims::KubernetesIdentity;
pub use claims::StandardClaims;
pub use config::JwtVerifierConfig;
pub use error::Error;
pub use error::Result;
pub use extractor::IdentityExtractor;
pub use extractor::KubernetesExtractor;
pub use verifier::JwtVerifier;
pub use verifier::VerifyJwt;

// Type alias for Kubernetes JWT verification (backwards compatibility)
/// A JWT verifier configured for Kubernetes service account tokens
///
/// This is a convenience type alias for `JwtVerifier<KubernetesExtractor>`.
/// Use this when verifying Kubernetes service account tokens.
pub type KubernetesJwtVerifier = JwtVerifier<KubernetesExtractor>;
