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
//! use mozambigue::{JwtVerifier, JwtVerifierConfig, VerifyJwt};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a verifier with custom configuration
//!     let config = JwtVerifierConfig::new(
//!         "https://kubernetes.default.svc.cluster.local",
//!         "my-service"
//!     ).with_cache_ttl(Duration::from_secs(1800)); // 30 minutes
//!
//!     let verifier = JwtVerifier::new(config).await?;
//!
//!     // Verify a token
//!     let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
//!     let subject = verifier.verify(token).await?;
//!
//!     println!("Service Account: {}", subject.service_account);
//!     println!("Namespace: {}", subject.namespace);
//!
//!     Ok(())
//! }
//! ```

mod claims;
mod config;
mod error;
mod jwks_cache;
mod verifier;

// Re-exports for public API
pub use claims::Subject;
pub use config::JwtVerifierConfig;
pub use error::Error;
pub use error::Result;
pub use verifier::JwtVerifier;
pub use verifier::VerifyJwt;
