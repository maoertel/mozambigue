//! Provider-specific implementations for different JWT issuers
//!
//! This module contains implementations of the [`IdentityExtractor`](crate::IdentityExtractor)
//! trait for various JWT providers. Each provider module includes:
//!
//! - **Claims**: Provider-specific JWT claims structure
//! - **Identity**: The extracted identity information
//! - **Extractor**: Implementation of `IdentityExtractor`
//!
//! ## Available Providers
//!
//! - [`kubernetes`]: Kubernetes service account tokens
//!
//! ## Example
//!
//! ```rust,no_run
//! use mozambigue::providers::kubernetes::KubernetesJwtVerifier;
//! use mozambigue::VerifyJwt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = KubernetesJwtVerifier::with_issuer(
//!     "https://kubernetes.default.svc",
//!     "my-service"
//! ).await?;
//!
//! let identity = verifier.verify("token").await?;
//! println!("Service Account: {}", identity.service_account);
//! # Ok(())
//! # }
//! ```

pub mod kubernetes;
