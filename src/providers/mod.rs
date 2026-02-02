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

pub mod kubernetes;
