//! Kubernetes service account token validation
//!
//! This module provides implementation for validating JWT tokens issued by Kubernetes
//! API servers for service accounts. It extracts service account name and namespace
//! information from the validated tokens.
//!
//! ## Claims Structure
//!
//! Kubernetes JWTs contain standard OIDC claims plus optional `kubernetes.io` custom claims:
//!
//! ```json
//! {
//!   "iss": "https://kubernetes.default.svc.cluster.local",
//!   "sub": "system:serviceaccount:default:my-service-account",
//!   "aud": ["my-service"],
//!   "exp": 1234567890,
//!   "kubernetes.io": {
//!     "namespace": "default",
//!     "serviceaccount": {
//!       "name": "my-service-account"
//!     }
//!   }
//! }
//! ```
//!
//! ## Identity Extraction
//!
//! The extractor first tries to extract from the `kubernetes.io` structured claim,
//! then falls back to parsing the `sub` field in the format:
//! `system:serviceaccount:<namespace>:<service_account>`
//!
//! ## Example
//!
//! ```rust,no_run
//! use mozambigue::providers::kubernetes::KubernetesJwtVerifier;
//! use mozambigue::VerifyJwt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Simple usage
//! let verifier = KubernetesJwtVerifier::with_issuer(
//!     "https://kubernetes.default.svc.cluster.local",
//!     "my-service"
//! ).await?;
//!
//! let identity = verifier.verify("eyJhbG...").await?;
//! println!("Service Account: {}", identity.service_account);
//! println!("Namespace: {}", identity.namespace);
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use serde::Deserialize;

use crate::claims::StandardClaims;
use crate::config::JwtVerifierConfig;
use crate::error::Error;
use crate::error::Result;
use crate::extractor::IdentityExtractor;
use crate::verifier::JwtVerifier;

/// JWT claims structure for Kubernetes service account tokens
#[derive(Debug, Deserialize)]
pub struct KubernetesClaims {
    /// Issuer - typically the Kubernetes API server URL
    pub iss: String,
    /// Subject - typically in format: system:serviceaccount:<namespace>:<service_account>
    pub sub: String,
    /// Audiences - the intended recipients of the token
    pub aud: Vec<String>,
    /// Expiration time as Unix timestamp
    pub exp: i64,
    /// Kubernetes-specific structured claims
    #[serde(rename = "kubernetes.io")]
    pub kubernetes_io: Option<KubernetesIo>,
}

impl StandardClaims for KubernetesClaims {
    fn iss(&self) -> &str {
        &self.iss
    }

    fn sub(&self) -> &str {
        &self.sub
    }

    fn aud(&self) -> &[String] {
        &self.aud
    }

    fn exp(&self) -> i64 {
        self.exp
    }
}

/// Kubernetes-specific claims under the "kubernetes.io" namespace
#[derive(Debug, Deserialize)]
pub struct KubernetesIo {
    pub serviceaccount: ServiceAccount,
    pub namespace: Arc<str>,
}

/// Service account information from Kubernetes claims
#[derive(Debug, Deserialize)]
pub struct ServiceAccount {
    pub name: Arc<str>,
}

/// Identity information extracted from Kubernetes service account tokens
#[derive(Debug, Deserialize, Hash, Eq, PartialEq, Clone)]
pub struct KubernetesIdentity {
    pub service_account: Arc<str>,
    pub namespace: Arc<str>,
}

impl TryFrom<String> for KubernetesIdentity {
    type Error = Error;

    /// Extracts the service account and namespace from the subject field of the JWT claims.
    /// This is just a fallback in case the kubernetes.io claim is not present in the JWT.
    ///
    /// The subject in the JWT is expected to be in the format:
    /// `system:serviceaccount:<namespace>:<service_account>`
    fn try_from(subject: String) -> Result<Self> {
        let split = subject.split(':').rev().collect::<Vec<_>>();

        if split.is_empty() || split.len() < 2 {
            return Err(Error::ServiceAccountNotPresentInSubject);
        }

        let service_account = Arc::from(
            *split
                .first()
                .ok_or(Error::ServiceAccountNotPresentInSubject)?,
        );

        let namespace = Arc::from(
            *split
                .get(1)
                .ok_or(Error::ServiceAccountNotPresentInSubject)?,
        );

        Ok(Self {
            service_account,
            namespace,
        })
    }
}

/// Extractor for Kubernetes service account tokens
///
/// Extracts service account name and namespace from Kubernetes JWT claims.
/// First tries to extract from the `kubernetes.io` custom claim, then falls back
/// to parsing the standard `sub` claim in the format:
/// `system:serviceaccount:<namespace>:<service_account>`
#[derive(Clone, Debug)]
pub struct KubernetesExtractor;

impl IdentityExtractor for KubernetesExtractor {
    type Claims = KubernetesClaims;
    type Identity = KubernetesIdentity;

    fn extract_identity(&self, claims: &Self::Claims) -> Result<Self::Identity> {
        if let Some(k8s) = &claims.kubernetes_io {
            return Ok(KubernetesIdentity {
                service_account: k8s.serviceaccount.name.clone(),
                namespace: k8s.namespace.clone(),
            });
        }

        extract_identity_from_sub(&claims.sub)
    }
}

/// Convenience type alias for Kubernetes JWT verifier
pub type KubernetesJwtVerifier = JwtVerifier<KubernetesExtractor>;

impl KubernetesJwtVerifier {
    /// Create a new Kubernetes JWT verifier with simple configuration
    ///
    /// This is a convenience constructor for verifying Kubernetes service account tokens.
    /// It automatically uses the `KubernetesExtractor` for identity extraction.
    pub async fn with_issuer(
        expected_issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self> {
        let config = JwtVerifierConfig::new(expected_issuer, audience);
        Self::new(config, KubernetesExtractor).await
    }
}

/// Extract identity from Kubernetes sub field
///
/// Expected format: `system:serviceaccount:<namespace>:<service_account>`
fn extract_identity_from_sub(sub: &str) -> Result<KubernetesIdentity> {
    let parts: Vec<&str> = sub.split(':').collect();

    if parts.len() != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
        return Err(Error::ServiceAccountNotPresentInSubject);
    }

    Ok(KubernetesIdentity {
        namespace: Arc::from(parts[2]),
        service_account: Arc::from(parts[3]),
    })
}
