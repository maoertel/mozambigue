use std::sync::Arc;

use serde::Deserialize;

use crate::error::Error;
use crate::error::Result;

/// Trait for accessing standard JWT/OIDC claims
///
/// All JWT claims types must implement this trait to provide access to
/// the standard OIDC fields that are used for validation (issuer, expiration, audience).
/// This allows the verifier to validate these fields generically across different
/// claim structures from different providers.
#[allow(dead_code)] // Some methods will be used by future OIDC extractors
pub trait StandardClaims {
    /// Get the issuer (iss) claim
    fn iss(&self) -> &str;

    /// Get the subject (sub) claim
    fn sub(&self) -> &str;

    /// Get the audience (aud) claim
    fn aud(&self) -> &[String];

    /// Get the expiration time (exp) claim as a Unix timestamp
    fn exp(&self) -> i64;

    /// Get the issued at (iat) claim as a Unix timestamp, if present
    fn iat(&self) -> Option<i64> {
        None
    }
}

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
///
/// Contains the service account name and namespace that identify a
/// Kubernetes workload.
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
