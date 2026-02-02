use std::sync::Arc;

use serde::de::DeserializeOwned;

use crate::claims::KubernetesIdentity;
use crate::claims::StandardClaims;
use crate::error::Error;
use crate::error::Result;

/// Trait for extracting identity information from validated JWT claims
///
/// This trait allows for different strategies of extracting identity information
/// from JWT claims. Implementations can define their own Claims type and Identity type,
/// providing maximum flexibility while maintaining type safety.
///
/// The associated `Claims` type must implement `StandardClaims` to provide access
/// to standard JWT fields (iss, exp, aud) that are used for validation.
pub trait IdentityExtractor: Send + Sync {
    /// The JWT claims structure for this extractor
    ///
    /// Must implement `StandardClaims` for standard field access and
    /// `DeserializeOwned` to be decoded from the JWT token.
    /// Must also be `Send` for use in async contexts.
    type Claims: StandardClaims + DeserializeOwned + Send;

    /// The type of identity information to extract
    type Identity;

    /// Extract identity information from validated JWT claims
    ///
    /// This method is called after the JWT has been fully validated (signature,
    /// issuer, audience, expiration). The claims parameter contains the fully
    /// deserialized claims structure specific to this extractor.
    fn extract_identity(&self, claims: &Self::Claims) -> Result<Self::Identity>;
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
    type Claims = crate::claims::KubernetesClaims;
    type Identity = KubernetesIdentity;

    fn extract_identity(&self, claims: &Self::Claims) -> Result<Self::Identity> {
        // Try kubernetes.io claim first
        if let Some(k8s) = &claims.kubernetes_io {
            return Ok(KubernetesIdentity {
                service_account: k8s.serviceaccount.name.clone(),
                namespace: k8s.namespace.clone(),
            });
        }

        // Fallback: parse from sub field
        extract_identity_from_sub(&claims.sub)
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
