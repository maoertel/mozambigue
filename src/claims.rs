use std::sync::Arc;

use serde::Deserialize;

use crate::error::Error;
use crate::error::Result;

#[derive(Debug, Deserialize)]
pub(crate) struct Claims {
    // Issuer
    pub(crate) iss: String,
    // Subject (Service Account identity)
    pub(crate) sub: String,
    #[allow(dead_code)]
    // Audiences (parsed but validated against config)
    pub(crate) aud: Vec<String>,
    // Expiration time
    pub(crate) exp: i64,
    // Kubernetes specific
    #[serde(rename = "kubernetes.io")]
    pub(crate) kubernetes_io: Option<KubernetesIo>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct KubernetesIo {
    pub(crate) serviceaccount: ServiceAccount,
    pub(crate) namespace: Arc<str>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ServiceAccount {
    pub(crate) name: Arc<str>,
}

#[derive(Debug, Deserialize, Hash, Eq, PartialEq, Clone)]
pub struct Subject {
    pub service_account: Arc<str>,
    pub namespace: Arc<str>,
}

impl TryFrom<String> for Subject {
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

pub(crate) fn get_subject_from_claims(claims: Claims) -> Result<Subject> {
    if let Some(k8s) = claims.kubernetes_io {
        return Ok(Subject {
            service_account: k8s.serviceaccount.name,
            namespace: k8s.namespace,
        });
    }

    Subject::try_from(claims.sub)
}
