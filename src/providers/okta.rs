//! Okta OAuth2/OIDC token validation
//!
//! This module provides implementation for validating JWT tokens issued by Okta
//! authorization servers. It supports both access tokens and ID tokens, extracting
//! user identity information such as email, name, groups, and client/user IDs.
//!
//! ## Claims Structure
//!
//! Okta access tokens contain standard OIDC claims plus Okta-specific fields:
//!
//! ```json
//! {
//!   "iss": "https://your-org.okta.com/oauth2/default",
//!   "sub": "00uXXXXXXXXXXXXXXXXX",
//!   "aud": "api://default",
//!   "exp": 1234567890,
//!   "iat": 1234567800,
//!   "cid": "0oaXXXXXXXXXXXXXXXXX",
//!   "uid": "00uXXXXXXXXXXXXXXXXX",
//!   "scp": ["openid", "profile", "email"],
//!   "email": "user@example.com",
//!   "groups": ["Everyone", "Developers"]
//! }
//! ```
//!
//! Okta ID tokens have an array audience:
//!
//! ```json
//! {
//!   "iss": "https://your-org.okta.com/oauth2/default",
//!   "sub": "00uXXXXXXXXXXXXXXXXX",
//!   "aud": ["0oaXXXXXXXXXXXXXXXXX"],
//!   "exp": 1234567890,
//!   "iat": 1234567800,
//!   "email": "user@example.com",
//!   "name": "Jane Doe"
//! }
//! ```
//!
//! ## Identity Extraction
//!
//! The extractor maps Okta claims directly to identity fields. All Okta-specific
//! fields are optional since access tokens and ID tokens contain different sets of claims.
//!
//! ## Example
//!
//! ```rust,no_run
//! use mozambigue::providers::okta::OktaJwtVerifier;
//! use mozambigue::VerifyJwt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = OktaJwtVerifier::with_issuer(
//!     "https://your-org.okta.com/oauth2/default",
//!     "api://default"
//! ).await?;
//!
//! let identity = verifier.verify("eyJhbG...").await?;
//! println!("Subject: {}", identity.subject);
//! if let Some(email) = &identity.email {
//!     println!("Email: {email}");
//! }
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use serde::Deserialize;

use crate::claims::StandardClaims;
use crate::config::JwtVerifierConfig;
use crate::error::Result;
use crate::extractor::IdentityExtractor;
use crate::verifier::JwtVerifier;

/// JWT claims structure for Okta OAuth2/OIDC tokens
///
/// Handles both access tokens (string `aud`) and ID tokens (array `aud`)
/// via the [`OktaAudience`] enum. All Okta-specific fields are optional
/// since different token types contain different claims.
#[derive(Debug, Deserialize)]
pub struct OktaClaims {
    /// Issuer - the Okta authorization server URL
    pub iss: String,
    /// Subject - opaque Okta user or client identifier
    pub sub: String,
    /// Audiences - string for access tokens, array for ID tokens
    pub aud: OktaAudience,
    /// Expiration time as Unix timestamp
    pub exp: i64,
    /// Issued-at time as Unix timestamp
    pub iat: Option<i64>,
    /// Okta user ID
    pub uid: Option<String>,
    /// Okta client ID
    pub cid: Option<String>,
    /// Scopes granted to the token
    pub scp: Option<Vec<String>>,
    /// User's email address
    pub email: Option<String>,
    /// Whether the email has been verified
    pub email_verified: Option<bool>,
    /// User's full name
    pub name: Option<String>,
    /// User's preferred username
    pub preferred_username: Option<String>,
    /// User's given (first) name
    pub given_name: Option<String>,
    /// User's family (last) name
    pub family_name: Option<String>,
    /// Groups the user belongs to
    pub groups: Option<Vec<String>>,
}

/// Okta's polymorphic audience claim
///
/// Okta access tokens use a single string audience (e.g., `"api://default"`),
/// while ID tokens use an array (e.g., `["0oaXXX"]`). This enum handles both
/// formats transparently via `#[serde(untagged)]` deserialization.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OktaAudience {
    /// Single string audience (typical for access tokens)
    Single(String),
    /// Array of audiences (typical for ID tokens)
    Multiple(Vec<String>),
}

impl OktaAudience {
    /// Returns the audience(s) as a slice
    ///
    /// For the single-string variant, uses `std::slice::from_ref` to avoid allocation.
    pub fn as_slice(&self) -> &[String] {
        match self {
            OktaAudience::Single(s) => std::slice::from_ref(s),
            OktaAudience::Multiple(v) => v,
        }
    }
}

impl StandardClaims for OktaClaims {
    fn iss(&self) -> &str {
        &self.iss
    }

    fn sub(&self) -> &str {
        &self.sub
    }

    fn aud(&self) -> &[String] {
        self.aud.as_slice()
    }

    fn exp(&self) -> i64 {
        self.exp
    }

    fn iat(&self) -> Option<i64> {
        self.iat
    }
}

/// Identity information extracted from Okta tokens
///
/// Contains the subject (always present) and optional Okta-specific fields.
/// Fields are `Option` because access tokens and ID tokens carry different claims.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct OktaIdentity {
    /// Subject identifier (always present in Okta tokens)
    pub subject: Arc<str>,
    /// Okta user ID (`uid` claim)
    pub user_id: Option<Arc<str>>,
    /// Okta client ID (`cid` claim)
    pub client_id: Option<Arc<str>>,
    /// User's email address
    pub email: Option<Arc<str>>,
    /// User's full name
    pub name: Option<Arc<str>>,
    /// Groups the user belongs to
    pub groups: Option<Vec<Arc<str>>>,
}

/// Extractor for Okta OAuth2/OIDC tokens
///
/// Maps Okta JWT claims directly to [`OktaIdentity`] fields.
/// The extraction is infallible — all Okta-specific fields are optional,
/// and the required `sub` claim is always present in valid Okta tokens.
#[derive(Clone, Debug)]
pub struct OktaExtractor;

impl IdentityExtractor for OktaExtractor {
    type Claims = OktaClaims;
    type Identity = OktaIdentity;

    fn extract_identity(&self, claims: &Self::Claims) -> Result<Self::Identity> {
        Ok(OktaIdentity {
            subject: Arc::from(claims.sub.as_str()),
            user_id: claims.uid.as_deref().map(Arc::from),
            client_id: claims.cid.as_deref().map(Arc::from),
            email: claims.email.as_deref().map(Arc::from),
            name: claims.name.as_deref().map(Arc::from),
            groups: claims
                .groups
                .as_ref()
                .map(|g| g.iter().map(|s| Arc::from(s.as_str())).collect()),
        })
    }
}

/// Convenience type alias for Okta JWT verifier
pub type OktaJwtVerifier = JwtVerifier<OktaExtractor>;

impl OktaJwtVerifier {
    /// Create a new Okta JWT verifier with simple configuration
    ///
    /// This is a convenience constructor for verifying Okta tokens.
    /// It automatically uses the `OktaExtractor` for identity extraction.
    ///
    /// # Arguments
    ///
    /// * `expected_issuer` - The Okta authorization server URL
    ///   (e.g., `"https://your-org.okta.com/oauth2/default"`)
    /// * `audience` - The expected audience
    ///   (e.g., `"api://default"` for access tokens)
    pub async fn with_issuer(
        expected_issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self> {
        let config = JwtVerifierConfig::new(expected_issuer, audience);
        Self::new(config, OktaExtractor).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_access_token_claims() {
        // Given an Okta access token with a string audience
        let json = r#"{
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "sub": "00u1234567890",
            "aud": "api://default",
            "exp": 1700000000,
            "iat": 1699996400,
            "cid": "0oa1234567890",
            "uid": "00u1234567890",
            "scp": ["openid", "profile", "email"],
            "email": "user@example.com",
            "email_verified": true,
            "groups": ["Everyone", "Developers"]
        }"#;

        // When deserializing the claims
        let claims: OktaClaims = serde_json::from_str(json).unwrap();

        // Then all fields are correctly parsed
        assert_eq!(claims.iss, "https://dev-123456.okta.com/oauth2/default");
        assert_eq!(claims.sub, "00u1234567890");
        assert_eq!(claims.aud.as_slice(), &["api://default".to_string()]);
        assert_eq!(claims.exp, 1700000000);
        assert_eq!(claims.iat, Some(1699996400));
        assert_eq!(claims.cid.as_deref(), Some("0oa1234567890"));
        assert_eq!(claims.uid.as_deref(), Some("00u1234567890"));
        assert_eq!(
            claims.scp,
            Some(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string()
            ])
        );
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(
            claims.groups,
            Some(vec!["Everyone".to_string(), "Developers".to_string()])
        );
    }

    #[test]
    fn deserialize_id_token_claims() {
        // Given an Okta ID token with an array audience
        let json = r#"{
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "sub": "00u1234567890",
            "aud": ["0oa1234567890"],
            "exp": 1700000000,
            "email": "user@example.com",
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe"
        }"#;

        // When deserializing the claims
        let claims: OktaClaims = serde_json::from_str(json).unwrap();

        // Then the array audience is correctly parsed
        assert_eq!(claims.aud.as_slice(), &["0oa1234567890".to_string()]);
        assert_eq!(claims.name.as_deref(), Some("Jane Doe"));
        assert_eq!(claims.given_name.as_deref(), Some("Jane"));
        assert_eq!(claims.family_name.as_deref(), Some("Doe"));
        // Then optional fields not present are None
        assert!(claims.iat.is_none());
        assert!(claims.uid.is_none());
        assert!(claims.cid.is_none());
        assert!(claims.scp.is_none());
        assert!(claims.groups.is_none());
    }

    #[test]
    fn standard_claims_implementation() {
        // Given Okta claims with a string audience
        let claims = OktaClaims {
            iss: "https://dev-123456.okta.com/oauth2/default".to_string(),
            sub: "00u1234567890".to_string(),
            aud: OktaAudience::Single("api://default".to_string()),
            exp: 1700000000,
            iat: Some(1699996400),
            uid: None,
            cid: None,
            scp: None,
            email: None,
            email_verified: None,
            name: None,
            preferred_username: None,
            given_name: None,
            family_name: None,
            groups: None,
        };

        // When accessing standard claims
        // Then they return the correct values
        assert_eq!(claims.iss(), "https://dev-123456.okta.com/oauth2/default");
        assert_eq!(claims.sub(), "00u1234567890");
        assert_eq!(claims.aud(), &["api://default".to_string()]);
        assert_eq!(claims.exp(), 1700000000);
        assert_eq!(claims.iat(), Some(1699996400));
    }

    #[test]
    fn extract_identity_from_access_token() {
        // Given Okta access token claims with all optional fields present
        let claims = OktaClaims {
            iss: "https://dev-123456.okta.com/oauth2/default".to_string(),
            sub: "00u1234567890".to_string(),
            aud: OktaAudience::Single("api://default".to_string()),
            exp: 1700000000,
            iat: Some(1699996400),
            uid: Some("00u1234567890".to_string()),
            cid: Some("0oa1234567890".to_string()),
            scp: Some(vec!["openid".to_string()]),
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Jane Doe".to_string()),
            preferred_username: Some("user@example.com".to_string()),
            given_name: Some("Jane".to_string()),
            family_name: Some("Doe".to_string()),
            groups: Some(vec!["Everyone".to_string(), "Developers".to_string()]),
        };

        // When extracting identity
        let identity = OktaExtractor.extract_identity(&claims).unwrap();

        // Then all fields are correctly mapped
        assert_eq!(&*identity.subject, "00u1234567890");
        assert_eq!(identity.user_id.as_deref(), Some("00u1234567890"));
        assert_eq!(identity.client_id.as_deref(), Some("0oa1234567890"));
        assert_eq!(identity.email.as_deref(), Some("user@example.com"));
        assert_eq!(identity.name.as_deref(), Some("Jane Doe"));
        let groups: Vec<&str> = identity
            .groups
            .as_ref()
            .unwrap()
            .iter()
            .map(|g| &**g)
            .collect();
        assert_eq!(groups, vec!["Everyone", "Developers"]);
    }

    #[test]
    fn extract_identity_with_minimal_claims() {
        // Given Okta claims with only required fields
        let claims = OktaClaims {
            iss: "https://dev-123456.okta.com/oauth2/default".to_string(),
            sub: "00u1234567890".to_string(),
            aud: OktaAudience::Multiple(vec!["0oa1234567890".to_string()]),
            exp: 1700000000,
            iat: None,
            uid: None,
            cid: None,
            scp: None,
            email: None,
            email_verified: None,
            name: None,
            preferred_username: None,
            given_name: None,
            family_name: None,
            groups: None,
        };

        // When extracting identity
        let identity = OktaExtractor.extract_identity(&claims).unwrap();

        // Then subject is present and optional fields are None
        assert_eq!(&*identity.subject, "00u1234567890");
        assert!(identity.user_id.is_none());
        assert!(identity.client_id.is_none());
        assert!(identity.email.is_none());
        assert!(identity.name.is_none());
        assert!(identity.groups.is_none());
    }

    #[test]
    fn okta_identity_equality() {
        // Given two identical Okta identities
        let identity_a = OktaIdentity {
            subject: Arc::from("00u1234567890"),
            user_id: Some(Arc::from("00u1234567890")),
            client_id: None,
            email: Some(Arc::from("user@example.com")),
            name: None,
            groups: None,
        };
        let identity_b = identity_a.clone();

        // When comparing them
        // Then they are equal
        assert_eq!(identity_a, identity_b);
    }
}
