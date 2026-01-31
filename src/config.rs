use std::time::Duration;

use reqwest::Client;

use crate::error::Error;
use crate::error::Result;

/// Configuration for the JWT verifier
#[derive(Debug, Clone)]
pub struct JwtVerifierConfig {
    /// The expected issuer of the JWT tokens
    pub(crate) expected_issuer: String,
    /// Expected audiences - the token's audience must match at least one of these
    pub(crate) expected_audiences: Vec<String>,
    /// Time-to-live for cached JWKS (default: 1 hour)
    pub(crate) jwks_cache_ttl: Duration,
    /// Optional custom HTTP client for fetching JWKS
    /// If not provided, a default client will be created
    pub(crate) http_client: Option<Client>,
}

const DEFAULT_JWKS_CACHE_TTL_SECS: u64 = 3600;

impl JwtVerifierConfig {
    /// Create a new configuration with the given issuer and a single expected audience
    /// The token's audience claim must match this audience
    pub fn new(expected_issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            expected_audiences: vec![audience.into()],
            jwks_cache_ttl: Duration::from_secs(DEFAULT_JWKS_CACHE_TTL_SECS),
            http_client: None,
        }
    }

    /// Create a new configuration with the given issuer and multiple expected audiences
    /// The token's audience claim must match at least one of these audiences
    ///
    /// # Errors
    /// Returns `Error::NoAudiencesConfigured` if the audiences vector is empty
    pub fn new_with_audiences(
        expected_issuer: impl Into<String>,
        expected_audiences: Vec<String>,
    ) -> Result<Self> {
        if expected_audiences.is_empty() {
            return Err(Error::NoAudiencesConfigured);
        }

        Ok(Self {
            expected_issuer: expected_issuer.into(),
            expected_audiences,
            jwks_cache_ttl: Duration::from_secs(DEFAULT_JWKS_CACHE_TTL_SECS),
            http_client: None,
        })
    }

    /// Set the expected audiences that tokens must have
    /// The token's audience claim must match at least one of these values
    ///
    /// # Errors
    /// Returns `Error::NoAudiencesConfigured` if the audiences vector is empty
    pub fn with_audiences(mut self, audiences: Vec<String>) -> Result<Self> {
        if audiences.is_empty() {
            return Err(Error::NoAudiencesConfigured);
        }
        self.expected_audiences = audiences;
        Ok(self)
    }

    /// Add a single expected audience
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audiences.push(audience.into());
        self
    }

    /// Set the JWKS cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_cache_ttl = ttl;
        self
    }

    /// Set a custom HTTP client
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http_client = Some(client);
        self
    }
}
