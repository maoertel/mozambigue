use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::fetch_jwks_error;
use crate::error::openid_jwks_error;
use crate::error::Result;

#[derive(Debug, Deserialize)]
struct OpenIdConfig {
    jwks_uri: String,
}

struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

impl CachedJwks {
    fn new(jwks: JwkSet) -> Self {
        Self {
            jwks,
            fetched_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.fetched_at.elapsed() >= ttl
    }
}

/// Cache for JWKS (JSON Web Key Sets) with automatic expiration and refresh
pub(crate) struct JwksCache {
    cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
    ttl: Duration,
    client: Client,
}

impl JwksCache {
    /// Create a new JWKS cache with the given TTL and HTTP client
    pub(crate) fn new(ttl: Duration, client: Client) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            client,
        }
    }

    /// Get JWKS for the given issuer, fetching from the network if not cached or expired
    pub(crate) async fn get_jwks(&self, issuer: &str) -> Result<JwkSet> {
        if let Some(jwks) = self.try_get_cached(issuer).await {
            return Ok(jwks);
        }

        // Cache miss or expired, refresh
        self.refresh(issuer).await
    }

    /// Try to get JWKS from cache if present and not expired
    async fn try_get_cached(&self, issuer: &str) -> Option<JwkSet> {
        let cache = self.cache.read().await;
        let cached = cache.get(issuer)?;

        if cached.is_expired(self.ttl) {
            return None;
        }

        Some(cached.jwks.clone())
    }

    /// Force refresh the JWKS for the given issuer
    async fn refresh(&self, issuer: &str) -> Result<JwkSet> {
        let jwks = self.fetch_jwks(issuer).await?;

        let mut cache = self.cache.write().await;
        cache.insert(issuer.to_string(), CachedJwks::new(jwks.clone()));

        Ok(jwks)
    }

    /// Fetch JWKS from the OpenID configuration endpoint
    async fn fetch_jwks(&self, issuer: &str) -> Result<JwkSet> {
        let openid_url = format!("{issuer}/.well-known/openid-configuration");
        let OpenIdConfig { jwks_uri, .. } = self
            .client
            .get(&openid_url)
            .send()
            .await
            .map_err(openid_jwks_error)?
            .json()
            .await
            .map_err(openid_jwks_error)?;

        let jwks: JwkSet = self
            .client
            .get(&jwks_uri)
            .send()
            .await
            .map_err(fetch_jwks_error)?
            .json()
            .await
            .map_err(fetch_jwks_error)?;

        Ok(jwks)
    }
}
