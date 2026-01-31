use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::dangerous;
use jsonwebtoken::decode;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::jwk::RSAKeyParameters;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::TokenData;
use jsonwebtoken::Validation;

use crate::claims::get_subject_from_claims;
use crate::claims::Claims;
use crate::claims::Subject;
use crate::config::JwtVerifierConfig;
use crate::error::Error;
use crate::error::Result;
use crate::jwks_cache::JwksCache;

/// Trait for JWT verification
#[async_trait]
pub trait VerifyJwt {
    /// Verify a JWT token and extract the subject information
    async fn verify(&self, token: &str) -> Result<Subject>;
}

/// JWT verifier with JWKS caching support
pub struct JwtVerifier {
    jwks_cache: JwksCache,
    expected_issuer: String,
    expected_audiences: Vec<String>,
}

impl JwtVerifier {
    /// Create a new JWT verifier with the given configuration
    pub async fn new(config: JwtVerifierConfig) -> Result<Self> {
        let client = config.http_client.unwrap_or_default();

        Ok(Self {
            jwks_cache: JwksCache::new(config.jwks_cache_ttl, client),
            expected_issuer: config.expected_issuer,
            expected_audiences: config.expected_audiences,
        })
    }

    /// Create a new JWT verifier with simple configuration
    pub async fn with_issuer(
        expected_issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self> {
        let config = JwtVerifierConfig::new(expected_issuer, audience);
        Self::new(config).await
    }

    /// Parse token data without signature validation to extract header and claims
    fn parse_token_data(&self, token: &str) -> Result<TokenData<Claims>> {
        // Signature validation is disabled here as we only parse our token to get header, issuer and the audience
        // Full validation including signature verification happens in validate_jwt()
        let token_data = dangerous::insecure_decode::<Claims>(token)?;
        Ok(token_data)
    }

    /// Validate the JWT token with full signature verification
    fn validate_jwt(
        &self,
        token_data: TokenData<Claims>,
        token: &str,
        jwks: &JwkSet,
    ) -> Result<Subject> {
        let (decoding_key, validation) =
            get_decoding_key_and_validation(token_data.header, &self.expected_audiences, jwks)?;

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;

        if token_data.claims.iss != self.expected_issuer {
            return Err(Error::WrongIssuer(token_data.claims.iss));
        }

        if token_data.claims.exp < Utc::now().timestamp() {
            return Err(Error::TokenExpired(token_data.claims.exp));
        }

        get_subject_from_claims(token_data.claims)
    }
}

#[async_trait]
impl VerifyJwt for JwtVerifier {
    async fn verify(&self, token: &str) -> Result<Subject> {
        let token_data = self.parse_token_data(token)?;
        let jwks = self.jwks_cache.get_jwks(&token_data.claims.iss).await?;

        self.validate_jwt(token_data, token, &jwks)
    }
}

/// Get the decoding key and validation settings for JWT verification
fn get_decoding_key_and_validation(
    header: Header,
    expected_audiences: &[String],
    jwks: &JwkSet,
) -> Result<(DecodingKey, Validation)> {
    let kid = header.kid.ok_or(Error::KeyIdMissing)?;

    let decoding_key = get_decoding_key_for_kid(&kid, jwks)?;

    // Runtime safety check: ensure audiences are configured
    if expected_audiences.is_empty() {
        return Err(Error::NoAudiencesConfigured);
    }

    let mut validation = Validation::new(header.alg);

    // Validate against expected audiences from configuration, not the token's own audiences
    validation.set_audience(expected_audiences);

    Ok((decoding_key, validation))
}

/// Get the decoding key for the given key ID from the JWKS
fn get_decoding_key_for_kid(kid: &str, jwks: &JwkSet) -> Result<DecodingKey> {
    let jwk = jwks.find(kid).ok_or(Error::KeyNotMatchInJwks)?;

    match &jwk.algorithm {
        AlgorithmParameters::RSA(RSAKeyParameters { n, e, .. }) => {
            Ok(DecodingKey::from_rsa_components(n, e)?)
        }
        AlgorithmParameters::OctetKey(params) => {
            Ok(DecodingKey::from_secret(params.value.as_bytes()))
        }
        other_algo => Err(Error::AlgorithmNotSupported(format!("{other_algo:?}"))),
    }
}
