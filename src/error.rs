use std::fmt::Debug;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("The provided JWT does not match the expected issuer. Provided issuer: {0}")]
    WrongIssuer(String),
    #[error("The provided JWT has expired. Expiration timestamp: {0}")]
    TokenExpired(i64),
    #[error("Missing 'kid' in the header of the provided JWT")]
    KeyIdMissing,
    #[error("Key of your provided JWT does not match in JWKs")]
    KeyNotMatchInJwks,
    #[error("Only RSA or Octet keys are currently supported, got: {0:?}")]
    AlgorithmNotSupported(String),
    #[error("ServiceAccount name not present in subject")]
    ServiceAccountNotPresentInSubject,
    #[error("JWKS cache error: {0}")]
    JwksCacheError(String),
    #[error(
        "No audiences configured - at least one expected audience must be configured for security"
    )]
    NoAudiencesConfigured,
}

pub(crate) fn openid_jwks_error(error: reqwest::Error) -> Error {
    Error::JwksCacheError(format!("Failed to fetch OpenID config: {error}"))
}

pub(crate) fn fetch_jwks_error(error: reqwest::Error) -> Error {
    Error::JwksCacheError(format!("Failed to fetch JWKS: {error}"))
}
