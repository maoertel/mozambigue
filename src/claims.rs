/// Trait for accessing standard JWT/OIDC claims
///
/// All JWT claims types must implement this trait to provide access to
/// the standard OIDC fields that are used for validation (issuer, expiration, audience).
/// This allows the verifier to validate these fields generically across different
/// claim structures from different providers.
///
/// # Example
///
/// ```rust
/// use mozambigue::StandardClaims;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct MyClaims {
///     iss: String,
///     sub: String,
///     aud: Vec<String>,
///     exp: i64,
/// }
///
/// impl StandardClaims for MyClaims {
///     fn iss(&self) -> &str { &self.iss }
///     fn sub(&self) -> &str { &self.sub }
///     fn aud(&self) -> &[String] { &self.aud }
///     fn exp(&self) -> i64 { self.exp }
/// }
/// ```
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
