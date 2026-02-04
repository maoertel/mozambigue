use serde::de::DeserializeOwned;

use crate::claims::StandardClaims;
use crate::error::Result;

/// Trait for extracting identity information from validated JWT claims
///
/// This trait allows for different strategies of extracting identity information
/// from JWT claims. Implementations can define their own Claims type and Identity type,
/// providing maximum flexibility while maintaining type safety.
///
/// The associated `Claims` type must implement [`StandardClaims`] to provide access
/// to standard JWT fields (iss, exp, aud) that are used for validation.
///
/// # Example
///
/// ```rust
/// use mozambigue::{IdentityExtractor, StandardClaims};
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct MyClaims {
///     iss: String,
///     sub: String,
///     aud: Vec<String>,
///     exp: i64,
///     custom_field: String,
/// }
///
/// impl StandardClaims for MyClaims {
///     fn iss(&self) -> &str { &self.iss }
///     fn sub(&self) -> &str { &self.sub }
///     fn aud(&self) -> &[String] { &self.aud }
///     fn exp(&self) -> i64 { self.exp }
/// }
///
/// struct MyIdentity {
///     user_id: String,
///     custom_data: String,
/// }
///
/// struct MyExtractor;
///
/// impl IdentityExtractor for MyExtractor {
///     type Claims = MyClaims;
///     type Identity = MyIdentity;
///
///     fn extract_identity(&self, claims: &Self::Claims) -> mozambigue::Result<Self::Identity> {
///         Ok(MyIdentity {
///             user_id: claims.sub.clone(),
///             custom_data: claims.custom_field.clone(),
///         })
///     }
/// }
/// ```
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
