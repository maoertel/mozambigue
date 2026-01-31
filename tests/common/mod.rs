use std::sync::Arc;

use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::CommonParameters;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::jwk::PublicKeyUse;
use jsonwebtoken::jwk::RSAKeyParameters;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mockito::ServerGuard;
use serde::Serialize;
use serde_json::json;

/// Test RSA key pair
pub struct TestKeyPair {
    pub encoding_key: EncodingKey,
    pub kid: String,
    pub jwk: Jwk,
}

/// Generate a test RSA key pair
pub fn generate_test_keypair() -> TestKeyPair {
    let kid = "test-key-1".to_string();

    // RSA private key in PEM format (fresh test key, DO NOT use in production)
    let private_pem = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7EEbUelNkc489
p7FAHZ7ZjeJ78w8CaX9g1+ty0JOuXBYtx19cEhi/VaRl24M2GHAdllWLy037qMzf
h8MzCjZ92lzJRqXM/Stuhr+iOrC314ete8zWn56MC1jVPmjMch0zg5Z6IhW7Ux+W
ZT8wu5ehyFkgncdUZYD5l5zcDkSIYURE955IHog35eQJWPr1kci2ziEE4oYsnYoq
qhPJDvElSdUJpBGBO6Otkpin8B9lfWe7CSz7JHQcjE9pNrwwwycxB4kApUEwb4IY
U06P4y7qwa8rA/44lg72rZRYgNLcg9QXhv9qeWKai97a6JNOT9NEKb+1DDyu7k5D
9ESRKzK9AgMBAAECggEAAtPDpkl1AjMm6pEiwivQb0xQLHxncStkA/QveExDtyJo
KWf2fn89hYLHWczABmzHIQNZJqQ7eP67nfNA1YAlg7Btr5MURW1cHy8FLXACpLyq
rcoNtf6ymD5BqPNpBRICc/lcqFrkhjDC7PR5yIRFTeonwrDvxsxD70HF2qOSkJcV
GgiHvOTNiFk8BUk2P5kCOhkit8el3LQ4b2hnEmYklObGAc0DSKTFbK7Vo8HeKVA+
NBIvco9WwA5OLOBMKys41/T2efXqBx2X4R4uNSooUxU9drKX8JNdo8e4Plqt7x4J
USu5T8CLYPc7dkxeEZIac70OlCfydIedklxo4FV5IQKBgQDxWoOJ3ScsG9rNQnOY
AiUEFMlA7m3BHzcxLW02p3H9zbUFQEi/J674qrKM4RksUPy8NSfNj9glJ8ZmunKF
YycUQnp+QgB/IT9+rEu6kpGDi0Ls1cOe/p37GNGIE6obJ/+iyu7sCnpC1aLtMC8s
dyjr8Sxu2M9SCTBBnGDJ9KcR8QKBgQDGalrPbg6jyrCp1S4h/6KSdwWRqxpGD1Ee
SWUPEH/hHAt3YCkHvrh1ZMNGKfSQTaVdxqb1AFpQZ6RhE3Eb7rhfIUIbb1N6EmMP
QaCg88qABQTip/E/x8g1K263FrlwCUwf7dwN0wviQRGrW/B8siX+PQS6pIi+ljd/
SR2P3vphjQKBgDYVkHBubH7H5yoj//9KS700Yzz3sQSb2CRfB6A9uZ+kXzJEC4k6
fU0gA07qileR9nC+gKLh3w/EcANJOKyHYZR6qTRt2eqjKrVaKsYuXglaRa8I4ANb
D0/baejSb0YSmoiCbTPbzTX45b+9EnUmZrconkpgr2S0xmmNf2sCNgYhAoGAQKQP
l7qMTHJRYdMQ54SoCz15c/6hXafJzqssoF7IuqbvWWHbnClXYO+F6srqYUTalhWM
+Q63XbCWTgYOeIIqUNu99MAtGvz4htTjpuwl0dVQxSLfpt7IbAINXNqraUOuKEzO
vzY9jeWTAxe93nIPjKeGbeQCpMy9odtJJUEIo1UCgYAJMeF7iZ7YLu7N38dH5g79
h7JoZa7BwUl1brFC6/UhboKtlf2n7FyaYNe5cB7zGuxfDPykdKhrxZx1phxAMJhf
6ZN0DO1u2OnnOfSF2nWDKxzYGX4z0Kdl3gSi7JMQX5hrnbb1Iymjt65ULSEbGx03
qJMyfqo9ycZI9G491ENX0A==
-----END PRIVATE KEY-----"#;

    let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
        .expect("Failed to create encoding key");

    // Create JWK for this key
    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: None,  // Will be inferred from AlgorithmParameters
            key_id: Some(kid.clone()),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
            n: "ALsQRtR6U2Rzjz2nsUAdntmN4nvzDwJpf2DX63LQk65cFi3HX1wSGL9VpGXbgzYYcB2WVYvLTfuozN-HwzMKNn3aXMlGpcz9K26Gv6I6sLfXh617zNafnowLWNU-aMxyHTODlnoiFbtTH5ZlPzC7l6HIWSCdx1RlgPmXnNwORIhhRET3nkgeiDfl5AlY-vWRyLbOIQTihiydiiqqE8kO8SVJ1QmkEYE7o62SmKfwH2V9Z7sJLPskdByMT2k2vDDDJzEHiQClQTBvghhTTo_jLurBrysD_jiWDvatlFiA0tyD1BeG_2p5YpqL3trok05P00Qpv7UMPK7uTkP0RJErMr0".to_string(),
            e: "AQAB".to_string(),
        }),
    };

    TestKeyPair {
        encoding_key,
        kid,
        jwk,
    }
}

/// Create a test JWT with custom claims
pub fn create_test_jwt<T: Serialize>(
    claims: &T,
    key: &EncodingKey,
    kid: &str,
) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());

    jsonwebtoken::encode(&header, claims, key)
        .expect("Failed to encode JWT")
}

/// Create a mock JWKS response
pub fn create_mock_jwks(jwks: Vec<Jwk>) -> JwkSet {
    JwkSet { keys: jwks }
}

/// Setup a mock server with OpenID configuration and JWKS endpoints
pub async fn setup_mock_oidc_server(keypair: &TestKeyPair) -> ServerGuard {
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();
    let jwks_uri = format!("{}/jwks", issuer);

    // Mock OpenID configuration endpoint
    let openid_config = json!({
        "issuer": issuer,
        "jwks_uri": jwks_uri,
        "authorization_endpoint": format!("{}/auth", issuer),
        "token_endpoint": format!("{}/token", issuer),
    });

    server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openid_config.to_string())
        .create_async()
        .await;

    // Mock JWKS endpoint
    let jwks = create_mock_jwks(vec![keypair.jwk.clone()]);
    let jwks_json = serde_json::to_string(&jwks).unwrap();

    server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_json)
        .create_async()
        .await;

    server
}

/// Create test claims for Kubernetes service account token
#[derive(Debug, Serialize)]
pub struct TestClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    #[serde(rename = "kubernetes.io", skip_serializing_if = "Option::is_none")]
    pub kubernetes_io: Option<KubernetesIo>,
}

#[derive(Debug, Serialize)]
pub struct KubernetesIo {
    pub serviceaccount: ServiceAccount,
    pub namespace: Arc<str>,
}

#[derive(Debug, Serialize)]
pub struct ServiceAccount {
    pub name: Arc<str>,
}

impl TestClaims {
    /// Create valid claims that expire in 1 hour
    pub fn valid(issuer: String, audience: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer,
            sub: "system:serviceaccount:default:test-sa".to_string(),
            aud: vec![audience],
            exp: now + 3600,
            iat: now,
            kubernetes_io: Some(KubernetesIo {
                serviceaccount: ServiceAccount {
                    name: Arc::from("test-sa"),
                },
                namespace: Arc::from("default"),
            }),
        }
    }

    /// Create expired claims
    pub fn expired(issuer: String, audience: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer,
            sub: "system:serviceaccount:default:test-sa".to_string(),
            aud: vec![audience],
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 7200,
            kubernetes_io: Some(KubernetesIo {
                serviceaccount: ServiceAccount {
                    name: Arc::from("test-sa"),
                },
                namespace: Arc::from("default"),
            }),
        }
    }

    /// Create claims with wrong issuer
    pub fn wrong_issuer(audience: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: "https://wrong-issuer.example.com".to_string(),
            sub: "system:serviceaccount:default:test-sa".to_string(),
            aud: vec![audience],
            exp: now + 3600,
            iat: now,
            kubernetes_io: Some(KubernetesIo {
                serviceaccount: ServiceAccount {
                    name: Arc::from("test-sa"),
                },
                namespace: Arc::from("default"),
            }),
        }
    }

    /// Create claims with wrong audience
    pub fn wrong_audience(issuer: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer,
            sub: "system:serviceaccount:default:test-sa".to_string(),
            aud: vec!["wrong-audience".to_string()],
            exp: now + 3600,
            iat: now,
            kubernetes_io: Some(KubernetesIo {
                serviceaccount: ServiceAccount {
                    name: Arc::from("test-sa"),
                },
                namespace: Arc::from("default"),
            }),
        }
    }

    /// Create claims without kubernetes.io (fallback to sub parsing)
    pub fn without_kubernetes_io(issuer: String, audience: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            iss: issuer,
            sub: "system:serviceaccount:kube-system:my-service".to_string(),
            aud: vec![audience],
            exp: now + 3600,
            iat: now,
            kubernetes_io: None,
        }
    }
}
