mod common;

use std::time::Duration;

use mozambigue::{JwtVerifier, JwtVerifierConfig, VerifyJwt};

use common::{create_test_jwt, generate_test_keypair, setup_mock_oidc_server, TestClaims};

#[tokio::test]
async fn verify_valid_jwt_succeeds() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_ok());

    let subject = result.unwrap();
    assert_eq!(subject.service_account.as_ref(), "test-sa");
    assert_eq!(subject.namespace.as_ref(), "default");
}

#[tokio::test]
async fn verify_jwt_with_kubernetes_io_claim() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await.unwrap();

    // Should extract from kubernetes.io claim
    assert_eq!(result.service_account.as_ref(), "test-sa");
    assert_eq!(result.namespace.as_ref(), "default");
}

#[tokio::test]
async fn verify_jwt_with_sub_claim_fallback() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::without_kubernetes_io(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await.unwrap();

    // Should extract from sub claim
    assert_eq!(result.service_account.as_ref(), "my-service");
    assert_eq!(result.namespace.as_ref(), "kube-system");
}

#[tokio::test]
async fn verify_expired_token_fails() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::expired(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), mozambigue::Error::TokenExpired(_)));
}

#[tokio::test]
async fn verify_wrong_issuer_fails() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::wrong_issuer("my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), mozambigue::Error::WrongIssuer(_)));
}

#[tokio::test]
async fn verify_wrong_audience_fails() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::wrong_audience(issuer.clone());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    // Configure with expected audience "my-service" but token has "wrong-audience"
    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_err());
    // JWT validation error for invalid audience
    assert!(matches!(result.unwrap_err(), mozambigue::Error::Jwt(_)));
}

#[tokio::test]
async fn verify_token_with_missing_kid_fails() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::valid(issuer.clone(), "my-service".to_string());

    // Create JWT without kid in header
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let token = jsonwebtoken::encode(&header, &claims, &keypair.encoding_key).unwrap();

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), mozambigue::Error::KeyIdMissing));
}

#[tokio::test]
async fn accepts_token_matching_one_of_multiple_audiences() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    // Token has audience "service-b"
    let claims = TestClaims::valid(issuer.clone(), "service-b".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    // Configure with multiple audiences including "service-b"
    let config = JwtVerifierConfig::new_with_audiences(
        &issuer,
        vec!["service-a".to_string(), "service-b".to_string(), "service-c".to_string()],
    ).unwrap();
    let verifier = JwtVerifier::new(config).await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn validates_against_config_not_token_audience() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    // Token claims audience "attacker-service"
    let claims = TestClaims::valid(issuer.clone(), "attacker-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    // But we expect "my-service"
    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    // Should fail because we validate against config, not token's own audience
    let result = verifier.verify(&token).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn with_issuer_convenience_method_works() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let claims = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let verifier = JwtVerifier::with_issuer(&issuer, "my-service").await.unwrap();

    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn custom_cache_ttl_is_respected() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let config = JwtVerifierConfig::new(&issuer, "my-service")
        .with_cache_ttl(Duration::from_secs(1800));

    let verifier = JwtVerifier::new(config).await.unwrap();

    let claims = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn custom_http_client_works() {
    let keypair = generate_test_keypair();
    let server = setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let custom_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let config = JwtVerifierConfig::new(&issuer, "my-service")
        .with_http_client(custom_client);

    let verifier = JwtVerifier::new(config).await.unwrap();

    let claims = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token = create_test_jwt(&claims, &keypair.encoding_key, &keypair.kid);

    let result = verifier.verify(&token).await;
    assert!(result.is_ok());
}
