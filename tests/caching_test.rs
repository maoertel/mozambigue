mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use mozambigue::{JwtVerifier, JwtVerifierConfig, VerifyJwt};
use mockito::ServerGuard;

use common::{create_test_jwt, generate_test_keypair, TestClaims, TestKeyPair};

async fn setup_mock_server_with_counter(counter: Arc<AtomicU32>) -> (ServerGuard, TestKeyPair) {
    let keypair = generate_test_keypair();
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();
    let jwks_uri = format!("{}/jwks", issuer);

    // Mock OpenID configuration endpoint
    let openid_config = serde_json::json!({
        "issuer": &issuer,
        "jwks_uri": &jwks_uri,
    });

    server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(openid_config.to_string())
        .create_async()
        .await;

    // Mock JWKS endpoint with counter
    let jwks = common::create_mock_jwks(vec![keypair.jwk.clone()]);
    let jwks_json = serde_json::to_string(&jwks).unwrap();

    let counter_clone = Arc::clone(&counter);
    server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |_| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            jwks_json.clone().into()
        })
        .create_async()
        .await;

    (server, keypair)
}

#[tokio::test]
async fn jwks_cached_between_requests() {
    let fetch_counter = Arc::new(AtomicU32::new(0));
    let (server, keypair) = setup_mock_server_with_counter(Arc::clone(&fetch_counter)).await;
    let issuer = server.url();

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = JwtVerifier::new(config).await.unwrap();

    // First request - should fetch JWKS
    let claims1 = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token1 = create_test_jwt(&claims1, &keypair.encoding_key, &keypair.kid);
    let result1 = verifier.verify(&token1).await;
    assert!(result1.is_ok());

    // Wait a bit to ensure the first request completed
    tokio::time::sleep(Duration::from_millis(100)).await;

    let fetches_after_first = fetch_counter.load(Ordering::SeqCst);
    assert_eq!(fetches_after_first, 1, "First request should fetch JWKS");

    // Second request - should use cache
    let claims2 = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token2 = create_test_jwt(&claims2, &keypair.encoding_key, &keypair.kid);
    let result2 = verifier.verify(&token2).await;
    assert!(result2.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;

    let fetches_after_second = fetch_counter.load(Ordering::SeqCst);
    assert_eq!(fetches_after_second, 1, "Second request should use cached JWKS, not fetch again");

    // Third request - still cached
    let claims3 = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token3 = create_test_jwt(&claims3, &keypair.encoding_key, &keypair.kid);
    let result3 = verifier.verify(&token3).await;
    assert!(result3.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;

    let fetches_after_third = fetch_counter.load(Ordering::SeqCst);
    assert_eq!(fetches_after_third, 1, "Third request should still use cached JWKS");
}

#[tokio::test]
async fn jwks_cache_expires_after_ttl() {
    let fetch_counter = Arc::new(AtomicU32::new(0));
    let (server, keypair) = setup_mock_server_with_counter(Arc::clone(&fetch_counter)).await;
    let issuer = server.url();

    // Set very short cache TTL (1 second)
    let config = JwtVerifierConfig::new(&issuer, "my-service")
        .with_cache_ttl(Duration::from_secs(1));
    let verifier = JwtVerifier::new(config).await.unwrap();

    // First request
    let claims1 = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token1 = create_test_jwt(&claims1, &keypair.encoding_key, &keypair.kid);
    verifier.verify(&token1).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fetch_counter.load(Ordering::SeqCst), 1);

    // Wait for cache to expire (1 second + buffer)
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Second request after expiration - should fetch again
    let claims2 = TestClaims::valid(issuer.clone(), "my-service".to_string());
    let token2 = create_test_jwt(&claims2, &keypair.encoding_key, &keypair.kid);
    verifier.verify(&token2).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fetch_counter.load(Ordering::SeqCst), 2, "Cache should have expired, forcing a refresh");
}

#[tokio::test]
async fn multiple_verifiers_can_verify_concurrently() {
    let keypair = generate_test_keypair();
    let server = common::setup_mock_oidc_server(&keypair).await;
    let issuer = server.url();

    let config = JwtVerifierConfig::new(&issuer, "my-service");
    let verifier = Arc::new(JwtVerifier::new(config).await.unwrap());

    // Create multiple verification tasks
    let mut handles = vec![];

    for _ in 0..10 {
        let verifier_clone = Arc::clone(&verifier);
        let issuer_clone = issuer.clone();
        let keypair_kid = keypair.kid.clone();
        let encoding_key = keypair.encoding_key.clone();

        let handle = tokio::spawn(async move {
            let claims = TestClaims::valid(issuer_clone, "my-service".to_string());
            let token = create_test_jwt(&claims, &encoding_key, &keypair_kid);
            verifier_clone.verify(&token).await
        });

        handles.push(handle);
    }

    // Wait for all verifications to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent verification failed");
    }
}

#[tokio::test]
async fn cache_handles_different_issuers() {
    let keypair1 = generate_test_keypair();
    let server1 = common::setup_mock_oidc_server(&keypair1).await;
    let issuer1 = server1.url();

    let keypair2 = generate_test_keypair();
    let server2 = common::setup_mock_oidc_server(&keypair2).await;
    let issuer2 = server2.url();

    // Create verifier for issuer1
    let config1 = JwtVerifierConfig::new(&issuer1, "service-1");
    let verifier1 = JwtVerifier::new(config1).await.unwrap();

    // Create verifier for issuer2
    let config2 = JwtVerifierConfig::new(&issuer2, "service-2");
    let verifier2 = JwtVerifier::new(config2).await.unwrap();

    // Verify token from issuer1
    let claims1 = TestClaims::valid(issuer1.clone(), "service-1".to_string());
    let token1 = create_test_jwt(&claims1, &keypair1.encoding_key, &keypair1.kid);
    let result1 = verifier1.verify(&token1).await;
    assert!(result1.is_ok());

    // Verify token from issuer2
    let claims2 = TestClaims::valid(issuer2.clone(), "service-2".to_string());
    let token2 = create_test_jwt(&claims2, &keypair2.encoding_key, &keypair2.kid);
    let result2 = verifier2.verify(&token2).await;
    assert!(result2.is_ok());

    // Both should work independently
    assert_eq!(result1.unwrap().namespace.as_ref(), "default");
    assert_eq!(result2.unwrap().namespace.as_ref(), "default");
}
