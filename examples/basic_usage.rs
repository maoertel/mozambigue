use mozambigue::JwtVerifier;
use mozambigue::JwtVerifierConfig;
use mozambigue::KubernetesExtractor;
use mozambigue::VerifyJwt;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Simple usage with default settings
    println!("=== Example 1: Simple Usage ===");
    let verifier =
        JwtVerifier::with_issuer("https://kubernetes.default.svc.cluster.local", "my-service")
            .await?;

    // Example JWT token (this is just a placeholder - use a real token in practice)
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

    // Verify the token
    match verifier.verify(token).await {
        Ok(identity) => {
            println!("✓ Token verified successfully!");
            println!("  Service Account: {}", identity.service_account);
            println!("  Namespace: {}", identity.namespace);
        }
        Err(e) => {
            eprintln!("✗ Token verification failed: {}", e);
        }
    }

    println!();

    // Example 2: Custom configuration with cache TTL
    println!("=== Example 2: Custom Configuration ===");
    let config = JwtVerifierConfig::new("https://your-issuer.example.com", "my-service")
        .with_cache_ttl(Duration::from_secs(1800)); // 30 minutes cache

    let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;

    match verifier.verify(token).await {
        Ok(identity) => {
            println!("✓ Token verified successfully!");
            println!("  Service Account: {}", identity.service_account);
            println!("  Namespace: {}", identity.namespace);
        }
        Err(e) => {
            eprintln!("✗ Token verification failed: {}", e);
        }
    }

    println!();

    // Example 3: With custom HTTP client and multiple audiences
    println!("=== Example 3: Custom HTTP Client and Multiple Audiences ===");
    let custom_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let config = JwtVerifierConfig::new_with_audiences(
        "https://your-issuer.example.com",
        vec!["service-a".to_string(), "service-b".to_string()],
    )?
    .with_cache_ttl(Duration::from_secs(3600))
    .with_http_client(custom_client);

    let verifier = JwtVerifier::new(config, KubernetesExtractor).await?;

    match verifier.verify(token).await {
        Ok(identity) => {
            println!("✓ Token verified successfully!");
            println!("  Service Account: {}", identity.service_account);
            println!("  Namespace: {}", identity.namespace);
        }
        Err(e) => {
            eprintln!("✗ Token verification failed: {}", e);
        }
    }

    Ok(())
}
