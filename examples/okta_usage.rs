use mozambigue::JwtVerifier;
use mozambigue::JwtVerifierConfig;
use mozambigue::OktaExtractor;
use mozambigue::OktaJwtVerifier;
use mozambigue::VerifyJwt;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Simple usage with default settings
    println!("=== Example 1: Simple Okta Usage ===");
    let verifier =
        OktaJwtVerifier::with_issuer("https://your-org.okta.com/oauth2/default", "api://default")
            .await?;

    // Example JWT token (this is just a placeholder - use a real token in practice)
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

    // Verify the token
    match verifier.verify(token).await {
        Ok(identity) => {
            println!("Token verified successfully!");
            println!("  Subject: {}", identity.subject);
            if let Some(email) = &identity.email {
                println!("  Email: {email}");
            }
            if let Some(name) = &identity.name {
                println!("  Name: {name}");
            }
            if let Some(groups) = &identity.groups {
                println!("  Groups: {groups:?}");
            }
        }
        Err(e) => {
            eprintln!("Token verification failed: {e}");
        }
    }

    println!();

    // Example 2: Custom configuration with cache TTL
    println!("=== Example 2: Custom Configuration ===");
    let config =
        JwtVerifierConfig::new("https://your-org.okta.com/oauth2/default", "api://default")
            .with_cache_ttl(Duration::from_secs(1800)); // 30 minutes cache

    let verifier = JwtVerifier::new(config, OktaExtractor).await?;

    match verifier.verify(token).await {
        Ok(identity) => {
            println!("Token verified successfully!");
            println!("  Subject: {}", identity.subject);
            if let Some(email) = &identity.email {
                println!("  Email: {email}");
            }
        }
        Err(e) => {
            eprintln!("Token verification failed: {e}");
        }
    }

    Ok(())
}
