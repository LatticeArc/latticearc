#![deny(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::print_stdout)]
#![allow(clippy::indexing_slicing)]

//! TLS 1.3 Hybrid Client Example
//!
//! This example demonstrates how to use the TLS 1.3 client with
//! post-quantum key exchange (X25519MLKEM768).
//!
//! Run with:
//! ```bash
//! cargo run --example tls13_hybrid_client --features pq
//! ```
//!
//! Note: You'll need a TLS server running for this to connect to.

use arc_tls::*;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== TLS 1.3 Hybrid Client (Post-Quantum Key Exchange) ===\n");

    // Check if PQ support is enabled
    if !pq_enabled() {
        println!("⚠️  Post-quantum support not enabled!");
        println!("   Run with: cargo run --example tls13_hybrid_client --features pq\n");
    } else {
        println!("✅ Post-quantum support enabled");
        println!("   Using X25519MLKEM768 hybrid key exchange\n");
    }

    // Create TLS configuration (default: hybrid mode)
    let tls_config = TlsConfig::default();
    println!("TLS Configuration:");
    println!("  Mode: {:?}", tls_config.mode);
    println!("  Info: {}\n", get_config_info(&tls_config));

    // Get key exchange information
    let kex_mode = PqKexMode::RustlsPq;
    let kex_info = get_kex_info(tls_config.mode, kex_mode);
    println!("Key Exchange Info:");
    println!("  Method: {}", kex_info.method);
    println!("  Security: {}", kex_info.security_level);
    println!("  PQ Secure: {}", kex_info.is_pq_secure);
    println!("  Public Key Size: {} bytes", kex_info.pk_size);
    println!("  Shared Secret Size: {} bytes\n", kex_info.ss_size);

    // Server to connect to (change this to a real server)
    let server_addr = "example.com:443";
    let server_domain = "example.com";

    println!("Connecting to: {}\n", server_addr);

    // Note: This will fail with example.com as we don't have a real server
    // Replace with your own server for testing
    match tls_connect(server_addr, server_domain, &tls_config).await {
        Ok(mut stream) => {
            println!("✅ TLS connection established!\n");

            // Send HTTP GET request
            let request = format!(
                "GET / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Connection: close\r\n\r\n",
                server_domain
            );
            stream.write_all(request.as_bytes()).await?;
            println!("Sent HTTP request to server\n");

            // Read response
            let mut buffer = vec![0u8; 4096];
            let n = stream.read(&mut buffer).await?;
            println!("Received {} bytes from server", n);

            if n > 0 {
                let response = String::from_utf8_lossy(&buffer[..n]);
                println!("\n=== Response ===");
                println!("{}", response);
            }

            println!("\n✅ Connection completed successfully!");
        }
        Err(e) => {
            println!("❌ Connection failed: {}", e);
            println!("\nNote: This is expected with example.com");
            println!("Replace 'example.com:443' with your own server for testing");
        }
    }

    Ok(())
}
