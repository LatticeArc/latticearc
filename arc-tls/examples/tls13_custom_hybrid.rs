#![deny(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::print_stdout)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::format_in_format_args)]

//! Custom Hybrid Key Exchange Example
//!
//! This example demonstrates how to use the custom hybrid key exchange
//! implementation from arc-hybrid module.
//!
//! This uses:
//! - ML-KEM-768 from arc-primitives
//! - X25519 from x25519-dalek
//! - HKDF for secret combination (NIST SP 800-56C)
//!
//! Run with:
//! ```bash
//! cargo run --example tls13_custom_hybrid
//! ```

use arc_tls::pq_key_exchange::{
    perform_hybrid_decapsulate, perform_hybrid_encapsulate, perform_hybrid_keygen,
};
use arc_tls::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Custom Hybrid Key Exchange Demo ===\n");

    // Check availability
    if !is_custom_hybrid_available() {
        println!("Custom hybrid implementation not available");
        return Ok(());
    }

    println!("Custom hybrid implementation available\n");

    // Get key exchange information
    let kex_info = get_kex_info(TlsMode::Hybrid, PqKexMode::CustomHybrid);
    println!("Key Exchange Info:");
    println!("  Method: {}", kex_info.method);
    println!("  Security: {}", kex_info.security_level);
    println!("  PQ Secure: {}", kex_info.is_pq_secure);
    println!("  Public Key Size: {} bytes", kex_info.pk_size);
    println!("  Secret Key Size: {} bytes", kex_info.sk_size);
    println!("  Ciphertext Size: {} bytes", kex_info.ct_size);
    println!("  Shared Secret Size: {} bytes\n", kex_info.ss_size);

    // Demonstrate key generation
    println!("=== Key Generation ===");
    let mut rng = rand::thread_rng();

    // Server generates keypair
    println!("Generating server keypair...");
    let (server_pk, server_sk) = perform_hybrid_keygen(&mut rng)?;
    println!("Server keypair generated");
    println!("  ML-KEM PK length: {} bytes", server_pk.ml_kem_pk.len());
    println!("  X25519 PK length: {} bytes\n", server_pk.ecdh_pk.len());

    // Demonstrate encapsulation (client side)
    println!("=== Encapsulation (Client) ===");
    println!("Client encapsulates to server's public key...");
    let encapsulated = perform_hybrid_encapsulate(&mut rng, &server_pk)?;
    println!("Encapsulation completed");
    println!("  ML-KEM CT length: {} bytes", encapsulated.ml_kem_ct.len());
    println!("  X25519 PK length: {} bytes", encapsulated.ecdh_pk.len());
    println!("  Shared Secret length: {} bytes\n", encapsulated.shared_secret.len());

    // Demonstrate decapsulation (server side)
    println!("=== Decapsulation (Server) ===");
    println!("Server decapsulates client's ciphertext...");
    let decapsulated_ss = perform_hybrid_decapsulate(&server_sk, &encapsulated)?;
    println!("Decapsulation completed");
    println!("  Shared Secret length: {} bytes\n", decapsulated_ss.len());

    // Verify shared secrets match
    println!("=== Verification ===");
    let encapsulated_ss: &[u8] = encapsulated.shared_secret.as_ref();
    if encapsulated_ss == decapsulated_ss.as_slice() {
        println!("Shared secrets match!");
        println!(
            "  Encapsulated: {}",
            format!("{:02x?}", &encapsulated_ss[..8.min(encapsulated_ss.len())])
        );
        println!(
            "  Decapsulated: {}",
            format!("{:02x?}", &decapsulated_ss[..8.min(decapsulated_ss.len())])
        );
        println!("\nKey exchange successful!");
    } else {
        println!("Shared secrets do NOT match!");
        println!(
            "  Encapsulated: {}",
            format!("{:02x?}", &encapsulated_ss[..8.min(encapsulated_ss.len())])
        );
        println!(
            "  Decapsulated: {}",
            format!("{:02x?}", &decapsulated_ss[..8.min(decapsulated_ss.len())])
        );
    }

    println!("\n=== Performance Characteristics ===");
    println!("This hybrid approach provides:");
    println!("  - Post-quantum security (ML-KEM-768)");
    println!("  - Classical security (X25519)");
    println!("  - Security requires breaking BOTH components");
    println!("  - Graceful fallback if ML-KEM is broken");
    println!("  - NIST SP 800-56C compliant key derivation");

    Ok(())
}
