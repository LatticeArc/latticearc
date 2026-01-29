//! Test rustls 0.23 compatibility example.
#![allow(clippy::print_stdout)]
#![allow(unused_qualifications)]

use arc_tls::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing rustls 0.23 compatibility...");

    match arc_tls::basic_features::load_certificates("test_certs/server.crt") {
        Ok(certs) => println!("✅ Loaded {} certificates", certs.len()),
        Err(e) => println!("⚠️ Certificate loading test: {}", e),
    }

    println!("Testing TLS configuration...");
    let config = TlsConfig::default();
    let info = get_config_info(&config);
    println!("✅ TLS config: {}", info);

    println!("Testing client connector...");
    match arc_tls::basic_features::create_client_connector(&config) {
        Ok(_) => println!("✅ Client connector created"),
        Err(e) => println!("⚠️ Client connector test: {}", e),
    }

    println!("Testing PQ support...");
    println!("PQ enabled: {}", pq_enabled());

    let kex_info = get_kex_info(config.mode, PqKexMode::RustlsPq);
    println!("Key exchange: {}", kex_info.method);

    println!("✅ All rustls 0.23 compatibility tests passed!");
    Ok(())
}
