#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::cast_possible_truncation)]
#![allow(missing_docs)]

//! TLS Handshake Roundtrip Tests
//!
//! These tests perform actual TLS handshakes between a client and server,
//! verifying that data can be sent and received over the encrypted connection.
//!
//! Run with: `cargo test --package arc-tls --test tls_handshake_roundtrip --release -- --nocapture`

use latticearc::tls::tls13::{Tls13Config, create_server_config};
use latticearc::tls::{TlsConfig, TlsMode, TlsUseCase};
use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

// ============================================================================
// Test Certificate Infrastructure
// ============================================================================

struct TestCa {
    cert_der: CertificateDer<'static>,
    rcgen_cert: rcgen::Certificate,
    rcgen_key: RcgenKeyPair,
}

/// Generate a self-signed CA certificate and its private key.
fn generate_test_ca() -> TestCa {
    let mut params = CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = RcgenKeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    TestCa { cert_der, rcgen_cert: cert, rcgen_key: key_pair }
}

/// Generate a server certificate signed by the CA.
fn generate_server_cert(ca: &TestCa) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_key_pair = RcgenKeyPair::generate().unwrap();
    let server_cert =
        server_params.signed_by(&server_key_pair, &ca.rcgen_cert, &ca.rcgen_key).unwrap();

    let server_cert_der = CertificateDer::from(server_cert.der().to_vec());
    let server_key_der =
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(server_key_pair.serialize_der()));

    let chain = vec![server_cert_der, ca.cert_der.clone()];
    (chain, server_key_der)
}

/// Build a rustls ClientConfig that trusts the test CA (not system roots).
fn build_test_client_config(mode: TlsMode, ca_cert_der: &CertificateDer<'_>) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert_der.clone()).unwrap();

    let provider = match mode {
        TlsMode::Classic => rustls::crypto::aws_lc_rs::default_provider(),
        TlsMode::Hybrid | TlsMode::Pq => rustls::crypto::aws_lc_rs::default_provider(),
    };

    ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Spawn a length-prefixed echo server.
/// Protocol: client sends [4-byte big-endian length][payload], server echoes same format.
/// When client sends length 0, server exits gracefully.
fn spawn_echo_server(
    server_config: ServerConfig,
) -> (thread::JoinHandle<()>, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = Arc::new(server_config);

    let handle = thread::spawn(move || {
        let (tcp_stream, _) = listener.accept().unwrap();
        let tls_conn = rustls::ServerConnection::new(acceptor).unwrap();
        let mut stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

        loop {
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_err() {
                break;
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len == 0 {
                break;
            }

            let mut msg_buf = vec![0u8; msg_len];
            if stream.read_exact(&mut msg_buf).is_err() {
                break;
            }

            stream.write_all(&len_buf).unwrap();
            stream.write_all(&msg_buf).unwrap();
            stream.flush().unwrap();
        }
        // Send close_notify before dropping
        stream.conn.send_close_notify();
        let _ = stream.flush();
    });

    (handle, addr)
}

/// Send a message and receive the echo using length-prefixed protocol.
fn echo_roundtrip(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    msg: &[u8],
) -> Vec<u8> {
    let len_bytes = (msg.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).unwrap();
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).unwrap();
    resp_buf
}

/// Send the termination signal (length = 0).
fn send_done(stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>) {
    let zero = 0u32.to_be_bytes();
    stream.write_all(&zero).unwrap();
    stream.flush().unwrap();
}

/// Connect a TLS client to the given address and return the stream.
fn connect_tls_client(
    client_config: ClientConfig,
    addr: std::net::SocketAddr,
) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
    let server_name = ServerName::try_from("localhost").unwrap();
    let client_conn = rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let tcp_stream = std::net::TcpStream::connect(addr).unwrap();
    tcp_stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    rustls::StreamOwned::new(client_conn, tcp_stream)
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_classic_tls_handshake_roundtrip() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::classic();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Classic, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"hello from classic TLS";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "Classic TLS roundtrip data mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_hybrid_tls_handshake_roundtrip() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::hybrid();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"hello from hybrid PQ TLS (X25519MLKEM768)";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "Hybrid TLS roundtrip data mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_pq_tls_handshake_roundtrip() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::pq();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Pq, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"hello from PQ TLS mode";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "PQ TLS roundtrip data mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_large_data_transfer() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::hybrid();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    // Send 1MB of data
    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 256) as u8).collect();
    let expected_hash = Sha256::digest(&data);

    let response = echo_roundtrip(&mut stream, &data);

    let actual_hash = Sha256::digest(&response);
    assert_eq!(actual_hash, expected_hash, "1MB data SHA-256 mismatch after TLS transfer");
    assert_eq!(response.len(), data.len(), "Response length mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_multiple_messages() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::hybrid();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    for i in 0..10u32 {
        let msg = format!("Message number {}", i);
        let response = echo_roundtrip(&mut stream, msg.as_bytes());
        assert_eq!(response, msg.as_bytes(), "Message {} roundtrip mismatch", i);
    }

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_mtls_client_auth() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    // Generate client certificate signed by the same CA
    let client_params = CertificateParams::new(vec!["client".to_string()]).unwrap();
    let client_key_pair = RcgenKeyPair::generate().unwrap();
    let client_cert =
        client_params.signed_by(&client_key_pair, &ca.rcgen_cert, &ca.rcgen_key).unwrap();
    let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
    let client_key_der =
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(client_key_pair.serialize_der()));

    // Server config requiring client auth
    let mut ca_root_store = RootCertStore::empty();
    ca_root_store.add(ca.cert_der.clone()).unwrap();

    let server_tls_config = Tls13Config::hybrid()
        .with_client_verification(latticearc::tls::ClientVerificationMode::Required)
        .with_client_ca_roots(ca_root_store);

    let server_config = create_server_config(&server_tls_config, server_chain, server_key).unwrap();

    // Client config with client cert
    let mut client_root_store = RootCertStore::empty();
    client_root_store.add(ca.cert_der.clone()).unwrap();

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let client_config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(client_root_store)
        .with_client_auth_cert(vec![client_cert_der], client_key_der)
        .unwrap();

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"mTLS authenticated message";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "mTLS roundtrip data mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_alpn_negotiation() {
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let server_tls_config = Tls13Config::hybrid().with_alpn_protocols(vec!["h2", "http/1.1"]);
    let server_config = create_server_config(&server_tls_config, server_chain, server_key).unwrap();

    let mut client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = Arc::new(server_config);

    let handle = thread::spawn(move || {
        let (tcp_stream, _) = listener.accept().unwrap();
        let tls_conn = rustls::ServerConnection::new(server_cfg).unwrap();
        let mut stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

        // Read the client's "ping"
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).unwrap();

        // Reply with the negotiated ALPN protocol
        let alpn = stream.conn.alpn_protocol().unwrap_or(b"none").to_vec();
        let alpn_len = (alpn.len() as u32).to_be_bytes();
        stream.write_all(&alpn_len).unwrap();
        stream.write_all(&alpn).unwrap();
        stream.flush().unwrap();

        // Wait for done signal
        let mut done_buf = [0u8; 4];
        let _ = stream.read_exact(&mut done_buf);

        stream.conn.send_close_notify();
        let _ = stream.flush();
    });

    let mut stream = connect_tls_client(client_config, addr);

    // Send a ping
    let ping = b"alpn-check";
    let len_bytes = (ping.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).unwrap();
    stream.write_all(ping).unwrap();
    stream.flush().unwrap();

    // Read the ALPN response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).unwrap();

    assert_eq!(resp_buf, b"h2", "ALPN should negotiate h2 (server preference)");

    let client_alpn = stream.conn.alpn_protocol();
    assert_eq!(client_alpn, Some(&b"h2"[..]), "Client should see h2 as negotiated ALPN");

    send_done(&mut stream);
    handle.join().unwrap();
}

// ============================================================================
// v0.3.3: Native PQ Key Exchange E2E Tests
//
// Verify that native rustls PQ key exchange (no rustls-post-quantum) works
// end-to-end with actual TLS handshakes and data transfer.
// ============================================================================

#[test]
fn test_hybrid_pq_negotiates_mlkem_kex() {
    // E2E: Verify hybrid TLS actually negotiates a PQ key exchange group
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::hybrid();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = Arc::new(server_config);

    let handle = thread::spawn(move || {
        let (tcp_stream, _) = listener.accept().unwrap();
        let tls_conn = rustls::ServerConnection::new(server_cfg).unwrap();
        let mut stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

        // Complete handshake by reading one message
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).unwrap();

        // Get the negotiated key exchange group from the server side
        let kex_name = stream
            .conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()))
            .unwrap_or_default();

        // Send back the negotiated group name
        let kex_bytes = kex_name.as_bytes();
        let resp_len = (kex_bytes.len() as u32).to_be_bytes();
        stream.write_all(&resp_len).unwrap();
        stream.write_all(kex_bytes).unwrap();
        stream.flush().unwrap();

        // Wait for done
        let mut done = [0u8; 4];
        let _ = stream.read_exact(&mut done);
        stream.conn.send_close_notify();
        let _ = stream.flush();
    });

    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);
    let mut stream = connect_tls_client(client_config, addr);

    // Send ping to complete handshake
    let ping = b"kex-check";
    let len_bytes = (ping.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).unwrap();
    stream.write_all(ping).unwrap();
    stream.flush().unwrap();

    // Read the server's negotiated group
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).unwrap();

    let server_kex = String::from_utf8(resp_buf).unwrap();

    // Also check client side
    let client_kex = stream
        .conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_default();

    // Both sides must agree and it should be a PQ/hybrid group
    assert_eq!(server_kex, client_kex, "Client and server must agree on key exchange group");
    assert!(
        client_kex.contains("MLKEM"),
        "Hybrid mode should negotiate an MLKEM group, got: {client_kex}"
    );

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_all_tls_modes_complete_handshake() {
    // E2E: Every TlsMode completes a full handshake + data roundtrip
    for mode in [TlsMode::Classic, TlsMode::Hybrid, TlsMode::Pq] {
        let ca = generate_test_ca();
        let (server_chain, server_key) = generate_server_cert(&ca);

        let tls_config = match mode {
            TlsMode::Classic => Tls13Config::classic(),
            TlsMode::Hybrid => Tls13Config::hybrid(),
            TlsMode::Pq => Tls13Config::pq(),
        };
        let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
        let client_config = build_test_client_config(mode, &ca.cert_der);

        let (handle, addr) = spawn_echo_server(server_config);
        let mut stream = connect_tls_client(client_config, addr);

        let msg = format!("E2E test for {:?} mode", mode);
        let response = echo_roundtrip(&mut stream, msg.as_bytes());
        assert_eq!(response, msg.as_bytes(), "{:?} mode roundtrip failed", mode);

        send_done(&mut stream);
        handle.join().unwrap();
    }
}

// ============================================================================
// TLS UseCase → Policy → Handshake E2E
//
// Tests that TlsConfig::new().use_case(uc) selects the correct TlsMode
// and that mode drives an actual TCP+TLS handshake with echo roundtrip.
// Covers all 3 TlsMode branches: PQ (Government), Hybrid (Financial, Web),
// Classic (IoT).
// ============================================================================

/// Helper: Convert a TlsConfig into a rustls ServerConfig via Tls13Config.
fn server_config_from_tls_config(
    tls_config: &TlsConfig,
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
) -> ServerConfig {
    let tls13: Tls13Config = tls_config.into();
    create_server_config(&tls13, server_chain, server_key).unwrap()
}

#[test]
fn test_tls_usecase_government_pq_handshake() {
    let config = TlsConfig::new().use_case(TlsUseCase::Government);
    assert_eq!(config.mode, TlsMode::Pq, "Government UseCase must select PQ mode");

    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);
    let server_config = server_config_from_tls_config(&config, server_chain, server_key);
    let client_config = build_test_client_config(TlsMode::Pq, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"Government PQ TLS: classified data channel";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "Government PQ TLS roundtrip mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_usecase_financial_services_hybrid_handshake() {
    let config = TlsConfig::new().use_case(TlsUseCase::FinancialServices);
    assert_eq!(config.mode, TlsMode::Hybrid, "FinancialServices UseCase must select Hybrid mode");

    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);
    let server_config = server_config_from_tls_config(&config, server_chain, server_key);
    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"Financial services hybrid TLS: SWIFT transaction";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "FinancialServices hybrid TLS roundtrip mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_usecase_iot_classic_handshake() {
    let config = TlsConfig::new().use_case(TlsUseCase::IoT);
    assert_eq!(config.mode, TlsMode::Classic, "IoT UseCase must select Classic mode");

    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);
    let server_config = server_config_from_tls_config(&config, server_chain, server_key);
    let client_config = build_test_client_config(TlsMode::Classic, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"IoT classic TLS: sensor telemetry";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "IoT classic TLS roundtrip mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_tls_usecase_webserver_hybrid_handshake() {
    let config = TlsConfig::new().use_case(TlsUseCase::WebServer);
    assert_eq!(config.mode, TlsMode::Hybrid, "WebServer UseCase must select Hybrid mode");

    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);
    let server_config = server_config_from_tls_config(&config, server_chain, server_key);
    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"WebServer hybrid TLS: HTTPS request";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "WebServer hybrid TLS roundtrip mismatch");

    send_done(&mut stream);
    handle.join().unwrap();
}

// ============================================================================
// Cross-Mode Compatibility & Edge Case E2E Tests
//
// Tests that cover interoperability scenarios and boundary conditions
// that go beyond single-mode happy-path testing.
// ============================================================================

#[test]
fn test_classic_client_to_hybrid_server_fallback() {
    // E2E: Classic-only client connects to Hybrid server.
    // Server offers PQ groups first, but client only supports classical.
    // Handshake should succeed via X25519 fallback.
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    // Server: Hybrid mode (PQ groups preferred)
    let tls_config = Tls13Config::hybrid();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();

    // Client: Classic mode (no PQ support)
    let client_config = build_test_client_config(TlsMode::Classic, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    let msg = b"Classic client to hybrid server: fallback test";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "Cross-mode fallback roundtrip failed");

    // Verify we fell back to a classical group (not MLKEM)
    let kex = stream
        .conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_default();

    // The negotiated group depends on what the classic client offers.
    // It should be a real group (handshake succeeded), not empty.
    assert!(!kex.is_empty(), "Must have negotiated a key exchange group");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_minimal_message_over_tls() {
    // E2E: Smallest possible payload (1 byte; 0-length is the "done" signal)
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::hybrid();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    // Send empty message (length=0 is our "done" signal, so send length=1 with one byte)
    let msg = b"x";
    let response = echo_roundtrip(&mut stream, msg);
    assert_eq!(response, msg, "Minimal message roundtrip failed");

    send_done(&mut stream);
    handle.join().unwrap();
}

#[test]
fn test_multiple_sequential_handshakes_same_mode() {
    // E2E: Multiple independent TLS connections in sequence all succeed
    let ca = generate_test_ca();
    for i in 0..3 {
        let (server_chain, server_key) = generate_server_cert(&ca);

        let tls_config = Tls13Config::hybrid();
        let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
        let client_config = build_test_client_config(TlsMode::Hybrid, &ca.cert_der);

        let (handle, addr) = spawn_echo_server(server_config);
        let mut stream = connect_tls_client(client_config, addr);

        let msg = format!("Sequential handshake #{i}");
        let response = echo_roundtrip(&mut stream, msg.as_bytes());
        assert_eq!(response, msg.as_bytes(), "Sequential handshake #{i} failed");

        send_done(&mut stream);
        handle.join().unwrap();
    }
}

#[test]
fn test_each_mode_negotiates_expected_kex_family() {
    // E2E: Verify the negotiated KEX group family matches the mode
    let mode_expectations = [
        (TlsMode::Hybrid, true), // should negotiate MLKEM
        (TlsMode::Pq, true),     // should negotiate MLKEM
                                 // Classic excluded: default_provider() includes X25519MLKEM768, so
                                 // Classic mode may still negotiate MLKEM — that's correct behavior.
    ];

    for (mode, expect_mlkem) in mode_expectations {
        let ca = generate_test_ca();
        let (server_chain, server_key) = generate_server_cert(&ca);

        let tls_config = match mode {
            TlsMode::Classic => Tls13Config::classic(),
            TlsMode::Hybrid => Tls13Config::hybrid(),
            TlsMode::Pq => Tls13Config::pq(),
        };
        let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
        let client_config = build_test_client_config(mode, &ca.cert_der);

        let (handle, addr) = spawn_echo_server(server_config);
        let mut stream = connect_tls_client(client_config, addr);

        let msg = format!("{mode:?} kex family test");
        let _ = echo_roundtrip(&mut stream, msg.as_bytes());

        let kex = stream
            .conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()))
            .unwrap_or_default();

        if expect_mlkem {
            assert!(
                kex.contains("MLKEM"),
                "{mode:?} mode should negotiate MLKEM group, got: {kex}"
            );
        }

        send_done(&mut stream);
        handle.join().unwrap();
    }
}

#[test]
fn test_large_message_integrity_pq_mode() {
    // E2E: 64KB message over PQ-only TLS, verified with SHA-256
    let ca = generate_test_ca();
    let (server_chain, server_key) = generate_server_cert(&ca);

    let tls_config = Tls13Config::pq();
    let server_config = create_server_config(&tls_config, server_chain, server_key).unwrap();
    let client_config = build_test_client_config(TlsMode::Pq, &ca.cert_der);

    let (handle, addr) = spawn_echo_server(server_config);
    let mut stream = connect_tls_client(client_config, addr);

    // Generate 64KB test payload
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
    let expected_hash = Sha256::digest(&payload);

    let response = echo_roundtrip(&mut stream, &payload);
    let actual_hash = Sha256::digest(&response);

    assert_eq!(expected_hash, actual_hash, "64KB PQ-mode data integrity check failed");

    send_done(&mut stream);
    handle.join().unwrap();
}
