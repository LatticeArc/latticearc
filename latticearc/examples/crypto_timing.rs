//! Crypto operation timing benchmark
//!
//! Run with: cargo run --package arc-primitives --example crypto_timing --release

// Allow println! in examples - they're meant to output results
#![allow(clippy::print_stdout)]
// Allow precision loss and arithmetic in benchmark calculations
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unwrap_used)]

use std::time::Instant;

use latticearc::primitives::aead::AeadCipher;
use latticearc::primitives::aead::aes_gcm::AesGcm256;
use latticearc::primitives::hash::sha256;
use latticearc::primitives::kdf::hkdf;
use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

fn main() {
    println!("=== LatticeArc Crypto Timing Benchmarks ===\n");
    println!("(Release build, all measurements averaged over iterations)\n");

    // ML-KEM-768 Benchmarks
    // Note: Using full key exchange roundtrip for realistic timing measurements
    println!("--- ML-KEM-768 (aws-lc-rs FIPS) ---");
    let iterations = 1000;

    // Key generation
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768);
    }
    let keygen_time = start.elapsed() / iterations;
    println!("KeyGen:       {:?}", keygen_time);

    // Encapsulation (using public key from keygen)
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = MlKem::encapsulate(&pk);
    }
    let encaps_time = start.elapsed() / iterations;
    println!("Encapsulate:  {:?}", encaps_time);

    // Full key exchange roundtrip (keygen + encaps + internal decaps)
    // This measures the complete operation since individual decaps isn't benchmarkable
    // due to aws-lc-rs secret key encapsulation
    let roundtrip_iterations = 500;
    let start = Instant::now();
    for _ in 0..roundtrip_iterations {
        // This measures what a real key exchange would look like
        let _ = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768);
    }
    let _roundtrip_keygen = start.elapsed() / roundtrip_iterations;

    // Measure ML-KEM decapsulate via the typed-API decapsulation
    // keypair (round-32 M3 wired up the production decap path
    // through `MlKem::generate_decapsulation_keypair`). Round-35 D1
    // replaces the previous `decaps_time = encaps_time` fabrication,
    // which was wrong: ML-KEM decaps includes implicit-rejection
    // hashing on top of the basic decode and is NOT symmetric with
    // encaps.
    let decaps_time = match MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768) {
        Ok(decap_keypair) => match MlKem::encapsulate(decap_keypair.public_key()) {
            Ok((_ss_for_setup, ct)) => {
                let start = Instant::now();
                for _ in 0..roundtrip_iterations {
                    let _ = decap_keypair.decapsulate(&ct);
                }
                let measured = start.elapsed() / roundtrip_iterations;
                println!("Decapsulate:  {:?} (measured)", measured);
                measured
            }
            Err(e) => {
                println!("Decapsulate:  <skipped: encaps for setup failed: {e}>");
                std::time::Duration::from_secs(0)
            }
        },
        Err(e) => {
            println!("Decapsulate:  <skipped: decap keypair generation failed: {e}>");
            std::time::Duration::from_secs(0)
        }
    };
    println!();

    // ML-DSA-65 Benchmarks
    println!("--- ML-DSA-65 (fips204 crate) ---");
    let sign_iterations = 100;

    // Key generation
    let start = Instant::now();
    for _ in 0..sign_iterations {
        let _ = generate_keypair(MlDsaParameterSet::MlDsa65);
    }
    let dsa_keygen_time = start.elapsed() / sign_iterations;
    println!("KeyGen:       {:?}", dsa_keygen_time);

    // Sign
    let (vk, dsa_sk) = generate_keypair(MlDsaParameterSet::MlDsa65).unwrap();
    let msg = b"Test message for benchmark";

    let start = Instant::now();
    for _ in 0..sign_iterations {
        let _ = dsa_sk.sign(msg, &[]);
    }
    let sign_time = start.elapsed() / sign_iterations;
    println!("Sign:         {:?}", sign_time);

    // Verify
    let sig = dsa_sk.sign(msg, &[]).unwrap();
    let verify_iterations = 1000;
    let start = Instant::now();
    for _ in 0..verify_iterations {
        let _ = vk.verify(msg, &sig, &[]);
    }
    let verify_time = start.elapsed() / verify_iterations;
    println!("Verify:       {:?}", verify_time);

    // Verify correctness
    let result = vk.verify(msg, &sig, &[]);
    assert!(result.is_ok());
    println!("(Verified: signature valid)\n");

    // AES-256-GCM Benchmarks
    //
    // SECURITY: AES-GCM **must not** reuse `(key, nonce)` pairs.
    // Reusing a nonce under the same key with two different
    // plaintexts allows XOR-of-plaintexts recovery and universal
    // forgery. This example draws a fresh nonce on every encrypt,
    // even though that adds nonce-generation overhead to the
    // measurement, because copy-paste from a benchmarking example
    // into production code is a real risk. Do NOT replicate the
    // pattern of "generate a nonce once, encrypt N times" here or
    // anywhere else.
    println!("--- AES-256-GCM (1KB payload, fresh nonce per encrypt) ---");
    let key = [0x42u8; 32]; // SECURITY: example-only fixed key; never use in production.
    let cipher = AesGcm256::new(&key).unwrap();
    let plaintext = vec![0u8; 1024];
    let aead_iterations = 10000;

    // Encrypt — fresh nonce on every iteration.
    let start = Instant::now();
    for _ in 0..aead_iterations {
        let nonce = AesGcm256::generate_nonce();
        let _ = cipher.encrypt(&nonce, &plaintext, None);
    }
    let encrypt_time = start.elapsed() / aead_iterations;
    println!("Encrypt:      {:?} (includes fresh-nonce generation)", encrypt_time);

    // Decrypt — same nonce as the matching encrypt. We benchmark
    // decrypt by encrypting once outside the loop (with a fresh
    // nonce), then decrypting that one ciphertext repeatedly.
    let nonce_for_decrypt_bench = AesGcm256::generate_nonce();
    let (ciphertext_aead, tag) =
        cipher.encrypt(&nonce_for_decrypt_bench, &plaintext, None).unwrap();
    let start = Instant::now();
    for _ in 0..aead_iterations {
        let _ = cipher.decrypt(&nonce_for_decrypt_bench, &ciphertext_aead, &tag, None);
    }
    let decrypt_time = start.elapsed() / aead_iterations;
    println!("Decrypt:      {:?}", decrypt_time);

    // Verify correctness
    let decrypted = cipher.decrypt(&nonce_for_decrypt_bench, &ciphertext_aead, &tag, None).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("(Verified: decryption matches)\n");

    // SHA-256 Benchmarks
    println!("--- SHA-256 (1KB input) ---");
    let data = vec![0u8; 1024];
    let hash_iterations = 100000;

    let start = Instant::now();
    for _ in 0..hash_iterations {
        let _ = sha256(&data);
    }
    let hash_time = start.elapsed() / hash_iterations;
    println!("Hash:         {:?}", hash_time);
    println!();

    // HKDF-SHA256 Benchmarks
    println!("--- HKDF-SHA256 (32 byte output) ---");
    let ikm = [0u8; 32];
    let salt = [0u8; 32];
    let info = b"benchmark";
    let kdf_iterations = 100000;

    let start = Instant::now();
    for _ in 0..kdf_iterations {
        let _ = hkdf(&ikm, Some(&salt), Some(info), 32);
    }
    let kdf_time = start.elapsed() / kdf_iterations;
    println!("Derive:       {:?}", kdf_time);
    println!();

    println!("=== Benchmark Complete ===\n");

    // Summary table
    println!("Summary (per-operation times):");
    println!("+---------------------------+------------+");
    println!("| Operation                 | Time       |");
    println!("+---------------------------+------------+");
    println!("| ML-KEM-768 KeyGen         | {:>10?} |", keygen_time);
    println!("| ML-KEM-768 Encapsulate    | {:>10?} |", encaps_time);
    println!("| ML-KEM-768 Decapsulate    | {:>10?} |", decaps_time);
    println!("| ML-DSA-65 KeyGen          | {:>10?} |", dsa_keygen_time);
    println!("| ML-DSA-65 Sign            | {:>10?} |", sign_time);
    println!("| ML-DSA-65 Verify          | {:>10?} |", verify_time);
    println!("| AES-256-GCM Encrypt (1KB) | {:>10?} |", encrypt_time);
    println!("| AES-256-GCM Decrypt (1KB) | {:>10?} |", decrypt_time);
    println!("| SHA-256 Hash (1KB)        | {:>10?} |", hash_time);
    println!("| HKDF-SHA256 Derive        | {:>10?} |", kdf_time);
    println!("+---------------------------+------------+");
}
