//! Key generation command.
//!
//! Generates cryptographic keys for signing, encryption, or key exchange.
//! Supports 12 algorithm variants across three categories:
//!
//! - **Post-quantum signatures:** ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205),
//!   FN-DSA-512 (FIPS 206 draft)
//! - **Classical & hybrid:** Ed25519 (RFC 8032), AES-256 (FIPS 197),
//!   Hybrid ML-DSA+Ed25519, Hybrid ML-KEM+X25519
//! - **Key encapsulation:** ML-KEM-512/768/1024 (FIPS 203)
//!
//! Key files are written as JSON with Base64-encoded key material.
//! Secret and symmetric keys are restricted to 0600 permissions on Unix
//! and zeroized from memory on drop.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Supported key generation algorithms.
#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum Algorithm {
    /// AES-256 symmetric key (32 random bytes).
    Aes256,
    /// ML-KEM-768 key encapsulation (FIPS 203). Default hybrid encryption.
    MlKem768,
    /// ML-KEM-512 key encapsulation (FIPS 203). Faster, smaller.
    MlKem512,
    /// ML-KEM-1024 key encapsulation (FIPS 203). Highest security.
    MlKem1024,
    /// ML-DSA-65 digital signature (FIPS 204). Default signing.
    MlDsa65,
    /// ML-DSA-44 digital signature (FIPS 204). Faster, smaller.
    MlDsa44,
    /// ML-DSA-87 digital signature (FIPS 204). Highest security.
    MlDsa87,
    /// SLH-DSA-SHAKE-128s hash-based signature (FIPS 205). Stateless, conservative.
    SlhDsa128s,
    /// FN-DSA-512 lattice signature (FIPS 206 draft). Compact signatures.
    FnDsa512,
    /// Ed25519 classical signature. Fast, small keys.
    Ed25519,
    /// Hybrid ML-KEM-768 + X25519 encryption keypair.
    Hybrid,
    /// Hybrid ML-DSA-65 + Ed25519 signing keypair.
    HybridSign,
}

/// Arguments for the `keygen` subcommand.
#[derive(Args)]
pub(crate) struct KeygenArgs {
    /// Algorithm to generate keys for.
    #[arg(short, long, value_enum)]
    pub algorithm: Algorithm,
    /// Output directory for key files (defaults to current directory).
    #[arg(short, long, default_value = ".")]
    pub output: PathBuf,
    /// Optional label for the key.
    #[arg(short, long)]
    pub label: Option<String>,
}

/// Execute the keygen command.
pub(crate) fn run(args: KeygenArgs) -> Result<()> {
    std::fs::create_dir_all(&args.output)?;

    match args.algorithm {
        Algorithm::Aes256 => generate_symmetric(&args),
        Algorithm::MlKem768 => {
            generate_ml_kem(&args, latticearc::primitives::kem::MlKemSecurityLevel::MlKem768)
        }
        Algorithm::MlKem512 => {
            generate_ml_kem(&args, latticearc::primitives::kem::MlKemSecurityLevel::MlKem512)
        }
        Algorithm::MlKem1024 => {
            generate_ml_kem(&args, latticearc::primitives::kem::MlKemSecurityLevel::MlKem1024)
        }
        Algorithm::MlDsa65 => {
            generate_ml_dsa(&args, latticearc::primitives::sig::MlDsaParameterSet::MLDSA65)
        }
        Algorithm::MlDsa44 => {
            generate_ml_dsa(&args, latticearc::primitives::sig::MlDsaParameterSet::MLDSA44)
        }
        Algorithm::MlDsa87 => {
            generate_ml_dsa(&args, latticearc::primitives::sig::MlDsaParameterSet::MLDSA87)
        }
        Algorithm::SlhDsa128s => generate_slh_dsa(&args),
        Algorithm::FnDsa512 => generate_fn_dsa(&args),
        Algorithm::Ed25519 => generate_ed25519(&args),
        Algorithm::Hybrid => generate_hybrid_kem(&args),
        Algorithm::HybridSign => generate_hybrid_sign(&args),
    }
}

fn generate_symmetric(args: &KeygenArgs) -> Result<()> {
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);

    let kf = KeyFile::new("aes-256", KeyType::Symmetric, &key, args.label.clone());
    let path = args.output.join("aes256.key.json");
    kf.write_to(&path)?;

    // Zeroize the key bytes
    zeroize::Zeroize::zeroize(&mut key);

    println!("Generated AES-256 symmetric key: {}", path.display());
    Ok(())
}

fn generate_ml_kem(
    args: &KeygenArgs,
    level: latticearc::primitives::kem::MlKemSecurityLevel,
) -> Result<()> {
    let alg_name = match level {
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem512 => "ml-kem-512",
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem768 => "ml-kem-768",
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem1024 => "ml-kem-1024",
    };

    let (pk, sk) = latticearc::generate_ml_kem_keypair(level)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_file = KeyFile::new(alg_name, KeyType::Public, pk.as_ref(), args.label.clone());
    let sk_file = KeyFile::new(alg_name, KeyType::Secret, sk.as_ref(), args.label.clone());

    let pk_path = args.output.join(format!("{alg_name}.pub.json"));
    let sk_path = args.output.join(format!("{alg_name}.sec.json"));

    pk_file.write_to(&pk_path)?;
    sk_file.write_to(&sk_path)?;

    println!("Generated {alg_name} keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_ml_dsa(
    args: &KeygenArgs,
    param_set: latticearc::primitives::sig::MlDsaParameterSet,
) -> Result<()> {
    let alg_name = match param_set {
        latticearc::primitives::sig::MlDsaParameterSet::MLDSA44 => "ml-dsa-44",
        latticearc::primitives::sig::MlDsaParameterSet::MLDSA65 => "ml-dsa-65",
        latticearc::primitives::sig::MlDsaParameterSet::MLDSA87 => "ml-dsa-87",
        _ => return Err(anyhow::anyhow!("Unsupported ML-DSA parameter set")),
    };

    let (pk, sk) = latticearc::generate_ml_dsa_keypair(param_set)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_file = KeyFile::new(alg_name, KeyType::Public, pk.as_ref(), args.label.clone());
    let sk_file = KeyFile::new(alg_name, KeyType::Secret, sk.as_ref(), args.label.clone());

    let pk_path = args.output.join(format!("{alg_name}.pub.json"));
    let sk_path = args.output.join(format!("{alg_name}.sec.json"));

    pk_file.write_to(&pk_path)?;
    sk_file.write_to(&sk_path)?;

    println!("Generated {alg_name} signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_slh_dsa(args: &KeygenArgs) -> Result<()> {
    let level = latticearc::primitives::sig::slh_dsa::SecurityLevel::Shake128s;
    let (pk, sk) = latticearc::generate_slh_dsa_keypair(level)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_file =
        KeyFile::new("slh-dsa-shake-128s", KeyType::Public, pk.as_ref(), args.label.clone());
    let sk_file =
        KeyFile::new("slh-dsa-shake-128s", KeyType::Secret, sk.as_ref(), args.label.clone());

    let pk_path = args.output.join("slh-dsa-shake-128s.pub.json");
    let sk_path = args.output.join("slh-dsa-shake-128s.sec.json");

    pk_file.write_to(&pk_path)?;
    sk_file.write_to(&sk_path)?;

    println!("Generated SLH-DSA-SHAKE-128s signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_fn_dsa(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_fn_dsa_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_file = KeyFile::new("fn-dsa-512", KeyType::Public, pk.as_ref(), args.label.clone());
    let sk_file = KeyFile::new("fn-dsa-512", KeyType::Secret, sk.as_ref(), args.label.clone());

    let pk_path = args.output.join("fn-dsa-512.pub.json");
    let sk_path = args.output.join("fn-dsa-512.sec.json");

    pk_file.write_to(&pk_path)?;
    sk_file.write_to(&sk_path)?;

    println!("Generated FN-DSA-512 signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_ed25519(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_file = KeyFile::new("ed25519", KeyType::Public, pk.as_ref(), args.label.clone());
    let sk_file = KeyFile::new("ed25519", KeyType::Secret, sk.as_ref(), args.label.clone());

    let pk_path = args.output.join("ed25519.pub.json");
    let sk_path = args.output.join("ed25519.sec.json");

    pk_file.write_to(&pk_path)?;
    sk_file.write_to(&sk_path)?;

    println!("Generated Ed25519 signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

/// Encode a component length as a 4-byte little-endian u32 prefix.
fn encode_len_prefix(len: usize) -> Result<[u8; 4]> {
    let len_u32 = u32::try_from(len).context("Key component too large for serialization format")?;
    Ok(len_u32.to_le_bytes())
}

fn generate_hybrid_kem(args: &KeygenArgs) -> Result<()> {
    let (pk, _sk) =
        latticearc::generate_hybrid_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    // Save the public key components: [ml_kem_pk_len(u32le)][ml_kem_pk][ecdh_pk]
    let mut pk_bytes = Vec::new();
    pk_bytes.extend_from_slice(&encode_len_prefix(pk.ml_kem_pk.len())?);
    pk_bytes.extend_from_slice(&pk.ml_kem_pk);
    pk_bytes.extend_from_slice(&pk.ecdh_pk);

    let pk_file =
        KeyFile::new("hybrid-ml-kem-768-x25519", KeyType::Public, &pk_bytes, args.label.clone());
    let pk_path = args.output.join("hybrid-kem.pub.json");
    pk_file.write_to(&pk_path)?;

    println!("Generated Hybrid ML-KEM-768 + X25519 keypair:");
    println!("  Public:  {}", pk_path.display());
    println!();
    println!("  NOTE: Hybrid secret keys are in-memory only (aws-lc-rs limitation).");
    println!("  Use 'latticearc encrypt --hybrid' to generate + encrypt in one step.");
    Ok(())
}

fn generate_hybrid_sign(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_hybrid_signing_keypair(latticearc::SecurityMode::Unverified)
            .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    // Serialize public key: [ml_dsa_pk_len(u32le)][ml_dsa_pk][ed25519_pk]
    let mut pk_bytes = Vec::new();
    pk_bytes.extend_from_slice(&encode_len_prefix(pk.ml_dsa_pk.len())?);
    pk_bytes.extend_from_slice(&pk.ml_dsa_pk);
    pk_bytes.extend_from_slice(&pk.ed25519_pk);

    // Serialize secret key: [ml_dsa_sk_len(u32le)][ml_dsa_sk][ed25519_sk]
    // Wrapped in Zeroizing for automatic cleanup on drop
    let mut sk_bytes = zeroize::Zeroizing::new(Vec::new());
    sk_bytes.extend_from_slice(&encode_len_prefix(sk.ml_dsa_sk.len())?);
    sk_bytes.extend_from_slice(&sk.ml_dsa_sk);
    sk_bytes.extend_from_slice(&sk.ed25519_sk);

    let pk_file =
        KeyFile::new("hybrid-ml-dsa-65-ed25519", KeyType::Public, &pk_bytes, args.label.clone());
    let sk_file =
        KeyFile::new("hybrid-ml-dsa-65-ed25519", KeyType::Secret, &sk_bytes, args.label.clone());

    let pk_path = args.output.join("hybrid-sign.pub.json");
    let sk_path = args.output.join("hybrid-sign.sec.json");

    pk_file.write_to(&pk_path)?;
    sk_file.write_to(&sk_path)?;

    println!("Generated Hybrid ML-DSA-65 + Ed25519 signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

/// Decode a 4-byte little-endian length prefix from the start of a byte slice.
/// Returns the decoded length and validates that the full expected content exists.
fn decode_header(
    bytes: &[u8],
    second_component_len: usize,
    context: &str,
) -> Result<(usize, usize, usize)> {
    let header = bytes.get(..4).context(format!("{context} too short"))?;
    let b0 = *header.first().context("header byte 0")?;
    let b1 = *header.get(1).context("header byte 1")?;
    let b2 = *header.get(2).context("header byte 2")?;
    let b3 = *header.get(3).context("header byte 3")?;
    let first_len = u32::from_le_bytes([b0, b1, b2, b3]) as usize;

    let first_start: usize = 4;
    let first_end =
        first_start.checked_add(first_len).context(format!("{context} length overflow"))?;
    let total = first_end
        .checked_add(second_component_len)
        .context(format!("{context} length overflow"))?;

    if bytes.len() < total {
        bail!("{context} truncated (expected {total} bytes, got {})", bytes.len());
    }

    Ok((first_start, first_end, total))
}

/// Parse a hybrid public key from the serialized format.
pub(crate) fn parse_hybrid_kem_pk(
    bytes: &[u8],
) -> Result<latticearc::hybrid::kem_hybrid::HybridPublicKey> {
    let (start, mid, end) = decode_header(bytes, 32, "Hybrid KEM public key")?;

    Ok(latticearc::hybrid::kem_hybrid::HybridPublicKey {
        ml_kem_pk: bytes.get(start..mid).context("ml_kem_pk slice")?.to_vec(),
        ecdh_pk: bytes.get(mid..end).context("ecdh_pk slice")?.to_vec(),
        security_level: latticearc::primitives::kem::MlKemSecurityLevel::MlKem768,
    })
}

/// Parse a hybrid signing public key from the serialized format.
pub(crate) fn parse_hybrid_sign_pk(
    bytes: &[u8],
) -> Result<latticearc::hybrid::sig_hybrid::HybridPublicKey> {
    let (start, mid, end) = decode_header(bytes, 32, "Hybrid signing public key")?;

    Ok(latticearc::hybrid::sig_hybrid::HybridPublicKey {
        ml_dsa_pk: bytes.get(start..mid).context("ml_dsa_pk slice")?.to_vec(),
        ed25519_pk: bytes.get(mid..end).context("ed25519_pk slice")?.to_vec(),
    })
}

/// Parse a hybrid signing secret key from the serialized format.
pub(crate) fn parse_hybrid_sign_sk(
    bytes: &[u8],
) -> Result<latticearc::hybrid::sig_hybrid::HybridSecretKey> {
    let (start, mid, end) = decode_header(bytes, 32, "Hybrid signing secret key")?;

    Ok(latticearc::hybrid::sig_hybrid::HybridSecretKey {
        ml_dsa_sk: zeroize::Zeroizing::new(
            bytes.get(start..mid).context("ml_dsa_sk slice")?.to_vec(),
        ),
        ed25519_sk: zeroize::Zeroizing::new(
            bytes.get(mid..end).context("ed25519_sk slice")?.to_vec(),
        ),
    })
}
