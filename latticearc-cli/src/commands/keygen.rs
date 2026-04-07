//! Key generation command.
//!
//! Generates cryptographic keys for signing, encryption, or key exchange.
//! Supports 12 algorithm variants across three categories:
//!
//! - **Post-quantum signatures:** ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205),
//!   FN-DSA-512 (FIPS 206)
//! - **Classical & hybrid:** Ed25519 (RFC 8032), AES-256 (FIPS 197),
//!   Hybrid ML-DSA+Ed25519, Hybrid ML-KEM+X25519
//! - **Key encapsulation:** ML-KEM-512/768/1024 (FIPS 203)
//!
//! Key files are written in the LatticeArc Portable Key (LPK) format via
//! [`latticearc::PortableKey`]. See `docs/KEY_FORMAT.md` for the specification.

use anyhow::{Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use latticearc::unified_api::key_format::{KeyAlgorithm, KeyType};

use crate::keyfile;

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
    /// FN-DSA-512 lattice signature (FIPS 206). Compact signatures.
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
    /// Algorithm to generate keys for (expert override).
    /// When --use-case is provided, algorithm is selected automatically and this flag is ignored.
    #[arg(short, long, value_enum)]
    pub algorithm: Option<Algorithm>,
    /// Use case for automatic algorithm selection (recommended).
    /// The library's policy engine selects the optimal algorithm based on this.
    #[arg(long, value_parser = super::common::parse_use_case,
          value_name = "USE_CASE")]
    pub use_case: Option<latticearc::types::types::UseCase>,
    /// Security level override (default: high).
    #[arg(long, value_parser = super::common::parse_security_level,
          value_name = "LEVEL")]
    pub security_level: Option<latticearc::types::types::SecurityLevel>,
    /// Compliance mode (default, fips, cnsa-2.0).
    #[arg(long, value_parser = super::common::parse_compliance,
          value_name = "MODE")]
    pub compliance: Option<latticearc::types::types::ComplianceMode>,
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

    // Use-case-driven path: let the library select the algorithm
    if args.use_case.is_some() {
        if args.algorithm.is_some() {
            eprintln!(
                "Warning: --algorithm is ignored when --use-case is provided. \
                 The library selects the optimal algorithm automatically."
            );
        }
        return generate_from_config(&args);
    }

    // Expert path: explicit algorithm selection
    let Some(algorithm) = &args.algorithm else {
        bail!(
            "Either --use-case or --algorithm is required.\n\
             Recommended: latticearc-cli keygen --use-case <USE_CASE>\n\
             Expert:      latticearc-cli keygen --algorithm <ALGORITHM>"
        )
    };
    match algorithm {
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
            generate_ml_dsa(&args, latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa65)
        }
        Algorithm::MlDsa44 => {
            generate_ml_dsa(&args, latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa44)
        }
        Algorithm::MlDsa87 => {
            generate_ml_dsa(&args, latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa87)
        }
        Algorithm::SlhDsa128s => generate_slh_dsa(&args),
        Algorithm::FnDsa512 => generate_fn_dsa(&args),
        Algorithm::Ed25519 => generate_ed25519(&args),
        Algorithm::Hybrid => generate_hybrid_kem(&args),
        Algorithm::HybridSign => generate_hybrid_sign(&args),
    }
}

/// Use-case-driven key generation via the library's unified API.
fn generate_from_config(args: &KeygenArgs) -> Result<()> {
    let config = super::common::build_config(args.use_case, args.security_level, &args.compliance);

    // Generate signing keypair — library selects the scheme
    let (pk, sk, scheme) = latticearc::generate_signing_keypair(config)
        .map_err(|e| anyhow::anyhow!("Signing keygen failed: {e}"))?;

    let safe_scheme = scheme.replace(' ', "-");
    let pk_path = args.output.join(format!("{safe_scheme}.pub.json"));
    let sk_path = args.output.join(format!("{safe_scheme}.sec.json"));

    // Detect algorithm from scheme name
    let alg = parse_scheme_to_algorithm(&scheme)?;
    keyfile::write_key(&pk_path, alg, KeyType::Public, &pk, args.label.clone())?;
    keyfile::write_key(&sk_path, alg, KeyType::Secret, sk.as_ref(), args.label.clone())?;

    let uc_desc = args.use_case.as_ref().map(|uc| format!(" for {:?}", uc)).unwrap_or_default();

    println!("Generated {scheme} signing keypair{uc_desc}:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());

    // Also generate hybrid encryption keypair
    match latticearc::generate_hybrid_keypair() {
        Ok((enc_pk, enc_sk)) => {
            let (portable_pk, portable_sk) = latticearc::PortableKey::from_hybrid_kem_keypair(
                args.use_case.unwrap_or(latticearc::types::types::UseCase::SecureMessaging),
                &enc_pk,
                &enc_sk,
            )
            .map_err(|e| anyhow::anyhow!("Hybrid key export failed: {e}"))?;

            let enc_pk_path = args.output.join("encryption.pub.json");
            let enc_sk_path = args.output.join("encryption.sec.json");
            portable_pk
                .write_to_file(&enc_pk_path)
                .map_err(|e| anyhow::anyhow!("Write PK: {e}"))?;
            portable_sk
                .write_to_file(&enc_sk_path)
                .map_err(|e| anyhow::anyhow!("Write SK: {e}"))?;

            println!("  Encrypt PK: {}", enc_pk_path.display());
            println!("  Encrypt SK: {}", enc_sk_path.display());
        }
        Err(e) => {
            eprintln!("  Note: Encryption keygen skipped ({e})");
        }
    }

    Ok(())
}

fn generate_symmetric(args: &KeygenArgs) -> Result<()> {
    let rand_bytes = latticearc::primitives::rand::csprng::random_bytes(32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&rand_bytes);

    let path = args.output.join("aes256.key.json");
    keyfile::write_key(&path, KeyAlgorithm::Aes256, KeyType::Symmetric, &key, args.label.clone())?;

    zeroize::Zeroize::zeroize(&mut key);

    println!("Generated AES-256 symmetric key: {}", path.display());
    Ok(())
}

fn generate_ml_kem(
    args: &KeygenArgs,
    level: latticearc::primitives::kem::MlKemSecurityLevel,
) -> Result<()> {
    let (alg_name, alg) = match level {
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem512 => {
            ("ml-kem-512", KeyAlgorithm::MlKem512)
        }
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem768 => {
            ("ml-kem-768", KeyAlgorithm::MlKem768)
        }
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem1024 => {
            ("ml-kem-1024", KeyAlgorithm::MlKem1024)
        }
        _ => anyhow::bail!("Unsupported MlKemSecurityLevel variant"),
    };

    let (pk, sk) = latticearc::generate_ml_kem_keypair(level)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join(format!("{alg_name}.pub.json"));
    let sk_path = args.output.join(format!("{alg_name}.sec.json"));

    keyfile::write_key(&pk_path, alg, KeyType::Public, pk.as_ref(), args.label.clone())?;
    keyfile::write_key(&sk_path, alg, KeyType::Secret, sk.as_ref(), args.label.clone())?;

    println!("Generated {alg_name} keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_ml_dsa(
    args: &KeygenArgs,
    param_set: latticearc::primitives::sig::ml_dsa::MlDsaParameterSet,
) -> Result<()> {
    let (alg_name, alg) = match param_set {
        latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa44 => {
            ("ml-dsa-44", KeyAlgorithm::MlDsa44)
        }
        latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa65 => {
            ("ml-dsa-65", KeyAlgorithm::MlDsa65)
        }
        latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa87 => {
            ("ml-dsa-87", KeyAlgorithm::MlDsa87)
        }
        _ => return Err(anyhow::anyhow!("Unsupported ML-DSA parameter set")),
    };

    let (pk, sk) = latticearc::generate_ml_dsa_keypair(param_set)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join(format!("{alg_name}.pub.json"));
    let sk_path = args.output.join(format!("{alg_name}.sec.json"));

    keyfile::write_key(&pk_path, alg, KeyType::Public, pk.as_ref(), args.label.clone())?;
    keyfile::write_key(&sk_path, alg, KeyType::Secret, sk.as_ref(), args.label.clone())?;

    println!("Generated {alg_name} signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_slh_dsa(args: &KeygenArgs) -> Result<()> {
    let level = latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel::Shake128s;
    let (pk, sk) = latticearc::generate_slh_dsa_keypair(level)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join("slh-dsa-shake-128s.pub.json");
    let sk_path = args.output.join("slh-dsa-shake-128s.sec.json");

    keyfile::write_key(
        &pk_path,
        KeyAlgorithm::SlhDsaShake128s,
        KeyType::Public,
        pk.as_ref(),
        args.label.clone(),
    )?;
    keyfile::write_key(
        &sk_path,
        KeyAlgorithm::SlhDsaShake128s,
        KeyType::Secret,
        sk.as_ref(),
        args.label.clone(),
    )?;

    println!("Generated SLH-DSA-SHAKE-128s signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_fn_dsa(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_fn_dsa_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join("fn-dsa-512.pub.json");
    let sk_path = args.output.join("fn-dsa-512.sec.json");

    keyfile::write_key(
        &pk_path,
        KeyAlgorithm::FnDsa512,
        KeyType::Public,
        pk.as_ref(),
        args.label.clone(),
    )?;
    keyfile::write_key(
        &sk_path,
        KeyAlgorithm::FnDsa512,
        KeyType::Secret,
        sk.as_ref(),
        args.label.clone(),
    )?;

    println!("Generated FN-DSA-512 signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_ed25519(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join("ed25519.pub.json");
    let sk_path = args.output.join("ed25519.sec.json");

    keyfile::write_key(
        &pk_path,
        KeyAlgorithm::Ed25519,
        KeyType::Public,
        pk.as_ref(),
        args.label.clone(),
    )?;
    keyfile::write_key(
        &sk_path,
        KeyAlgorithm::Ed25519,
        KeyType::Secret,
        sk.as_ref(),
        args.label.clone(),
    )?;

    println!("Generated Ed25519 signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_hybrid_kem(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_hybrid_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    // Use PortableKey composite format — no more bespoke length-prefix encoding
    let (portable_pk, portable_sk) = latticearc::PortableKey::from_hybrid_kem_keypair(
        latticearc::types::types::UseCase::SecureMessaging,
        &pk,
        &sk,
    )
    .map_err(|e| anyhow::anyhow!("Key export failed: {e}"))?;

    let pk_path = args.output.join("hybrid-kem.pub.json");
    let sk_path = args.output.join("hybrid-kem.sec.json");

    portable_pk.write_to_file(&pk_path).map_err(|e| anyhow::anyhow!("Write PK: {e}"))?;
    portable_sk.write_to_file(&sk_path).map_err(|e| anyhow::anyhow!("Write SK: {e}"))?;

    println!("Generated Hybrid ML-KEM-768 + X25519 keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

fn generate_hybrid_sign(args: &KeygenArgs) -> Result<()> {
    let (pk, sk) =
        latticearc::generate_hybrid_signing_keypair(latticearc::SecurityMode::Unverified)
            .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    // Use PortableKey composite format — no more bespoke length-prefix encoding
    let pk_path = args.output.join("hybrid-sign.pub.json");
    let sk_path = args.output.join("hybrid-sign.sec.json");

    keyfile::write_composite_key(
        &pk_path,
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Public,
        pk.ml_dsa_pk(),
        pk.ed25519_pk(),
        args.label.clone(),
    )?;
    keyfile::write_composite_key(
        &sk_path,
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Secret,
        sk.ml_dsa_sk(),
        sk.ed25519_sk(),
        args.label.clone(),
    )?;

    println!("Generated Hybrid ML-DSA-65 + Ed25519 signing keypair:");
    println!("  Public:  {}", pk_path.display());
    println!("  Secret:  {}", sk_path.display());
    Ok(())
}

/// Map a scheme name string (from `generate_signing_keypair`) to a `KeyAlgorithm`.
fn parse_scheme_to_algorithm(scheme: &str) -> Result<KeyAlgorithm> {
    match scheme {
        "hybrid-ml-dsa-65-ed25519" => Ok(KeyAlgorithm::HybridMlDsa65Ed25519),
        "hybrid-ml-dsa-44-ed25519" => Ok(KeyAlgorithm::HybridMlDsa44Ed25519),
        "hybrid-ml-dsa-87-ed25519" => Ok(KeyAlgorithm::HybridMlDsa87Ed25519),
        "ml-dsa-44" => Ok(KeyAlgorithm::MlDsa44),
        "ml-dsa-65" => Ok(KeyAlgorithm::MlDsa65),
        "ml-dsa-87" => Ok(KeyAlgorithm::MlDsa87),
        "ed25519" => Ok(KeyAlgorithm::Ed25519),
        other => bail!("Unrecognized scheme from library: '{other}'"),
    }
}
