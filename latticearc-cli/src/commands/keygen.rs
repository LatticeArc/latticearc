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

/// Print the standard "Generated <name> keypair" report block — the
/// `Public:` / `Secret:` paths and the optional passphrase note. This
/// block previously appeared verbatim in 8 keygen functions; centralising
/// it here keeps the output format consistent and avoids drift when one
/// site is touched and the others are not.
fn print_keypair_report(
    label: &str,
    pk_path: &std::path::Path,
    sk_path: &std::path::Path,
    passphrase_protected: bool,
) {
    eprintln!("Generated {label} keypair:");
    eprintln!("  Public:  {}", pk_path.display());
    eprintln!("  Secret:  {}", sk_path.display());
    if passphrase_protected {
        eprintln!("  (secret key encrypted with passphrase)");
    }
}

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
    /// Protect the on-disk secret key with a passphrase (PBKDF2-HMAC-SHA256 +
    /// AES-256-GCM). The passphrase is read from the `LATTICEARC_PASSPHRASE`
    /// environment variable if set, otherwise prompted on the terminal
    /// (no echo, asks twice). Public keys are written unencrypted regardless.
    ///
    /// This flag is a boolean — it does NOT take the passphrase as a value.
    /// Passing passphrases on the command line is unsafe because they are
    /// visible in `ps` and shell history; use the env var or the tty prompt.
    #[arg(long)]
    pub passphrase: bool,
}

/// Resolve the optional passphrase for protecting newly-generated secret keys.
///
/// Returns `None` when `--passphrase` was not set; otherwise prompts (or
/// reads `LATTICEARC_PASSPHRASE`) and returns the bytes wrapped in
/// [`zeroize::Zeroizing`] so they are wiped after use.
fn resolve_keygen_passphrase(args: &KeygenArgs) -> Result<Option<zeroize::Zeroizing<String>>> {
    if !args.passphrase {
        return Ok(None);
    }
    Ok(Some(keyfile::resolve_new_passphrase()?))
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
    let passphrase = resolve_keygen_passphrase(args)?;
    if passphrase.is_some() {
        // `--use-case` produces both a signing keypair and an encryption
        // keypair. The same passphrase encrypts both secret keys, which is
        // a documented anti-pattern (PKCS#11 / PKIX) but the simplest
        // ergonomic for a single-shot CLI invocation. Disclose explicitly
        // so the user can decide whether to re-key one of the two halves
        // with a separate `--algorithm` keygen pass.
        eprintln!(
            "note: the same passphrase will encrypt the signing AND encryption \
             secret keys. If you require distinct passphrases per role, generate \
             each role separately with `keygen --algorithm <…>`."
        );
    }
    let config = super::common::build_config(args.use_case, args.security_level, &args.compliance);

    // Generate signing keypair — library selects the scheme.
    let (pk, sk, scheme) = latticearc::generate_signing_keypair(config)
        .map_err(|e| anyhow::anyhow!("Signing keygen failed: {e}"))?;

    let safe_scheme = scheme.replace(' ', "-");
    let pk_path = args.output.join(format!("{safe_scheme}.pub.json"));
    let sk_path = args.output.join(format!("{safe_scheme}.sec.json"));

    // Hybrid signing schemes return `pq_bytes || ed25519_bytes`; routing them
    // through `PortableKey::from_hybrid_sig_keypair` preserves the use case in
    // the key file and uses the library's canonical composite encoding. PQ-only
    // / classical schemes write as a single key.
    let use_case = args.use_case.unwrap_or(latticearc::types::types::UseCase::SecureMessaging);
    if is_hybrid_ml_dsa_scheme(&scheme) {
        let (mut portable_pk, mut portable_sk) =
            build_hybrid_sig_portable_keys(use_case, &scheme, &pk, sk.as_ref())?;
        if let Some(l) = args.label.clone() {
            portable_pk.set_label(l.clone());
            portable_sk.set_label(l);
        }
        if let Some(pp) = passphrase.as_ref() {
            portable_sk
                .encrypt_with_passphrase(pp.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to encrypt secret key: {e}"))?;
        }
        // Round-8 audit fix #4: write SK first. If we wrote PK first and
        // the SK write failed (disk full, permission), the PK would be
        // orphaned on disk; subsequent retry would hit the new
        // "refusing to overwrite" guard against the orphan and surface
        // a confusing "file exists" error for a keypair half the user
        // didn't know was created. SK-first ensures the PK only lands
        // when there's a matching usable SK.
        portable_sk
            .write_to_file(&sk_path)
            .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", sk_path.display()))?;
        portable_pk
            .write_to_file(&pk_path)
            .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", pk_path.display()))?;
    } else {
        // PQ-only or classical signing scheme — concatenated bytes are the
        // entire key and should be written as a Single KeyData.
        let alg = parse_scheme_to_algorithm(&scheme)?;
        // SK first — see fix #1/#4 explanation above.
        keyfile::write_key_protected(
            &sk_path,
            alg,
            KeyType::Secret,
            sk.as_ref(),
            args.label.clone(),
            passphrase.as_ref().map(|p| p.as_bytes()),
        )?;
        keyfile::write_key(&pk_path, alg, KeyType::Public, &pk, args.label.clone())?;
    }

    let uc_desc = args.use_case.as_ref().map(|uc| format!(" for {:?}", uc)).unwrap_or_default();

    eprintln!("Generated {scheme} signing keypair{uc_desc}:");
    eprintln!("  Public:  {}", pk_path.display());
    eprintln!("  Secret:  {}", sk_path.display());

    // Also generate the matching hybrid encryption keypair. A failure here is
    // fatal: the user asked for a use-case bundle (signing + encryption) and
    // silently delivering only the signing half would leave them unable to
    // run encrypt/decrypt with the same workflow.
    let (enc_pk, enc_sk) = latticearc::generate_hybrid_keypair()
        .map_err(|e| anyhow::anyhow!("Hybrid encryption keygen failed: {e}"))?;
    let (portable_pk, mut portable_sk) = latticearc::PortableKey::from_hybrid_kem_keypair(
        args.use_case.unwrap_or(latticearc::types::types::UseCase::SecureMessaging),
        &enc_pk,
        &enc_sk,
    )
    .map_err(|e| anyhow::anyhow!("Hybrid encryption key export failed: {e}"))?;

    if let Some(pp) = passphrase.as_ref() {
        portable_sk
            .encrypt_with_passphrase(pp.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt encryption SK: {e}"))?;
    }

    let enc_pk_path = args.output.join("encryption.pub.json");
    let enc_sk_path = args.output.join("encryption.sec.json");
    // SK first — see fix #4 explanation in the signing-keypair branch.
    portable_sk
        .write_to_file(&enc_sk_path)
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", enc_sk_path.display()))?;
    portable_pk
        .write_to_file(&enc_pk_path)
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", enc_pk_path.display()))?;

    eprintln!("  Encrypt PK: {}", enc_pk_path.display());
    eprintln!("  Encrypt SK: {}", enc_sk_path.display());

    if passphrase.is_some() {
        eprintln!("  (secret keys encrypted with passphrase)");
    }

    Ok(())
}

fn generate_symmetric(args: &KeygenArgs) -> Result<()> {
    let passphrase = resolve_keygen_passphrase(args)?;
    // Round-12 audit fix (M-3): wrap the intermediate Vec in
    // `Zeroizing` so the 32-byte CSPRNG draw doesn't leak via heap
    // copies after we've split it into the stack-allocated `key` array.
    let rand_bytes =
        zeroize::Zeroizing::new(latticearc::primitives::rand::csprng::random_bytes(32));
    let mut key = [0u8; 32];
    key.copy_from_slice(&rand_bytes);

    let path = args.output.join("aes256.key.json");
    keyfile::write_key_protected(
        &path,
        KeyAlgorithm::Aes256,
        KeyType::Symmetric,
        &key,
        args.label.clone(),
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;

    zeroize::Zeroize::zeroize(&mut key);

    eprintln!("Generated AES-256 symmetric key: {}", path.display());
    if passphrase.is_some() {
        eprintln!("  (encrypted with passphrase)");
    }
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

    let passphrase = resolve_keygen_passphrase(args)?;
    let (pk, sk) = latticearc::generate_ml_kem_keypair(level)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join(format!("{alg_name}.pub.json"));
    let sk_path = args.output.join(format!("{alg_name}.sec.json"));

    // SK first — see fix #1/#4 explanation above.
    //
    // The PQ-only decryption path requires the recipient's ML-KEM
    // public key at HKDF-info construction time (HPKE / RFC 9180 §5.1
    // channel binding). Bundle the PK into the SK file's metadata so
    // the decryption path is self-contained — it never needs to
    // re-load the `.pub.json` separately. This mirrors the hybrid-KEM
    // bundling pattern in `key_format::from_hybrid_keypair`.
    let pk_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.as_ref());
    keyfile::write_key_protected_with_metadata(
        &sk_path,
        alg,
        KeyType::Secret,
        sk.expose_secret(),
        args.label.clone(),
        &[("ml_kem_pk", serde_json::Value::String(pk_b64))],
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;
    keyfile::write_key(&pk_path, alg, KeyType::Public, pk.as_ref(), args.label.clone())?;

    print_keypair_report(alg_name, &pk_path, &sk_path, passphrase.is_some());
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

    let passphrase = resolve_keygen_passphrase(args)?;
    let (pk, sk) = latticearc::generate_ml_dsa_keypair(param_set)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join(format!("{alg_name}.pub.json"));
    let sk_path = args.output.join(format!("{alg_name}.sec.json"));

    // SK first — see fix #1/#4 explanation above.
    keyfile::write_key_protected(
        &sk_path,
        alg,
        KeyType::Secret,
        sk.expose_secret(),
        args.label.clone(),
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;
    keyfile::write_key(&pk_path, alg, KeyType::Public, pk.as_ref(), args.label.clone())?;

    print_keypair_report(&format!("{alg_name} signing"), &pk_path, &sk_path, passphrase.is_some());
    Ok(())
}

fn generate_slh_dsa(args: &KeygenArgs) -> Result<()> {
    let passphrase = resolve_keygen_passphrase(args)?;
    let level = latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel::Shake128s;
    let (pk, sk) = latticearc::generate_slh_dsa_keypair(level)
        .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join("slh-dsa-shake-128s.pub.json");
    let sk_path = args.output.join("slh-dsa-shake-128s.sec.json");

    // SK first — see fix #1/#4 explanation above.
    keyfile::write_key_protected(
        &sk_path,
        KeyAlgorithm::SlhDsaShake128s,
        KeyType::Secret,
        sk.expose_secret(),
        args.label.clone(),
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;
    keyfile::write_key(
        &pk_path,
        KeyAlgorithm::SlhDsaShake128s,
        KeyType::Public,
        pk.as_ref(),
        args.label.clone(),
    )?;

    print_keypair_report("SLH-DSA-SHAKE-128s signing", &pk_path, &sk_path, passphrase.is_some());
    Ok(())
}

fn generate_fn_dsa(args: &KeygenArgs) -> Result<()> {
    let passphrase = resolve_keygen_passphrase(args)?;
    let (pk, sk) =
        latticearc::generate_fn_dsa_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join("fn-dsa-512.pub.json");
    let sk_path = args.output.join("fn-dsa-512.sec.json");

    // SK first — see fix #1/#4 explanation above.
    keyfile::write_key_protected(
        &sk_path,
        KeyAlgorithm::FnDsa512,
        KeyType::Secret,
        sk.expose_secret(),
        args.label.clone(),
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;
    keyfile::write_key(
        &pk_path,
        KeyAlgorithm::FnDsa512,
        KeyType::Public,
        pk.as_ref(),
        args.label.clone(),
    )?;

    print_keypair_report("FN-DSA-512 signing", &pk_path, &sk_path, passphrase.is_some());
    Ok(())
}

fn generate_ed25519(args: &KeygenArgs) -> Result<()> {
    let passphrase = resolve_keygen_passphrase(args)?;
    let (pk, sk) =
        latticearc::generate_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    let pk_path = args.output.join("ed25519.pub.json");
    let sk_path = args.output.join("ed25519.sec.json");

    // SK first — see fix #1/#4 explanation above.
    keyfile::write_key_protected(
        &sk_path,
        KeyAlgorithm::Ed25519,
        KeyType::Secret,
        sk.expose_secret(),
        args.label.clone(),
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;
    keyfile::write_key(
        &pk_path,
        KeyAlgorithm::Ed25519,
        KeyType::Public,
        pk.as_ref(),
        args.label.clone(),
    )?;

    print_keypair_report("Ed25519 signing", &pk_path, &sk_path, passphrase.is_some());
    Ok(())
}

fn generate_hybrid_kem(args: &KeygenArgs) -> Result<()> {
    let passphrase = resolve_keygen_passphrase(args)?;
    let (pk, sk) =
        latticearc::generate_hybrid_keypair().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    // Use PortableKey composite format — no more bespoke length-prefix encoding
    let (portable_pk, mut portable_sk) = latticearc::PortableKey::from_hybrid_kem_keypair(
        latticearc::types::types::UseCase::SecureMessaging,
        &pk,
        &sk,
    )
    .map_err(|e| anyhow::anyhow!("Key export failed: {e}"))?;

    if let Some(pp) = passphrase.as_ref() {
        portable_sk
            .encrypt_with_passphrase(pp.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt secret key: {e}"))?;
    }

    let pk_path = args.output.join("hybrid-kem.pub.json");
    let sk_path = args.output.join("hybrid-kem.sec.json");

    // SK first — see fix #4 explanation in `generate_signing` above.
    portable_sk.write_to_file(&sk_path).map_err(|e| anyhow::anyhow!("Write SK: {e}"))?;
    portable_pk.write_to_file(&pk_path).map_err(|e| anyhow::anyhow!("Write PK: {e}"))?;

    print_keypair_report("Hybrid ML-KEM-768 + X25519", &pk_path, &sk_path, passphrase.is_some());
    Ok(())
}

fn generate_hybrid_sign(args: &KeygenArgs) -> Result<()> {
    let passphrase = resolve_keygen_passphrase(args)?;
    let (pk, sk) =
        latticearc::generate_hybrid_signing_keypair(latticearc::SecurityMode::Unverified)
            .map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;

    // Use PortableKey composite format — no more bespoke length-prefix encoding
    let pk_path = args.output.join("hybrid-sign.pub.json");
    let sk_path = args.output.join("hybrid-sign.sec.json");

    // SK first — round-9 audit fix #1 (extending round-8 fix #4 to the
    // 4th keygen site that was missed). SK-write failure no longer
    // orphans a PK on disk that retry would refuse-to-overwrite.
    keyfile::write_composite_key_protected(
        &sk_path,
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Secret,
        sk.expose_ml_dsa_secret(),
        sk.expose_ed25519_secret(),
        args.label.clone(),
        passphrase.as_ref().map(|p| p.as_bytes()),
    )?;
    keyfile::write_composite_key(
        &pk_path,
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyType::Public,
        pk.ml_dsa_pk(),
        pk.ed25519_pk(),
        args.label.clone(),
    )?;

    print_keypair_report(
        "Hybrid ML-DSA-65 + Ed25519 signing",
        &pk_path,
        &sk_path,
        passphrase.is_some(),
    );
    Ok(())
}

/// Map a scheme name string (from `generate_signing_keypair`) to a `KeyAlgorithm`.
///
/// Accepts both the canonical name and the `pq-` / `ml-dsa-*-hybrid-ed25519`
/// aliases that the library's scheme selector can emit.
fn parse_scheme_to_algorithm(scheme: &str) -> Result<KeyAlgorithm> {
    match scheme {
        "hybrid-ml-dsa-44-ed25519" | "ml-dsa-44-hybrid-ed25519" => {
            Ok(KeyAlgorithm::HybridMlDsa44Ed25519)
        }
        "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => {
            Ok(KeyAlgorithm::HybridMlDsa65Ed25519)
        }
        "hybrid-ml-dsa-87-ed25519" | "ml-dsa-87-hybrid-ed25519" => {
            Ok(KeyAlgorithm::HybridMlDsa87Ed25519)
        }
        "ml-dsa-44" | "pq-ml-dsa-44" => Ok(KeyAlgorithm::MlDsa44),
        "ml-dsa-65" | "pq-ml-dsa-65" => Ok(KeyAlgorithm::MlDsa65),
        "ml-dsa-87" | "pq-ml-dsa-87" => Ok(KeyAlgorithm::MlDsa87),
        "slh-dsa-shake-128s" => Ok(KeyAlgorithm::SlhDsaShake128s),
        "fn-dsa" | "fn-dsa-512" => Ok(KeyAlgorithm::FnDsa512),
        "fn-dsa-1024" => Ok(KeyAlgorithm::FnDsa1024),
        "ed25519" => Ok(KeyAlgorithm::Ed25519),
        other => bail!(
            "Unrecognized scheme '{other}' — the library selected a scheme the CLI \
             cannot serialize. This is a CLI bug; please file an issue."
        ),
    }
}

/// Returns `true` if `scheme` is a hybrid ML-DSA + Ed25519 signing scheme.
///
/// Accepts both the canonical and the `ml-dsa-*-hybrid-ed25519` aliases.
fn is_hybrid_ml_dsa_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "hybrid-ml-dsa-44-ed25519"
            | "ml-dsa-44-hybrid-ed25519"
            | "hybrid-ml-dsa-65-ed25519"
            | "ml-dsa-65-hybrid-ed25519"
            | "hybrid-ml-dsa-87-ed25519"
            | "ml-dsa-87-hybrid-ed25519"
    )
}

/// Reconstruct split `HybridSigPublicKey` / `HybridSigSecretKey` objects
/// from the raw `pq_bytes || ed25519_bytes` concatenation returned by
/// `latticearc::generate_signing_keypair`, and wrap them in `PortableKey`s
/// via the library's canonical factory. The factory auto-detects the
/// ML-DSA parameter set from the public-key length and preserves the
/// originating `use_case` in the serialized key file.
fn build_hybrid_sig_portable_keys(
    use_case: latticearc::types::types::UseCase,
    scheme: &str,
    pk_bytes: &[u8],
    sk_bytes: &[u8],
) -> Result<(latticearc::PortableKey, latticearc::PortableKey)> {
    use latticearc::hybrid::sig_hybrid::{HybridSigPublicKey, HybridSigSecretKey};
    use latticearc::primitives::ec::ed25519::{ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_KEY_LEN};
    use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;

    let params = match scheme {
        "hybrid-ml-dsa-44-ed25519" | "ml-dsa-44-hybrid-ed25519" => MlDsaParameterSet::MlDsa44,
        "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => MlDsaParameterSet::MlDsa65,
        "hybrid-ml-dsa-87-ed25519" | "ml-dsa-87-hybrid-ed25519" => MlDsaParameterSet::MlDsa87,
        other => bail!("Not a hybrid ML-DSA + Ed25519 signing scheme: {other}"),
    };

    let pq_pk_len = params.public_key_size();
    let pq_sk_len = params.secret_key_size();
    let expected_pk = pq_pk_len
        .checked_add(ED25519_PUBLIC_KEY_LEN)
        .ok_or_else(|| anyhow::anyhow!("hybrid PK length overflow"))?;
    let expected_sk = pq_sk_len
        .checked_add(ED25519_SECRET_KEY_LEN)
        .ok_or_else(|| anyhow::anyhow!("hybrid SK length overflow"))?;
    if pk_bytes.len() != expected_pk {
        bail!("hybrid {scheme} PK length: expected {expected_pk}, got {}", pk_bytes.len());
    }
    if sk_bytes.len() != expected_sk {
        bail!("hybrid {scheme} SK length: expected {expected_sk}, got {}", sk_bytes.len());
    }

    let (pq_pk, ed_pk) = pk_bytes.split_at(pq_pk_len);
    let (pq_sk, ed_sk) = sk_bytes.split_at(pq_sk_len);

    let hybrid_pk = HybridSigPublicKey::new(params, pq_pk.to_vec(), ed_pk.to_vec());
    let hybrid_sk = HybridSigSecretKey::new(
        params,
        zeroize::Zeroizing::new(pq_sk.to_vec()),
        zeroize::Zeroizing::new(ed_sk.to_vec()),
    );
    latticearc::PortableKey::from_hybrid_sig_keypair(use_case, &hybrid_pk, &hybrid_sk)
        .map_err(|e| anyhow::anyhow!("Hybrid signing key export failed: {e}"))
}
