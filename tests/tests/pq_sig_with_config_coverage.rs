//! Coverage tests for pq_sig.rs _with_config and SecurityMode variants.
//! Targets the `sign_pq_*_with_config`, `verify_pq_*_with_config`,
//! and their `_unverified` wrapper variants.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
use latticearc::primitives::sig::slh_dsa::SecurityLevel as SlhDsaSecurityLevel;
use latticearc::unified_api::config::CoreConfig;
use latticearc::unified_api::convenience::{
    generate_fn_dsa_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair, sign_pq_fn_dsa,
    sign_pq_fn_dsa_with_config, sign_pq_fn_dsa_with_config_unverified, sign_pq_ml_dsa,
    sign_pq_ml_dsa_with_config, sign_pq_ml_dsa_with_config_unverified, sign_pq_slh_dsa,
    sign_pq_slh_dsa_with_config, sign_pq_slh_dsa_with_config_unverified, verify_pq_fn_dsa,
    verify_pq_fn_dsa_with_config, verify_pq_fn_dsa_with_config_unverified, verify_pq_ml_dsa,
    verify_pq_ml_dsa_with_config, verify_pq_ml_dsa_with_config_unverified, verify_pq_slh_dsa,
    verify_pq_slh_dsa_with_config, verify_pq_slh_dsa_with_config_unverified,
};
use latticearc::unified_api::zero_trust::SecurityMode;

// ============================================================
// ML-DSA with _with_config_unverified wrappers
// ============================================================

#[test]
fn test_ml_dsa_44_sign_verify_with_config_unverified() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let config = CoreConfig::default();
    let message = b"ML-DSA-44 config unverified test";

    let sig = sign_pq_ml_dsa_with_config_unverified(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        &config,
    )
    .unwrap();
    let valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &sig,
        &pk,
        MlDsaParameterSet::MLDSA44,
        &config,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_65_sign_verify_with_config_unverified() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    let config = CoreConfig::default();
    let message = b"ML-DSA-65 config unverified test";

    let sig = sign_pq_ml_dsa_with_config_unverified(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        &config,
    )
    .unwrap();
    let valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &sig,
        &pk,
        MlDsaParameterSet::MLDSA65,
        &config,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_87_sign_verify_with_config_unverified() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).unwrap();
    let config = CoreConfig::default();
    let message = b"ML-DSA-87 config unverified test";

    let sig = sign_pq_ml_dsa_with_config_unverified(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA87,
        &config,
    )
    .unwrap();
    let valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &sig,
        &pk,
        MlDsaParameterSet::MLDSA87,
        &config,
    )
    .unwrap();
    assert!(valid);
}

// ============================================================
// ML-DSA with explicit SecurityMode
// ============================================================

#[test]
fn test_ml_dsa_sign_verify_explicit_mode() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let message = b"ML-DSA explicit SecurityMode::Unverified";

    let sig =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MLDSA44, SecurityMode::Unverified)
            .unwrap();
    let valid =
        verify_pq_ml_dsa(message, &sig, &pk, MlDsaParameterSet::MLDSA44, SecurityMode::Unverified)
            .unwrap();
    assert!(valid);
}

#[test]
fn test_ml_dsa_with_config_explicit_mode() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let config = CoreConfig::default();
    let message = b"ML-DSA with config + explicit SecurityMode";

    let sig = sign_pq_ml_dsa_with_config(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        &config,
        SecurityMode::Unverified,
    )
    .unwrap();
    let valid = verify_pq_ml_dsa_with_config(
        message,
        &sig,
        &pk,
        MlDsaParameterSet::MLDSA44,
        &config,
        SecurityMode::Unverified,
    )
    .unwrap();
    assert!(valid);
}

// ============================================================
// SLH-DSA with config + SecurityMode
// ============================================================

#[test]
fn test_slh_dsa_128s_sign_verify_with_security_mode() {
    std::thread::Builder::new()
        .name("slh_128s_mode".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
            let message = b"SLH-DSA-128s SecurityMode test";

            let sig = sign_pq_slh_dsa(
                message,
                sk.as_ref(),
                SlhDsaSecurityLevel::Shake128s,
                SecurityMode::Unverified,
            )
            .unwrap();
            let valid = verify_pq_slh_dsa(
                message,
                &sig,
                &pk,
                SlhDsaSecurityLevel::Shake128s,
                SecurityMode::Unverified,
            )
            .unwrap();
            assert!(valid);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_slh_dsa_128s_sign_verify_with_config_unverified() {
    std::thread::Builder::new()
        .name("slh_128s_cfg".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
            let config = CoreConfig::default();
            let message = b"SLH-DSA-128s config unverified";

            let sig = sign_pq_slh_dsa_with_config_unverified(
                message,
                sk.as_ref(),
                SlhDsaSecurityLevel::Shake128s,
                &config,
            )
            .unwrap();
            let valid = verify_pq_slh_dsa_with_config_unverified(
                message,
                &sig,
                &pk,
                SlhDsaSecurityLevel::Shake128s,
                &config,
            )
            .unwrap();
            assert!(valid);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_slh_dsa_with_config_explicit_mode() {
    std::thread::Builder::new()
        .name("slh_cfg_mode".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).unwrap();
            let config = CoreConfig::default();
            let message = b"SLH-DSA explicit config + mode";

            let sig = sign_pq_slh_dsa_with_config(
                message,
                sk.as_ref(),
                SlhDsaSecurityLevel::Shake128s,
                &config,
                SecurityMode::Unverified,
            )
            .unwrap();
            let valid = verify_pq_slh_dsa_with_config(
                message,
                &sig,
                &pk,
                SlhDsaSecurityLevel::Shake128s,
                &config,
                SecurityMode::Unverified,
            )
            .unwrap();
            assert!(valid);
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================
// FN-DSA with config + SecurityMode
// ============================================================

#[test]
fn test_fn_dsa_sign_verify_with_security_mode() {
    std::thread::Builder::new()
        .name("fn_dsa_mode".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (pk, sk) = generate_fn_dsa_keypair().unwrap();
            let message = b"FN-DSA SecurityMode test";

            let sig = sign_pq_fn_dsa(message, sk.as_ref(), SecurityMode::Unverified).unwrap();
            let valid = verify_pq_fn_dsa(message, &sig, &pk, SecurityMode::Unverified).unwrap();
            assert!(valid);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_fn_dsa_sign_verify_with_config_unverified() {
    std::thread::Builder::new()
        .name("fn_dsa_cfg".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (pk, sk) = generate_fn_dsa_keypair().unwrap();
            let config = CoreConfig::default();
            let message = b"FN-DSA config unverified";

            let sig = sign_pq_fn_dsa_with_config_unverified(message, sk.as_ref(), &config).unwrap();
            let valid =
                verify_pq_fn_dsa_with_config_unverified(message, &sig, &pk, &config).unwrap();
            assert!(valid);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_fn_dsa_with_config_explicit_mode() {
    std::thread::Builder::new()
        .name("fn_dsa_cfg_m".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (pk, sk) = generate_fn_dsa_keypair().unwrap();
            let config = CoreConfig::default();
            let message = b"FN-DSA explicit config + mode";

            let sig =
                sign_pq_fn_dsa_with_config(message, sk.as_ref(), &config, SecurityMode::Unverified)
                    .unwrap();
            let valid =
                verify_pq_fn_dsa_with_config(message, &sig, &pk, &config, SecurityMode::Unverified)
                    .unwrap();
            assert!(valid);
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================
// Error paths: invalid keys
// ============================================================

#[test]
fn test_ml_dsa_sign_with_invalid_key() {
    let bad_sk = vec![0xAA; 10];
    let message = b"test";

    let result =
        sign_pq_ml_dsa(message, &bad_sk, MlDsaParameterSet::MLDSA44, SecurityMode::Unverified);
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_verify_with_invalid_key() {
    let bad_pk = vec![0xBB; 10];
    let bad_sig = vec![0xCC; 100];
    let message = b"test";

    let result = verify_pq_ml_dsa(
        message,
        &bad_sig,
        &bad_pk,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    );
    assert!(result.is_err());
}

#[test]
fn test_slh_dsa_sign_with_invalid_key() {
    std::thread::Builder::new()
        .name("slh_bad_key".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bad_sk = vec![0xAA; 10];
            let message = b"test";

            let result = sign_pq_slh_dsa(
                message,
                &bad_sk,
                SlhDsaSecurityLevel::Shake128s,
                SecurityMode::Unverified,
            );
            assert!(result.is_err());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_fn_dsa_sign_with_invalid_key() {
    std::thread::Builder::new()
        .name("fn_bad_key".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bad_sk = vec![0xAA; 10];
            let message = b"test";

            let result = sign_pq_fn_dsa(message, &bad_sk, SecurityMode::Unverified);
            assert!(result.is_err());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn test_fn_dsa_verify_with_invalid_key() {
    std::thread::Builder::new()
        .name("fn_bad_vk".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bad_pk = vec![0xBB; 10];
            let bad_sig = vec![0xCC; 100];
            let message = b"test";

            let result = verify_pq_fn_dsa(message, &bad_sig, &bad_pk, SecurityMode::Unverified);
            assert!(result.is_err());
        })
        .unwrap()
        .join()
        .unwrap();
}

// ============================================================
// Config-based error paths
// ============================================================

#[test]
fn test_ml_dsa_with_config_invalid_key() {
    let bad_sk = vec![0xAA; 10];
    let config = CoreConfig::default();
    let message = b"test";

    let result = sign_pq_ml_dsa_with_config_unverified(
        message,
        &bad_sk,
        MlDsaParameterSet::MLDSA44,
        &config,
    );
    assert!(result.is_err());
}

#[test]
fn test_ml_dsa_verify_with_config_invalid() {
    let bad_pk = vec![0xBB; 10];
    let bad_sig = vec![0xCC; 100];
    let config = CoreConfig::default();
    let message = b"test";

    let result = verify_pq_ml_dsa_with_config_unverified(
        message,
        &bad_sig,
        &bad_pk,
        MlDsaParameterSet::MLDSA44,
        &config,
    );
    assert!(result.is_err());
}
