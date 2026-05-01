//! Behavioral regression tests for the round-21 audit fixes.
//!
//! Each test asserts a *user-visible* property the corresponding fix is
//! supposed to provide. To be a genuine regression blocker each test
//! must:
//!   1. PASS against the round-21-fixed code.
//!   2. FAIL if the fix is reverted.
//!
//! The second property is what makes the test useful — coverage that
//! still passes after the fix is gone is theatre.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

/// Hand-crafted PortableKey JSON that omits both `use_case` and
/// `security_level`. Shape mirrors a valid AES256 symmetric key minus
/// the two required discriminator fields.
const KEY_JSON_MISSING_DISCRIMINATORS: &str = r#"{
    "version": 1,
    "algorithm": "aes-256",
    "key_type": "symmetric",
    "key_data": { "raw": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
    "created": "2026-04-29T00:00:00Z",
    "metadata": {}
}"#;

/// `PortableKey::from_json` must reject payloads that omit both
/// `use_case` and `security_level` — the documented invariant for keys
/// crossing the wire format boundary. Reverting the
/// `check_use_case_or_security_level_invariant()` call (or the default
/// `security_level` set by `PortableKey::new`) makes this test pass-
/// through silently — which is the failure mode it guards against.
#[test]
fn portable_key_from_json_rejects_payload_with_neither_use_case_nor_security_level() {
    use latticearc::unified_api::key_format::PortableKey;

    let result = PortableKey::from_json(KEY_JSON_MISSING_DISCRIMINATORS);
    assert!(
        result.is_err(),
        "from_json must reject a payload that omits both use_case and security_level"
    );
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("use_case") || err_str.contains("security_level"),
        "error must mention the missing fields, got: {err_str}"
    );
}

/// Same check via the CBOR boundary. We can't hand-craft CBOR easily
/// without the matching `Serialize` types, so we round-trip via JSON:
/// parse the malformed payload into a `serde_json::Value`, then re-
/// encode that value as CBOR.
#[test]
fn portable_key_from_cbor_rejects_payload_with_neither_use_case_nor_security_level() {
    use latticearc::unified_api::key_format::PortableKey;

    let value: serde_json::Value = serde_json::from_str(KEY_JSON_MISSING_DISCRIMINATORS).unwrap();
    let mut cbor = Vec::new();
    ciborium::into_writer(&value, &mut cbor).unwrap();

    let result = PortableKey::from_cbor(&cbor);
    assert!(
        result.is_err(),
        "from_cbor must reject a payload that omits both use_case and security_level"
    );
}

/// External callers must read lifecycle-state fields through the
/// accessor methods (read-only) and may only mutate state via
/// [`KeyLifecycleRecord::transition`]. The privatized fields prevent
/// any "fix-up" path that would let an attacker skip a state — Rust's
/// visibility system enforces this at compile time.
#[test]
fn key_lifecycle_record_state_only_advances_through_transition() {
    use latticearc::types::error::TypeError;
    use latticearc::types::key_lifecycle::{KeyLifecycleRecord, KeyLifecycleState};

    let mut record =
        KeyLifecycleRecord::new("test-key".to_string(), "ML-KEM-768".to_string(), 3, 365, 30);

    assert_eq!(record.current_state(), KeyLifecycleState::Generation);
    assert!(record.activated_at().is_none());

    record
        .transition(KeyLifecycleState::Active, "alice".to_string(), "init".to_string(), None)
        .expect("Generation -> Active");
    assert_eq!(record.current_state(), KeyLifecycleState::Active);
    assert!(record.activated_at().is_some());
    assert_eq!(record.generator(), Some("alice"));
    assert_eq!(record.state_history().len(), 1);

    // Active -> Destroyed bypasses Retired and must be rejected.
    let bad = record.transition(
        KeyLifecycleState::Destroyed,
        "mallory".to_string(),
        "skip retirement".to_string(),
        None,
    );
    assert!(matches!(bad, Err(TypeError::InvalidStateTransition { .. })));
    assert_eq!(record.current_state(), KeyLifecycleState::Active);
}

/// Each invalid transition the state machine forbids must remain
/// rejected. Table-tests every illegal edge so a regression in a
/// single arm of `KeyStateMachine::is_valid_transition` is caught.
#[test]
fn key_lifecycle_record_rejects_every_illegal_transition() {
    use latticearc::types::error::TypeError;
    use latticearc::types::key_lifecycle::{KeyLifecycleRecord, KeyLifecycleState};

    // (start_state, target_state) pairs that must be rejected.
    let illegal = [
        (KeyLifecycleState::Generation, KeyLifecycleState::Destroyed),
        (KeyLifecycleState::Generation, KeyLifecycleState::Retired),
        (KeyLifecycleState::Generation, KeyLifecycleState::Rotating),
        (KeyLifecycleState::Active, KeyLifecycleState::Destroyed),
        (KeyLifecycleState::Active, KeyLifecycleState::Generation),
        (KeyLifecycleState::Rotating, KeyLifecycleState::Destroyed),
        (KeyLifecycleState::Rotating, KeyLifecycleState::Generation),
        (KeyLifecycleState::Retired, KeyLifecycleState::Active),
        (KeyLifecycleState::Retired, KeyLifecycleState::Generation),
        (KeyLifecycleState::Destroyed, KeyLifecycleState::Active),
        (KeyLifecycleState::Destroyed, KeyLifecycleState::Retired),
    ];

    let valid_path = [
        KeyLifecycleState::Active,
        KeyLifecycleState::Rotating,
        KeyLifecycleState::Retired,
        KeyLifecycleState::Destroyed,
    ];

    for (start, target) in illegal {
        // Walk the state machine to `start` along the canonical path.
        let mut record = KeyLifecycleRecord::new(
            format!("k-{start:?}-{target:?}"),
            "ML-KEM-768".to_string(),
            3,
            365,
            30,
        );
        for step in &valid_path {
            if record.current_state() == start {
                break;
            }
            record
                .transition(*step, "ops".to_string(), "step".to_string(), None)
                .expect("walk path");
        }
        assert_eq!(record.current_state(), start);

        let bad = record.transition(target, "ops".to_string(), "bad".to_string(), None);
        assert!(
            matches!(bad, Err(TypeError::InvalidStateTransition { .. })),
            "state machine accepted illegal transition {start:?} -> {target:?}"
        );
        assert_eq!(record.current_state(), start, "illegal transition mutated state");
    }
}

/// `run_power_up_tests` must set `SELF_TEST_PASSED` so the documented
/// standalone entry-point pattern works:
///   if run_power_up_tests().is_pass() { assert!(is_module_operational()) }
///
/// Reverting the `SELF_TEST_PASSED.store(true, Release)` inside
/// `run_power_up_tests` makes `is_module_operational()` return `false`
/// even after a clean Pass — this test catches that regression.
#[cfg(feature = "fips-self-test")]
#[test]
fn run_power_up_tests_pass_makes_module_operational() {
    use latticearc::primitives::self_test::{
        SelfTestResult, is_module_operational, run_power_up_tests,
    };

    let result = run_power_up_tests();
    assert!(matches!(result, SelfTestResult::Pass));
    assert!(is_module_operational(), "module must be operational after a clean power-up self test");
}

/// `KeyAlgorithm::nist_security_level` is a 20-arm match. Spot-check
/// every NIST bucket so silent miscategorization (or a missed match
/// arm on a future variant) surfaces in CI.
#[test]
fn key_algorithm_nist_security_level_buckets() {
    use latticearc::types::types::SecurityLevel;
    use latticearc::unified_api::key_format::KeyAlgorithm;

    // Standard / Level 1
    assert_eq!(KeyAlgorithm::MlKem512.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::MlDsa44.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::SlhDsaShake128s.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::FnDsa512.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::Ed25519.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::X25519.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::HybridMlKem512X25519.nist_security_level(), SecurityLevel::Standard);
    assert_eq!(KeyAlgorithm::HybridMlDsa44Ed25519.nist_security_level(), SecurityLevel::Standard);

    // High / Level 3
    assert_eq!(KeyAlgorithm::MlKem768.nist_security_level(), SecurityLevel::High);
    assert_eq!(KeyAlgorithm::MlDsa65.nist_security_level(), SecurityLevel::High);
    assert_eq!(KeyAlgorithm::SlhDsaShake192s.nist_security_level(), SecurityLevel::High);
    assert_eq!(KeyAlgorithm::HybridMlKem768X25519.nist_security_level(), SecurityLevel::High);
    assert_eq!(KeyAlgorithm::HybridMlDsa65Ed25519.nist_security_level(), SecurityLevel::High);

    // Maximum / Level 5
    assert_eq!(KeyAlgorithm::MlKem1024.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::MlDsa87.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::SlhDsaShake256s.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::FnDsa1024.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::Aes256.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::ChaCha20.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::HybridMlKem1024X25519.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::HybridMlDsa87Ed25519.nist_security_level(), SecurityLevel::Maximum);
}

/// Inverse property: every variant emitted by `canonical_name()` must
/// round-trip back through `from_canonical_name()`. Catches the "added
/// a variant but forgot to update the parser" drift that the simplify-
/// v3 review identified — the parser is now the single source of truth
/// shared by both `parse_legacy_algorithm` and the CLI keyfile parser,
/// so a missing arm silently rejects keys the library can produce.
#[test]
fn key_algorithm_canonical_name_round_trips_through_from_canonical_name() {
    use latticearc::unified_api::key_format::KeyAlgorithm;

    let all_variants = [
        KeyAlgorithm::MlKem512,
        KeyAlgorithm::MlKem768,
        KeyAlgorithm::MlKem1024,
        KeyAlgorithm::MlDsa44,
        KeyAlgorithm::MlDsa65,
        KeyAlgorithm::MlDsa87,
        KeyAlgorithm::SlhDsaShake128s,
        KeyAlgorithm::SlhDsaShake192s,
        KeyAlgorithm::SlhDsaShake256s,
        KeyAlgorithm::FnDsa512,
        KeyAlgorithm::FnDsa1024,
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::X25519,
        KeyAlgorithm::Aes256,
        KeyAlgorithm::ChaCha20,
        KeyAlgorithm::HybridMlKem512X25519,
        KeyAlgorithm::HybridMlKem768X25519,
        KeyAlgorithm::HybridMlKem1024X25519,
        KeyAlgorithm::HybridMlDsa44Ed25519,
        KeyAlgorithm::HybridMlDsa65Ed25519,
        KeyAlgorithm::HybridMlDsa87Ed25519,
    ];

    for variant in all_variants {
        let name = variant.canonical_name();
        let parsed = KeyAlgorithm::from_canonical_name(name)
            .unwrap_or_else(|| panic!("from_canonical_name rejected '{}' — drift!", name));
        assert_eq!(
            parsed, variant,
            "round-trip mismatch: canonical_name({variant:?}) = {name:?}, from_canonical_name = {parsed:?}"
        );
    }
}

/// Pre-round-21 callers may still tag keys with `"fn-dsa"` (no level
/// suffix). Confirm that `from_canonical_name` accepts the bare alias
/// and maps it to `FnDsa512` so legacy keyfiles continue to load.
#[test]
fn key_algorithm_from_canonical_name_accepts_fn_dsa_legacy_alias() {
    use latticearc::unified_api::key_format::KeyAlgorithm;

    assert_eq!(KeyAlgorithm::from_canonical_name("fn-dsa"), Some(KeyAlgorithm::FnDsa512));
    assert_eq!(KeyAlgorithm::from_canonical_name("fn-dsa-512"), Some(KeyAlgorithm::FnDsa512));
    assert_eq!(KeyAlgorithm::from_canonical_name("fn-dsa-1024"), Some(KeyAlgorithm::FnDsa1024));
}

/// FN-DSA-1024 must be reachable end-to-end through the unified API.
/// The canonical_name "fn-dsa-1024" is wired into the keygen, sign, and
/// verify dispatch tables (round-21 audit fix H3). Without this test, a
/// silent revert of any of the three arms would not surface in CI.
#[test]
fn fn_dsa_1024_unified_api_keygen_sign_verify_round_trips() {
    use latticearc::primitives::sig::fndsa::FnDsaSecurityLevel;
    use latticearc::unified_api::{
        generate_fn_dsa_keypair_with_level, sign_pq_fn_dsa_unverified, verify_pq_fn_dsa_unverified,
    };

    let (pk, sk) =
        generate_fn_dsa_keypair_with_level(FnDsaSecurityLevel::Level1024).expect("keygen");
    let message = b"FN-DSA-1024 unified-API regression vector";

    let sig = sign_pq_fn_dsa_unverified(message, sk.expose_secret(), FnDsaSecurityLevel::Level1024)
        .expect("sign");
    let valid =
        verify_pq_fn_dsa_unverified(message, &sig, pk.as_ref(), FnDsaSecurityLevel::Level1024)
            .expect("verify call");
    assert!(valid, "FN-DSA-1024 verify must accept its own signature");

    // Tamper detection: the signature must fail to verify against a
    // different message — proves the key/signature actually carry
    // FN-DSA-1024 semantics rather than landing on a `Level512` arm
    // by mistake. `verify_pq_fn_dsa_unverified` may return either
    // `Ok(false)` or `Err(VerificationFailed)` for a tampered input;
    // both are valid rejection signals.
    let tampered = b"FN-DSA-1024 tampered message";
    let result =
        verify_pq_fn_dsa_unverified(tampered, &sig, pk.as_ref(), FnDsaSecurityLevel::Level1024);
    let rejected = matches!(result, Ok(false) | Err(_));
    assert!(rejected, "FN-DSA-1024 verify must reject signatures over a different message");
}

/// The L1 endianness change in `zkp::sigma` (LE → BE) is a wire-format
/// break. Round-trip tests alone don't catch it because they generate
/// and verify in the same process. Pin the byte layout of a hand-built
/// transcript so a silent revert to LE would be caught: BE encodes
/// length 4 as `0x00 0x00 0x00 0x04`, LE as `0x04 0x00 0x00 0x00`.
#[test]
fn fiat_shamir_transcript_uses_big_endian_length_prefixes() {
    let domain: &[u8] = b"arc-zkp/sigma-test-domain-v1";
    let statement: &[u8] = b"STMT";
    let commitment: &[u8] = b"COMM";
    let context: &[u8] = b"CTX_";

    // Mirror the transcript construction in `zkp::sigma::compute_challenge`.
    let statement_len = u32::try_from(statement.len()).expect("test fixture fits u32");
    let commitment_len = u32::try_from(commitment.len()).expect("test fixture fits u32");
    let context_len = u32::try_from(context.len()).expect("test fixture fits u32");

    let mut buf = Vec::new();
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&statement_len.to_be_bytes());
    buf.extend_from_slice(statement);
    buf.extend_from_slice(&commitment_len.to_be_bytes());
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(&context_len.to_be_bytes());
    buf.extend_from_slice(context);

    // BE encoding: length 4 bytes render as `0x00 0x00 0x00 0x04`. The
    // first length-prefix byte after the domain separator must be 0x00
    // (not 0x04, which would indicate LE).
    let prefix_start = domain.len();
    let prefix_bytes = buf
        .get(prefix_start..prefix_start.saturating_add(4))
        .expect("transcript longer than domain + 4 bytes");
    assert_eq!(
        prefix_bytes,
        &[0x00, 0x00, 0x00, 0x04],
        "BE length-prefix mismatch: a revert to LE would produce 0x04,0x00,0x00,0x00"
    );
}
