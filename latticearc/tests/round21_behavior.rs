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
    assert_eq!(KeyAlgorithm::HybridMlKem768X25519.nist_security_level(), SecurityLevel::High);
    assert_eq!(KeyAlgorithm::HybridMlDsa65Ed25519.nist_security_level(), SecurityLevel::High);

    // Maximum / Level 5
    assert_eq!(KeyAlgorithm::MlKem1024.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::MlDsa87.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::SlhDsaShake256f.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::FnDsa1024.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::Aes256.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::ChaCha20.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::HybridMlKem1024X25519.nist_security_level(), SecurityLevel::Maximum);
    assert_eq!(KeyAlgorithm::HybridMlDsa87Ed25519.nist_security_level(), SecurityLevel::Maximum);
}
