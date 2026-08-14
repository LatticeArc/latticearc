//! `unified_api::self_tests_passed()` must report the latch that actually
//! gates cryptographic operations.
//!
//! Two separate booleans track self-test state: `unified_api`'s own
//! `SELF_TESTS_PASSED`, set by `init()`, and `primitives::self_test`'s
//! `SELF_TEST_PASSED`, which is what `fips_verify_operational` enforces on
//! every gated operation. If the public query reports only the first, it can
//! answer "yes, self-tests passed" for a module that refuses every operation —
//! a misleading answer to the one question a FIPS evidence collector asks.
//!
//! Both assertions run in one test function: the latches are process-global,
//! so a second `#[test]` in this binary would race.

#![cfg(all(feature = "fips-self-test", feature = "test-utils"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use latticearc::primitives::self_test::{
    ModuleErrorCode, clear_error_state, initialize_and_test, set_module_error,
};

#[test]
fn test_self_tests_passed_tracks_the_latch_that_gates_operations_succeeds() {
    clear_error_state();

    // init() must leave the module genuinely operational — not just flip its
    // own private flag. A caller who runs init() and gets Ok must be able to
    // perform a gated operation immediately afterwards.
    latticearc::unified_api::init().expect("init must succeed on a healthy module");

    assert!(
        latticearc::unified_api::self_tests_passed(),
        "self_tests_passed() must be true after a successful init()"
    );
    assert!(
        latticearc::primitives::self_test::self_tests_passed(),
        "init() must drive the primitives power-up path that gated operations \
         enforce, not a separate private test run"
    );
    assert!(
        latticearc::unified_api::hash_data(b"post-init").is_ok(),
        "a gated operation must succeed immediately after init() returns Ok"
    );

    // FIPS 140-3 §9.6: once the module is in an error state it provides no
    // cryptographic services — so the public self-test query must stop
    // claiming the self-tests are passing.
    set_module_error(ModuleErrorCode::SelfTestFailure);
    let reported_while_in_error = latticearc::unified_api::self_tests_passed();
    let op_refused_while_in_error = latticearc::unified_api::hash_data(b"in-error").is_err();

    // Restore before asserting so a failure cannot leave the process-wide
    // latch tripped for anything that runs after.
    clear_error_state();
    let _ = initialize_and_test();

    assert!(
        op_refused_while_in_error,
        "gated operations must be refused while the module is in an error state"
    );
    assert!(
        !reported_while_in_error,
        "self_tests_passed() must report false while the module is in an error \
         state — it must track the operational latch, not a stale init()-time flag"
    );
}
