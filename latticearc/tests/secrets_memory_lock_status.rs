//! Exact create/drop accounting for `memory_lock_status()`.
//!
//! This binary holds a single test so no other thread creates `SecretVec`s
//! while the process-wide counters are compared exactly. The assertions are
//! environment-independent: each buffer's own `is_locked()` decides whether
//! it should be counted as locked or as failed.

use latticearc::{SecretVec, memory_lock_status};

#[test]
fn secrets_memory_lock_status_counts_live_buffers_exactly() {
    let before = memory_lock_status();
    assert_eq!(before.feature_enabled, cfg!(feature = "secret-mlock"));
    assert_eq!(before.supported, cfg!(all(feature = "secret-mlock", not(target_os = "windows"))));

    let alive: Vec<SecretVec> =
        (0..16usize).map(|i| SecretVec::new(vec![0xC3u8; 64 + i * 512])).collect();
    let locked = alive.iter().filter(|sv| sv.is_locked()).count();
    // Without lock support no attempt is made, so nothing counts as failed.
    let failed = if before.supported { alive.len() - locked } else { 0 };
    if !before.supported {
        assert_eq!(locked, 0, "is_locked() must be false without lock support");
    }

    let during = memory_lock_status();
    assert_eq!(during.locked_buffers, before.locked_buffers + locked);
    assert_eq!(during.failed_buffers, before.failed_buffers + failed);
    if failed > 0 {
        assert!(during.last_error.is_some());
    }

    // An empty buffer is never an attempt: neither counter moves.
    let empty = SecretVec::zero(0);
    assert!(!empty.is_locked());
    assert_eq!(memory_lock_status(), during);

    drop(alive);
    drop(empty);
    let after = memory_lock_status();
    assert_eq!(after.locked_buffers, before.locked_buffers);
    // Failures are cumulative and survive the drop.
    assert_eq!(after.failed_buffers, during.failed_buffers);
}
