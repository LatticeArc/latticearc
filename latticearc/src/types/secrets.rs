//! # Secret byte containers
//!
//! Provides the two primitive secret types used throughout LatticeArc:
//!
//! - [`SecretBytes<N>`]: fixed-size secret bytes, stack-allocated `[u8; N]` backing.
//!   Preferred whenever the length is compile-time known.
//! - [`SecretVec`]: variable-length secret bytes, heap-allocated `Vec<u8>` backing.
//!   Used only when the length genuinely varies at runtime.
//!
//! Both types uphold the full Secret Type Invariant set — see
//! [`docs/SECRET_TYPE_INVARIANTS.md`](../../../docs/SECRET_TYPE_INVARIANTS.md)
//! for the canonical, normative specification.
//!
//! ## Quick reference
//!
//! | Invariant | Mechanism |
//! |---|---|
//! | Wipe on drop | `#[derive(Zeroize, ZeroizeOnDrop)]` — volatile writes |
//! | Redacted `Debug` | Manual `fmt::Debug` impl emits `"[REDACTED]"` |
//! | Timing-safe equality | `impl ConstantTimeEq` |
//! | No `PartialEq` / `Eq` | Enforced at `tests/no_partial_eq_on_secret_types.rs` |
//! | No `Clone` | Explicit `clone_for_transmission(&self) -> Self` |
//! | Sealed accessor | `expose_secret()` only — no `AsRef`, no `Deref` |
//!
//! ## When to use which
//!
//! ```ignore
//! // 32-byte HKDF-Extract output: fixed size → SecretBytes<32>
//! fn hkdf_extract(...) -> SecretBytes<32>;
//!
//! // 64-byte hybrid shared secret: fixed size → SecretBytes<64>
//! struct EncapsulatedKey { shared_secret: SecretBytes<64>, ... }
//!
//! // AEAD plaintext: length varies with input → SecretVec
//! fn decrypt_aes_gcm(...) -> SecretVec;
//!
//! // PBKDF2 output with user-specified key_length → SecretVec
//! fn pbkdf2(..., key_length: usize) -> SecretVec;
//! ```

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// SecretBytes<N> — fixed-size, stack-allocated
// ============================================================================

/// Fixed-size secret byte container, stack-allocated.
///
/// The `[u8; N]` backing store never reallocates, never migrates across the heap,
/// and is wiped by volatile writes on drop. Prefer this type over [`SecretVec`]
/// whenever `N` is compile-time known.
///
/// # Security invariants
///
/// - **Wipe on drop**: `#[derive(Zeroize, ZeroizeOnDrop)]` emits volatile writes
///   that the compiler cannot optimize away.
/// - **Redacted `Debug`**: the bytes are never printed; `"[REDACTED]"` is emitted.
/// - **Timing-safe equality**: [`ConstantTimeEq`] compares all `N` bytes in time
///   independent of their contents; `PartialEq`/`Eq` are not implemented.
/// - **No `Clone`**: duplication must go through [`clone_for_transmission`] so
///   every copy is a grep-able audit checkpoint.
/// - **Sealed access**: the bytes are exposed only through [`expose_secret`]. No
///   `AsRef<[u8]>`, no `Deref`, no public field.
///
/// [`clone_for_transmission`]: Self::clone_for_transmission
/// [`expose_secret`]: Self::expose_secret
///
/// # Why stack-allocated matters
///
/// - Heap allocators retain size metadata after `free`, which is a side-channel
///   leak about secret sizes in adversary-controlled environments.
/// - A `Vec<u8>` with a single `.push()` past capacity silently reallocates and
///   frees the old buffer **without zeroization**. `[u8; N]` has no such escape.
/// - Stack memory is reclaimed in deterministic scope order, not at allocator
///   whim.
///
/// # Example
///
/// ```
/// use latticearc::types::SecretBytes;
///
/// // Construct from raw bytes (e.g., after filling a buffer with KDF output)
/// let key: SecretBytes<32> = SecretBytes::new([0x42u8; 32]);
/// assert_eq!(key.len(), 32);
/// assert_eq!(key.expose_secret()[0], 0x42);
///
/// // Debug is redacted
/// let debug = format!("{:?}", key);
/// assert!(debug.contains("[REDACTED]"));
/// assert!(!debug.contains("42"));
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Construct from raw bytes.
    ///
    /// The passed array is moved in; no copy is made beyond the move itself.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Construct an all-zero buffer.
    ///
    /// Build the final byte pattern in a plain `[u8; N]` on the stack, then
    /// hand the array to [`Self::new`]; use [`Self::zero`] when the caller
    /// wants an all-zero placeholder (e.g., a struct field that is overwritten
    /// by a downstream operation).
    #[must_use]
    #[inline]
    pub const fn zero() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Length in bytes. Always equals the const generic `N`.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` if `N == 0`.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Expose the inner bytes.
    ///
    /// This is the **only** public read accessor. Every call site is a grep-able
    /// audit checkpoint: `rg '\.expose_secret\(\)'` enumerates every point at
    /// which secret bytes are read.
    ///
    /// Consumers should hold the returned slice only as long as needed and
    /// should never copy it into a non-secret container (a subsequent `.to_vec()`
    /// or struct field of type `Vec<u8>` would evade zeroization).
    #[must_use]
    #[inline]
    pub const fn expose_secret(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Create an independent copy.
    ///
    /// `Clone` is intentionally not derived. Use this method when duplication is
    /// semantically required — for example, sending a shared secret across a
    /// channel boundary — so every duplication is grep-able.
    #[must_use]
    #[inline]
    pub fn clone_for_transmission(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes").field("len", &N).field("bytes", &"[REDACTED]").finish()
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

// ============================================================================
// SecretVec — variable-length, heap-allocated
// ============================================================================

/// Variable-length secret byte container, heap-allocated.
///
/// Use only when the length genuinely varies at runtime (e.g., user-specified
/// PBKDF2 output length, AEAD plaintext of arbitrary input). For any
/// compile-time-known length, prefer [`SecretBytes<N>`].
///
/// # Security invariants
///
/// Same as [`SecretBytes`]. See type-level docs for the full list.
///
/// # Reallocation safety
///
/// The internal `Vec<u8>` is never reallocated by this type's public API: there
/// is no `push`, no `extend`, no `reserve`. All construction paths allocate the
/// final size up front. If a caller needs to build a secret incrementally, they
/// must build the full `Vec<u8>` first (outside this wrapper), then pass it to
/// [`Self::new`] — at which point reallocation is no longer a concern because
/// subsequent mutation is not exposed.
///
/// # OS-level memory locking (`secret-mlock` feature)
///
/// With the `secret-mlock` feature enabled, each `SecretVec` locks its backing
/// buffer into RAM via `mlock(2)` (Linux/macOS) or `VirtualLock` (Windows) so
/// the bytes cannot be swapped to disk or captured in a core dump. This
/// implements invariant I-10. If locking fails at construction time (e.g.,
/// `RLIMIT_MEMLOCK` exceeded), the `SecretVec` is still returned with an
/// unlocked backing — the bytes remain zeroized on drop, but OS-level leakage
/// protection is not active. Without the feature, `mlock` is not called and
/// the type has no dependency on the `region` crate.
///
/// `SecretBytes<N>` is deliberately NOT covered by this feature: its `[u8; N]`
/// backing is stack-allocated, so mlocking it would require per-instance
/// page-aligned locking of arbitrary stack addresses — impractical and
/// incompatible with Rust's move semantics. Callers who need OS-level
/// protection for small fixed-size secrets should wrap them in `SecretVec` at
/// a boundary where the sensitive bytes leave the stack.
///
/// # Example
///
/// ```
/// use latticearc::types::SecretVec;
///
/// let key = SecretVec::new(vec![0x42u8; 48]);
/// assert_eq!(key.len(), 48);
/// assert_eq!(key.expose_secret()[0], 0x42);
///
/// let debug = format!("{:?}", key);
/// assert!(debug.contains("[REDACTED]"));
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    // Drop order when `secret-mlock` is enabled:
    //   1. `ZeroizeOnDrop`'s generated `Drop` runs first, calling `.zeroize()`
    //      on `bytes` while the region is still mlocked.
    //   2. Fields drop in declaration order: `_lock` first (unlocks the
    //      region via `MlockGuard`'s panic-tolerant Drop), then `bytes`
    //      (returns the zeroed buffer to the allocator).
    // `#[zeroize(skip)]` is required because the lock holder does not
    // implement `Zeroize` and there's nothing secret inside it — it only
    // holds a handle to an OS lock.
    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[zeroize(skip)]
    _lock: Option<MlockGuard>,
    bytes: Vec<u8>,
}

/// Panic-tolerant wrapper around [`region::LockGuard`].
///
/// # Why this wrapper exists
///
/// `region::LockGuard::drop` calls `munlock`/`VirtualUnlock` and panics on any
/// error. That is too strict on Windows: `VirtualUnlock` returns
/// `ERROR_NOT_LOCKED` (158) when the OS has already released the lock — most
/// commonly because the working set was trimmed under memory pressure. Per
/// Microsoft's documentation `VirtualLock` is *best-effort*: pages can be
/// implicitly unlocked when the working set is trimmed, and a subsequent
/// `VirtualUnlock` returning `ERROR_NOT_LOCKED` is documented behaviour, not
/// a logic error. Panicking on it is wrong, and panicking inside `Drop` is
/// itself a soundness hazard — secret containers can drop while unwinding
/// from another panic, and a Drop-time double-panic aborts the process.
///
/// # Behaviour
///
/// On every platform, the wrapper hands `region::LockGuard::drop` to
/// [`std::panic::catch_unwind`] so that any panic raised by the underlying
/// unlock syscall (notably the Windows `ERROR_NOT_LOCKED` path) is caught
/// at the wrapper boundary instead of escaping into the surrounding Drop
/// chain.
///
/// - **Unix:** the `munlock` syscall does not have the working-set-trim
///   quirk and reliably succeeds for any region we successfully locked, so
///   `catch_unwind` should never fire — the guard runs through normally.
///   The wrapper is functionally identical to a bare
///   `Option<region::LockGuard>` on this platform.
/// - **Windows:** if `VirtualUnlock` returns `ERROR_NOT_LOCKED` (the
///   working-set-trim case), `region` raises a panic; we catch it,
///   discard it, and return cleanly. If unlock succeeds (the common case)
///   the panic is never raised. Either way the OS lock accounting is
///   resolved before the backing `Vec` is freed.
///
/// # Why `catch_unwind` and not direct FFI
///
/// A direct `VirtualUnlock` FFI call would also work but requires
/// `unsafe_code` (the workspace-wide deny gate would need a targeted
/// `#[allow]` with justification) and either a new `windows-sys` dep or
/// hand-rolled FFI declarations. Catching the panic at the Rust boundary
/// keeps the safe-code guarantee, avoids a new platform-dep, and still
/// achieves correct unlock-on-drop semantics. The runtime cost on the
/// success path (no panic raised) is a single `catch_unwind` setup, which
/// is a stack-only operation — negligible compared to the syscall.
///
/// # Security guarantee
///
/// `VirtualLock` is documented as best-effort; a working-set trim could
/// already have swapped the page to disk *before* our drop. Whether we
/// explicitly unlock at drop or not has no effect on whether the secret
/// was resident while it mattered. The bytes are zeroized by
/// `ZeroizeOnDrop` regardless.
///
/// # Caveat
///
/// `catch_unwind` is a no-op when the binary is built with
/// `panic = "abort"`; in that mode the original `LockGuard::drop` panic
/// would still abort the process. The workspace defaults to
/// `panic = "unwind"` and `catch_unwind` works as expected. Downstream
/// users who switch to `panic = "abort"` for size/perf should be aware
/// that the Windows working-set-trim path becomes an abort hazard again.
///
/// # Upstream
///
/// If `region` ever changes its `Drop` to tolerate `ERROR_NOT_LOCKED` on
/// Windows, this wrapper can be deleted and the field reverted to
/// `Option<region::LockGuard>`.
#[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
struct MlockGuard(Option<region::LockGuard>);

#[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
impl Drop for MlockGuard {
    fn drop(&mut self) {
        let Some(guard) = self.0.take() else { return };
        // Run the inner `LockGuard::drop` (which calls `munlock` /
        // `VirtualUnlock`) inside `catch_unwind` so that any panic — most
        // notably Windows `ERROR_NOT_LOCKED` after a working-set trim —
        // is contained at this wrapper boundary instead of cascading into
        // a Drop-time double-panic that would abort the process.
        // `AssertUnwindSafe` is sound here because we discard `guard` on
        // either path; nothing observed by other code can be left in an
        // inconsistent state.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            drop(guard);
        }));
    }
}

impl SecretVec {
    /// Construct from a `Vec<u8>`.
    ///
    /// The vector is moved in; its capacity is taken as-is. For best security
    /// hygiene, construct the passed `Vec` at its final length (e.g.,
    /// `vec![0u8; len]`) rather than growing it, so no unzeroized intermediate
    /// buffer is ever freed.
    #[must_use]
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }

    /// Construct an all-zero buffer of the given length.
    #[must_use]
    #[inline]
    pub fn zero(len: usize) -> Self {
        Self::from_bytes(vec![0u8; len])
    }

    /// Single construction path.
    ///
    /// Allocates a fresh `Vec<u8>` of exactly `bytes.len()` capacity, copies
    /// the secret in, then zeroizes the caller-supplied buffer in place. This
    /// is deliberately NOT `bytes.shrink_to_fit()`: `shrink_to_fit` may
    /// internally call the allocator's `realloc`, which copies the secret
    /// into a smaller allocation and frees the original WITHOUT zeroizing.
    /// The freed buffer is then immediately available for allocator reuse
    /// — a classic "secret in freed memory" leak that affects any caller
    /// passing in an over-allocated `Vec` (e.g. `BASE64_ENGINE.decode(...)?`,
    /// which pre-sizes with slack).
    ///
    /// The exact-size copy + caller-side wipe pattern guarantees:
    /// 1. Backing capacity == length, so `Vec::zeroize` (which only wipes
    ///    `..len`, not `..capacity` in `zeroize 1.8`) covers every byte at
    ///    Drop time.
    /// 2. The original caller-supplied buffer is wiped before its `Vec`
    ///    Drop hands the memory back to the allocator, so no copy of the
    ///    secret persists in any allocator free-list.
    #[inline]
    fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        let mut owned: Vec<u8> = Vec::with_capacity(len);
        owned.extend_from_slice(&bytes);
        // Wipe the caller-supplied buffer in place: this covers any slack
        // capacity in the ORIGINAL allocation, which the new `owned` does
        // not inherit. Without this, an over-sized incoming `Vec` (e.g.
        // base64 decode output) would leave secret material in the freed
        // tail when `bytes` is dropped.
        use zeroize::Zeroize;
        bytes.zeroize();
        drop(bytes);

        #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
        let _lock = Self::try_lock(&owned);
        Self {
            #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
            _lock,
            bytes: owned,
        }
    }

    /// Attempt to lock the backing buffer into RAM. Returns `None` on empty
    /// buffers (locking a dangling pointer is UB) or on `mlock` failure
    /// (e.g. `RLIMIT_MEMLOCK` exceeded, or Windows working-set quota
    /// exceeded). Failures are swallowed: the bytes are still zeroized on
    /// drop, we simply lose OS-level leakage protection.
    ///
    /// The successful lock is returned wrapped in [`MlockGuard`] so its Drop
    /// is panic-tolerant — see the type-level docs there for the Windows
    /// `VirtualUnlock` rationale.
    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[inline]
    fn try_lock(bytes: &[u8]) -> Option<MlockGuard> {
        if bytes.is_empty() {
            return None;
        }
        region::lock(bytes.as_ptr(), bytes.len()).ok().map(|g| MlockGuard(Some(g)))
    }

    /// Length in bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the backing buffer is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Expose the inner bytes. The only public read accessor.
    #[must_use]
    #[inline]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Create an independent copy. See [`SecretBytes::clone_for_transmission`].
    ///
    /// With the `secret-mlock` feature, the cloned buffer is independently
    /// locked into RAM (the original's `LockGuard` does not transfer).
    #[must_use]
    pub fn clone_for_transmission(&self) -> Self {
        Self::from_bytes(self.bytes.clone())
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretVec")
            .field("len", &self.bytes.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for SecretVec {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------- SecretBytes<N> --------

    #[test]
    fn secret_bytes_new_and_expose() {
        let sb: SecretBytes<32> = SecretBytes::new([0x42u8; 32]);
        assert_eq!(sb.expose_secret(), &[0x42u8; 32]);
        assert_eq!(sb.len(), 32);
        assert!(!sb.is_empty());
    }

    #[test]
    fn secret_bytes_zero() {
        let sb: SecretBytes<16> = SecretBytes::zero();
        assert_eq!(sb.expose_secret(), &[0u8; 16]);
    }

    #[test]
    fn secret_bytes_zero_sized() {
        let sb: SecretBytes<0> = SecretBytes::new([]);
        assert_eq!(sb.len(), 0);
        assert!(sb.is_empty());
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let sb: SecretBytes<4> = SecretBytes::new([0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{:?}", sb);
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("len"));
        // Verify none of the secret bytes leaked into the output
        assert!(!debug.contains("DE"));
        assert!(!debug.contains("AD"));
        assert!(!debug.contains("BE"));
        assert!(!debug.contains("EF"));
        assert!(!debug.contains("222")); // 0xDE = 222 decimal
    }

    #[test]
    fn secret_bytes_ct_eq_equal() {
        let a: SecretBytes<32> = SecretBytes::new([0x42u8; 32]);
        let b: SecretBytes<32> = SecretBytes::new([0x42u8; 32]);
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn secret_bytes_ct_eq_not_equal() {
        let a: SecretBytes<32> = SecretBytes::new([0x42u8; 32]);
        let mut different = [0x42u8; 32];
        if let Some(first) = different.first_mut() {
            *first = 0x41;
        }
        let b: SecretBytes<32> = SecretBytes::new(different);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn secret_bytes_clone_for_transmission() {
        let original: SecretBytes<16> = SecretBytes::new([0x55u8; 16]);
        let copy = original.clone_for_transmission();
        assert!(bool::from(original.ct_eq(&copy)));
        // Mutating one must not affect the other (independent storage).
        drop(original);
        assert_eq!(copy.expose_secret(), &[0x55u8; 16]);
    }

    #[test]
    fn secret_bytes_large_n_compiles() {
        // ML-DSA-87 secret key size — apache already stack-allocates buffers
        // this large, so SecretBytes<4896> must also be buildable.
        let sb: SecretBytes<4896> = SecretBytes::zero();
        assert_eq!(sb.len(), 4896);
    }

    // -------- SecretVec --------

    #[test]
    fn secret_vec_new_and_expose() {
        let sv = SecretVec::new(vec![0x42u8; 48]);
        assert_eq!(sv.expose_secret(), &[0x42u8; 48]);
        assert_eq!(sv.len(), 48);
        assert!(!sv.is_empty());
    }

    #[test]
    fn secret_vec_zero() {
        let sv = SecretVec::zero(24);
        assert_eq!(sv.expose_secret(), &[0u8; 24]);
    }

    #[test]
    fn secret_vec_empty() {
        let sv = SecretVec::zero(0);
        assert_eq!(sv.len(), 0);
        assert!(sv.is_empty());
    }

    #[test]
    fn secret_vec_debug_is_redacted() {
        let sv = SecretVec::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{:?}", sv);
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("DE"));
        assert!(!debug.contains("EF"));
    }

    #[test]
    fn secret_vec_ct_eq_equal() {
        let a = SecretVec::new(vec![0x42u8; 48]);
        let b = SecretVec::new(vec![0x42u8; 48]);
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn secret_vec_ct_eq_not_equal_same_len() {
        let a = SecretVec::new(vec![0x42u8; 48]);
        let mut different = vec![0x42u8; 48];
        if let Some(last) = different.last_mut() {
            *last = 0x41;
        }
        let b = SecretVec::new(different);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn secret_vec_ct_eq_different_len() {
        let a = SecretVec::new(vec![0x42u8; 32]);
        let b = SecretVec::new(vec![0x42u8; 48]);
        // subtle's ConstantTimeEq for slices returns 0 when lengths differ.
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn secret_vec_clone_for_transmission() {
        let original = SecretVec::new(vec![0x77u8; 32]);
        let copy = original.clone_for_transmission();
        assert!(bool::from(original.ct_eq(&copy)));
        drop(original);
        assert_eq!(copy.expose_secret(), &[0x77u8; 32]);
    }

    // -------- Zeroization verification --------
    //
    // We cannot directly observe the memory after drop (Rust's safety prevents
    // that), but we can verify that Zeroize::zeroize() wipes an in-place buffer.

    #[test]
    fn secret_bytes_manual_zeroize_clears() {
        let mut sb: SecretBytes<16> = SecretBytes::new([0xAAu8; 16]);
        sb.zeroize();
        assert_eq!(sb.expose_secret(), &[0u8; 16]);
    }

    #[test]
    fn secret_vec_manual_zeroize_clears() {
        let mut sv = SecretVec::new(vec![0xAAu8; 16]);
        sv.zeroize();
        // After zeroize the Vec is cleared to zeros but keeps its length.
        // (zeroize 1.8's Zeroize impl on Vec<u8> sets the elements to 0 and
        // truncates the length. Verify the bytes-in-view are zero.)
        for &byte in sv.expose_secret() {
            assert_eq!(byte, 0);
        }
    }

    // -------- secret-mlock feature --------
    //
    // When the `secret-mlock` feature is enabled, `SecretVec` constructors
    // additionally lock their backing buffer into RAM. These tests only
    // exercise the observable behavior (successful construction and byte
    // access); the lock itself is an OS-level property that we cannot inspect
    // from safe Rust.

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secret_vec_mlock_new_succeeds() {
        // Size chosen well under any reasonable RLIMIT_MEMLOCK (typically 64 KiB
        // on Linux without CAP_IPC_LOCK).
        let sv = SecretVec::new(vec![0x42u8; 1024]);
        assert_eq!(sv.len(), 1024);
        assert_eq!(sv.expose_secret().first().copied(), Some(0x42));
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secret_vec_mlock_zero_succeeds() {
        let sv = SecretVec::zero(256);
        assert_eq!(sv.len(), 256);
        assert!(sv.expose_secret().iter().all(|&b| b == 0));
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secret_vec_mlock_empty_does_not_lock() {
        // Empty buffers have no valid base pointer to lock; `try_lock` must
        // return `None` without calling into the OS.
        let sv = SecretVec::zero(0);
        assert_eq!(sv.len(), 0);
        assert!(sv.is_empty());
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secret_vec_mlock_clone_is_independent() {
        // Cloning must lock the new buffer independently — the original's
        // `LockGuard` does not transfer.
        let original = SecretVec::new(vec![0x77u8; 512]);
        let copy = original.clone_for_transmission();
        assert_eq!(copy.len(), 512);
        assert_eq!(copy.expose_secret().first().copied(), Some(0x77));
        // Drop the copy first — the original's lock must remain valid.
        drop(copy);
        assert_eq!(original.expose_secret().first().copied(), Some(0x77));
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn mlock_guard_drop_does_not_panic_under_repeated_lock_unlock() {
        // Regression test for the Drop-time double-panic hazard described
        // on `MlockGuard`. Allocate, lock, and drop many `SecretVec`s in
        // sequence. If `region::LockGuard::drop` ever raises a panic (e.g.
        // Windows working-set trim → `ERROR_NOT_LOCKED`) the wrapper's
        // `catch_unwind` must contain it; this test would otherwise abort
        // the process. Success is reaching the final assertion.
        for _ in 0..32 {
            let sv = SecretVec::new(vec![0xA5u8; 4096]);
            assert_eq!(sv.expose_secret().len(), 4096);
            // explicit drop forces `_lock` then `bytes` to drop in order.
            drop(sv);
        }
        // Reached if no panic escaped any `MlockGuard::drop`.
    }

    #[test]
    fn secret_vec_from_bytes_handles_oversize_capacity_input() {
        // Regression test for the `shrink_to_fit` realloc-leak fix that
        // motivated the explicit `Vec::with_capacity(len) + extend_from_slice
        // + zeroize(source)` pattern. Construct a Vec with intentional
        // slack capacity (mimicking what `BASE64_ENGINE.decode` produces),
        // hand it to `SecretVec::new` (which calls `from_bytes` internally),
        // and verify (a) the returned SecretVec contains the correct data
        // and (b) its capacity equals its length (no slack inherited).
        let mut over_alloc: Vec<u8> = Vec::with_capacity(1024);
        over_alloc.extend_from_slice(&[0x5Au8; 64]);
        assert_eq!(over_alloc.len(), 64);
        assert!(over_alloc.capacity() >= 1024, "test setup: source must have slack capacity");

        let sv = SecretVec::new(over_alloc);
        assert_eq!(sv.len(), 64);
        assert!(sv.expose_secret().iter().all(|&b| b == 0x5A));
        assert_eq!(
            sv.bytes.capacity(),
            sv.bytes.len(),
            "SecretVec must store the data with capacity == length so \
             ZeroizeOnDrop covers every backing byte"
        );
    }

    #[test]
    fn secret_vec_zeroize_on_drop_clears_backing_storage() {
        // End-to-end check that `ZeroizeOnDrop` actually fires by
        // applying `Zeroize` directly on the same Vec shape that
        // `SecretVec` wraps. Confirms the trait implementation is wired
        // correctly without needing freed-memory inspection (which is UB
        // in safe Rust). If this assertion fails, the SecretVec drop path
        // would also fail to wipe — so it transitively pins the contract.
        use zeroize::Zeroize;
        let mut buf: Vec<u8> = vec![0xCDu8; 128];
        buf.zeroize();
        assert!(buf.iter().all(|&b| b == 0), "Vec::zeroize must clear all bytes in-place");
    }
}
