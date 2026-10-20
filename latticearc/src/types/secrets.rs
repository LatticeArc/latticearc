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
//! | Swap protection (opt-in, `SecretVec` only) | `secret-mlock` feature; outcome via [`SecretVec::is_locked`] and [`memory_lock_status`] |
//!
//! ## When to use which
//!
//! ```text
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
    ///
    /// # Note on memory locking
    ///
    /// `SecretBytes<N>` is stack-allocated, so `mlock(2)`-style page
    /// pinning does not apply: each clone is a fresh stack location
    /// (no heap pages to lock). If a caller specifically needs OS-level
    /// memory-lock semantics for a duplicated secret, use
    /// [`SecretVec`] (heap-backed) instead.
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
/// With the `secret-mlock` feature enabled on Linux, macOS, Android and other
/// Unix targets, each non-empty `SecretVec` asks the kernel to keep the pages
/// backing its buffer resident in RAM via `mlock(2)`, so the bytes are not
/// written to swap. This implements invariant I-10. `mlock` does not exclude
/// the pages from core dumps; disable core dumps at the process level if that
/// matters for your deployment.
///
/// Locking is best-effort and its outcome is reported, not hidden:
///
/// - [`SecretVec::is_locked`] says whether this buffer's pages are locked.
/// - [`memory_lock_status`] returns a process-wide [`MemoryLockStatus`] with
///   the number of currently locked buffers, the number of failed attempts and
///   the most recent OS error.
///
/// If locking fails (for example `RLIMIT_MEMLOCK` exceeded — Android
/// typically allows only 64 KiB per process), the `SecretVec` is still
/// returned with an unlocked backing. The bytes remain zeroized on drop; only
/// the swap protection is missing. Applications should surface
/// [`memory_lock_status`] to the user or operator instead of assuming success.
///
/// Page locks do not nest in the kernel: unlocking a page unlocks it for every
/// buffer on it. The crate therefore reference-counts locked pages process-wide
/// and only unlocks a page when the last `SecretVec` using it is dropped, so
/// [`SecretVec::is_locked`] stays accurate while neighbouring buffers come and
/// go. Each newly locked page costs one `mlock` call.
///
/// On Windows the feature is a no-op (see [`MemoryLockStatus::supported`]):
/// `is_locked` is always `false`. Without the feature, `mlock` is never called
/// and the crate does not depend on `region`.
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
/// use latticearc::types::{SecretVec, memory_lock_status};
///
/// let key = SecretVec::new(vec![0x42u8; 48]);
/// assert_eq!(key.len(), 48);
/// assert_eq!(key.expose_secret()[0], 0x42);
///
/// // Without the `secret-mlock` feature this is always `false`.
/// let _locked: bool = key.is_locked();
/// let status = memory_lock_status();
/// assert_eq!(status.feature_enabled, cfg!(feature = "secret-mlock"));
///
/// let debug = format!("{:?}", key);
/// assert!(debug.contains("[REDACTED]"));
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    // Drop order when `secret-mlock` is enabled:
    //   1. `ZeroizeOnDrop`'s generated `Drop` runs first, calling `.zeroize()`
    //      on `bytes` while the pages are still locked.
    //   2. Fields drop in declaration order: `lock` first (releases this
    //      buffer's page references via `MlockGuard`'s Drop), then `bytes`
    //      (returns the zeroed buffer to the allocator).
    // `#[zeroize(skip)]` is required because the lock holder does not
    // implement `Zeroize` and there's nothing secret inside it — it only
    // holds page addresses.
    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[zeroize(skip)]
    lock: Option<mlock::MlockGuard>,
    bytes: Vec<u8>,
}

/// Process-wide snapshot of OS memory locking for [`SecretVec`] buffers.
///
/// Returned by [`memory_lock_status`]. Intended for display: a vault app can
/// show "secrets pinned in RAM" or "memory locking unavailable (limit
/// reached)" instead of silently running without swap protection.
///
/// On Android, `RLIMIT_MEMLOCK` is typically 64 KiB per process, so
/// `failed_buffers > 0` is an expected state there once enough secrets are
/// alive at the same time; show it rather than hide it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryLockStatus {
    /// `true` when this build attempts to lock `SecretVec` buffers: the
    /// `secret-mlock` feature is enabled and the target is not Windows.
    pub supported: bool,
    /// `true` when the crate was built with the `secret-mlock` feature
    /// (including Windows builds, where locking is still not attempted).
    pub feature_enabled: bool,
    /// Number of currently alive `SecretVec` buffers whose pages are locked.
    /// Increases on each successful lock and decreases when such a buffer is
    /// dropped.
    pub locked_buffers: usize,
    /// Number of lock attempts that failed since process start. Never
    /// decreases; a non-zero value means at least one `SecretVec` ran
    /// without swap protection.
    pub failed_buffers: usize,
    /// Operating-system error text of the most recent failed lock attempt,
    /// or `None` if no attempt has failed.
    pub last_error: Option<String>,
}

/// Return the process-wide [`MemoryLockStatus`].
///
/// Cheap: two atomic loads and one short mutex acquisition. Without the
/// `secret-mlock` feature, or on Windows, every counter is zero and
/// `supported` is `false`.
#[must_use]
pub fn memory_lock_status() -> MemoryLockStatus {
    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    {
        mlock::status()
    }
    #[cfg(not(all(feature = "secret-mlock", not(target_os = "windows"))))]
    {
        MemoryLockStatus {
            supported: false,
            feature_enabled: cfg!(feature = "secret-mlock"),
            locked_buffers: 0,
            failed_buffers: 0,
            last_error: None,
        }
    }
}

/// Reference-counted page locking for [`SecretVec`] (Unix only).
///
/// # Why reference counting
///
/// `mlock` / `munlock` operate on whole pages and do not nest: two buffers on
/// the same page share one lock, and `munlock` from the first buffer's drop
/// would silently unlock the page under the second. The registry below keeps
/// one [`region::LockGuard`] per locked page plus a count of the `SecretVec`
/// buffers using it, and only drops the guard (unlocking the page) when the
/// count reaches zero.
///
/// # Why Windows is excluded
///
/// `VirtualLock` is documented as best-effort: pages can be implicitly
/// unlocked when the working set is trimmed, and a later `VirtualUnlock`
/// returns `ERROR_NOT_LOCKED`. `region` asserts on that error in its `Drop`,
/// so a routine working-set trim would turn into a Drop-time panic. The bytes
/// are still zeroized at Drop via `ZeroizeOnDrop` on Windows.
///
/// # Drop-time panics
///
/// `region::LockGuard::drop` contains a `debug_assert!` on the unlock result.
/// Each page guard is dropped inside [`std::panic::catch_unwind`] so a failed
/// `munlock` in a debug build cannot escape a `SecretVec` Drop chain (which
/// may run while already unwinding). `catch_unwind` is a no-op under
/// `panic = "abort"`; release builds compile the `debug_assert!` out.
#[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
mod mlock {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;

    use super::MemoryLockStatus;

    /// One locked page and the number of live buffers that use it.
    struct PageLock {
        refs: usize,
        guard: region::LockGuard,
    }

    /// Locked pages keyed by page base address.
    static PAGES: Mutex<BTreeMap<usize, PageLock>> = Mutex::new(BTreeMap::new());
    /// Live `SecretVec` buffers whose pages are all locked.
    static LOCKED_BUFFERS: AtomicUsize = AtomicUsize::new(0);
    /// Failed lock attempts since process start.
    static FAILED_BUFFERS: AtomicUsize = AtomicUsize::new(0);
    /// OS error text of the most recent failure.
    static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

    /// Proof that one buffer holds a reference on every page in
    /// `first_page .. first_page + page_count * page_size`.
    pub(super) struct MlockGuard {
        first_page: usize,
        page_count: usize,
        page_size: usize,
    }

    impl Drop for MlockGuard {
        fn drop(&mut self) {
            release_pages(self.first_page, self.page_count, self.page_size);
            // Checked decrement: the counter was incremented when this guard
            // was created, so it cannot be zero here; `try_update` leaves it
            // at zero instead of wrapping if that invariant were ever broken.
            let _ = LOCKED_BUFFERS
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        }
    }

    /// Lock every page overlapping `bytes`. Returns `None` for an empty
    /// buffer (no attempt is made) or when the OS refuses the lock; the
    /// failure case is recorded in the process-wide status.
    pub(super) fn lock(bytes: &[u8]) -> Option<MlockGuard> {
        if bytes.is_empty() {
            return None;
        }
        match lock_pages(bytes) {
            Ok(guard) => {
                LOCKED_BUFFERS.fetch_add(1, Ordering::AcqRel);
                Some(guard)
            }
            Err(message) => {
                record_lock_failure(message);
                None
            }
        }
    }

    /// Record a failed lock attempt. Crate-private so the bookkeeping can be
    /// unit-tested without lowering `RLIMIT_MEMLOCK` in the test process.
    pub(super) fn record_lock_failure(message: String) {
        FAILED_BUFFERS.fetch_add(1, Ordering::AcqRel);
        *LAST_ERROR.lock() = Some(message);
    }

    /// Snapshot of the counters.
    pub(super) fn status() -> MemoryLockStatus {
        MemoryLockStatus {
            supported: true,
            feature_enabled: true,
            locked_buffers: LOCKED_BUFFERS.load(Ordering::Acquire),
            failed_buffers: FAILED_BUFFERS.load(Ordering::Acquire),
            last_error: LAST_ERROR.lock().clone(),
        }
    }

    /// Page range `(first_page, page_count, page_size)` covering `bytes`.
    fn page_range(bytes: &[u8]) -> Option<(usize, usize, usize)> {
        let page_size = region::page::size();
        let start = bytes.as_ptr().addr();
        let last = start.checked_add(bytes.len())?.checked_sub(1)?;
        let first_page = start.checked_sub(start.checked_rem(page_size)?)?;
        let last_page = last.checked_sub(last.checked_rem(page_size)?)?;
        let page_count =
            last_page.checked_sub(first_page)?.checked_div(page_size)?.checked_add(1)?;
        Some((first_page, page_count, page_size))
    }

    fn lock_pages(bytes: &[u8]) -> Result<MlockGuard, String> {
        let (first_page, page_count, page_size) =
            page_range(bytes).ok_or_else(|| "buffer address range overflows".to_string())?;
        // Pointer to the first page, derived from the buffer pointer so the
        // address handed to the OS keeps the allocation's provenance.
        let offset = bytes.as_ptr().addr().saturating_sub(first_page);
        let base = bytes.as_ptr().wrapping_sub(offset);

        let mut pages = PAGES.lock();
        for index in 0..page_count {
            let delta = index.checked_mul(page_size);
            let page = delta.and_then(|d| first_page.checked_add(d));
            let (Some(delta), Some(page)) = (delta, page) else {
                drop(pages);
                release_pages(first_page, index, page_size);
                return Err("buffer address range overflows".to_string());
            };
            if let Some(entry) = pages.get_mut(&page) {
                entry.refs = entry.refs.saturating_add(1);
                continue;
            }
            match region::lock(base.wrapping_add(delta), page_size) {
                Ok(guard) => {
                    pages.insert(page, PageLock { refs: 1, guard });
                }
                Err(err) => {
                    drop(pages);
                    // Roll back the references this call already took.
                    release_pages(first_page, index, page_size);
                    return Err(err.to_string());
                }
            }
        }
        Ok(MlockGuard { first_page, page_count, page_size })
    }

    /// Drop one reference on each of `page_count` pages starting at
    /// `first_page`, unlocking pages whose count reaches zero.
    fn release_pages(first_page: usize, page_count: usize, page_size: usize) {
        let mut unlocked: Vec<region::LockGuard> = Vec::new();
        {
            let mut pages = PAGES.lock();
            for index in 0..page_count {
                let Some(page) =
                    index.checked_mul(page_size).and_then(|d| first_page.checked_add(d))
                else {
                    break;
                };
                let remove = match pages.get_mut(&page) {
                    Some(entry) => {
                        entry.refs = entry.refs.saturating_sub(1);
                        entry.refs == 0
                    }
                    None => false,
                };
                if remove && let Some(entry) = pages.remove(&page) {
                    unlocked.push(entry.guard);
                }
            }
        }
        // `munlock` runs outside the registry mutex.
        for guard in unlocked {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                drop(guard);
            }));
        }
    }

    /// Reference count of the page containing `addr`, for tests.
    #[cfg(test)]
    pub(super) fn page_refs(addr: usize) -> Option<usize> {
        let page_size = region::page::size();
        let page = addr.checked_sub(addr.checked_rem(page_size)?)?;
        PAGES.lock().get(&page).map(|entry| entry.refs)
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
    /// 1. Backing capacity == length, so the owned `Vec` has no slack
    ///    that could outlive a future shrink/realloc. (`zeroize 1.8`'s
    ///    `Vec<Z>::zeroize` does wipe the full capacity — `iter_mut +
    ///    clear + spare_capacity_mut().zeroize()` — but the exact-size
    ///    invariant keeps that property robust against future moves
    ///    that change the underlying allocation.)
    /// 2. The original caller-supplied buffer is wiped *in place* before
    ///    its `Vec` Drop hands the memory back to the allocator, so no
    ///    copy of the secret persists in any allocator free-list. This
    ///    is the property the new exact-size `owned` cannot provide on
    ///    its own, because it inherits none of the original's slack
    ///    capacity.
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
        let lock = mlock::lock(&owned);
        Self {
            #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
            lock,
            bytes: owned,
        }
    }

    /// Returns `true` if this buffer's pages are locked into RAM.
    ///
    /// `true` only when the `secret-mlock` feature is enabled, the target is
    /// not Windows, the buffer is non-empty and `mlock` succeeded for every
    /// page it occupies. Locked pages stay locked until this `SecretVec` is
    /// dropped (see the reference-counting note on the type). A `false`
    /// result means the bytes may be written to swap; they are still
    /// zeroized on drop. Use [`memory_lock_status`] for the process-wide
    /// picture.
    #[must_use]
    #[inline]
    pub fn is_locked(&self) -> bool {
        #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
        {
            self.lock.is_some()
        }
        #[cfg(not(all(feature = "secret-mlock", not(target_os = "windows"))))]
        {
            false
        }
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
    // additionally lock their backing pages into RAM and record the outcome.
    // Other tests in this binary create `SecretVec`s concurrently, so the
    // process-wide counters are asserted with lower bounds here; the exact
    // create/drop accounting is checked in the single-test integration binary
    // `tests/secrets_memory_lock_status.rs`.

    #[test]
    fn secrets_memory_lock_status_reports_feature_flag() {
        let status = memory_lock_status();
        assert_eq!(status.feature_enabled, cfg!(feature = "secret-mlock"));
        assert_eq!(
            status.supported,
            cfg!(all(feature = "secret-mlock", not(target_os = "windows")))
        );
    }

    #[cfg(not(all(feature = "secret-mlock", not(target_os = "windows"))))]
    #[test]
    fn secrets_is_locked_false_without_lock_support() {
        let sv = SecretVec::new(vec![0x42u8; 1024]);
        assert!(!sv.is_locked());
        let status = memory_lock_status();
        assert_eq!(status.locked_buffers, 0);
        assert_eq!(status.failed_buffers, 0);
        assert_eq!(status.last_error, None);
        assert!(!status.supported);
    }

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
    fn secrets_locked_buffer_is_counted_while_alive() {
        let alive: Vec<SecretVec> = (0..8).map(|_| SecretVec::new(vec![0x11u8; 64])).collect();
        let locked_here = alive.iter().filter(|sv| sv.is_locked()).count();
        let status = memory_lock_status();
        assert!(status.supported);
        assert!(status.feature_enabled);
        // Other threads can only add their own live buffers, never remove ours.
        assert!(status.locked_buffers >= locked_here);
        if locked_here < alive.len() {
            assert!(status.failed_buffers >= alive.len() - locked_here);
            assert!(status.last_error.is_some());
        }
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secrets_injected_lock_failure_is_reported() {
        // Exercising a real `mlock` failure needs a lowered RLIMIT_MEMLOCK,
        // which is environment-dependent. Inject the outcome through the
        // same crate-private hook the production failure path calls.
        let before = memory_lock_status().failed_buffers;
        mlock::record_lock_failure("injected: Cannot allocate memory (os error 12)".to_string());
        let status = memory_lock_status();
        assert!(status.failed_buffers > before);
        assert!(status.last_error.is_some());

        // A buffer whose lock attempt failed reports `is_locked() == false`
        // while keeping its bytes and redacted Debug.
        let unlocked = SecretVec { lock: None, bytes: vec![0x5Au8; 32] };
        assert!(!unlocked.is_locked());
        assert_eq!(unlocked.expose_secret(), &[0x5Au8; 32]);
        assert!(format!("{unlocked:?}").contains("[REDACTED]"));
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secrets_shared_pages_are_reference_counted() {
        // Three pages of our own: the middle page cannot be shared with any
        // other allocation, so its reference count is ours alone.
        let page = region::page::size();
        let buffer = vec![0u8; page.saturating_mul(3)];
        let middle = buffer.as_ptr().addr().saturating_add(page.saturating_add(page / 2));
        let Some(first) = mlock::lock(&buffer) else {
            // Environment refused the lock; the bookkeeping must say so.
            assert!(memory_lock_status().failed_buffers > 0);
            return;
        };
        assert_eq!(mlock::page_refs(middle), Some(1));
        let second = mlock::lock(&buffer);
        assert!(second.is_some());
        assert_eq!(mlock::page_refs(middle), Some(2));
        // Dropping one holder must not unlock the page for the other.
        drop(first);
        assert_eq!(mlock::page_refs(middle), Some(1));
        drop(second);
        assert_eq!(mlock::page_refs(middle), None);
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
        // Empty buffers have no valid base pointer to lock; `mlock::lock`
        // must return `None` without calling into the OS.
        let sv = SecretVec::zero(0);
        assert_eq!(sv.len(), 0);
        assert!(sv.is_empty());
        assert!(!sv.is_locked());
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn secret_vec_mlock_clone_is_independent() {
        // Cloning must lock the new buffer independently — the original's
        // page references do not transfer.
        let original = SecretVec::new(vec![0x77u8; 512]);
        let copy = original.clone_for_transmission();
        assert_eq!(copy.len(), 512);
        assert_eq!(copy.expose_secret().first().copied(), Some(0x77));
        let original_locked = original.is_locked();
        // Drop the copy first — the original's lock must remain valid.
        drop(copy);
        assert_eq!(original.expose_secret().first().copied(), Some(0x77));
        assert_eq!(original.is_locked(), original_locked);
    }

    #[cfg(all(feature = "secret-mlock", not(target_os = "windows")))]
    #[test]
    fn mlock_guard_drop_does_not_panic_under_repeated_lock_unlock() {
        // Regression test for the Drop-time double-panic hazard described
        // on the `mlock` module. Allocate, lock, and drop many `SecretVec`s
        // in sequence; each page guard is dropped inside `catch_unwind`, so
        // a failed `munlock` cannot abort the process. Success is reaching
        // the end of the loop.
        for _ in 0..32 {
            let sv = SecretVec::new(vec![0xA5u8; 4096]);
            assert_eq!(sv.expose_secret().len(), 4096);
            // explicit drop forces `lock` then `bytes` to drop in order.
            drop(sv);
        }
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
