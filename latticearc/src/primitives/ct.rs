//! Constant-time helpers usable across primitive modules.
//!
//! Centralises CT predicates that several primitives share (AEAD weak-key
//! check, KDF salt validation, tag/MAC comparison, ...) so each call site cannot accidentally
//! reach for the early-exiting `iter().all()` form. All functions here use
//! [`subtle::ConstantTimeEq`] under the hood.

use subtle::ConstantTimeEq;

/// Constant-time equality of two byte slices.
///
/// Use this for comparing secret or attacker-influenced values (MAC tags,
/// derived keys, hashes of secrets) instead of `==`, which exits at the
/// first differing byte.
///
/// Slices of different lengths compare unequal and return `false`
/// immediately: lengths are treated as public, so this early return is
/// not a timing leak for fixed-size values. For slices of equal length the
/// running time is independent of the contents and of the position of any
/// difference. Two empty slices are equal.
///
/// When the length is known at compile time, prefer [`ct_eq_array`].
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Constant-time equality of two fixed-length byte arrays.
///
/// Like [`ct_eq`], but the shared length `N` is enforced by the type
/// system, so a length mismatch cannot occur and no length branch is taken.
/// Two zero-length arrays are equal.
#[inline]
#[must_use]
pub fn ct_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// Constant-time all-zero check for fixed-length byte arrays.
///
/// Prefer this over [`is_all_zero_bytes`] whenever the length is known
/// at compile time: the loop iteration count is `ceil(N / 32)` — a
/// constant — so the caller cannot accidentally pass a runtime-derived
/// length that would leak through timing. AEAD key validation (16-,
/// 24-, 32-byte keys) is the canonical call site.
///
/// Returns `false` when `N == 0` so a zero-length array cannot trigger
/// a false-positive weak-input rejection.
#[inline]
#[must_use]
pub fn is_all_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    if N == 0 {
        return false;
    }
    is_all_zero_bytes(bytes.as_slice())
}

/// Returns `true` iff every byte of `bytes` is zero, in constant time
/// **with respect to byte contents**.
///
/// Empty slices return `false` so that a caller passing a zero-length
/// secret cannot trigger a false-positive weak-input rejection.
///
/// # Constant-time scope and a length-leak caveat
///
/// Runtime is independent of *which byte* is non-zero, so an attacker
/// who can time this function cannot learn the position of the first
/// difference. The loop, however, iterates `ceil(bytes.len() / 32)`
/// times — the iteration count itself is **not constant-time over the
/// input length**. For variable-length secret inputs (KDF output of
/// caller-chosen size, secret-length nonces, etc.) the timing leaks
/// the length.
///
/// **Production callers must validate `bytes.len()` before calling this
/// function** (which the current sole caller `aead::is_all_zero_key`
/// does, by way of the AEAD constructors' fixed-size key requirement).
/// For new fixed-length use sites, prefer the const-generic
/// [`is_all_zero`] above — its type signature makes the length-non-
/// secrecy precondition compile-time enforced.
#[inline]
#[must_use]
pub fn is_all_zero_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    const CHUNK: usize = 32;
    let zero = [0u8; CHUNK];
    let mut acc = subtle::Choice::from(1u8);
    let mut i = 0usize;
    while i < bytes.len() {
        let end = i.saturating_add(CHUNK).min(bytes.len());
        let len = end.saturating_sub(i);
        let chunk = bytes.get(i..end).unwrap_or(&[]);
        let zero_slice = zero.get(..len).unwrap_or(&zero);
        acc &= chunk.ct_eq(zero_slice);
        i = end;
    }
    bool::from(acc)
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, ct_eq_array, is_all_zero_bytes};

    #[test]
    fn test_all_zero_returns_true() {
        assert!(is_all_zero_bytes(&[0u8; 16]));
        assert!(is_all_zero_bytes(&[0u8; 32]));
        assert!(is_all_zero_bytes(&[0u8; 33]));
        assert!(is_all_zero_bytes(&[0u8; 64]));
        assert!(is_all_zero_bytes(&[0u8; 100]));
    }

    #[test]
    fn test_any_nonzero_returns_false() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(!is_all_zero_bytes(&bytes));
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        assert!(!is_all_zero_bytes(&bytes));
        let mut bytes = [0u8; 64];
        bytes[63] = 1;
        assert!(!is_all_zero_bytes(&bytes));
    }

    #[test]
    fn test_empty_returns_false() {
        // Empty inputs are not "weak" — they're just unsupported. Returning
        // `false` prevents downstream callers from rejecting an empty key
        // as weak-zero when the actual issue is length validation.
        assert!(!is_all_zero_bytes(&[]));
    }

    #[test]
    fn test_oversize_chunked_path() {
        // Larger than CHUNK (32) and not a multiple, exercises the partial-
        // last-chunk branch. PBKDF2 salts in the wild are 16-64 bytes.
        assert!(is_all_zero_bytes(&[0u8; 65]));
        let mut bytes = [0u8; 65];
        bytes[64] = 1;
        assert!(!is_all_zero_bytes(&bytes));
    }

    #[test]
    fn test_ct_eq_equal_slices() {
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(ct_eq(&[0u8; 100], &[0u8; 100]));
    }

    #[test]
    fn test_ct_eq_empty_slices_are_equal() {
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn test_ct_eq_detects_difference_at_every_position() {
        let base = [0x5au8; 65];
        for i in 0..base.len() {
            let mut other = base;
            if let Some(byte) = other.get_mut(i) {
                *byte ^= 0x01;
            }
            assert!(!ct_eq(&base, &other), "difference at {i} not detected");
        }
    }

    #[test]
    fn test_ct_eq_length_mismatch_is_false() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
        assert!(!ct_eq(&[], &[0u8]));
        // A shared prefix must not make a shorter slice compare equal.
        assert!(!ct_eq(&[0u8; 32], &[0u8; 33]));
    }

    #[test]
    fn test_ct_eq_array_equal_and_different() {
        assert!(ct_eq_array(&[7u8; 32], &[7u8; 32]));
        let mut other = [7u8; 32];
        other[31] = 8;
        assert!(!ct_eq_array(&[7u8; 32], &other));
        other = [7u8; 32];
        other[0] = 0;
        assert!(!ct_eq_array(&[7u8; 32], &other));
    }

    #[test]
    fn test_ct_eq_array_zero_length_is_equal() {
        assert!(ct_eq_array(&[], &[]));
    }
}
