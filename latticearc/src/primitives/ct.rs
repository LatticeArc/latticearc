//! Constant-time helpers usable across primitive modules.
//!
//! Centralises CT predicates that several primitives share (AEAD weak-key
//! check, KDF salt validation, ...) so each call site cannot accidentally
//! reach for the early-exiting `iter().all()` form. All functions here use
//! [`subtle::ConstantTimeEq`] under the hood.

use subtle::ConstantTimeEq;

/// Returns `true` iff every byte of `bytes` is zero, in constant time.
///
/// Empty slices return `false` so that a caller passing a zero-length
/// secret cannot trigger a false-positive weak-input rejection.
///
/// # Constant-time behaviour
///
/// Runtime is independent of the position of the first non-zero byte.
/// Internally compares `bytes` against an all-zero stack buffer in
/// 32-byte chunks via [`subtle::ConstantTimeEq::ct_eq`]; longer inputs
/// (e.g. PBKDF2 salts greater than 32 bytes) are handled chunk-by-chunk
/// without falling back to a heap allocation, and without an early exit
/// on chunk boundaries (each chunk's `Choice` is `&`-folded).
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
    use super::is_all_zero_bytes;

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
}
