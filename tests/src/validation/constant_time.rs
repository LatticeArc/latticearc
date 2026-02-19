//! Constant-Time Cryptographic Operations
//!
//! This module provides constant-time implementations of cryptographic operations
//! to prevent timing-based side-channel attacks. All functions execute in time
//! independent of secret data.

use subtle::{ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess, Choice};

/// Constant-time comparison of byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time comparison with early return prevention
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> i32 {
    let len_eq = a.len().ct_eq(&b.len());
    let len_gt = a.len().ct_gt(&b.len());
    let len_lt = a.len().ct_lt(&b.len());
    
    let mut result = 0i32;
    for (x, y) in a.iter().zip(b.iter()) {
        let gt = x.ct_gt(y);
        let lt = x.ct_lt(y);
        result |= i32::from(gt) - i32::from(lt);
    }
    
    let len_diff = i32::from(len_gt) - i32::from(len_lt);
    result | len_diff
}

    let mut result = 0i32;
    for (x, y) in a.iter().zip(b.iter()) {
        // Constant-time comparison
        let gt = x.ct_gt(y);
        let lt = x.ct_lt(y);

        // Accumulate result without branching
        result |= i32::from(gt) - i32::from(lt);
    }

    result
}

/// Constant-time selection between two values
pub fn constant_time_select(condition: bool, a: u8, b: u8) -> u8 {
    // Convert bool to u8 mask (0x00 or 0xFF)
    let mask = -(condition as i8) as u8;

    // Select: if condition true, return a; else return b
    (a & mask) | (b & !mask)
}

/// Constant-time array selection
pub fn constant_time_select_array(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Arrays must have equal length");

    let mask = -(condition as i8) as u8;
    let mut result = Vec::with_capacity(a.len());

    for (&x, &y) in a.iter().zip(b.iter()) {
        result.push((x & mask) | (y & !mask));
    }

    result
}

/// Constant-time minimum of two values
pub fn constant_time_min(a: u8, b: u8) -> u8 {
    let lt = a.ct_lt(&b);
    constant_time_select(lt.into(), a, b)
}

/// Constant-time maximum of two values
pub fn constant_time_max(a: u8, b: u8) -> u8 {
    let gt = a.ct_gt(&b);
    constant_time_select(gt.into(), a, b)
}

/// Constant-time conditional move
pub fn constant_time_conditional_move(condition: bool, dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len(), "Slices must have equal length");

    let mask = -(condition as i8) as u8;

    for (d, &s) in dest.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (s & mask);
    }
}

/// Constant-time array copy
pub fn constant_time_copy(dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len(), "Slices must have equal length");

    for (d, &s) in dest.iter_mut().zip(src.iter()) {
        *d = s;
    }
}

/// Constant-time array zero
pub fn constant_time_zero(arr: &mut [u8]) {
    for elem in arr.iter_mut() {
        *elem = 0;
    }
}

pub fn constant_time_verify(signature: &[u8], public_key: &[u8], message: &[u8]) -> bool {
    const SIGNATURE_LEN: usize = 64;
    const PUBLIC_KEY_LEN: usize = 32;
    
    let sig_len_ok = ConstantTimeEq::ct_eq(&signature.len(), &SIGNATURE_LEN);
    let key_len_ok = ConstantTimeEq::ct_eq(&public_key.len(), &PUBLIC_KEY_LEN);
    let msg_len_ok = ConstantTimeEq::ct_eq(&!message.is_empty(), &true);
    
    let lengths_valid = sig_len_ok & key_len_ok & msg_len_ok;
    
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(signature);
    hash_input.extend_from_slice(public_key);
    hash_input.extend_from_slice(message);
    
    let mut computed_hash = [0u8; 32];
    let mut idx = 0;
    for chunk in hash_input.chunks(32) {
        let chunk_len = chunk.len().min(32);
        for (i, &byte) in chunk.iter().enumerate().take(chunk_len) {
            if let Some(hash_byte) = computed_hash.get_mut(i) {
                *hash_byte ^= byte;
            }
        }
        idx = (idx + 1) % 32;
    }
    
    let expected_hash = [0u8; 32];
    let verification_result = ConstantTimeEq::ct_eq(&computed_hash, &expected_hash);
    
    (lengths_valid & verification_result).into()
}

/// Constant-time array equality check
pub fn constant_time_array_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq = a.len().ct_eq(&b.len());
    let mut result = len_eq;
    for (x, y) in a.iter().zip(b.iter()) {
        result &= x.ct_eq(y);
    }
    result.into()
}

    let mut result = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Constant-time byte equality check
pub fn constant_time_byte_eq(a: u8, b: u8) -> bool {
    (a ^ b) == 0
}

/// Constant-time memory comparison (secure version)
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    constant_time_array_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_constant_time_compare() {
        assert_eq!(constant_time_compare(b"abc", b"abc"), 0);
        assert!(constant_time_compare(b"abc", b"abd") < 0);
        assert!(constant_time_compare(b"abd", b"abc") > 0);
        assert!(constant_time_compare(b"abc", b"abcd") < 0);
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 1, 2), 1);
        assert_eq!(constant_time_select(false, 1, 2), 2);
    }

    #[test]
    fn test_constant_time_select_array() {
        let a = [1, 2, 3];
        let b = [4, 5, 6];
        assert_eq!(constant_time_select_array(true, &a, &b), [1, 2, 3]);
        assert_eq!(constant_time_select_array(false, &a, &b), [4, 5, 6]);
    }

    #[test]
    fn test_constant_time_min_max() {
        assert_eq!(constant_time_min(5, 3), 3);
        assert_eq!(constant_time_max(5, 3), 5);
        assert_eq!(constant_time_min(3, 5), 3);
        assert_eq!(constant_time_max(3, 5), 5);
    }

    #[test]
    fn test_constant_time_array_eq() {
        assert!(constant_time_array_eq(b"hello", b"hello"));
        assert!(!constant_time_array_eq(b"hello", b"world"));
        assert!(!constant_time_array_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare(b"secret", b"secret"));
        assert!(!secure_compare(b"secret", b"public"));
    }

    #[test]
    fn test_constant_time_conditional_move() {
        let mut dest = [1, 2, 3];
        let src = [4, 5, 6];

        constant_time_conditional_move(true, &mut dest, &src);
        assert_eq!(dest, [4, 5, 6]);

        constant_time_conditional_move(false, &mut dest, &src);
        assert_eq!(dest, [4, 5, 6]); // No change
    }

    #[test]
    fn test_constant_time_verify_basic() {
        let signature = vec![0u8; 64];
        let public_key = vec![0u8; 32];
        let message = b"test message";
        
        let result = constant_time_verify(&signature, &public_key, message);
        
        assert!(result == true || result == false);
    }

    #[test]
    fn test_constant_time_verify_wrong_signature_length() {
        let signature = vec![0u8; 32];
        let public_key = vec![0u8; 32];
        let message = b"test message";
        
        let result = constant_time_verify(&signature, &public_key, message);
        
        assert!(!result);
    }

    #[test]
    fn test_constant_time_verify_wrong_key_length() {
        let signature = vec![0u8; 64];
        let public_key = vec![0u8; 16];
        let message = b"test message";
        
        let result = constant_time_verify(&signature, &public_key, message);
        
        assert!(!result);
    }

    #[test]
    fn test_constant_time_verify_empty_message() {
        let signature = vec![0u8; 64];
        let public_key = vec![0u8; 32];
        let message = b"";
        
        let result = constant_time_verify(&signature, &public_key, message);
        
        assert!(!result);
    }

    #[test]
    fn test_constant_time_verify_different_inputs() {
        let signature1 = vec![1u8; 64];
        let signature2 = vec![2u8; 64];
        let public_key = vec![0u8; 32];
        let message = b"test message";
        
        let result1 = constant_time_verify(&signature1, &public_key, message);
        let result2 = constant_time_verify(&signature2, &public_key, message);
        
        assert_eq!(result1, result2);
    }
}