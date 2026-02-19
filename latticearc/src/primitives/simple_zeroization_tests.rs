//! Simple zeroization tests
#![allow(clippy::unwrap_used)]

use zeroize::Zeroize;

fn create_test_secret(size: usize) -> Vec<u8> {
    vec![0xAA; size]
}

fn verify_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn verify_non_zero(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b != 0)
}

#[test]
fn test_simple_zeroize_function() {
    let mut data = create_test_secret(64);
    assert!(verify_non_zero(&data), "Data should be non-zero initially");

    data.zeroize();

    assert!(verify_all_zero(&data), "Data should be zeroized");
}

#[test]
fn test_concurrent_zeroization() {
    use std::sync::Arc;
    use std::thread;

    let test_data = Arc::new(create_test_secret(32));
    let mut handles = vec![];

    for i in 0..4 {
        let data_clone = Arc::clone(&test_data);
        let handle = thread::spawn(move || {
            let mut local_data = (*data_clone).clone();
            assert!(verify_non_zero(&local_data), "Thread {} data should be non-zero", i);

            local_data.zeroize();
            assert!(verify_all_zero(&local_data), "Thread {} data should be zeroized", i);

            local_data
        });
        handles.push(handle);
    }

    for handle in handles {
        let zeroized_data = handle.join().unwrap();
        assert!(verify_all_zero(&zeroized_data), "Thread data should be zeroized");
    }
}

#[test]
fn test_zeroization_with_large_data() {
    let expected_size = 1024 * 1024;
    let mut data = create_test_secret(expected_size);
    assert!(verify_non_zero(&data), "Large data should be non-zero");
    assert_eq!(data.len(), expected_size, "Data size should match");

    data.zeroize();

    // Vec::zeroize() zeros the content then clears the vector (length becomes 0)
    // This is by design in the zeroize crate for security
    assert!(data.is_empty(), "Vec should be cleared after zeroize");
}

#[test]
fn test_zeroization_edge_cases() {
    let mut empty_data: Vec<u8> = vec![];
    empty_data.zeroize();
    assert!(empty_data.is_empty(), "Empty data should remain empty after zeroize");

    // Vec::zeroize() zeros the content then clears the vector
    let mut single_data: Vec<u8> = vec![0xFF];
    single_data.zeroize();
    assert!(single_data.is_empty(), "Vec should be cleared after zeroize");

    let mut small_data: Vec<u8> = vec![0xAA, 0xBB];
    small_data.zeroize();
    assert!(small_data.is_empty(), "Vec should be cleared after zeroize");
}
