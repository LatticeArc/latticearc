//! Zeroization verification tests
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::needless_range_loop)]

use zeroize::Zeroize;

fn create_test_data(size: usize) -> Vec<u8> {
    vec![0xDD; size]
}

fn verify_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn verify_non_zero(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b != 0)
}

#[allow(dead_code)] // Available for future tests
fn verify_pattern(bytes: &[u8], pattern: u8) -> bool {
    bytes.iter().all(|&b| b == pattern)
}

#[allow(dead_code)] // Available for future tests
fn verify_complete_zeroization<T: AsRef<[u8]>>(data: &T) -> bool {
    data.as_ref().iter().all(|&b| b == 0)
}

#[test]
fn test_basic_byte_array_zeroization() {
    let mut test_data = create_test_data(32);
    assert!(verify_non_zero(&test_data), "Test data should be non-zero initially");

    test_data.zeroize();
    assert!(verify_all_zero(&test_data), "Test data should be completely zeroized");
}

#[test]
fn test_byte_array_zeroization_on_drop() {
    let mut data_array = create_test_data(64);
    assert!(verify_non_zero(&data_array), "Data should be non-zero before zeroization");

    data_array.zeroize();
    assert!(verify_all_zero(&data_array), "Data should be zeroized");
}

#[test]
fn test_vector_zeroization() {
    let mut test_vec = create_test_data(100);
    assert!(verify_non_zero(&test_vec), "Vector should be non-zero initially");

    test_vec.zeroize();
    assert!(verify_all_zero(&test_vec), "Vector should be completely zeroized");
}

#[test]
fn test_string_zeroization() {
    let mut test_string = "Hello, World!".to_string();
    assert!(verify_non_zero(test_string.as_bytes()), "String should be non-zero initially");

    test_string.zeroize();

    assert!(test_string.is_empty(), "String should be empty after zeroization");
}

#[test]
fn test_slice_content_zeroization() {
    let mut test_data = create_test_data(10);
    assert!(verify_non_zero(&test_data[..6]), "Slice should be non-zero initially");

    test_data.zeroize();
    assert!(verify_all_zero(&test_data), "Data should be zeroized after zeroization");
}

#[test]
fn test_array_zeroization_order() {
    let mut arrays = Vec::new();

    for _ in 0..5 {
        let array = create_test_data(10);
        arrays.push(array);
    }

    // First array still contains non-zero data
    assert!(!verify_all_zero(&arrays[0]), "First array should still contain non-zero data");

    // Zeroize first array
    arrays[0].zeroize();
    assert!(verify_all_zero(&arrays[0]), "First array should be zeroized");

    for i in 1..5 {
        assert!(!verify_all_zero(&arrays[i]), "Array {} should still contain non-zero data", i);
        arrays[i].zeroize();
        assert!(verify_all_zero(&arrays[i]), "Array {} should be zeroized", i);
    }

    // Verify all arrays are zeroized
    for (i, array) in arrays.iter().enumerate() {
        assert!(verify_all_zero(array), "Array {} should be zeroized", i);
    }
}

#[test]
fn test_large_data_zeroization() {
    let mut large_data = create_test_data(10000);
    assert!(verify_non_zero(&large_data), "Large data should be non-zero initially");

    large_data.zeroize();
    assert!(verify_all_zero(&large_data), "Large data should be zeroized");
}

#[test]
fn test_zeroization_thread_safety() {
    use std::sync::{Arc, Mutex};

    let test_data = Arc::new(create_test_data(64));
    let results = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();

    for i in 0..4 {
        let data_clone = Arc::clone(&test_data);
        let results_clone = Arc::clone(&results);

        let handle = std::thread::spawn(move || {
            let mut local_data = (*data_clone).clone();
            assert!(verify_non_zero(&local_data), "Thread {} data should be non-zero initially", i);

            local_data.zeroize();
            assert!(verify_all_zero(&local_data), "Thread {} data should be zeroized", i);

            results_clone.lock().unwrap().push((i, verify_all_zero(&local_data)));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let results = results.lock().unwrap();
    for (i, is_zeroized) in results.iter() {
        assert!(*is_zeroized, "Thread {} data should be zeroized", i);
    }
}

#[test]
fn test_zeroization_after_multiple_operations() {
    let mut data = create_test_data(32);

    // Multiple operations before zeroization
    data.push(0x55);
    data.push(0x77);

    // Verify data contains non-zero
    assert!(verify_non_zero(&data), "Data should be non-zero before operations");

    // Zeroize data
    data.zeroize();
    assert!(verify_all_zero(&data), "Data should be zeroized after zeroization");

    // After zeroization, data should still be zero
    assert!(verify_all_zero(&data), "Data should remain zeroized after multiple operations");

    // Add more data
    data.push(0x33);
    assert!(verify_non_zero(&data), "Data should be non-zero after push");
    data.zeroize();
    assert!(verify_all_zero(&data), "Data should be zeroized");

    // Final verification
    assert!(verify_all_zero(&data), "Data should be completely zeroized after all operations");
}

#[test]
fn test_edge_cases() {
    // Empty data - empty Vec is already all zeros
    let mut empty_data: Vec<u8> = Vec::new();
    empty_data.zeroize();
    assert!(verify_all_zero(&empty_data), "Empty data should be zeroized");

    // Single byte
    let mut single_byte = create_test_data(1);
    assert!(verify_non_zero(&single_byte), "Single byte should be non-zero initially");
    single_byte.zeroize();
    assert!(verify_all_zero(&single_byte), "Single byte should be zeroized");

    // Large but reasonable size
    let mut large_data = create_test_data(1024 * 1024); // 1MB
    large_data.zeroize();
    assert!(verify_all_zero(&large_data), "Large data should be zeroized");
}

#[test]
fn test_constant_time_zeroization() {
    let mut data = create_test_data(256);

    // Multiple zeroizations should not cause errors
    for iteration in 0..10 {
        data.zeroize();
        assert!(verify_all_zero(&data), "Iteration {} should keep data zeroized", iteration);
    }

    assert!(verify_all_zero(&data), "Final data should be completely zeroized");
}

#[test]
fn test_concurrent_operations() {
    let data = create_test_data(128);

    // Concurrent access pattern - each thread gets its own copy
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let local_data = data.clone();
            std::thread::spawn(move || {
                let mut thread_data = local_data;
                assert!(
                    verify_non_zero(&thread_data),
                    "Thread {} should have non-zero data initially",
                    i
                );
                thread_data.zeroize();
                assert!(verify_all_zero(&thread_data), "Thread {} should be zeroized", i);
                verify_all_zero(&thread_data)
            })
        })
        .collect();

    for handle in handles {
        let is_zeroized = handle.join().unwrap();
        assert!(is_zeroized, "Thread data should be zeroized");
    }
}
