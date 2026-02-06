//! Parallel Key Generation Tests
//!
//! Ensures key generation is safe when called from multiple threads simultaneously.

#[cfg(test)]
mod tests {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn concurrent_keygen_unique_keys_ml_kem_512() {
        const NUM_THREADS: usize = 8;
        const KEYS_PER_THREAD: usize = 5;

        let keys = Arc::new(Mutex::new(Vec::new()));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let keys = Arc::clone(&keys);
                thread::spawn(move || {
                    let mut rng = OsRng;
                    let mut local_keys = Vec::new();

                    for _ in 0..KEYS_PER_THREAD {
                        let (pk, _sk) =
                            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
                                .expect("keygen should succeed");
                        local_keys.push(pk.to_bytes());
                    }

                    keys.lock().expect("mutex not poisoned").extend(local_keys);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let keys = keys.lock().expect("mutex not poisoned");
        let unique: HashSet<_> = keys.iter().collect();

        assert_eq!(unique.len(), NUM_THREADS * KEYS_PER_THREAD, "All keys should be unique");
    }

    #[test]
    fn concurrent_keygen_mixed_security_levels() {
        let levels = [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        let results = Arc::new(Mutex::new(Vec::new()));
        let results_ref = Arc::clone(&results);

        let handles: Vec<_> = levels
            .iter()
            .flat_map(|&level| {
                let results_inner = Arc::clone(&results_ref);
                (0..3).map(move |_| {
                    let results = Arc::clone(&results_inner);
                    thread::spawn(move || {
                        let mut rng = OsRng;
                        let result = MlKem::generate_keypair(&mut rng, level);
                        results.lock().expect("mutex").push(result.is_ok());
                    })
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let results = results.lock().expect("mutex");
        assert!(results.iter().all(|&ok| ok), "All keygen should succeed");
        assert_eq!(results.len(), 9, "Should have 9 results (3 levels x 3 threads)");
    }

    #[test]
    fn concurrent_keygen_stress_test() {
        const NUM_THREADS: usize = 16;

        let success_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|i| {
                let success_count = Arc::clone(&success_count);
                thread::spawn(move || {
                    let mut rng = OsRng;
                    let level = match i % 3 {
                        0 => MlKemSecurityLevel::MlKem512,
                        1 => MlKemSecurityLevel::MlKem768,
                        _ => MlKemSecurityLevel::MlKem1024,
                    };

                    if MlKem::generate_keypair(&mut rng, level).is_ok() {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        assert_eq!(
            success_count.load(Ordering::SeqCst),
            NUM_THREADS,
            "All concurrent keygen should succeed"
        );
    }
}
