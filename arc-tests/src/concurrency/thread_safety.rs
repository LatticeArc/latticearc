//! Thread Safety Tests
//!
//! Verifies safe concurrent access to cryptographic operations.

#[cfg(test)]
mod tests {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization for decapsulation"]
    fn concurrent_encap_decap_same_keypair() {
        let mut rng = OsRng;
        let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
            .expect("keygen should succeed");

        let pk = Arc::new(pk);
        let sk = Arc::new(sk);
        let success = Arc::new(AtomicUsize::new(0));

        const NUM_THREADS: usize = 10;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let pk = Arc::clone(&pk);
                let sk = Arc::clone(&sk);
                let success = Arc::clone(&success);
                thread::spawn(move || {
                    let mut rng = OsRng;
                    let (ss_enc, ct) =
                        MlKem::encapsulate(&mut rng, &pk).expect("encap should succeed");
                    let ss_dec = MlKem::decapsulate(&sk, &ct).expect("decap should succeed");

                    if ss_enc.as_bytes() == ss_dec.as_bytes() {
                        success.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        assert_eq!(
            success.load(Ordering::SeqCst),
            NUM_THREADS,
            "All concurrent encap/decap should match"
        );
    }

    #[test]
    fn concurrent_read_public_key() {
        let mut rng = OsRng;
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)
            .expect("keygen should succeed");

        let pk = Arc::new(pk);
        let original_bytes = pk.to_bytes();
        let match_count = Arc::new(AtomicUsize::new(0));

        const NUM_THREADS: usize = 20;
        const READS_PER_THREAD: usize = 10;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let pk = Arc::clone(&pk);
                let original_bytes = original_bytes.clone();
                let match_count = Arc::clone(&match_count);
                thread::spawn(move || {
                    for _ in 0..READS_PER_THREAD {
                        if pk.to_bytes() == original_bytes {
                            match_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        assert_eq!(
            match_count.load(Ordering::SeqCst),
            NUM_THREADS * READS_PER_THREAD,
            "All reads should return consistent data"
        );
    }

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization for decapsulation"]
    fn concurrent_full_kem_cycle_no_panic() {
        const NUM_THREADS: usize = 8;
        const CYCLES_PER_THREAD: usize = 3;

        let panic_free = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let panic_free = Arc::clone(&panic_free);
                thread::spawn(move || {
                    let result = std::panic::catch_unwind(|| {
                        let mut rng = OsRng;
                        for _ in 0..CYCLES_PER_THREAD {
                            let (pk, sk) =
                                MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
                                    .expect("keygen");
                            let (ss_enc, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encap");
                            let ss_dec = MlKem::decapsulate(&sk, &ct).expect("decap");
                            assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
                        }
                    });

                    if result.is_ok() {
                        panic_free.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }

        assert_eq!(panic_free.load(Ordering::SeqCst), NUM_THREADS, "No threads should panic");
    }

    #[test]
    fn concurrent_rng_isolation() {
        // Verify each thread's RNG produces independent randomness
        let shared_secrets = Arc::new(Mutex::new(Vec::new()));

        const NUM_THREADS: usize = 4;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let shared_secrets = Arc::clone(&shared_secrets);
                thread::spawn(move || {
                    let mut rng = OsRng;
                    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
                        .expect("keygen");
                    let (ss, _ct) = MlKem::encapsulate(&mut rng, &pk).expect("encap");

                    shared_secrets.lock().expect("mutex").push(ss.as_bytes().to_vec());
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let secrets = shared_secrets.lock().expect("mutex");
        let unique: HashSet<_> = secrets.iter().collect();

        assert_eq!(unique.len(), NUM_THREADS, "Each thread should produce unique shared secret");
    }
}
