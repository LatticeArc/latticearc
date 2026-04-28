//! Thread Safety Tests
//!
//! Verifies safe concurrent access to cryptographic operations.

#[cfg(test)]
mod tests {
    use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn concurrent_encap_decap_same_keypair() {
        let (pk, sk) =
            MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");

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
                    let (ss_enc, ct) = MlKem::encapsulate(&pk).expect("encap should succeed");
                    let ss_dec = MlKem::decapsulate(&sk, &ct).expect("decap should succeed");

                    if ss_enc.expose_secret() == ss_dec.expose_secret() {
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
        let (pk, _sk) =
            MlKem::generate_keypair(MlKemSecurityLevel::MlKem1024).expect("keygen should succeed");

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
    fn concurrent_full_kem_cycle_no_panic() {
        const NUM_THREADS: usize = 8;
        const CYCLES_PER_THREAD: usize = 3;

        let panic_free = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let panic_free = Arc::clone(&panic_free);
                thread::spawn(move || {
                    let result = std::panic::catch_unwind(|| {
                        for _ in 0..CYCLES_PER_THREAD {
                            let (pk, sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
                                .expect("keygen");
                            let (ss_enc, ct) = MlKem::encapsulate(&pk).expect("encap");
                            let ss_dec = MlKem::decapsulate(&sk, &ct).expect("decap");
                            assert_eq!(ss_enc.expose_secret(), ss_dec.expose_secret());
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
                    let (pk, _sk) =
                        MlKem::generate_keypair(MlKemSecurityLevel::MlKem512).expect("keygen");
                    let (ss, _ct) = MlKem::encapsulate(&pk).expect("encap");

                    shared_secrets.lock().expect("mutex").push(ss.expose_secret().to_vec());
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

    #[test]
    fn concurrent_keygen_produces_unique_keys() {
        let public_keys = Arc::new(Mutex::new(Vec::new()));

        const NUM_THREADS: usize = 8;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let public_keys = Arc::clone(&public_keys);
                thread::spawn(move || {
                    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
                        .expect("keygen should succeed");
                    public_keys.lock().expect("mutex").push(pk.to_bytes());
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let keys = public_keys.lock().expect("mutex");
        let unique: HashSet<Vec<u8>> = keys.iter().cloned().collect();
        assert_eq!(unique.len(), NUM_THREADS, "Each thread should produce a unique public key");
    }

    #[test]
    fn concurrent_encapsulate_same_pk() {
        // Multiple threads encapsulating with the same public key should produce
        // different shared secrets and ciphertexts
        let (pk, _sk) =
            MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");

        let pk = Arc::new(pk);
        let results = Arc::new(Mutex::new(Vec::new()));

        const NUM_THREADS: usize = 10;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|_| {
                let pk = Arc::clone(&pk);
                let results = Arc::clone(&results);
                thread::spawn(move || {
                    let (ss, ct) = MlKem::encapsulate(&pk).expect("encap");
                    results
                        .lock()
                        .expect("mutex")
                        .push((ss.expose_secret().to_vec(), ct.as_bytes().to_vec()));
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let results = results.lock().expect("mutex");
        let unique_ss: HashSet<_> = results.iter().map(|(ss, _)| ss.clone()).collect();
        let unique_ct: HashSet<_> = results.iter().map(|(_, ct)| ct.clone()).collect();

        assert_eq!(unique_ss.len(), NUM_THREADS, "All shared secrets should be unique");
        assert_eq!(unique_ct.len(), NUM_THREADS, "All ciphertexts should be unique");
    }

    #[test]
    fn concurrent_aes_gcm_encrypt_decrypt() {
        use latticearc::primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

        let key = [0x42u8; 32];
        let success = Arc::new(AtomicUsize::new(0));

        const NUM_THREADS: usize = 8;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|i| {
                let success = Arc::clone(&success);
                thread::spawn(move || {
                    let cipher = AesGcm256::new(&key).expect("cipher init");
                    let nonce = AesGcm256::generate_nonce();
                    let plaintext = format!("thread {} message", i).into_bytes();

                    let (ciphertext, tag) =
                        cipher.encrypt(&nonce, &plaintext, None).expect("encrypt");
                    let decrypted =
                        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decrypt");

                    if decrypted.as_slice() == plaintext.as_slice() {
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
            "All concurrent AES-GCM roundtrips should succeed"
        );
    }

    #[test]
    fn concurrent_sha256_hashing() {
        use latticearc::primitives::hash::sha256;

        let success = Arc::new(AtomicUsize::new(0));

        const NUM_THREADS: usize = 8;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|i| {
                let success = Arc::clone(&success);
                thread::spawn(move || {
                    let input = format!("thread {} data", i).into_bytes();
                    let hash1 = sha256(&input).expect("hash1");
                    let hash2 = sha256(&input).expect("hash2");

                    // Same input should always produce same hash
                    if hash1 == hash2 {
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
            "All concurrent SHA-256 hashes should be deterministic"
        );
    }

    #[test]
    fn concurrent_hkdf_derivation() {
        use latticearc::primitives::kdf::hkdf;

        let success = Arc::new(AtomicUsize::new(0));

        const NUM_THREADS: usize = 6;

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|i| {
                let success = Arc::clone(&success);
                thread::spawn(move || {
                    let ikm = format!("thread-{}-ikm", i).into_bytes();
                    let salt = b"shared-salt";
                    let info = b"shared-info";

                    let key1 = hkdf(&ikm, Some(salt), Some(info), 32).expect("hkdf1");
                    let key2 = hkdf(&ikm, Some(salt), Some(info), 32).expect("hkdf2");

                    // Same inputs should always produce same key
                    if key1.expose_secret() == key2.expose_secret() {
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
            "All concurrent HKDF derivations should be deterministic"
        );
    }

    #[test]
    fn concurrent_ml_kem_all_security_levels() {
        // Test concurrent keygen across different security levels
        let success = Arc::new(AtomicUsize::new(0));
        let levels = [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        let handles: Vec<_> = levels
            .iter()
            .map(|&level| {
                let success = Arc::clone(&success);
                thread::spawn(move || {
                    let (pk, _sk) = MlKem::generate_keypair(level).expect("keygen should succeed");
                    let (ss, _ct) = MlKem::encapsulate(&pk).expect("encap should succeed");

                    if !ss.expose_secret().is_empty() {
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
            levels.len(),
            "All security levels should work concurrently"
        );
    }
}
