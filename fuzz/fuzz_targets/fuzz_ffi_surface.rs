#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the `latticearc-ffi` surface.
//!
//! Every function and constructor the UniFFI bindings expose is driven with
//! fuzz-chosen bytes through its Rust signature (the same functions the
//! generated C ABI calls). The invariants: nothing panics, forged or random
//! bytes never authenticate, and genuine round trips always succeed. A panic
//! here would abort a mobile app, so this target backs the "errors as typed
//! results" promise of the crate.

use std::sync::{Arc, OnceLock};

use latticearc_ffi::{
    Argon2Params, HybridKemPublicKey, HybridKemSecretKey, HybridKemSecretKeyParts,
    HybridSigPublicKey, HybridSigningKey, HybridSigningKeyParts, LatticeArcError,
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSigningKey, MlKemSecurityLevel, PrehashAlgorithm,
    SecretBytes, StreamDecryptor, StreamEncryptor, argon2id, counter_kdf, decapsulate,
    decrypt_hybrid, encapsulate, encrypt_hybrid, hkdf, memory_lock_status, unwrap_key, verify,
    verify_prehashed, version, wrap_key, wrap_key_padded,
};
use libfuzzer_sys::fuzz_target;

/// Long-lived keys so each iteration spends its time on the fuzzed paths,
/// not on ML-KEM / ML-DSA key generation.
struct Keys {
    kem: Arc<HybridKemSecretKey>,
    sig: Arc<HybridSigningKey>,
    ml_dsa: Arc<MlDsaSigningKey>,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        kem: HybridKemSecretKey::generate(MlKemSecurityLevel::MlKem768).expect("keygen"),
        sig: HybridSigningKey::generate(MlDsaParameterSet::MlDsa65).expect("keygen"),
        ml_dsa: MlDsaSigningKey::generate(MlDsaParameterSet::MlDsa44).expect("keygen"),
    })
}

fn level(b: u8) -> MlKemSecurityLevel {
    match b % 3 {
        0 => MlKemSecurityLevel::MlKem512,
        1 => MlKemSecurityLevel::MlKem768,
        _ => MlKemSecurityLevel::MlKem1024,
    }
}

fn set(b: u8) -> MlDsaParameterSet {
    match b % 3 {
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    }
}

fn hash(b: u8) -> PrehashAlgorithm {
    match b % 4 {
        0 => PrehashAlgorithm::Sha256,
        1 => PrehashAlgorithm::Sha512,
        2 => PrehashAlgorithm::Shake128,
        _ => PrehashAlgorithm::Shake256,
    }
}

fuzz_target!(|data: &[u8]| {
    // selector (1) || key material (32) || context length (1) || context || rest
    if data.len() < 35 {
        return;
    }
    let sel = data[0];
    // An all-zero 32-byte key is rejected as weak by the AEAD; keep the
    // fuzzed key material but never let it be all zero.
    let mut key_bytes = data[1..33].to_vec();
    key_bytes[0] |= 0x01;
    let key32 = SecretBytes::import(key_bytes);
    let ctx_len = usize::from(data[33]).min(data.len() - 34);
    let context = data[34..34 + ctx_len].to_vec();
    let rest = &data[34 + ctx_len..];
    let short = SecretBytes::import(rest.to_vec());
    let k = keys();

    assert!(!version().is_empty());
    let _ = memory_lock_status();
    assert_eq!(usize::try_from(short.len()).unwrap(), rest.len());
    assert_eq!(short.export_bytes(), rest);
    assert_eq!(short.is_empty(), rest.is_empty());
    let _ = SecretBytes::random(u32::from(sel));

    // --- KDFs: fuzzed lengths and parameters never panic; genuine calls work.
    let _ = hkdf(&key32, Some(rest.to_vec()), context.clone(), u32::from(sel) * 64);
    let _ = counter_kdf(&key32, rest.to_vec(), context.clone(), u32::from(sel));
    let params = Argon2Params {
        memory_kib: 8 + u32::from(sel) * 4, // bounded so the fuzzer stays fast
        iterations: u32::from(data[1] % 4),
        parallelism: u32::from(data[2] % 3),
        output_len: u32::from(data[3]),
    };
    let _ = argon2id(&short, rest.to_vec(), params);
    if !context.is_empty() {
        let a = hkdf(&key32, None, context.clone(), 32).expect("hkdf");
        let b = hkdf(&key32, None, context.clone(), 32).expect("hkdf");
        assert_eq!(a.export_bytes(), b.export_bytes());
    }

    // --- Key wrap: arbitrary bytes never unwrap; genuine records always do.
    let _ = unwrap_key(&key32, rest.to_vec(), context.clone());
    let _ = wrap_key_padded(&key32, &short, context.clone(), u32::from(data[1]) * 16);
    if !context.is_empty() && rest.len() == 32 {
        let wrapped = wrap_key(&key32, &short, context.clone()).expect("wrap");
        let back = unwrap_key(&key32, wrapped.clone(), context.clone()).expect("unwrap");
        assert_eq!(back.export_bytes(), rest);
        let mut bad = wrapped;
        let i = usize::from(sel) % bad.len();
        bad[i] ^= 0x01;
        // Flipping the version byte is a malformed encoding (`InvalidInput`);
        // any other flip is an authentication failure. Both must be errors.
        let err = unwrap_key(&key32, bad, context.clone()).unwrap_err();
        if i == 0 {
            assert!(matches!(err, LatticeArcError::InvalidInput { .. }));
        } else {
            assert_eq!(err, LatticeArcError::AuthenticationFailed);
        }
    }

    // --- Streaming AEAD: fuzzed headers and segments never open.
    let _ = StreamDecryptor::new(&key32, context.clone(), rest.to_vec());
    if let Ok(enc) = StreamEncryptor::new(&key32, context.clone(), 64 + u32::from(sel) * 8) {
        assert!(!context.is_empty());
        let first_len = usize::try_from(enc.first_plaintext_segment_size()).unwrap();
        if rest.len() != first_len {
            // Wrong-length plaintext is rejected without consuming an index.
            assert!(enc.seal_segment(rest.to_vec()).is_err());
            assert_eq!(enc.next_index().unwrap(), 0);
        }
        let first = vec![sel; first_len];
        let s0 = enc.seal_segment(first.clone()).expect("seal");
        let s1 = enc
            .finish(
                rest[..rest.len().min(usize::try_from(enc.plaintext_segment_size()).unwrap())]
                    .to_vec(),
            )
            .expect("finish");
        assert_eq!(enc.seal_segment(Vec::new()).unwrap_err(), LatticeArcError::StreamExhausted);
        let dec = StreamDecryptor::new(&key32, context.clone(), enc.header()).expect("open");
        assert_eq!(dec.open_segment(0, s0.clone(), false).expect("segment 0"), first);
        assert!(dec.open_segment(0, s0.clone(), true).is_err());
        assert!(dec.open_segment(1, s0, false).is_err());
        assert!(dec.open_next(rest.to_vec(), false).is_err());
        let _ = dec.open_segment(1, s1, true);
    }

    // --- Hybrid KEM: wire parsers and decapsulation on arbitrary bytes.
    let _ = HybridKemPublicKey::from_wire(rest.to_vec());
    let _ = decapsulate(&k.kem, rest.to_vec(), context.clone());
    let _ = decrypt_hybrid(&k.kem, rest.to_vec(), Some(context.clone()));
    let _ = HybridKemSecretKey::from_parts(HybridKemSecretKeyParts {
        security_level: level(sel),
        ml_kem_secret_key: rest.to_vec(),
        ml_kem_public_key: context.clone(),
        ecdh_seed: data[1..33].to_vec(),
    });
    if !context.is_empty() {
        let pk = k.kem.public_key();
        let enc = encapsulate(&pk, context.clone()).expect("encapsulate");
        let ss = decapsulate(&k.kem, enc.encapsulated_key.clone(), context.clone())
            .expect("decapsulate");
        assert_eq!(ss.export_bytes(), enc.shared_secret.export_bytes());
        let ct = encrypt_hybrid(&pk, rest.to_vec(), Some(context.clone())).expect("encrypt");
        assert_eq!(
            decrypt_hybrid(&k.kem, ct.clone(), Some(context.clone())).expect("decrypt"),
            rest
        );
        let mut bad = ct;
        let i = usize::from(sel) % bad.len();
        bad[i] ^= 0x01;
        assert!(decrypt_hybrid(&k.kem, bad, Some(context.clone())).is_err());
    }

    // --- Hybrid signatures: wire parsers and verification on arbitrary bytes.
    let _ = HybridSigPublicKey::from_wire(rest.to_vec());
    let pk = k.sig.public_key();
    let _ = verify(&pk, rest.to_vec(), rest.to_vec(), context.clone());
    let _ = verify_prehashed(&pk, rest.to_vec(), rest.to_vec(), context.clone());
    let _ = k.sig.sign_prehashed(rest.to_vec(), context.clone());
    let _ = HybridSigningKey::from_parts(HybridSigningKeyParts {
        parameter_set: set(sel),
        ml_dsa_public_key: rest.to_vec(),
        ed25519_public_key: context.clone(),
        ml_dsa_secret_key: rest.to_vec(),
        ed25519_secret_key: data[1..33].to_vec(),
    });
    let _ = HybridSigningKey::from_seed(&key32, set(sel));
    if !context.is_empty() && context.len() <= 200 {
        let sig = k.sig.sign(rest.to_vec(), context.clone()).expect("sign");
        assert!(verify(&pk, rest.to_vec(), sig.clone(), context.clone()).expect("verify"));
        let mut other = rest.to_vec();
        other.push(sel);
        assert!(!verify(&pk, other, sig, context.clone()).expect("verify"));
    }

    // --- ML-DSA: parsers, pre-hashed modes and seeds on arbitrary bytes.
    let _ = MlDsaPublicKey::from_bytes(rest.to_vec(), set(sel));
    let _ = MlDsaSigningKey::from_parts(&short, rest.to_vec(), set(sel));
    let _ = MlDsaSigningKey::from_seed(&key32, set(sel));
    let mpk = k.ml_dsa.public_key();
    let _ = mpk.verify(rest.to_vec(), rest.to_vec(), context.clone());
    let _ = mpk.verify_prehashed(rest.to_vec(), hash(sel), rest.to_vec(), context.clone());
    let _ = k.ml_dsa.sign_prehashed(rest.to_vec(), hash(sel), context.clone());
    if context.len() <= 255 && rest.len() <= 64 * 1024 {
        let sig = k.ml_dsa.sign(rest.to_vec(), context.clone()).expect("ml-dsa sign");
        assert!(mpk.verify(rest.to_vec(), sig, context.clone()).expect("ml-dsa verify"));
    }
});
