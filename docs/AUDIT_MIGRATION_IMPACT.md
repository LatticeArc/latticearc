# Apache → Proprietary Migration Impact Report

Generated during the deep-audit remediation session. Documents every
proprietary-repo file that needs follow-up work after breaking changes landed
in `latticearc`.

## Scope of breaking changes (apache_repo → latticearc v0.4.5)

| ID | Change | Rationale |
|----|--------|-----------|
| A1 | `derive_hybrid_shared_secret` `info` now uses HPKE §5.1 length-prefix encoding | Unambiguous domain separation |
| A2 | `X25519KeyPair::agree` / `X25519StaticKeyPair::agree` route peer bytes through `from_bytes` | Defense-in-depth low-order rejection |
| B1 | `AeadCipher::decrypt` returns `Result<Zeroizing<Vec<u8>>>` | Plaintext scrub on drop |
| B2 | AES-GCM `in_out` buffer is `Zeroizing<Vec<u8>>` internally | Plaintext scrub on drop |
| C3 | All hash sites route through `primitives::hash::*` wrappers | Swappable backends |
| D1/D2 | `to_bytes` / `from_bytes` added to ML-DSA (3 types) and ML-KEM (1 type) | API symmetry |
| E1 | `#[non_exhaustive]` on 7 + 1 error enums and `SignatureScheme` | Forward-compat |
| F1/F2 | Stale "XOR" docs fixed; stale NOTE comments removed | Doc hygiene |
| G1 | Deleted 4 ghost re-export files: `prelude/domains.rs`, `unified_api/config.rs`, `unified_api/hardware.rs`, `unified_api/key_lifecycle.rs` | Reduce indirection |
| G2 | Deleted 3 inline ghost submodules in `hybrid/mod.rs` (`kem`, `sig`, `encrypt`) | Reduce indirection |
| I2 | `MlKem::encapsulate_with_rng` → `encapsulate_with_seed` | Honest naming |
| I3 | Removed ignored `_rng` parameters from `MlKem::generate_keypair`, `MlKem::generate_keypair_with_config`, `MlKem::encapsulate`, `MlKem::encapsulate_with_config`, `hybrid::kem_hybrid::generate_keypair`, `hybrid::kem_hybrid::generate_keypair_with_level`, `hybrid::kem_hybrid::encapsulate`, `hybrid::sig_hybrid::generate_keypair`, `hybrid::encrypt_hybrid::encrypt`, `hybrid::encrypt_hybrid::encrypt_hybrid`, and TLS helpers (`perform_hybrid_keygen`, `perform_hybrid_encapsulate`) | aws-lc-rs owns entropy; the old params were vestigial |
| I4 | `SignatureScheme::FnDsa` renamed to `SignatureScheme::FnDsa512`; added `FnDsa1024` | Precision |
| I5 | Removed unused deps `arrayref`, `async-trait` from `latticearc/Cargo.toml` | Supply-chain hygiene |

## Affected proprietary files

Eight files need manual migration. Call counts are approximate.

### 1. `advanced/simd/src/tools.rs`
- **Changes needed:** drop `&mut rng` from `MlKem::generate_keypair`, `MlKem::encapsulate` (3 call sites)
- **Risk:** Low — mechanical rename.

### 2. `arc-enterprise-cce/tests/dimension_tests.rs`
- **Changes needed:** drop `&mut rng` from `MlKem::generate_keypair` (8 call sites) and `kem_hybrid::generate_keypair` (8 call sites)
- **Risk:** Low — mechanical rename; tests should re-run green.

### 3. `arc-enterprise-cce/examples/cce_encrypt_process.rs`
- **Changes needed:** drop `&mut rng` from `MlKem::generate_keypair`
- **Risk:** Low.

### 4. `arc-enterprise-cce/src/dimension/knowledge_factor.rs`
- **Changes needed:** drop `&mut rng` from `MlKem::encapsulate` and `kem_hybrid::encapsulate`
- **Risk:** Low.

### 5. `arc-enterprise-cce/src/dimension/quorum.rs`
- **Changes needed:** drop `&mut rng` from `kem_hybrid::generate_keypair` and `kem_hybrid::encapsulate`
- **Risk:** Low.

### 6. `arc-enterprise-tls/formal_verification_advanced/security_properties.rs`
- **Changes needed:** replace `use latticearc::hybrid::kem::{...}` with `use latticearc::hybrid::{...}`
- **Risk:** Low — alias rename.

### 7. `arc-enterprise-cce/examples/cce_decrypt_process.rs`
- **Changes needed:** `cipher.decrypt(...)` now returns `Zeroizing<Vec<u8>>`; if the downstream consumer needs `Vec<u8>`, call `.to_vec()` — otherwise the `Zeroizing` wrapper is transparent via `Deref`.
- **Risk:** Low to medium — depends on how tightly downstream code is typed.

### 8. `latticearc-enterprise/src/sp800_38a_ecb.rs`
- **Changes needed:** same as #7, any direct `Vec<u8>` bindings from `decrypt(...)` need `.to_vec()` or a type update.
- **Risk:** Low to medium.

## Categories with zero impact

All of the following are 0 hits in the proprietary repo, so they require no
follow-up work:

- `MlKem::encapsulate_with_config`, `MlKem::generate_keypair_with_config`, `MlKem::encapsulate_with_rng`
- `hybrid::sig::`, `hybrid::encrypt::` inline ghosts
- `kem_hybrid::generate_keypair_with_level`, `sig_hybrid::generate_keypair`
- `hybrid::encrypt`, `hybrid::encrypt_hybrid`
- `unified_api::config::*`, `unified_api::key_lifecycle::*`, `unified_api::hardware::*`
- `SignatureScheme::FnDsa` (not referenced by name in proprietary repo)
- New `to_bytes` / `from_bytes` methods on ML-DSA and ML-KEM (additive)
- `arrayref::array_ref!`
- `prelude::domains`

## Recommended migration strategy

1. **Run `cargo check --workspace` in proprietary_repo** after bumping the
   `latticearc` dependency — the compile errors will point at exactly the 8
   files above.
2. **Apply mechanical fixes** for #1-6 (drop `&mut rng,`), then #7-8 (add
   `.to_vec()` where a `Vec<u8>` binding is required).
3. **Re-run the proprietary test suite** to confirm no behavioural regression.
4. **No changes to data-on-disk formats.** The length-prefix reformat of
   `derive_hybrid_shared_secret` DOES change the HKDF `info` payload, so any
   stored hybrid shared secrets or ciphertexts derived before the upgrade will
   NOT decrypt with the new code. If the proprietary stack persists hybrid
   ciphertexts long-term, plan a re-wrap step before deploying this version.
