# KAT Test Vector Provenance

This document records the provenance and source of all Known Answer Test (KAT) vectors
used in `arc-validation/src/nist_kat/`.

## Vector Sources

| File | Algorithm | Source | Standard | Verification |
|------|-----------|--------|----------|-------------|
| `aes_gcm_kat.rs` | AES-128-GCM, AES-256-GCM | NIST SP 800-38D | FIPS 197 + SP 800-38D | Test Cases 1-3 (128-bit), 13-15 (256-bit) from Appendix C |
| `ml_kem_kat.rs` | ML-KEM-512/768/1024 | NIST CAVP ML-KEM | FIPS 203 | Deterministic keygen KAT vectors, Count=0,1 per security level |
| `ml_dsa_kat.rs` | ML-DSA-44/65/87 | NIST CAVP ML-DSA | FIPS 204 | Deterministic signing KAT vectors |
| `sha2_kat.rs` | SHA-224/256/384/512 | NIST FIPS 180-4 | FIPS 180-4 | Examples B.1-B.3 (short/long message tests) |
| `hmac_kat.rs` | HMAC-SHA-224/256/384/512 | RFC 4231 | RFC 4231 | Test Cases 1-2 (Section 4.2-4.3) |
| `hkdf_kat.rs` | HKDF-SHA-256 | RFC 5869 | RFC 5869 | Test vectors from Section A |
| `chacha20_poly1305_kat.rs` | ChaCha20-Poly1305 | RFC 8439 | RFC 8439 | Test vectors from Section 2.8 |

## Verification Process

To verify test vectors against authoritative sources:

1. **AES-GCM**: Compare against `gcmEncryptExtIV128.rsp` and `gcmEncryptExtIV256.rsp` from
   [NIST CAVP AES-GCM](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS)

2. **ML-KEM**: Compare against KAT response files from
   [NIST PQC Round 3 KAT](https://csrc.nist.gov/Projects/post-quantum-cryptography)

3. **SHA-2**: Compare against `SHA256ShortMsg.rsp` / `SHA256LongMsg.rsp` from
   [NIST CAVP SHA](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs)

4. **HMAC**: Compare against RFC 4231 Section 4 test vectors (authoritative, no CAVP download needed)

5. **HKDF**: Compare against RFC 5869 Appendix A test vectors

6. **ChaCha20-Poly1305**: Compare against RFC 8439 Section 2.8 test vectors

## Notes

- Test vectors are embedded as constants in source code for build-time availability
- FIPS power-up self-tests use these vectors via `arc-validation/src/fips_validation/global.rs`
- Module-level doc comments in each file reference the authoritative source
- Individual vector comments reference specific NIST CAVP test case numbers
