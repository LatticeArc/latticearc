# OSS-Fuzz Integration

This directory contains configuration files for integrating LatticeArc with [Google's OSS-Fuzz](https://google.github.io/oss-fuzz/) continuous fuzzing infrastructure.

## Status

| Stage | Status |
|-------|--------|
| Local fuzzing | ✅ Complete (`fuzz` crate) |
| OSS-Fuzz config | ✅ Prepared |
| Application | ⬜ Pending |
| Integration | ⬜ Pending |

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Build environment for OSS-Fuzz |
| `build.sh` | Script to build fuzz targets |
| `project.yaml` | Project configuration |

## Application Process

### Prerequisites

Before applying to OSS-Fuzz, ensure:

1. **Significant user base**: Project should be widely used
2. **Active maintenance**: Regular commits and releases
3. **Security-critical**: Cryptographic code qualifies
4. **Working fuzz targets**: Local fuzzing should work

### Steps to Apply

1. **Fork OSS-Fuzz repository**:
   ```bash
   git clone https://github.com/google/oss-fuzz
   cd oss-fuzz
   ```

2. **Create project directory**:
   ```bash
   mkdir projects/latticearc
   cp /path/to/latticearc/oss-fuzz/* projects/latticearc/
   ```

3. **Test locally**:
   ```bash
   python infra/helper.py build_image latticearc
   python infra/helper.py build_fuzzers latticearc
   python infra/helper.py run_fuzzer latticearc fuzz_aes_gcm
   ```

4. **Submit pull request** to https://github.com/google/oss-fuzz

### Review Criteria

Google reviews applications based on:
- Project importance and user base
- Quality of fuzz targets
- Maintenance commitment
- Security impact of bugs found

## Fuzz Targets

The following targets are configured for OSS-Fuzz:

| Target | Algorithm | Security Impact |
|--------|-----------|-----------------|
| `fuzz_aes_gcm` | AES-256-GCM | High - AEAD cipher |
| `fuzz_chacha20_poly1305` | ChaCha20-Poly1305 | High - AEAD cipher |
| `fuzz_ml_kem` | ML-KEM (FIPS 203) | Critical - PQC KEM |
| `fuzz_ml_dsa` | ML-DSA (FIPS 204) | Critical - PQC signatures |
| `fuzz_hybrid_encrypt` | Hybrid encryption | Critical - Main API |
| `fuzz_hkdf` | HKDF-SHA256 | High - Key derivation |
| `fuzz_ed25519` | Ed25519 | High - Classical signatures |
| `fuzz_x25519` | X25519 | High - Key exchange |

## Benefits of OSS-Fuzz

Once integrated, LatticeArc receives:

- **24/7 fuzzing** on Google infrastructure
- **Multiple fuzzing engines**: libFuzzer, AFL++, Honggfuzz
- **Multiple sanitizers**: ASan, MSan, UBSan
- **Automatic bug filing** via ClusterFuzz
- **Regression detection** on new commits
- **Coverage reports** and statistics

## Contact

For OSS-Fuzz integration questions:
- security@latticearc.com
- GitHub Issues

---

*Last Updated: 2026-01-29*
