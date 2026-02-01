# Test Coverage Report

**Generated:** 2026-01-31
**Tool:** cargo-llvm-cov v0.8.2
**Target:** Apache Repository (Open Source Core)

## Executive Summary

The LatticeArc apache repository currently has **56.63% line coverage**, which is **below the 80% target** specified in the codebase audit plan. This report provides a comprehensive breakdown of test coverage across all crates and identifies specific areas requiring additional testing.

### Overall Coverage Metrics

| Metric | Coverage | Status |
|--------|----------|--------|
| **Function Coverage** | 54.05% (1553/2873) | Below Target |
| **Line Coverage** | 56.63% (13371/23613) | Below Target |
| **Region Coverage** | 62.19% (23709/38126) | Below Target |
| **Target** | 80% | Not Met |

**Gap Analysis:** The codebase needs to increase line coverage by **23.37 percentage points** to meet the 80% target. This translates to approximately **5,533 additional lines** of code that need test coverage.

## Per-Crate Coverage Breakdown

### High Coverage Crates (>80%)

| Crate | Line Coverage | Status |
|-------|--------------|--------|
| `arc-prelude` (property_based_testing.rs) | 100.00% (97/97) | Excellent |
| `arc-primitives` (hash/sha2.rs) | 100.00% (27/27) | Excellent |
| `arc-primitives` (hash/sha3.rs) | 100.00% (27/27) | Excellent |
| `arc-primitives` (rand/csprng.rs) | 100.00% (23/23) | Excellent |
| `arc-validation` (cavp/vectors.rs) | 100.00% (126/126) | Excellent |
| `arc-hybrid` (compose.rs) | 99.04% (207/209) | Excellent |
| `arc-primitives` (kdf/hkdf.rs) | 98.59% (279/283) | Excellent |
| `arc-primitives` (polynomial/mod.rs) | 98.70% (76/77) | Excellent |
| `arc-perf` | 96.10% (370/385) | Excellent |
| `arc-primitives` (pct.rs) | 96.36% (212/220) | Excellent |
| `arc-primitives` (polynomial/montgomery.rs) | 96.34% (79/82) | Excellent |
| `arc-prelude` (side_channel_analysis.rs) | 95.37% (206/216) | Excellent |
| `arc-validation` (cavp/types.rs) | 95.97% (119/124) | Excellent |
| `arc-primitives` (sig/slh_dsa.rs) | 94.32% (448/475) | Excellent |
| `arc-tls` (selector.rs) | 94.21% (309/328) | Excellent |
| `arc-core` (logging.rs) | 94.53% (709/750) | Excellent |
| `arc-primitives` (aead/aes_gcm.rs) | 92.64% (365/394) | Excellent |
| `arc-primitives` (aead/chacha20poly1305.rs) | 93.74% (419/447) | Excellent |
| `arc-primitives` (sig/fndsa.rs) | 93.62% (352/376) | Excellent |

### Medium Coverage Crates (50-80%)

| Crate | Line Coverage | Files Needing Improvement |
|-------|--------------|---------------------------|
| `arc-core` | ~40-75% overall | config.rs (49.43%), convenience/* (17-60%), hardware.rs (15.27%), serialization.rs (0%) |
| `arc-hybrid` | ~50-65% | encrypt_hybrid.rs (50.62%), kem_hybrid.rs (65.68%) |
| `arc-primitives` | ~68-87% | ml_kem.rs (68.03%), ml_dsa.rs (66.57%), security.rs (20%), self_test.rs (62.80%) |
| `arc-tls` | ~39-71% | basic_features.rs (63.73%), error.rs (36.80%), pq_key_exchange.rs (39.60%), recovery.rs (52.72%) |
| `arc-validation` | ~38-84% | Multiple files need improvement (see detailed list below) |
| `arc-zkp` | ~65-95% | sigma.rs (65.13%) |

### Low Coverage Crates (<50%)

| File | Line Coverage | Priority |
|------|--------------|----------|
| `arc-core/src/serialization.rs` | 0.00% (0/126) | CRITICAL |
| `arc-core/src/convenience/pq_kem.rs` | 0.00% (0/156) | CRITICAL |
| `arc-core/src/hardware.rs` | 15.27% (20/131) | HIGH |
| `arc-core/src/convenience/hybrid.rs` | 17.10% (46/269) | HIGH |
| `arc-core/src/convenience/pq_sig.rs` | 16.42% (67/408) | HIGH |
| `arc-core/src/convenience/ed25519.rs` | 27.39% (43/157) | HIGH |
| `arc-prelude/src/prelude/error/error_recovery/*` | 0.00% (all files) | CRITICAL |
| `arc-tls/src/formal_verification/*` | 0.00% (all files) | MEDIUM |
| `arc-validation/src/cavp/pipeline.rs` | 0.00% (0/1042) | CRITICAL |
| `arc-validation/src/cavp/enhanced_framework.rs` | 0.00% (0/459) | CRITICAL |
| `arc-validation/src/fips_validation_impl.rs` | 0.00% (0/413) | CRITICAL |
| `arc-validation/src/validation_summary.rs` | 0.00% (0/408) | CRITICAL |
| `arc-validation/src/kat_tests/runners.rs` | 0.00% (0/332) | HIGH |
| `arc-validation/src/kat_tests/loaders.rs` | 0.00% (0/183) | HIGH |

## Critical Coverage Gaps

### 1. arc-core Convenience APIs (0-40% coverage)

The convenience layer that provides user-facing APIs has severe coverage gaps:

- **pq_kem.rs**: 0% coverage - No tests for post-quantum KEM convenience APIs
- **pq_sig.rs**: 16.42% - Minimal testing of post-quantum signature APIs
- **hybrid.rs**: 17.10% - Hybrid crypto convenience APIs mostly untested
- **ed25519.rs**: 27.39% - Classical signature APIs undertested
- **serialization.rs**: 0% - Complete lack of serialization testing

**Impact:** These are the primary user-facing APIs. Low coverage here means critical user workflows are not validated.

**Recommendation:** Prioritize integration tests that exercise complete workflows (key generation, encryption, decryption, signing, verification) through the convenience APIs.

### 2. Error Recovery Framework (0% coverage)

All error recovery modules in arc-prelude have **zero test coverage**:

- `error_recovery/circuit_breaker.rs`: 0/103 lines
- `error_recovery/core.rs`: 0/69 lines
- `error_recovery/degradation.rs`: 0/121 lines
- `error_recovery/handler.rs`: 0/89 lines
- `error_recovery/recovery.rs`: 0/200 lines

**Impact:** Error handling and recovery paths are completely untested, which is a critical security and reliability concern.

**Recommendation:** Create comprehensive error injection tests to validate all recovery paths.

### 3. CAVP/FIPS Validation Infrastructure (0% coverage)

Large portions of the validation framework are untested:

- `cavp/pipeline.rs`: 0/1042 lines
- `cavp/enhanced_framework.rs`: 0/459 lines
- `fips_validation_impl.rs`: 0/413 lines
- `validation_summary.rs`: 0/408 lines
- `kat_tests/runners.rs`: 0/332 lines

**Impact:** The automated validation and compliance testing infrastructure is not validated itself.

**Recommendation:** Add tests for the CAVP pipeline and validation framework to ensure compliance automation works correctly.

### 4. Hardware Detection (15.27% coverage)

`arc-core/src/hardware.rs` has only 15.27% line coverage (20/131 lines).

**Impact:** Hardware-aware algorithm selection is a key feature but is largely untested.

**Recommendation:** Add unit tests with mocked hardware capabilities and integration tests on different platforms.

### 5. TLS Formal Verification Stubs (0% coverage)

All formal verification modules in arc-tls have 0% coverage:

- `formal_verification/invariants.rs`: 0/6 lines
- `formal_verification/kani.rs`: 0/6 lines
- `formal_verification/property_based.rs`: 0/6 lines
- `formal_verification/saw_proofs.rs`: 0/6 lines
- `formal_verification/security_properties.rs`: 0/6 lines

**Note:** These appear to be placeholder/stub modules for future formal verification work.

**Recommendation:** Either implement and test these modules or remove them to reduce dead code warnings.

## Coverage by Category

### Cryptographic Primitives (arc-primitives)

| Component | Line Coverage | Assessment |
|-----------|--------------|------------|
| AEAD (AES-GCM) | 92.64% | Good |
| AEAD (ChaCha20Poly1305) | 93.74% | Good |
| Hash (SHA-2) | 100.00% | Excellent |
| Hash (SHA-3) | 100.00% | Excellent |
| KDF (HKDF) | 98.59% | Excellent |
| KDF (PBKDF2) | 87.21% | Good |
| KDF (SP800-108) | 88.77% | Good |
| KEM (ECDH) | 85.08% | Good |
| KEM (ML-KEM) | 68.03% | Needs Improvement |
| Signatures (FN-DSA) | 93.62% | Good |
| Signatures (ML-DSA) | 66.57% | Needs Improvement |
| Signatures (SLH-DSA) | 94.32% | Excellent |
| MAC (CMAC) | 93.19% | Good |
| MAC (HMAC) | 77.16% | Good |
| Self-Test | 62.80% | Needs Improvement |

**Analysis:** Core cryptographic primitives have generally good coverage (>85%), but post-quantum algorithms (ML-KEM, ML-DSA) need improvement.

### Unified API Layer (arc-core)

| Component | Line Coverage | Assessment |
|-----------|--------------|------------|
| Audit | 75.45% | Good |
| Config | 49.43% | Poor |
| Logging | 94.53% | Excellent |
| Key Lifecycle | 93.97% | Excellent |
| Hardware Detection | 15.27% | Critical Gap |
| Serialization | 0.00% | Critical Gap |
| Zero Trust | 41.16% | Poor |
| Convenience APIs | 0-60% | Critical Gaps |

**Analysis:** Core infrastructure (logging, key lifecycle) is well-tested, but user-facing convenience APIs and critical features like serialization need significant work.

### Hybrid Cryptography (arc-hybrid)

| Component | Line Coverage | Assessment |
|-----------|--------------|------------|
| Compose | 99.04% | Excellent |
| Hybrid Encryption | 50.62% | Needs Improvement |
| Hybrid KEM | 65.68% | Needs Improvement |
| Hybrid Signatures | 86.07% | Good |

**Analysis:** Composition layer is excellent, but actual hybrid encryption/KEM implementations need more tests.

### TLS Integration (arc-tls)

| Component | Line Coverage | Assessment |
|-----------|--------------|------------|
| Selector | 94.21% | Excellent |
| Session Store | 86.36% | Good |
| Context | 71.69% | Good |
| TLS 1.3 | 60.62% | Needs Improvement |
| Basic Features | 63.73% | Needs Improvement |
| PQ Key Exchange | 39.60% | Poor |
| Error Handling | 36.80% | Poor |
| Tracing | 39.51% | Poor |

**Analysis:** Core TLS selector and session management are well-tested, but protocol implementation and error handling need work.

### Validation & Compliance (arc-validation)

| Component | Line Coverage | Assessment |
|-----------|--------------|------------|
| CAVP Vectors | 100.00% | Excellent |
| CAVP Types | 95.97% | Excellent |
| NIST Functions | 84.50% | Good |
| NIST SP800-22 | 83.30% | Good |
| RFC Vectors | 78.42% | Good |
| Wycheproof | 60.44% | Needs Improvement |
| CAVP Pipeline | 0.00% | Critical Gap |
| FIPS Validation | 0-47% | Critical Gaps |
| KAT Infrastructure | 0% | Critical Gap |

**Analysis:** Test vectors and validation data structures are excellent, but the automation infrastructure is completely untested.

## Files with 100% Coverage

The following files achieve perfect test coverage:

1. `arc-prelude/src/prelude/property_based_testing.rs` (97/97 lines)
2. `arc-primitives/src/hash/sha2.rs` (27/27 lines)
3. `arc-primitives/src/hash/sha3.rs` (27/27 lines)
4. `arc-primitives/src/rand/csprng.rs` (23/23 lines)
5. `arc-validation/src/cavp/vectors.rs` (126/126 lines)
6. `arc-hybrid/src/compose.rs` (207/209 lines - 99.04%)

These files serve as examples of comprehensive testing practices.

## Test Suite Statistics

### Test Execution Summary

- **Total Tests Run:** ~900+ tests
- **Tests Passed:** All tests passed
- **Tests Ignored:** 7 tests
  - 3 ML-KEM roundtrip tests (aws-lc-rs limitation)
  - 4 ML-KEM wrong secret key tests (aws-lc-rs limitation)
  - 2 timing validation tests (inherently flaky)
- **Longest Running Tests:** SLH-DSA tests (>60 seconds each)

### Test Categories

1. **Unit Tests:** ~600 tests across all crates
2. **Integration Tests:** ~200 tests
3. **CAVP Validation Tests:** ~100 tests with NIST test vectors
4. **Property-Based Tests:** ~50 tests using proptest
5. **Known Answer Tests (KAT):** ~80 tests with official vectors

## Recommendations

### Immediate Actions (Priority: CRITICAL)

1. **Add serialization tests** for `arc-core/src/serialization.rs` (0% → 80%)
   - Test key serialization/deserialization
   - Test ciphertext serialization
   - Test error cases

2. **Implement error recovery tests** for all arc-prelude error_recovery modules (0% → 80%)
   - Circuit breaker patterns
   - Graceful degradation
   - Recovery strategies

3. **Test convenience APIs** in arc-core (0-40% → 80%)
   - End-to-end encryption workflows
   - Key generation and management
   - Hybrid operations

4. **Validate CAVP pipeline** (0% → 70%)
   - Test automation framework
   - Validation summary generation
   - FIPS compliance checking

### Short-Term Actions (Priority: HIGH)

5. **Improve post-quantum algorithm coverage**
   - ML-KEM: 68% → 85%
   - ML-DSA: 66% → 85%

6. **Add hardware detection tests** (15% → 70%)
   - Mock different CPU features
   - Test algorithm selection based on capabilities

7. **Improve TLS coverage**
   - PQ key exchange: 39% → 75%
   - Error handling: 36% → 70%
   - Tracing: 39% → 70%

8. **Test KAT infrastructure** (0% → 60%)
   - Loaders, runners, report generation

### Medium-Term Actions (Priority: MEDIUM)

9. **Increase hybrid crypto coverage**
   - Hybrid encryption: 50% → 80%
   - Hybrid KEM: 65% → 80%

10. **Add integration tests** for complete workflows
    - Multi-step operations
    - Cross-crate interactions
    - Error propagation

11. **Improve config and zero-trust coverage**
    - Config: 49% → 75%
    - Zero Trust: 41% → 70%

### Long-Term Actions (Priority: LOW)

12. **Implement or remove formal verification stubs** in arc-tls
13. **Add performance regression tests**
14. **Expand property-based testing** to more modules

## Coverage Improvement Plan

### Phase 1: Critical Gaps (Target: 65% overall coverage)

**Timeline:** 2-3 weeks
**Effort:** ~40-60 hours

Focus on 0% coverage files:
- Serialization (126 lines)
- Error recovery (582 lines total)
- PQ KEM convenience APIs (156 lines)
- CAVP pipeline (1042 lines - focus on core paths)

**Expected Impact:** +9 percentage points

### Phase 2: High-Priority Improvements (Target: 72% overall coverage)

**Timeline:** 3-4 weeks
**Effort:** ~50-70 hours

Focus on low coverage (<30%) files:
- Hardware detection
- Hybrid crypto convenience APIs
- PQ signature convenience APIs
- TLS error handling and PQ key exchange
- FIPS validation implementation

**Expected Impact:** +7 percentage points

### Phase 3: Reaching 80% Target (Target: 80% overall coverage)

**Timeline:** 4-5 weeks
**Effort:** ~60-80 hours

Focus on medium coverage (30-70%) files:
- ML-KEM and ML-DSA improvements
- TLS protocol implementation
- Config and zero-trust modules
- KAT infrastructure
- Integration tests

**Expected Impact:** +8 percentage points

**Total Estimated Effort:** 150-210 hours over 9-12 weeks

## HTML Coverage Report

The detailed HTML coverage report with line-by-line coverage information is available at:

```
target/llvm-cov/html/index.html
```

To view the report, open this file in a web browser:

```bash
open target/llvm-cov/html/index.html  # macOS
xdg-open target/llvm-cov/html/index.html  # Linux
start target/llvm-cov/html/index.html  # Windows
```

The HTML report provides:
- Interactive file browser
- Line-by-line coverage highlighting
- Function coverage details
- Region coverage analysis

## Continuous Integration

### Recommended CI Coverage Checks

1. **Coverage Threshold:** Set minimum coverage to current baseline (56%) and increment by 2% monthly
2. **Per-Crate Thresholds:** Enforce 80% for new crates
3. **Coverage Reporting:** Upload coverage to Codecov or Coveralls
4. **Coverage Trend:** Track coverage changes in pull requests

### Sample CI Configuration

```yaml
- name: Generate coverage report
  run: cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

- name: Check coverage threshold
  run: |
    COVERAGE=$(cargo llvm-cov --workspace --all-features --summary-only | grep -oP '\d+\.\d+(?=%)' | head -1)
    if (( $(echo "$COVERAGE < 56.0" | bc -l) )); then
      echo "Coverage $COVERAGE% is below minimum 56%"
      exit 1
    fi
```

## Comparison with Industry Standards

| Project Type | Typical Coverage | LatticeArc Status |
|--------------|------------------|-------------------|
| Cryptographic Libraries | 80-95% | 56.63% (Below Standard) |
| System Libraries | 70-85% | 56.63% (Below Standard) |
| Application Code | 60-80% | 56.63% (At Lower Bound) |
| Safety-Critical Systems | 90-100% | 56.63% (Well Below Standard) |

**Assessment:** For a cryptographic library with FIPS compliance goals, 56.63% coverage is insufficient. Industry best practices recommend 80-95% coverage for security-critical code.

## Conclusion

The LatticeArc apache repository has achieved **56.63% line coverage**, which is **23.37 percentage points below the 80% target**. While core cryptographic primitives show good coverage (>85% in many cases), critical gaps exist in:

1. User-facing convenience APIs (0-40% coverage)
2. Error recovery infrastructure (0% coverage)
3. CAVP/FIPS validation automation (0% coverage)
4. Hardware detection and serialization (0-15% coverage)

**Priority Recommendation:** Focus immediate effort on the CRITICAL gaps (0% coverage files) before expanding to other areas. The phased approach outlined above provides a realistic path to achieving 80% coverage within 3 months.

**Next Steps:**
1. Review this report with the development team
2. Assign ownership for each critical gap
3. Create tracking issues for coverage improvements
4. Implement CI coverage checks to prevent regression
5. Begin Phase 1 implementation immediately

---

**Report Generated By:** cargo-llvm-cov v0.8.2
**Report Date:** 2026-01-31
**Repository:** apache_repo (LatticeArc Open Source Core)
