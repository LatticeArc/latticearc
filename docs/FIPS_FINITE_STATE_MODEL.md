# LatticeArc Cryptographic Module Finite State Model

**Document Version:** 1.0
**Module Version:** 0.1.0
**FIPS 140-3 Compliance:** Section 7.2 - Finite State Model
**Date:** January 2026

## 1. Overview

This document defines the Finite State Model (FSM) for the LatticeArc Cryptographic Module as required by FIPS 140-3. The FSM specifies all possible states, transitions, and the conditions under which transitions occur.

## 2. State Definitions

### 2.1 Primary States

| State ID | State Name | Description |
|----------|------------|-------------|
| S0 | POWER_OFF | Module not loaded |
| S1 | UNINITIALIZED | Module loaded, not initialized |
| S2 | SELF_TEST | Running power-up self-tests |
| S3 | OPERATIONAL | Normal cryptographic operation |
| S4 | ERROR | Critical error, limited operation |
| S5 | ZEROIZATION | Destroying all SSPs |

### 2.2 Sub-States (Operational)

| Sub-State | Parent | Description |
|-----------|--------|-------------|
| S3.1 | OPERATIONAL | Idle - awaiting requests |
| S3.2 | OPERATIONAL | Encrypting |
| S3.3 | OPERATIONAL | Decrypting |
| S3.4 | OPERATIONAL | Signing |
| S3.5 | OPERATIONAL | Verifying |
| S3.6 | OPERATIONAL | Key Generating |
| S3.7 | OPERATIONAL | Hashing |
| S3.8 | OPERATIONAL | Key Deriving |
| S3.9 | OPERATIONAL | Conditional Self-Test |

### 2.3 Error Sub-States

| Sub-State | Parent | Description | Error Code |
|-----------|--------|-------------|------------|
| S4.1 | ERROR | Self-test failure | 0x0001 |
| S4.2 | ERROR | Entropy failure | 0x0002 |
| S4.3 | ERROR | Integrity failure | 0x0003 |
| S4.4 | ERROR | Critical crypto error | 0x0004 |
| S4.5 | ERROR | Zeroization failure | 0x0005 |
| S4.6 | ERROR | Authentication failure | 0x0006 |

## 3. State Diagram

```
                              ┌─────────────────┐
                              │   S0: POWER_OFF │
                              └────────┬────────┘
                                       │ Module Load
                                       ▼
                              ┌─────────────────┐
                              │ S1: UNINITIALIZED│
                              └────────┬────────┘
                                       │ init()
                                       ▼
                              ┌─────────────────┐
                         ┌───▶│  S2: SELF_TEST  │◀───┐
                         │    └────────┬────────┘    │
                         │             │             │
                         │    ┌────────┴────────┐    │
                         │    │                 │    │
                         │    ▼ Pass            ▼ Fail
                         │ ┌─────────────┐  ┌─────────────┐
        Manual Test ─────┼─│S3:OPERATIONAL│  │  S4: ERROR  │
                         │ └──────┬──────┘  └──────┬──────┘
                         │        │                │
                         │        │ zeroize()      │ recover()
                         │        ▼                │
                         │ ┌─────────────┐         │
                         │ │S5:ZEROIZATION│        │
                         │ └──────┬──────┘         │
                         │        │                │
                         │        │ Complete       │
                         │        ▼                │
                         │ ┌─────────────┐         │
                         └─│ S0:POWER_OFF│◀────────┘
                           └─────────────┘   (if unrecoverable)
```

## 4. State Transition Table

### 4.1 Primary Transitions

| From | To | Trigger | Condition | Action |
|------|----|---------|-----------| -------|
| S0 | S1 | Module load | OS loads library | Initialize memory |
| S1 | S2 | `init()` | None | Start self-tests |
| S2 | S3 | Self-test complete | All tests pass | Enable services |
| S2 | S4 | Self-test complete | Any test fails | Set error code |
| S3 | S3 | Service request | Valid request | Execute service |
| S3 | S4 | Critical error | Error detected | Set error code |
| S3 | S5 | `zeroize_all()` | Explicit request | Start zeroization |
| S4 | S3 | `recover()` | Error recoverable | Re-run self-tests |
| S4 | S5 | `zeroize_all()` | Explicit request | Start zeroization |
| S5 | S0 | Zeroization complete | All SSPs zeroed | Module shutdown |

### 4.2 Operational Sub-State Transitions

| From | To | Trigger | Action |
|------|----|---------| -------|
| S3.1 | S3.2 | `encrypt()` | Begin encryption |
| S3.1 | S3.3 | `decrypt()` | Begin decryption |
| S3.1 | S3.4 | `sign()` | Begin signing |
| S3.1 | S3.5 | `verify()` | Begin verification |
| S3.1 | S3.6 | `generate_keypair()` | Begin key generation |
| S3.1 | S3.7 | `hash()` | Begin hashing |
| S3.1 | S3.8 | `derive_key()` | Begin derivation |
| S3.1 | S3.9 | `run_self_test()` | Begin conditional test |
| S3.2-S3.9 | S3.1 | Operation complete | Return to idle |
| S3.2-S3.9 | S4 | Operation fails | Enter error state |

## 5. Detailed State Descriptions

### 5.1 S0: POWER_OFF

**Description:** Module is not loaded into memory.

**Entry Actions:**
- None (external state)

**Exit Actions:**
- OS loads shared library into process memory

**Allowed Operations:**
- None

### 5.2 S1: UNINITIALIZED

**Description:** Module is loaded but has not been initialized.

**Entry Actions:**
- Allocate static memory structures
- Set module state flag to UNINITIALIZED

**Exit Actions:**
- Call `init()` to begin initialization

**Allowed Operations:**
- `init()` only

**Error Conditions:**
- Memory allocation failure → Remain in S1

### 5.3 S2: SELF_TEST

**Description:** Module is running power-up self-tests.

**Entry Actions:**
- Set module state flag to SELF_TEST
- Initialize self-test report structure

**Self-Test Sequence:**
1. Software integrity test
2. SHA-256 Known Answer Test (KAT)
3. AES-256-GCM Known Answer Test
4. ML-KEM-768 Known Answer Test
5. HKDF-SHA256 Known Answer Test
6. Entropy source health tests

**Exit Actions (Success):**
- Set SELF_TEST_PASSED flag
- Clear error state
- Transition to S3

**Exit Actions (Failure):**
- Set error code for failed test
- Clear SELF_TEST_PASSED flag
- Transition to S4

**Allowed Operations:**
- None (blocking state)

### 5.4 S3: OPERATIONAL

**Description:** Module is ready for normal cryptographic operations.

**Entry Conditions:**
- All power-up self-tests passed
- Error state cleared (if recovering)

**Entry Actions:**
- Set module state to OPERATIONAL
- Enable all cryptographic services

**Allowed Operations:**
- All cryptographic services (encrypt, decrypt, sign, verify, etc.)
- Key management services
- Status queries
- Manual self-tests

**Error Conditions:**
| Condition | Action |
|-----------|--------|
| Entropy health test fails | Transition to S4.2 |
| Conditional self-test fails | Transition to S4.1 |
| Critical crypto error | Transition to S4.4 |
| Explicit zeroization request | Transition to S5 |

### 5.5 S4: ERROR

**Description:** Module has encountered a critical error and is in limited operation mode.

**Entry Actions:**
- Set error code
- Clear SELF_TEST_PASSED flag
- Disable cryptographic services
- Log error event

**Allowed Operations:**
- `get_error_state()` - Query error details
- `get_module_status()` - Query module status
- `recover()` - Attempt recovery (if recoverable)
- `zeroize_all()` - Force zeroization

**Recovery Conditions:**
| Error Type | Recoverable | Recovery Action |
|------------|-------------|-----------------|
| Self-test failure | Yes | Re-run self-tests |
| Entropy failure | Yes | Re-initialize RNG |
| Integrity failure | No | Module restart required |
| Critical crypto | Yes | Re-run affected test |
| Zeroization failure | No | Module restart required |

### 5.6 S5: ZEROIZATION

**Description:** Module is destroying all Sensitive Security Parameters.

**Entry Actions:**
- Disable all services
- Set module state to ZEROIZATION

**Zeroization Sequence:**
1. Zeroize all active session keys
2. Zeroize all cached key material
3. Zeroize intermediate computation buffers
4. Zeroize DRBG state
5. Clear all SSP memory locations
6. Verify zeroization complete

**Exit Actions:**
- Set module state to POWER_OFF
- Release all memory

**Allowed Operations:**
- None (blocking state)

## 6. Input/Output Specifications

### 6.1 Control Inputs

| Input | Valid States | Description |
|-------|--------------|-------------|
| `init()` | S1 | Initialize module |
| `zeroize_all()` | S3, S4 | Zeroize all SSPs |
| `recover()` | S4 | Attempt error recovery |
| `run_self_test()` | S3 | Manual self-test |

### 6.2 Data Inputs

| Input | Valid States | Description |
|-------|--------------|-------------|
| Plaintext | S3 | Data for encryption |
| Ciphertext | S3 | Data for decryption |
| Message | S3 | Data for signing/hashing |
| Key material | S3 | Keys for import |

### 6.3 Status Outputs

| Output | Description |
|--------|-------------|
| Module state | Current FSM state |
| Error code | Error details (if in S4) |
| Self-test results | Pass/fail for each test |
| Operational status | Ready/not ready |

### 6.4 Data Outputs

| Output | Valid States | Description |
|--------|--------------|-------------|
| Ciphertext | S3 | Encrypted data |
| Plaintext | S3 | Decrypted data |
| Signature | S3 | Digital signature |
| Verification result | S3 | Valid/invalid |
| Hash digest | S3 | Hash output |
| Key pair | S3 | Generated keys |

## 7. Error Code Definitions

### 7.1 Error Code Structure

```
Error Code: 0xCCNN

CC = Category (01-FF)
NN = Specific error (01-FF)

Categories:
01 = Self-test errors
02 = Entropy errors
03 = Integrity errors
04 = Cryptographic errors
05 = Key management errors
06 = Authentication errors
```

### 7.2 Error Code Table

| Code | Name | Description | Recoverable |
|------|------|-------------|-------------|
| 0x0101 | SELF_TEST_SHA256_FAILED | SHA-256 KAT failed | Yes |
| 0x0102 | SELF_TEST_AES_FAILED | AES-GCM KAT failed | Yes |
| 0x0103 | SELF_TEST_MLKEM_FAILED | ML-KEM KAT failed | Yes |
| 0x0104 | SELF_TEST_HKDF_FAILED | HKDF KAT failed | Yes |
| 0x0105 | SELF_TEST_PCT_FAILED | Pairwise consistency failed | Yes |
| 0x0201 | ENTROPY_REPETITION_FAILED | Repetition test failed | Yes |
| 0x0202 | ENTROPY_FREQUENCY_FAILED | Frequency test failed | Yes |
| 0x0203 | ENTROPY_MONOBIT_FAILED | Monobit test failed | Yes |
| 0x0204 | ENTROPY_RUNS_FAILED | Runs test failed | Yes |
| 0x0205 | ENTROPY_PROPORTION_FAILED | Adaptive proportion failed | Yes |
| 0x0301 | INTEGRITY_CHECK_FAILED | Module integrity failed | No |
| 0x0401 | CRYPTO_ENCRYPT_FAILED | Encryption operation failed | Yes |
| 0x0402 | CRYPTO_DECRYPT_FAILED | Decryption operation failed | Yes |
| 0x0403 | CRYPTO_SIGN_FAILED | Signing operation failed | Yes |
| 0x0404 | CRYPTO_VERIFY_FAILED | Verification operation failed | Yes |
| 0x0501 | KEY_GENERATION_FAILED | Key generation failed | Yes |
| 0x0502 | KEY_ZEROIZATION_FAILED | Key zeroization failed | No |
| 0x0601 | AUTH_REPEATED_FAILURES | Multiple auth failures | Yes |

## 8. Implementation Notes

### 8.1 Thread Safety

- All state transitions are protected by atomic operations
- State queries use atomic reads
- State changes use compare-and-swap

```rust
use std::sync::atomic::{AtomicU32, Ordering};

static MODULE_STATE: AtomicU32 = AtomicU32::new(STATE_UNINITIALIZED);

fn transition_state(from: u32, to: u32) -> bool {
    MODULE_STATE.compare_exchange(
        from, to,
        Ordering::SeqCst,
        Ordering::SeqCst
    ).is_ok()
}
```

### 8.2 State Persistence

- Module state is NOT persisted across process restarts
- On restart, module always begins in S0 (POWER_OFF)
- No automatic state recovery

### 8.3 Concurrent Operations

- Multiple threads may perform operations in S3 concurrently
- State transitions are serialized
- Error state (S4) affects all threads

## 9. Compliance Verification

### 9.1 FSM Requirements (FIPS 140-3 Section 7.2)

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Defined states | 6 primary, 15 sub-states | Complete |
| Defined transitions | 20+ transitions | Complete |
| Input/output defined | Section 6 | Complete |
| Error states | Section 7 | Complete |
| Self-test states | S2, S3.9 | Complete |
| Zeroization state | S5 | Complete |

### 9.2 Test Cases

| Test | Description | Expected Result |
|------|-------------|-----------------|
| FSM-01 | Module load | S0 → S1 |
| FSM-02 | Initialization | S1 → S2 → S3 |
| FSM-03 | Self-test failure | S2 → S4 |
| FSM-04 | Error recovery | S4 → S2 → S3 |
| FSM-05 | Zeroization | S3 → S5 → S0 |
| FSM-06 | Operation in error state | Blocked |
| FSM-07 | Invalid transition | Rejected |

## 10. Revision History

| Version | Date | Description |
|---------|------|-------------|
| 1.0 | January 2026 | Initial release |

---

**END OF FINITE STATE MODEL DOCUMENT**
