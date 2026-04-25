# Secret Type Invariants

**Status**: Normative. Applies to both `apache_repo` (LatticeArc core) and `proprietary_repo` (LatticeArc Enterprise). Every type that holds secret material MUST satisfy every invariant below.

**Rationale**: Crypto libraries that do this piecemeal drift — some types get strict handling, others get shortcuts, and shortcuts become the pattern. This document elevates the rules to structural, compile-time-enforced invariants.

---

## What counts as "secret material"

A type holds secret material if its compromise would allow an attacker to:

- Forge signatures, decrypt ciphertexts, or impersonate a key holder
- Recover earlier or future shared secrets
- Compromise protocol security properties (e.g., recover proof randomness, commitment openings)

This includes:

- Private/signing keys (ML-DSA, SLH-DSA, FN-DSA, Ed25519, Secp256k1, X25519, ECDH P-*)
- KEM decapsulation keys (ML-KEM)
- Shared secrets (hybrid KEM output, ECDH output, KEM output)
- Symmetric keys (AEAD keys, MAC keys, KDF keys)
- KDF inputs (IKM) and intermediate KDF state
- AEAD plaintext (while in memory, post-decrypt)
- ZKP witnesses, commitment openings, proof randomness
- Password/passphrase material

This does **not** include:

- Public keys (publishable)
- Ciphertexts (publishable once produced)
- Signatures (publishable)
- KEM ciphertexts, MAC tags, hashes of public data
- Ephemeral public keys in hybrid schemes

---

## The 10 Invariants

### I-1. Newtype, never type alias

Every secret type is a named `struct`, not a `type Foo = Vec<u8>` alias. This enables all subsequent invariants (trait barriers, sealed access, compile-time checks).

```rust
// WRONG
type SigningKey = Vec<u8>;

// RIGHT
pub struct SigningKey(SecretVec);
```

### I-2. Fixed-size backing whenever the length is compile-time known

Use `SecretBytes<N>` (stack-allocated `[u8; N]` backing) for anything whose length is known at compile time. Use `SecretVec` (heap `Vec<u8>` backing) only when the length genuinely varies at runtime.

**Why fixed-size matters:**

- Heap allocators retain size metadata after `free`, which is a side-channel leak about secret sizes in adversary-controlled environments.
- `Vec<u8>` with a single `.push()` or `.extend()` past capacity silently reallocates and frees the old buffer **without zeroization** — a common rot path. `[u8; N]` has no such escape.
- Stack secrets are freed in a deterministic order tied to scope, not to allocator whims.

**When `SecretVec` is legitimate:**

- Variable-length KDF output with runtime-parameterized length (PBKDF2, SP800-108)
- Decrypted plaintext of arbitrary user data
- Variable-length signing-key serializations where length varies by algorithm parameter set

### I-3. `Zeroize` and `ZeroizeOnDrop`

Every secret type derives or manually implements both. `Zeroize` provides the explicit `zeroize()` call; `ZeroizeOnDrop` attaches it to `Drop`. Together they guarantee that dropping a secret value wipes its memory via volatile writes that the compiler cannot optimize away.

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey { bytes: SecretBytes<32> }
```

### I-4. Manual redacted `Debug`

`#[derive(Debug)]` on a secret struct prints the secret bytes. Every secret type must hand-write `Debug` that emits `"[REDACTED]"` for secret fields. Non-secret fields (e.g., key IDs, algorithm parameters) may be printed normally.

```rust
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
```

### I-5. `ConstantTimeEq` for comparison; no `PartialEq`, no `Eq`

Rust's `==` is the short-circuiting `PartialEq::eq`. It returns `false` on the first mismatch, leaking timing information about prefix agreement. Every secret type must:

- Implement `subtle::ConstantTimeEq` for timing-safe comparison
- NOT implement `PartialEq` or `Eq` (enforced by I-6)

### I-6. Compile-time barrier against `PartialEq`/`Eq`

Every secret type must have a corresponding line in `latticearc/tests/no_partial_eq_on_secret_types.rs`:

```rust
use static_assertions::assert_not_impl_any;
assert_not_impl_any!(SigningKey: PartialEq, Eq);
```

This is a structural barrier: a future `#[derive(PartialEq)]` added inadvertently will fail compilation, not ship quietly.

### I-7. No `Clone`; explicit `clone_for_transmission()`

`#[derive(Clone)]` on a secret creates uncontrolled copies. Every secret type:

- Does NOT derive `Clone`
- Provides `fn clone_for_transmission(&self) -> Self` when duplication is semantically required (e.g., for network transmission, for protocol-layer retry)

Every duplication is grep-able via the method name. Apache established this pattern for ZKP proof types (`SchnorrProof::clone_for_transmission`) in v0.7.1; we generalize it to every secret type.

### I-8. Single sealed accessor: `expose_secret()`

Every secret type exposes its bytes through exactly one public method:

```rust
pub fn expose_secret(&self) -> &[u8];       // for variable-size (SecretVec)
pub fn expose_secret(&self) -> &[u8; N];    // for fixed-size (SecretBytes<N>)
```

No `AsRef<[u8]>`. No `Deref<Target = [u8]>`. No public field access. No `as_bytes()` alias.

Rationale:

- **Grep-able**: every call site that touches secret bytes appears in `rg expose_secret`
- **Cognitive checkpoint**: the verb prompts the reader to think about what they're about to do with the bytes
- **Single point of instrumentation**: mlock, audit logging, or runtime hardening can be added in one place
- **Ecosystem-aligned**: matches the `secrecy` crate's `ExposeSecret::expose_secret()` idiom without taking on the crate as a dependency

**Exception**: `expose_secret_mut()` exists `pub(crate)` for in-place initialization of zeroed buffers (e.g., to receive HKDF output). It is not public API.

### I-9. `to_bytes()` returns a secret wrapper, never bare bytes

When a secret type offers an owned-bytes export, it must return one of:

- `SecretBytes<N>` (preferred when size is known)
- `SecretVec`
- `Zeroizing<[u8; N]>` or `Zeroizing<Vec<u8>>` (legacy; prefer the newtypes going forward)

Never `Vec<u8>`, never `[u8; N]`. An owned secret that escapes its wrapper is indistinguishable from a leak at the type level.

```rust
// WRONG
pub fn to_bytes(&self) -> Vec<u8> { self.bytes.clone() }

// RIGHT
pub fn to_bytes(&self) -> SecretVec { SecretVec::new(self.bytes.expose_secret().to_vec()) }
```

### I-10. Optional OS-level memory locking via `secret-mlock` feature

The base invariants above protect against in-process leaks (use-after-free, accidental logging, compiler dead-store elimination). They do NOT protect against swap-to-disk or core-dump exposure of secrets still resident in RAM.

A feature flag `secret-mlock` (off by default) upgrades `SecretBytes<N>` and `SecretVec` storage to OS-locked pages via the `region` crate:

- Linux: `mlock(2)` on the backing memory
- macOS: `mlock(2)` (same semantics)
- Windows: `VirtualLock`

Default-off because `mlock` has kernel-side limits (`RLIMIT_MEMLOCK`) that can make the feature fail in some deployments. High-threat deployments explicitly opt in.

When the feature is enabled, construction may fail if the kernel limit is exceeded; types return `Result` from constructors rather than panicking. When the feature is disabled, locking is a no-op and constructors remain infallible.

---

## Enforcement

### CI gates

1. **`latticearc/tests/no_partial_eq_on_secret_types.rs`** — must list every secret type. Missing entries fail type-check.

2. **`scripts/ci/secret_type_audit.sh`** — greps for structs whose name matches `(Secret|Private|Signing|Keypair|KeyPair)` and asserts:
   - Definition file contains `#[derive(.*Zeroize.*)]` or `impl Zeroize for`
   - Definition file contains `impl.*ConstantTimeEq`
   - Definition file contains manual `Debug` (no `#[derive(Debug)]`)
   - Definition file contains `expose_secret` method

3. **Clippy deny lints** (workspace-level):
   - `clippy::derive_partial_eq_without_eq` — already on
   - Custom: no new types matching secret-naming without the enforcer test

### Code review checklist

For every PR that adds or modifies a secret type:

- [ ] Uses `SecretBytes<N>` if size is known, `SecretVec` otherwise
- [ ] Derives `Zeroize` + `ZeroizeOnDrop` (or equivalent manual impl)
- [ ] Manual `Debug` redacts secret fields
- [ ] `ConstantTimeEq` implemented
- [ ] No `Clone` / `PartialEq` / `Eq` derived
- [ ] `clone_for_transmission()` added if duplication needed
- [ ] Entry added to `no_partial_eq_on_secret_types.rs`
- [ ] Single `expose_secret()` accessor; no `AsRef`, `Deref`, or public field
- [ ] Any `to_bytes()` / `into_bytes()` returns a secret wrapper

---

## Comparison to existing libraries

| Library | Zeroize | Fixed-size | Const-time eq | PartialEq barrier | Sealed accessor | mlock |
|---|---|---|---|---|---|---|
| RustCrypto `secrecy` | ✓ | caller | via caller | ✗ | ✓ `expose_secret` | ✗ |
| `dalek` (ed25519 / curve25519) | ✓ | ✓ | ✓ | ✗ | partial (`as_bytes`) | ✗ |
| `rustls::pki_types` | via `Zeroizing` | ✗ (DER) | ✗ | ✗ | opaque enum | ✗ |
| `ring` / `aws-lc-rs` | ✓ (internal) | ✓ | ✓ | n/a (FFI) | opaque handle | ✗ |
| `libsodium` | ✓ | ✓ | ✓ | ✗ | accessor | ✓ default |
| `age` encryption | ✓ | ✗ | partial | ✗ | ✗ | ✗ |
| **LatticeArc (this spec)** | **✓** | **✓** | **✓** | **✓** | **✓** | **✓ optional** |

The only dimension where this spec is deliberately weaker than a peer is opaque-handle isolation (ring / rustls). That pattern trades ergonomics and HSM/serialization compatibility for a stronger isolation property. It is infeasible for a library that must support key export for persistent storage, cross-machine protocols, and hardware backends.

The compile-time `PartialEq` barrier (I-6) is, as of this writing, stricter than any of the listed peers.

---

## Out of scope for this spec

- Guard pages and allocation canaries (`sodium_malloc` style): 4 KiB per secret is prohibitive for a general-purpose library. Revisit if the deployment target is narrowed to HSM-equivalent hosts.
- Constant-time memory allocator: not available in stable Rust and not a meaningful win over the protections above for the threat model we address.
- Covert-channel mitigations beyond constant-time comparison: out of scope for API design; belongs in per-algorithm implementations.

---

## Revision log

- **2026-04-23** (initial): ratified by decision. Applies to apache 0.8 / proprietary next release. Existing 0.7.x types are non-compliant pending the Phase A sweep (see `CHANGELOG.md`).
