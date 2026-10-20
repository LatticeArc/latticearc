# LatticeArc Binary Wire Format (v1)

**Version**: 1
**Status**: Implemented (0.13)
**Module**: `latticearc::hybrid::wire`

## Overview

A compact, fixed-layout binary encoding for the hybrid values an application
stores or transmits: hybrid KEM public keys, hybrid KEM encapsulations, hybrid
ciphertexts, hybrid signature public keys and hybrid signatures. It is meant
for fixed-size records on disk or on untrusted storage where JSON and CBOR are
unwanted. Keys with metadata (use case, security level, expiry) keep using the
[Portable Key Format](KEY_FORMAT.md); detached signatures keep their own
[detached signature format](DETACHED_SIGNATURE_FORMAT.md).

```rust
use latticearc::{HybridCiphertext, WireEncode};

fn store(ct: &HybridCiphertext) -> Result<Vec<u8>, latticearc::WireError> {
    ct.to_wire()
}

fn load(record: &[u8]) -> Result<HybridCiphertext, latticearc::WireError> {
    HybridCiphertext::from_wire(record)
}
```

`WireEncode` is sealed: it is implemented only for `HybridKemPublicKey`,
`EncapsulatedKey`, `HybridCiphertext`, `HybridSigPublicKey` and
`HybridSignature`. `to_wire` returns `Result` because values assembled by hand
through the public constructors can hold component lengths that no algorithm
id describes; values produced by the library always encode.

## Common header

Every value starts with the same 5-byte header. There are no padding bytes and
no terminators; integers are big-endian.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 2 | magic | `0x4C 0x41` (ASCII `"LA"`) |
| 2 | 1 | version | `0x01` |
| 3 | 1 | type tag | see below |
| 4 | 1 | algorithm id | per type, see below |
| 5 | … | body | fixed fields in the order listed per type |

### Type tags

| Tag | Type | Algorithm id |
|---|---|---|
| `0x00` | never assigned | — |
| `0x01` | `HybridKemPublicKey` | ML-KEM level |
| `0x02` | `EncapsulatedKey` | ML-KEM level |
| `0x03` | `HybridCiphertext` | ML-KEM level |
| `0x04` | `HybridSigPublicKey` | ML-DSA parameter set |
| `0x05` | `HybridSignature` | ML-DSA parameter set |
| `0x06` | **reserved**: `WrappedKey` (0.13, `primitives::aead::key_wrap`) | defined with that type |
| `0x07`–`0xFF` | unassigned | — |

### Algorithm ids

Algorithm ids are the NIST security category, matching the discriminants of
`MlKemSecurityLevel` and `MlDsaParameterSet`.

| Id | ML-KEM (tags 0x01–0x03) | ML-DSA (tags 0x04–0x05) |
|---|---|---|
| 1 | ML-KEM-512 | — |
| 2 | — | ML-DSA-44 |
| 3 | ML-KEM-768 | ML-DSA-65 |
| 5 | ML-KEM-1024 | ML-DSA-87 |

The classical half is fixed by the type: X25519 for KEM types, Ed25519 for
signature types.

## Body layouts

All sizes in bytes. "Total" includes the 5-byte header.

### `0x01` HybridKemPublicKey

| Field | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| ML-KEM encapsulation key | 800 | 1184 | 1568 |
| X25519 public key | 32 | 32 | 32 |
| **Total** | **837** | **1221** | **1605** |

`HybridKemPublicKey::to_bytes` (an older layout with its own version byte, a
1/2/3 level tag and `u32` length prefixes) is unchanged and remains readable by
`from_bytes`; it is not a wire-format v1 value. The wire format drops its length
prefixes because the algorithm id fixes every length, and uses the shared
header so every hybrid type follows one version rule.

### `0x02` EncapsulatedKey

| Field | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| ML-KEM ciphertext | 768 | 1088 | 1568 |
| X25519 ephemeral public key | 32 | 32 | 32 |
| **Total** | **805** | **1125** | **1605** |

Only the public encapsulation is encoded. The 64-byte shared secret is never
written; decoding returns `EncapsulatedKey::for_decapsulate`. The encoder
derives the algorithm id from the ciphertext length (the three lengths are
distinct). An ML-KEM-1024 public key and ciphertext have the same total length;
only the type tag tells them apart.

### `0x03` HybridCiphertext

| Field | Size |
|---|---|
| ML-KEM ciphertext | 768 / 1088 / 1568 (by algorithm id) |
| X25519 ephemeral public key | 32 |
| AES-256-GCM nonce | 12 |
| AES-256-GCM tag | 16 |
| symmetric ciphertext length `n` | 4 (`u32`, big-endian) |
| AES-256-GCM ciphertext | `n`, at most 104 857 600 (100 MiB) |

Total: `5 + kem_ct + 64 + n`, i.e. `837 + n`, `1157 + n` or `1637 + n`. This is
the only variable-length field in v1. The AEAD additional data and HKDF context
are not part of the ciphertext and must be supplied by the application at
decryption, as with `decrypt_hybrid`.

### `0x04` HybridSigPublicKey

| Field | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| ML-DSA public key | 1312 | 1952 | 2592 |
| Ed25519 public key | 32 | 32 | 32 |
| **Total** | **1349** | **1989** | **2629** |

### `0x05` HybridSignature

| Field | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| ML-DSA signature | 2420 | 3309 | 4627 |
| Ed25519 signature | 64 | 64 | 64 |
| **Total** | **2489** | **3378** | **4696** |

`HybridSignature` does not store its parameter set, so the encoder derives the
algorithm id from the ML-DSA signature length (the three lengths are distinct).
Verifiers must still pin the parameter set through the public key; the
signature's algorithm id is not a policy input.

## Size limits

Each decoder compares the whole input length with a hard maximum
(`WireEncode::MAX_WIRE_LEN`) before reading the header or allocating. The
variable ciphertext length is checked against its own cap
(`MAX_SYMMETRIC_CIPHERTEXT_LEN`) and is only honoured when that many bytes are
actually present, so allocation never exceeds the input supplied.

| Type | `MAX_WIRE_LEN` |
|---|---|
| `HybridKemPublicKey` | 1605 |
| `EncapsulatedKey` | 1605 |
| `HybridCiphertext` | 104 859 237 (1637 + 100 MiB) |
| `HybridSigPublicKey` | 2629 |
| `HybridSignature` | 4696 |

## Decoding rules

A v1 decoder rejects, in this order:

1. input longer than the type's maximum: `WireError::TooLarge`;
2. input shorter than the 5-byte header: `WireError::Truncated`;
3. wrong magic: `WireError::BadMagic`;
4. a version other than 1: `WireError::UnsupportedVersion`;
5. a type tag other than the one requested: `WireError::WrongType`;
6. an algorithm id not listed for that type: `WireError::UnknownAlgorithm`;
7. a body that ends before the last field: `WireError::Truncated`;
8. a ciphertext length prefix above its cap: `WireError::TooLarge`;
9. any byte after the last field: `WireError::TrailingBytes`.

Decoding is structural only. Component bytes are not checked cryptographically
(no point or modulus validation); that happens when the value is used. The
error variants are distinguishable because every check reads only the public
bytes the sender chose, before any key material is involved. Decryption and
verification of a decoded value keep their opaque errors.

Because every field has one length and trailing bytes are rejected, each value
has exactly one encoding: `from_wire(x)` succeeding implies `to_wire()` returns
`x` byte for byte. The fuzz target checks this.

## Compatibility policy

1. **A decoder accepts only versions it knows.** A v1 decoder rejects every
   other version byte. There is no "best effort" parsing of unknown versions.
2. **Field meaning never changes within a version.** No field of an existing
   (version, type tag, algorithm id) triple is ever reinterpreted, reordered or
   resized.
3. **Additions use new tags or ids, not new versions.** A new value type gets an
   unassigned type tag; a new parameter set gets a new algorithm id. Older
   decoders reject them with `WrongType` or `UnknownAlgorithm`, which is the
   intended behaviour.
4. **The version byte changes only for a breaking change to the header or to the
   rules above.** A new version is accompanied by a decoder that still accepts
   v1 for at least one minor release, and by a CHANGELOG entry.
5. **Reserved tags.** `0x06` is reserved for the `WrappedKey` encoding defined
   with `primitives::aead::key_wrap` in 0.13. That type's body begins with its
   own version byte; the envelope rules above still apply. `0x00` is never
   assigned, so an all-zero record cannot decode.
6. **Limits are part of the format.** Raising `MAX_SYMMETRIC_CIPHERTEXT_LEN` is
   a compatible change for decoders; lowering it is breaking.

## Test vectors

- `latticearc/tests/fixtures/wire-v1.json`: one vector per type and algorithm
  id (15 in total). Component bytes are deterministic filler, not real keys:
  each field starts from a seed `b` and emits `b = (b * 29 + 7) mod 256` for its
  length.
- `scripts/generate-wire-fixtures.py` regenerates the file from this document
  without calling LatticeArc.
- `latticearc/tests/wire_format_kat.rs` checks that every vector encodes to the
  stored bytes and decodes to the stored components.
- `latticearc/src/hybrid/wire.rs` unit tests: round trips with real keys at every
  level, every truncation point, trailing bytes, wrong magic, version, type tag
  and algorithm id, oversized inputs, and property tests.
- `fuzz/fuzz_targets/fuzz_wire_decode.rs`: totality and canonical re-encoding
  for every decoder.

## Version history

| Version | Release | Changes |
|---|---|---|
| 1 | 0.13 | Initial format: tags `0x01`–`0x05`, `0x06` reserved for `WrappedKey`. |
