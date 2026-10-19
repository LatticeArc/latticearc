# Detached signature format v1

V1 supports pure ML-DSA-44, ML-DSA-65, ML-DSA-87 and explicit Ed25519 compatibility.
`generate_detached_keypair(CryptoConfig::new())` chooses ML-DSA-65. The Rust API
uses typed keys and the same `CryptoConfig` policy/session settings as encryption.
Verification pins both the key and its algorithm; a record cannot choose a
weaker algorithm. Ed25519 is unavailable with the `fips` feature.

## Simple post-quantum API

```rust
use latticearc::{CryptoConfig, DetachedSignature, generate_detached_keypair,
    sign_detached, verify_detached_with_key};

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let (public_key, secret_key) = generate_detached_keypair(CryptoConfig::new())?;
    let claims = br#"{"sub":"alice","role":"reader"}"#;
    let domain = "example.com/access-token";
    let signed = sign_detached(claims, &secret_key, domain, CryptoConfig::new())?;
    let wire = signed.to_json()?;

    // A receiver obtains public_key from trusted configuration, independently
    // of the untrusted claims or signature record.
    let received = DetachedSignature::from_json(&wire)?;
    let authentic = verify_detached_with_key(
        claims, &received, &public_key, domain, CryptoConfig::new(),
    )?;
    if !authentic {
        return Err("signature rejected".into());
    }
    // Now parse claims and enforce expiry, audience, authorization and replay policy.
    Ok(())
}
```

Explicit `SecurityLevel::Standard`, `High`, or `Maximum` on key generation chooses
ML-DSA-44, ML-DSA-65, or ML-DSA-87. Signing and verification infer the parameter
set from the typed key and enforce any explicitly requested minimum security
level. The secret key is zeroized on drop. ML-DSA signing uses randomized entropy.

Raw keys can be imported using `MlDsaPublicKey::from_bytes` and
`MlDsaSecretKey::from_bytes` with the intended `MlDsaParameterSet`. These APIs
expect expanded FIPS 204 bytes, not a seed or PKCS#8 container.

For existing classical keys, explicitly wrap them with
`DetachedSigningKey::Ed25519(seed)` or `DetachedVerificationKey::Ed25519(key)`.
Ed25519 is rejected by PQ-only, CNSA, or FIPS policies. There is no automatic
fallback from post-quantum signing or verification to Ed25519.

Configuration validates sessions, compliance and minimum security level.
Use-case selection and forced-scheme selection are rejected because detached
algorithms come from typed keys. `max_age` is also rejected: detached records
have no timestamp, so callers must enforce expiration in authenticated claims.

## Signed bytes

Concatenate these fields without padding or implicit terminators:

| Field | Encoding |
|---|---|
| Prefix | ASCII `LatticeArc-Detached-Signature` followed by `0x00` |
| Version | One byte: `0x01` |
| Algorithm | One-byte ID from the table below |
| Domain length | Unsigned 16-bit big-endian byte count |
| Domain | 1–255 bytes, each in `0x21..=0x7e` (printable ASCII without spaces) |
| Claims length | Unsigned 64-bit big-endian byte count |
| Claims | Exact bytes, possibly empty |

| Algorithm name | ID | Public key | Secret key | Signature | Base64 signature |
|---|---|---|---|---|---|
| `ed25519` | `0x01` | 32 bytes | 32-byte RFC 8032 seed | 64 bytes | 88 characters |
| `ml-dsa-44` | `0x02` | 1,312 bytes | 2,560 expanded bytes | 2,420 bytes | 3,228 characters |
| `ml-dsa-65` | `0x03` | 1,952 bytes | 4,032 expanded bytes | 3,309 bytes | 4,412 characters |
| `ml-dsa-87` | `0x04` | 2,592 bytes | 4,896 expanded bytes | 4,627 bytes | 6,172 characters |

ML-DSA signs the entire transcript in **pure FIPS 204 mode with an empty native
context**, not HashML-DSA. Ed25519 signs the transcript with ordinary Ed25519,
not Ed25519ph or Ed25519ctx. Do not hash the transcript first. The application
domain is authenticated inside the transcript for every algorithm.

Use an application-specific domain such as `example.com/access-token`, pinned
independently at verification. Matching is case-sensitive. Length prefixes
prevent different domain/claims boundaries from sharing a transcript. The
complete transcript is subject to the configurable signature-input resource
limit (64 KiB by default), checked before allocation.

Claims are opaque bytes. For JSON, preserve the signed bytes: whitespace,
object ordering, number representations and Unicode normalization affect the
signature. This contract does not prescribe JSON canonicalization. Verify the
bytes before parsing and authorizing their contents. Signature validity alone
does not check claim semantics, expiration or replay.

## Detached JSON record

Exactly four fields are required:

```json
{
  "version": 1,
  "algorithm": "ml-dsa-65",
  "domain": "example.com/access-token",
  "signature": "<3309 signature bytes in padded standard Base64>"
}
```

The placeholder above is descriptive. Complete records are in
[`detached-pq-v1.json`](../latticearc/tests/fixtures/detached-pq-v1.json) and
[`detached-v1.json`](../latticearc/tests/fixtures/detached-v1.json).

`DetachedSignature::from_json` rejects records larger than 8,192 bytes, missing,
duplicate or unknown fields, unsupported versions/algorithms, invalid domains
and malformed signature encodings. Base64 must be canonical standard Base64,
with padding when required. Base64url, missing required padding, invalid trailing
bits and the wrong signature length are rejected. ML-DSA-65 signature length is
exactly divisible by three, so its Base64 representation has no `=` padding.
JSON field order and whitespace in the signature record itself are not signed.

There is no public key, key URL, key identifier or claims payload in the record.
Never choose a trust anchor from unverified claims. Future formats require
explicit support; verification does not guess a format or retry another algorithm.
Algorithm mismatch, wrong keys, altered claims, malformed records and domain
mismatch return `Ok(false)`. Invalid caller key/domain/policy, resource limits
and operational/session failures return `Err`. Verification revalidates records
constructed directly or deserialized with serde.

## Relationship to existing formats

| API / format | Signed representation |
|---|---|
| `sign_ed25519` / raw | Supplied message bytes |
| Unified `SignedData`, `ed25519` scheme | `SHA-512(b"LatticeArc-Sig-ed25519-v1\0" || message)` |
| Raw ML-DSA | Supplied message bytes and its native context |
| Detached v1 | Length-prefixed transcript above; empty ML-DSA native context |

Do not copy signature bytes between these formats. For legacy envelopes use
`verify_with_anchor`; raw signatures use the corresponding primitive and an
independently trusted key.

## Interoperability and CI

Fixtures use independent OpenSSL Ed25519 and ML-DSA implementations. All fixture
keys are **public test keys**, never suitable for deployment. Deterministic
OpenSSL ML-DSA signing is used only to make fixtures reproducible; production
LatticeArc signing remains randomized. Regenerate with OpenSSL 3.5 or newer:

```sh
OPENSSL=/path/to/openssl python3 scripts/generate-detached-fixtures.py
cargo test --locked -p latticearc --test detached_interoperability --test detached_pq_interoperability
```

Ed25519 signatures match fixtures byte-for-byte. ML-DSA fixtures verify through
LatticeArc, and freshly generated signatures verify independently with AWS-LC.
Negative vectors cover altered/reserialized claims, wrong keys, domain mismatch
and relabeling, unsupported tags, malformed signatures, wrong ML-DSA native
context, algorithm substitution and raw/unified format confusion. Separate policy
tests reject a valid classical signature when the pinned key is post-quantum.
Both suites execute natively on `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`; both matrix results are required by the main CI
`Pipeline Status` job.
