# arc-zkp

Zero-knowledge proof systems for LatticeArc.

## Overview

`arc-zkp` provides zero-knowledge proof primitives:

- **Schnorr proofs** - Proof of discrete log knowledge
- **Sigma protocols** - General sigma protocol framework
- **Commitment schemes** - Hiding and binding commitments

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
arc-zkp = "0.1"
```

### Schnorr Proof

Prove knowledge of a discrete logarithm without revealing it:

```rust
use arc_zkp::schnorr::*;

// Prover has secret x where Y = g^x
let secret = generate_secret()?;
let public = compute_public(&secret)?;

// Generate proof
let proof = SchnorrProof::prove(&secret, &public)?;

// Verifier checks proof
let is_valid = proof.verify(&public)?;
assert!(is_valid);
```

### Sigma Protocols

Build custom zero-knowledge proofs:

```rust
use arc_zkp::sigma::*;

// AND composition: prove knowledge of both x and y
let proof = SigmaProtocol::and(
    SchnorrProof::prove(&x, &X)?,
    SchnorrProof::prove(&y, &Y)?,
)?;

// OR composition: prove knowledge of x OR y
let proof = SigmaProtocol::or(
    SchnorrProof::prove(&x, &X)?,
    SchnorrProof::simulate(&Y)?,  // Simulate the one we don't know
)?;
```

### Commitment Schemes

```rust
use arc_zkp::commitment::*;

// Pedersen commitment
let (commitment, opening) = pedersen_commit(&value, &blinding)?;

// Later, open the commitment
let is_valid = pedersen_verify(&commitment, &value, &opening)?;
```

## Properties

| Property | Description |
|----------|-------------|
| **Completeness** | Valid proofs always verify |
| **Soundness** | Invalid proofs are rejected |
| **Zero-knowledge** | Proofs reveal nothing about secrets |

## Modules

| Module | Description |
|--------|-------------|
| `schnorr` | Schnorr proof of knowledge |
| `sigma` | Sigma protocol framework |
| `commitment` | Commitment schemes |

## Use Cases

- **Authentication** - Prove identity without revealing credentials
- **Voting** - Prove vote validity without revealing choice
- **Credentials** - Prove attributes without revealing full identity
- **Blockchain** - Prove transaction validity privately

## Security

- Proofs are simulation-sound
- Commitments are computationally hiding and binding
- No trusted setup required (for Schnorr)

## License

Apache-2.0
