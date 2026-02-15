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

Prove knowledge of a discrete logarithm without revealing it (secp256k1):

```rust
use arc_zkp::schnorr::{SchnorrProver, SchnorrVerifier};

// Create prover with random secret key
let (prover, public_key) = SchnorrProver::new()?;

// Generate non-interactive proof (Fiat-Shamir)
let proof = prover.prove(b"context")?;

// Verifier checks proof using only the public key
let verifier = SchnorrVerifier::new(&public_key)?;
let is_valid = verifier.verify(&proof, b"context")?;
```

### Sigma Protocols

Fiat-Shamir transformed sigma protocols:

```rust
use arc_zkp::sigma::{SigmaProof, FiatShamir};

// Sigma proofs provide a general framework for
// zero-knowledge proofs with Fiat-Shamir heuristic
```

### Commitment Schemes

```rust
use arc_zkp::commitment::PedersenCommitment;

// Pedersen commitment (computationally hiding, binding)
let (commitment, opening) = PedersenCommitment::commit(&value)?;

// Later, verify the commitment
let is_valid = commitment.verify(&opening)?;
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
