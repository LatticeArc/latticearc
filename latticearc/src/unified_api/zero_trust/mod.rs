//! Zero-trust authentication primitives.
//!
//! Provides challenge-response authentication with zero-knowledge proofs,
//! proof-of-possession, and continuous session verification.
//!
//! # Session State Machine
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    ZERO-TRUST SESSION LIFECYCLE                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │                          ┌─────────────┐                                │
//! │                          │   Created   │                                │
//! │                          │  (Initial)  │                                │
//! │                          └──────┬──────┘                                │
//! │                                 │ generate_challenge()                  │
//! │                                 ▼                                       │
//! │                          ┌─────────────┐                                │
//! │                          │  Challenged │                                │
//! │                          │ (Awaiting   │                                │
//! │                          │  Response)  │                                │
//! │                          └──────┬──────┘                                │
//! │                                 │                                       │
//! │              ┌──────────────────┼──────────────────┐                    │
//! │              │ verify_proof()   │                  │ timeout            │
//! │              │ SUCCESS          │                  │                    │
//! │              ▼                  │                  ▼                    │
//! │       ┌─────────────┐           │           ┌─────────────┐             │
//! │       │   Active    │           │           │   Failed    │             │
//! │       │ (Verified)  │           │           │ (Rejected)  │             │
//! │       └──────┬──────┘           │           └─────────────┘             │
//! │              │                  │                                       │
//! │              │ needs_verification()?                                    │
//! │              │ (interval elapsed)                                       │
//! │              ▼                  │                                       │
//! │       ┌─────────────┐           │                                       │
//! │       │  Reverify   │───────────┘                                       │
//! │       │  (Pending)  │  re-challenge and verify                          │
//! │       └──────┬──────┘                                                   │
//! │              │                                                          │
//! │       ┌──────┴──────┐                                                   │
//! │       │ verify()    │                                                   │
//! │       ▼             ▼                                                   │
//! │ ┌───────────┐ ┌───────────┐                                             │
//! │ │ Upgraded  │ │Downgraded │                                             │
//! │ │  Trust    │ │  Trust    │                                             │
//! │ └─────┬─────┘ └─────┬─────┘                                             │
//! │       │             │                                                   │
//! │       └──────┬──────┘                                                   │
//! │              ▼                                                          │
//! │       ┌─────────────┐                                                   │
//! │       │   Expired   │  session_duration > max_lifetime                  │
//! │       │ (Terminal)  │                                                   │
//! │       └─────────────┘                                                   │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         TRUST LEVEL TRANSITIONS                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │   ┌───────────┐    verify()     ┌───────────┐    verify()    ┌────────┐│
//! │   │ Untrusted │ ───────────────►│  Partial  │ ──────────────►│Trusted ││
//! │   │   (0)     │  (success)      │   (1)     │  (success)     │  (2)   ││
//! │   └─────┬─────┘                 └─────┬─────┘                └────┬───┘│
//! │         ▲                             ▲                          │    │
//! │         │         downgrade()         │        downgrade()       │    │
//! │         │◄────────────────────────────┼──────────────────────────┘    │
//! │         │        (verification fail)  │                               │
//! │         │                             │         verify()              │
//! │         │                             │         (success)             │
//! │         │                             ▼                               │
//! │         │                      ┌─────────────┐                        │
//! │         │                      │   Fully     │                        │
//! │         └──────────────────────│  Trusted    │                        │
//! │             (revoke)           │    (3)      │                        │
//! │                                └─────────────┘                        │
//! │                                                                       │
//! │   Trust Score: 0 (none) → 1 (partial) → 2 (trusted) → 3 (full)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Challenge-Response Protocol
//!
//! 1. **Challenge Generation**: Server generates random nonce with complexity level
//! 2. **Proof Construction**: Client creates ZK proof using private key + nonce
//! 3. **Verification**: Server verifies proof without learning private key
//! 4. **Session Update**: Trust level adjusted based on verification result

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

// Re-export TrustLevel from types module (pure Rust, no FFI deps)
pub use crate::types::zero_trust::TrustLevel;

mod auth;
mod proof_data;
mod protocol_types;
mod security_mode;
mod session;
#[cfg(test)]
mod tests;
mod verified_session;

pub use auth::ZeroTrustAuth;
pub use protocol_types::{Challenge, ContinuousSession, ProofOfPossessionData, ZeroKnowledgeProof};
pub use security_mode::SecurityMode;
pub use session::ZeroTrustSession;
pub use verified_session::VerifiedSession;
