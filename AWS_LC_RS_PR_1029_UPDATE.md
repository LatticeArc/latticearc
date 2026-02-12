# aws-lc-rs PR #1029 Merged - February 11, 2026

## Summary

🎉 **PR #1029 has been merged into aws-lc-rs!**

**PR Title:** Add serialization for `DecapsulationKey` (ML-KEM private keys)
**Merged:** February 10, 2026
**Branch:** main
**Reviewers:** dkostic (Feb 3), skmcgrail (Feb 9)
**CI Status:** 461 of 468 checks passed

---

## What This Means

### Immediate Impact
- ML-KEM `DecapsulationKey` can now be serialized and deserialized
- Enables persistent storage of ML-KEM private keys
- Exposes existing C functions: `EVP_PKEY_kem_new_raw_secret_key` and related serialization functions

### For LatticeArc
- **Unblocks:** True hybrid encryption key persistence
- **Tracking Issue:** #16 (ML-KEM DecapsulationKey serialization)
- **Status:** ✅ Can close issue #16 once we verify the functionality

---

## Next Steps

### 1. Wait for aws-lc-rs Release
PR #1029 is merged to `main` but not yet in a published crate version.

**Current version:** 1.15.4
**Expected next version:** 1.16.0 (minor bump for new API)
**Release cadence:** Every 2-5 months (last was Jan 23, 2026)

**Options:**
- **Wait for release** - Conservative, recommended
- **Use git dependency** - Test immediately but adds instability
- **Monitor releases** - Check https://github.com/aws/aws-lc-rs/releases weekly

### 2. Update Our Code When Available

Once aws-lc-rs 1.16.0 is released:

```rust
// Will be possible:
use aws_lc_rs::unstable::kem::{DecapsulationKey, ML_KEM_768};

// Generate key
let dk = DecapsulationKey::generate(&ML_KEM_768)?;

// Serialize (NEW!)
let serialized = dk.key_bytes()?;

// Deserialize (NEW!)
let restored = DecapsulationKey::from_bytes(&ML_KEM_768, &serialized)?;
```

### 3. Update Our Implementation

Files to update once available:
- `arc-primitives/src/kem/ml_kem.rs` - Add serialization support
- `arc-core/src/kem_hybrid.rs` - Update `MlKemDecapsulationKeyPair` to use real serialization
- Tests: Add roundtrip serialization tests

### 4. Close Issue #16

Once verified:
```bash
gh issue close 16 --comment "Resolved by aws-lc-rs PR #1029 (merged Feb 10, 2026). Serialization support available in aws-lc-rs 1.16.0+"
```

---

## Related Work

### Our Other aws-lc-rs PRs

**PR #1034** - "Add deterministic seed-based key generation for ML-DSA"
- **Status:** Open, 4 tasks completed
- **Purpose:** Deterministic ML-DSA keypair generation from seed
- **Tracking Issue:** #17 (ML-DSA migration from fips204 to aws-lc-rs)

**Note:** PR #1034 is for ML-DSA (signatures), separate from #1029 (ML-KEM encryption)

### Commit History Reference

From our memory:
```
9973d0c - Hybrid Encryption Fix (Feb 7, 2026)
  - Added X25519StaticKeyPair (real ECDH)
  - Added MlKemDecapsulationKeyPair (real ML-KEM)
  - Added HybridSecretKey (both keys)
  - Added encrypt_true_hybrid() / decrypt_true_hybrid()
```

**Note:** Our current implementation can do encapsulation/decapsulation but NOT serialization. Once aws-lc-rs 1.16.0 is released, we can add persistent key storage.

---

## Timeline Estimate

| Event | Date | Status |
|-------|------|--------|
| PR #1029 merged | Feb 10, 2026 | ✅ DONE |
| aws-lc-rs 1.16.0 release | **Est: Mar-Jun 2026** | ⏳ Waiting |
| Update our code | Within 1 week of release | 📋 Planned |
| Close issue #16 | After verification | 📋 Planned |

**Release cadence reference:**
- v1.15.4: Jan 23, 2026
- v1.15.0: ~2 weeks prior
- v1.14.0: ~2-3 months prior

Based on this pattern, 1.16.0 could arrive anywhere from March to June 2026.

---

## Monitoring Plan

### Weekly Check (Every Monday)
```bash
# Check for new aws-lc-rs releases
gh release list --repo aws/aws-lc-rs --limit 5

# Or check crates.io
cargo search aws-lc-rs
```

### Automated Option
Set up dependabot to notify us:
- Dependabot already configured for weekly Rust dependency checks
- Will automatically create PR when aws-lc-rs 1.16.0 is published

---

## Documentation Updates

### Already Documented
- ✅ Memory (MEMORY.md): PR #1028/#1029 tracking
- ✅ GitHub Issue #16: Tracking ML-KEM serialization
- ✅ Commit messages: Reference aws-lc-rs limitations

### To Update When Released
- [ ] CLAUDE.md: Update aws-lc-rs section
- [ ] MEMORY.md: Mark #1029 as resolved, update version
- [ ] Issue #16: Close with resolution comment
- [ ] Upgrade guide: Document migration from workaround to native API

---

**Signed:** LatticeArc Dev Team <Dev@LatticeArc.com>
**Date:** February 11, 2026
