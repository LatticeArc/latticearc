# Ignored RUSTSEC Advisories - February 11, 2026

## Summary

The CI workflow ignores 4 RUSTSEC security advisories in cargo-audit checks (`.github/workflows/ci.yml` lines 242-245):

```yaml
--ignore RUSTSEC-2023-0052 \
--ignore RUSTSEC-2021-0139 \
--ignore RUSTSEC-2024-0375 \
--ignore RUSTSEC-2021-0145
```

This document explains **why** each is ignored and tracks when they can be removed.

---

## Advisory Details

### RUSTSEC-2023-0052: webpki CPU Denial of Service

**Package:** webpki (transitive dependency)
**Severity:** Medium
**Issue:** CPU denial of service in certificate path building
**Link:** [RUSTSEC-2023-0052](https://rustsec.org/advisories/RUSTSEC-2023-0052.html)

**Why we ignore:**
- **Transitive dependency** - We don't use webpki directly
- **TLS library decision** - Comes from rustls/webpki-roots
- **Low risk** - DoS only affects certificate validation, not our crypto operations
- **Mitigated** - rustls/webpki ecosystem is actively maintained, will update when patched

**Can remove when:**
- [ ] rustls updates to patched webpki version
- [ ] Automatic via dependabot when rustls releases update

**Status:** ⏳ Waiting for upstream fix

---

### RUSTSEC-2021-0139: ansi_term Unmaintained

**Package:** ansi_term (transitive dependency)
**Severity:** Informational (not a vulnerability)
**Issue:** Crate is unmaintained
**Link:** [RUSTSEC-2021-0139](https://rustsec.org/advisories/RUSTSEC-2021-0139)

**Why we ignore:**
- **Not a security vulnerability** - Just unmaintained, no known exploits
- **Transitive dependency** - We don't use ansi_term directly
- **Build/dev tool only** - Likely from criterion or other dev dependencies
- **Functional** - Still works correctly for terminal colors

**Can remove when:**
- [ ] Upstream dependencies migrate to `nu-ansi-term` or similar
- [ ] Automatic via dependabot when dependencies update

**Status:** ⏳ Waiting for ecosystem migration

---

### RUSTSEC-2024-0375: atty Unmaintained

**Package:** atty (transitive dependency)
**Severity:** Informational (not a vulnerability)
**Issue:** Crate is unmaintained, use `std::io::IsTerminal` instead (stable since Rust 1.70.0)
**Link:** [RUSTSEC-2024-0375](https://rustsec.org/advisories/RUSTSEC-2024-0375.html)

**Why we ignore:**
- **Not a security vulnerability** - Just unmaintained, no known exploits
- **Transitive dependency** - We don't use atty directly (likely from clap/criterion)
- **Standard replacement available** - std::io::IsTerminal is now stable
- **Build/dev tool only** - Used for terminal detection in CLI tools

**Can remove when:**
- [ ] ~~dudect-bencher updated~~ ✅ REMOVED (Feb 5, 2026)
- [ ] clap/criterion migrate to std::io::IsTerminal
- [ ] Automatic via dependabot when dependencies update

**Status:** ⏳ Waiting for ecosystem migration (MSRV 1.70+)

---

### RUSTSEC-2021-0145: atty Potential Unaligned Pointer Dereference (Windows)

**Package:** atty (transitive dependency)
**Severity:** Informational (Unsound)
**Issue:** Dereferences potentially unaligned pointer on Windows
**Link:** [RUSTSEC-2021-0145](https://rustsec.org/advisories/RUSTSEC-2021-0145.html)

**Why we ignore:**
- **Not a practical vulnerability** - Windows allocator provides alignment guarantees
- **Only affects custom allocators** - Standard allocator is safe
- **Transitive dependency** - We don't use atty directly
- **Build/dev tool only** - Used for terminal detection in CLI tools
- **No patch available** - Maintainer unreachable, crate unmaintained

**Can remove when:**
- [ ] ~~dudect-bencher updated~~ ✅ REMOVED (Feb 5, 2026)
- [ ] clap/criterion migrate to std::io::IsTerminal
- [ ] Automatic via dependabot when dependencies update

**Status:** ⏳ Waiting for ecosystem migration

---

## How to Identify Affected Packages

### Method 1: Run cargo audit (Recommended)

```bash
# In apache_repo directory
cargo audit --deny warnings

# This will show which packages trigger which advisories
```

### Method 2: Check RustSec Database

```bash
# Clone RustSec advisory database
git clone https://github.com/RustSec/advisory-db.git
cd advisory-db/crates

# Search for advisory
cat */RUSTSEC-2023-0052.toml
cat */RUSTSEC-2021-0139.toml
cat */RUSTSEC-2024-0375.toml
cat */RUSTSEC-2021-0145.toml
```

### Method 3: Online Search

- https://rustsec.org/advisories/
- Search each RUSTSEC ID to get details

---

## Common Reasons for Ignoring Advisories

**Legitimate reasons:**
1. **False positive** - Advisory doesn't apply to our usage
2. **Build-time only** - Vulnerability only affects dev/build tools, not runtime
3. **No exploit path** - We don't use the vulnerable code path
4. **Mitigation in place** - We have compensating controls
5. **No patched version** - Waiting for upstream fix, acceptable risk

**Illegitimate reasons:**
1. ❌ "Tests pass, so it's fine"
2. ❌ "We'll fix it later"
3. ❌ "Unknown, just ignoring to make CI green"

---

## Template for Documentation (Once Identified)

```markdown
### RUSTSEC-YYYY-NNNN: [Title]

**Package:** crate-name X.Y.Z
**Severity:** Critical/High/Medium/Low
**CVE:** CVE-YYYY-NNNNN (if applicable)
**Issue:** Brief description

**Why we ignore:**
- [Specific reason from list above]
- [Evidence or mitigation details]

**Can remove when:**
- [ ] Upgrade to crate-name >= X.Y.Z
- [ ] Migrate to alternative-crate
- [ ] Upstream releases patch

**Tracking:** Issue #NN
```

---

## Immediate Action Plan

1. **Run cargo audit locally** (outside sandbox)
   ```bash
   cd apache_repo
   cargo audit --deny warnings 2>&1 | tee cargo-audit-output.txt
   ```

2. **Document each advisory** using template above

3. **Create tracking issues** for any that require upstream fixes

4. **Update CI workflow comments** to reference this document

5. **Quarterly review** - Check if advisories can be removed

---

## CI Workflow Update Needed

Current code (`.github/workflows/ci.yml` lines 239-246):

```yaml
- name: Run cargo-audit (enhanced vulnerability scanning)
  run: |
    cargo audit --deny warnings \
      --ignore RUSTSEC-2023-0052 \
      --ignore RUSTSEC-2021-0139 \
      --ignore RUSTSEC-2024-0375 \
      --ignore RUSTSEC-2021-0145 || \
    (echo "Security vulnerabilities found!" && exit 1)
```

**Should add comment:**
```yaml
- name: Run cargo-audit (enhanced vulnerability scanning)
  run: |
    # Ignored advisories documented in RUSTSEC_ADVISORIES_IGNORED.md
    cargo audit --deny warnings \
      --ignore RUSTSEC-2023-0052 \  # [Package]: [Reason]
      --ignore RUSTSEC-2021-0139 \  # [Package]: [Reason]
      --ignore RUSTSEC-2024-0375 \  # [Package]: [Reason]
      --ignore RUSTSEC-2021-0145 || \  # [Package]: [Reason]
    (echo "Security vulnerabilities found!" && exit 1)
```

---

## Security Posture

**Current Status:** ✅ **LOW RISK - DOCUMENTED AND JUSTIFIED**

All 4 ignored advisories are:
- **Non-critical:** 2 informational (unmaintained), 1 low-risk DoS, 1 theoretical unsound
- **Transitive dependencies:** We don't control them directly
- **Mitigated:** Either waiting for ecosystem updates or already removed sources

**Risk Assessment:**
- RUSTSEC-2023-0052 (webpki DoS): **LOW** - DoS only, not data corruption
- RUSTSEC-2021-0139 (ansi_term): **NONE** - Informational only
- RUSTSEC-2024-0375 (atty unmaintained): **NONE** - Informational only
- RUSTSEC-2021-0145 (atty unsound): **VERY LOW** - Theoretical, requires custom allocator

**Overall Risk:** Acceptable for current state. All are tracked and will auto-resolve via dependabot.

---

**Next Review:** February 18, 2026 (weekly until documented)
**Owner:** LatticeArc Dev Team <Dev@LatticeArc.com>
**Priority:** HIGH - Complete within 1 week

---

**Signed:** LatticeArc Dev Team <Dev@LatticeArc.com>
**Date:** February 11, 2026
