# CII Best Practices Badge Checklist

> **Registration URL**: https://www.bestpractices.dev/
>
> This document tracks LatticeArc's compliance with the [CII Best Practices](https://bestpractices.coreinfrastructure.org/) criteria for the **Passing** level badge.

## Badge Levels

| Level | Criteria | Status |
|-------|----------|--------|
| Passing | 66 criteria | 🔄 In Progress |
| Silver | Additional criteria | ⬜ Not Started |
| Gold | Highest level | ⬜ Not Started |

---

## Passing Level Criteria

### 1. Basics

| Criterion | Requirement | Status | Evidence |
|-----------|-------------|--------|----------|
| **basics_description** | Project has a brief description | ✅ | README.md |
| **basics_website** | Project has a website | ✅ | GitHub repo |
| **basics_repository_public** | Source code is in a public repository | ✅ | GitHub |
| **basics_repository_track** | Repository tracks changes | ✅ | Git |
| **basics_repository_interim** | Allow interim versions for review | ✅ | GitHub PRs |
| **basics_interact** | Contributors can submit suggestions | ✅ | GitHub Issues |
| **basics_contribution** | Has contributing guide | ✅ | CONTRIBUTING.md |
| **basics_contribution_requirements** | States contribution requirements | ✅ | CONTRIBUTING.md |
| **license_declared** | Has OSI-approved license | ✅ | Apache-2.0 |
| **license_location** | License in standard location | ✅ | LICENSE file |
| **license_recommended** | License is common | ✅ | Apache-2.0 |

### 2. Change Control

| Criterion | Requirement | Status | Evidence |
|-----------|-------------|--------|----------|
| **version_unique** | Unique version numbering | ✅ | Cargo.toml, git tags |
| **version_semver** | Uses semantic versioning | ✅ | v1.0.0 format |
| **version_tags** | Tagged releases | ✅ | GitHub releases |
| **change_log** | Human-readable changelog | ✅ | CHANGELOG.md |
| **change_log_vulns** | Changelog notes security fixes | ✅ | CHANGELOG.md |

### 3. Reporting

| Criterion | Requirement | Status | Evidence |
|-----------|-------------|--------|----------|
| **report_url** | URL for reporting bugs | ✅ | GitHub Issues |
| **report_archive** | Reports are archived | ✅ | GitHub Issues |
| **report_tracker** | Bug tracker is public | ✅ | GitHub Issues |
| **report_process** | Bug handling process documented | ✅ | CONTRIBUTING.md |
| **report_responses** | Reports get responses | ✅ | GitHub Issues |
| **enhancement_responses** | Enhancement requests get responses | ✅ | GitHub Issues |
| **report_tracker_public** | Public bug tracker | ✅ | GitHub Issues |

### 4. Quality

| Criterion | Requirement | Status | Evidence |
|-----------|-------------|--------|----------|
| **build** | Working build system | ✅ | Cargo |
| **build_common** | Common tools can build | ✅ | cargo build |
| **build_floss** | FLOSS tools can build | ✅ | Rust toolchain |
| **build_oss** | Build with OSS tools | ✅ | Cargo |
| **installation_common** | Standard install process | ✅ | cargo install |
| **installation_automated** | Automated install | ✅ | cargo install |
| **test** | Test suite exists | ✅ | cargo test |
| **test_invocation** | Standard test invocation | ✅ | cargo test |
| **test_most** | Most tests pass | ✅ | CI passing |
| **test_continuous_integration** | CI/CD system | ✅ | GitHub Actions |
| **test_policy** | Test policy documented | ✅ | CONTRIBUTING.md |
| **tests_documented_added** | New functionality requires tests | ✅ | CONTRIBUTING.md |

### 5. Security

| Criterion | Requirement | Status | Evidence |
|-----------|-------------|--------|----------|
| **vulnerability_report_process** | Security vulnerability reporting | ✅ | SECURITY.md |
| **vulnerability_report_private** | Private vulnerability reporting | ✅ | SECURITY.md |
| **vulnerability_report_response** | Response timeline documented | ✅ | SECURITY.md (24h) |
| **no_leaked_credentials** | No credentials in repo | ✅ | .gitignore, audits |
| **vulnerabilities_critical_fixed** | Critical vulns fixed promptly | ✅ | Policy |
| **vulnerabilities_fixed_60_days** | Vulns fixed in 60 days | ✅ | Policy |
| **security_mechanisms** | Security mechanisms documented | ✅ | SECURITY.md |
| **hardening** | Project hardened | ✅ | Strict lints |
| **input_validation** | Inputs validated | ✅ | arc-validation |
| **crypto_published** | Crypto algorithms published | ✅ | FIPS standards |
| **crypto_floss** | Uses FLOSS crypto | ✅ | Open source deps |
| **crypto_keylength** | Uses adequate key lengths | ✅ | PQC algorithms |
| **crypto_working** | Crypto algorithms work correctly | ✅ | CAVP validation |
| **crypto_pfs** | Perfect forward secrecy | ✅ | Hybrid KEM |
| **crypto_certificate_verification** | Cert verification (if applicable) | ✅ | arc-tls |

### 6. Analysis

| Criterion | Requirement | Status | Evidence |
|-----------|-------------|--------|----------|
| **static_analysis** | Static analysis tools | ✅ | Clippy, cargo-audit |
| **static_analysis_fixed** | Static analysis issues fixed | ✅ | CI enforced |
| **static_analysis_often** | Regular static analysis | ✅ | Every PR |
| **dynamic_analysis** | Dynamic analysis tools | ✅ | Fuzzing |
| **dynamic_analysis_unsafe** | Test for memory-unsafe code | ✅ | Sanitizers, Fuzzing |
| **dynamic_analysis_fixed** | Dynamic issues fixed | ✅ | CI enforced |
| **dynamic_analysis_enable_assertions** | Run with assertions | ✅ | Default in tests |

---

## Implementation Evidence

### Documentation
- [x] README.md - Project description and usage
- [x] CONTRIBUTING.md - Contribution guidelines
- [x] SECURITY.md - Security policy and vulnerability reporting
- [x] LICENSE - Apache 2.0 license
- [x] CHANGELOG.md - Release notes

### Security Infrastructure
- [x] Private vulnerability reporting (GitHub Security Advisories)
- [x] Security email (security@latticearc.com)
- [x] Response timeline: 24h initial, 48h assessment
- [x] No credentials in repository
- [x] Dependency auditing (cargo-audit)
- [x] License compliance (cargo-deny)

### Quality Infrastructure
- [x] Automated testing (cargo test)
- [x] Continuous integration (GitHub Actions)
- [x] Code coverage tracking
- [x] Static analysis (Clippy with strict lints)
- [x] Dynamic analysis (Fuzzing, Sanitizers)

### Cryptographic Compliance
- [x] FIPS 203/204/205/206 compliant algorithms
- [x] Published, well-known algorithms
- [x] CAVP test vector validation
- [x] Wycheproof edge case testing
- [x] Constant-time operations (subtle crate)

---

## CI Workflows Supporting CII Criteria

| Workflow | CII Criteria Supported |
|----------|----------------------|
| `ci.yml` | build, test, static_analysis |
| `security.yml` | vulnerabilities_*, no_leaked_credentials |
| `fuzzing.yml` | dynamic_analysis |
| `sanitizers.yml` | dynamic_analysis_unsafe |
| `coverage.yml` | test_most |
| `scorecard.yml` | Multiple security criteria |
| `codeql.yml` | static_analysis |

---

## Registration Steps

1. Go to https://www.bestpractices.dev/en/projects/new
2. Enter GitHub repository URL
3. Answer questionnaire (most answers can be auto-detected)
4. Provide evidence links for each criterion
5. Submit for review

### Expected Score

Based on the checklist above, LatticeArc should achieve:
- **Passing Level**: ~95%+ criteria met
- **Timeline**: 1-2 weeks to complete registration

---

## Badge Code

Once approved, add to README.md:

```markdown
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/XXXXX/badge)](https://bestpractices.coreinfrastructure.org/projects/XXXXX)
```

---

*Last Updated: 2026-01-29*
