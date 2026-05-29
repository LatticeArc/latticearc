# Module Pattern Registries

Per-module canonical entry points and forbidden alternatives. Prose
patterns in [`DESIGN_PATTERNS.md`](DESIGN_PATTERNS.md) are inherently
unenforced — the compiler does not check them, and reviewers reading
surrounding code see whatever examples already exist (which may be the
un-canonical ones). This file co-locates the registry with module
documentation so contributors see "MUST USE / NEVER USE" before they
`git add`.

Mechanical enforcement of the patterns below lives in:

- [`clippy.toml`](../clippy.toml) — workspace-level `disallowed_methods` /
  `disallowed_types`. Limited to patterns that are *always* wrong because
  clippy lints are global, not module-scoped.
- [`.github/workflows/lint-extras.yml`](../.github/workflows/lint-extras.yml)
  — CI grep rules for context-specific bans (e.g. "raw `OpenOptions::open`
  is forbidden in `audit.rs`"). Anything `clippy.toml` cannot express
  belongs here.

## When to add a registry entry

Every audit finding that is an **asymmetry** (helper exists, parallel
non-helper path doesn't use it) goes here. Concrete trigger: if
the audit-response commit body says "X bypasses Y," then this file gets
a "MUST USE Y / NEVER USE X" line, and the lint-extras grep rule is
added simultaneously.

---

## `latticearc::unified_api::audit`

Source: [`latticearc/src/unified_api/audit.rs`](../latticearc/src/unified_api/audit.rs)

### MUST USE

| For | Use this | Reason |
|-----|----------|--------|
| Adding metadata to an `AuditEvent` | `AuditEvent::with_metadata(k, v)` or `AuditEventBuilder::metadata(k, v)` (which routes through `with_metadata`) | Enforces `MAX_METADATA_ENTRIES`, `MAX_METADATA_KEY_LEN`, `MAX_METADATA_VALUE_LEN`. Bypassing these via raw `HashMap::insert` is a DoS-amplification path. |
| Creating an audit-log file | `OpenOptions::new().create(true).append(true).mode(0o600).open(...)` on Unix | Audit logs may contain operation context (key IDs, paths, actors). World-readable audit logs leak metadata to other users on the host. |
| Computing the integrity hash of an event | `compute_integrity_hash(event, previous_hash)` with the length-prefixed format via `append_lenp_field` | Prefix-collision attacks (`"ab"+"c"` vs `"a"+"bc"`) become impossible — do not re-introduce undelimited concatenation. |

### NEVER USE

| Anti-pattern | Alternative |
|--------------|-------------|
| `event.metadata.insert(k, v)` directly | `event.with_metadata(k, v)` or builder `.metadata(k, v)` |
| Bare `OpenOptions::new().create(true).append(true).open(path)` for audit files | Add `.mode(0o600)` on Unix |
| Hashing audit fields with raw `extend_from_slice` (no length prefix) | `Self::append_lenp_field(&mut buf, bytes)` |

---

## `latticearc::unified_api::atomic_write`

Source: [`latticearc/src/unified_api/atomic_write.rs`](../latticearc/src/unified_api/atomic_write.rs)

### MUST USE

| For | Use this | Reason |
|-----|----------|--------|
| Writing a file that holds key material or audit data | `AtomicWrite::new(bytes).secret_mode().write(path)` | `secret_mode()` sets 0o600 atomically before the rename, closing the world-readable window the bare `std::fs::write` path leaves. |
| Writing any file that should not be clobbered | `AtomicWrite::new(...).write(path)` (default refuses to clobber) | Uses `persist_noclobber` (`link(2) + unlink(2)`) so the exclusive-create check is a single syscall, not TOCTOU. |
| Writing any file at all | `AtomicWrite` (parent-directory fsync is built in) | Closes the rename-durability gap on ext4/XFS `data=ordered` after a power-loss event. |

### NEVER USE

| Anti-pattern | Alternative |
|--------------|-------------|
| `std::fs::write(path, bytes)` for secret material | `AtomicWrite::new(bytes).secret_mode().write(path)` |
| `std::fs::rename(tmp, target)` to commit a temp file | `AtomicWrite::write` (handles overwrite vs noclobber correctly) |

---

## `latticearc::primitives::security`

Source: [`latticearc/src/primitives/security.rs`](../latticearc/src/primitives/security.rs)

### MUST USE

| For | Use this | Reason |
|-----|----------|--------|
| Owning secret bytes long-term | `SecretVec` (heap) or `SecretBytes<N>` (stack, fixed size) | `ZeroizeOnDrop`, manual `Debug` redaction, no `PartialEq` derive. |
| Transient secret bytes (function-local) | `Zeroizing<Vec<u8>>` or `Zeroizing<String>` | Drop wipes contents. Use this for derived KDF output, decrypted plaintext etc. |
| Generating secret-grade random bytes | `generate_secure_random_bytes(len)` returning `Zeroizing<Vec<u8>>` | Forces caller to handle as secret material. |

### NEVER USE

| Anti-pattern | Why | Alternative |
|--------------|-----|-------------|
| Returning secret-derived bytes as `Vec<u8>` | Heap copy drops without zeroize | `Zeroizing<Vec<u8>>` |
| `expose_secret().to_vec()` | Escapes the `Zeroizing` wrapper | Borrow via `as_slice()` / `expose_secret()` if read-only; if owned copy is genuinely needed, wrap immediately with `Zeroizing::new(...)` |
| `MemoryPool::deallocate(buf)` then expecting buffer reuse on next allocate | The pool does not reuse buffers (cross-holder secret-leak risk); deallocate drops, allocate always allocates fresh | If reuse matters for performance, refactor to keep the buffer alive |

---

## `latticearc::unified_api::zero_trust`

Source: [`latticearc/src/unified_api/zero_trust.rs`](../latticearc/src/unified_api/zero_trust.rs)

### MUST USE

| For | Use this | Reason |
|-----|----------|--------|
| Verifying a session before consuming a challenge | `ZeroTrustAuth::verify_challenge_age(&challenge)?` BEFORE `verify_response` | Captured challenge-response pairs replay indefinitely without an age check. |
| Establishing a verified session | `VerifiedSession::establish(public_key, private_key)` | Self-authentication path — includes the age check by construction. |

### NEVER USE

| Anti-pattern | Alternative |
|--------------|-------------|
| Calling `auth.verify_response(proof)` on a challenge that hasn't been age-checked | Always pair with `verify_challenge_age` first |
| Constructing a `Challenge` directly with arbitrary `timestamp` for non-test code | Use `auth.create_challenge()` so timestamp is `Utc::now()` |

---

## `latticearc-cli::commands` (CLI command modules)

Source: [`latticearc-cli/src/commands/`](../latticearc-cli/src/commands/)

### MUST USE

| For | Use this | Reason |
|-----|----------|--------|
| Reading any file path from CLI args | `super::common::read_file_or_stdin(path, limit_bytes, op_name)` OR `enforce_input_size_limit(path, limit, op)` before `std::fs::read` | Prevents OOM on multi-gig inputs. Bare `std::fs::read(path)` has no upper bound. |
| Reading a password / passphrase | `--input-stdin` (preferred) or `LATTICEARC_KDF_INPUT` env | argv-passed secrets leak to `ps`, `/proc/<pid>/cmdline`, shell history. |
| Printing decrypted plaintext as hex | `print!("{}", Zeroizing::new(hex::encode(data)))` | Plain `String` from `hex::encode` lingers on the heap until allocator reclaim. |
| Bounding KDF output length | Cap at `CLI_MAX_KDF_OUTPUT_LEN` (8192 bytes) | PBKDF2 has no algorithmic ceiling — bare `--length 1<<30` is self-DoS. |

### NEVER USE

| Anti-pattern | Why | Alternative |
|--------------|-----|-------------|
| `std::fs::read_to_string(&path)` without prior size guard | OOM on multi-gig file | `enforce_input_size_limit` first, then read |
| `--input <password>` with `--algorithm pbkdf2` and no `--allow-argv-secret` | Password visible to `ps` | Use `--input-stdin` or `LATTICEARC_KDF_INPUT`. `--allow-argv-secret` for KAT replay only AND requires `LATTICEARC_ALLOW_UNSAFE_CLI=1` in the environment as a second-factor opt-in (the env-gate stops shell-completion or copy-paste from a doc example silently re-enabling the escape hatch in production). |
| `echo $PASS \| latticearc-cli kdf --input-stdin` in docs/examples | Writes the password line to `.bash_history` | `read -rs PASS && printf '%s' "$PASS" \| latticearc-cli kdf --input-stdin` |
| Hex-encoding decrypted data via `print!("{}", hex::encode(data))` directly | `String` is not zeroized | `let s = Zeroizing::new(hex::encode(data)); print!("{}", s.as_str())` |

---

## Maintaining this file

When adding a new helper to a module:

1. Add it to the **MUST USE** column of the relevant section.
2. Add the corresponding raw-API anti-pattern to **NEVER USE**.
3. Add a CI grep rule in
   [`.github/workflows/lint-extras.yml`](../.github/workflows/lint-extras.yml)
   that fails the build if the anti-pattern appears in the relevant
   module path.
4. Sweep all existing call sites in the module to use the new helper.
   A typical missed-sweep failure mode looks like this: a helper
   (`with_metadata`, `secret_mode`, `verify_challenge_age`, …) is added
   to wrap an unsafe pattern, but the existing call sites that already
   used the unsafe pattern keep using it — the helper just gives new
   code somewhere safe to land. The lint-extras grep rule from step 3
   catches that.

The point of this file is that step 4 cannot be silently skipped.
