//! Windows ACL hardening for secret-bearing files and directories.
//!
//! On Unix the crate enforces tight `mode(0o600)` (files) /
//! `mode(0o700)` (directories) atomically at create-time via
//! `OpenOptionsExt` / `DirBuilderExt`. Windows has no equivalent
//! convenience; the caller must replace the file/directory's DACL
//! after creation. This module is the single canonical entry point
//! for that operation, used by:
//!
//! - [`unified_api::audit::FileAuditStorage`] when creating audit logs
//! - [`unified_api::atomic_write::AtomicWrite::secret_mode`] when
//!   persisting secret-key files
//! - `latticearc-cli`'s `keygen` command when creating the output
//!   directory
//!
//! All paths converge on a single SDDL string so the policy is
//! identical across call sites: protected DACL granting full access
//! to **three principals only** — the file owner (current user),
//! Built-in Administrators (`BA`), and `LocalSystem` (`SY`). No
//! inheritance from the parent directory; no entry for `Everyone`,
//! `Users`, or `Authenticated Users`. The function is named
//! [`set_local_admin_dacl`] (not "owner-only") to avoid promising
//! more than the policy delivers — the `BA` entry is necessary so
//! a local administrator can recover the file when the user account
//! is later disabled, matching the posture Windows applies to
//! per-user `%USERPROFILE%` files; the `SY` entry is necessary so
//! VSS / backup services that run as `SYSTEM` can read the file.
//!
//! The implementation is gated on `cfg(windows)`. On non-Windows
//! targets the entry points are present but compile to no-ops so the
//! call sites stay platform-agnostic.

#[cfg(windows)]
use crate::unified_api::error::CoreError;
use crate::unified_api::error::Result;
use std::path::Path;

/// SDDL string applied to secret-bearing files and directories.
///
/// - `D:P`     — protected DACL (no inheritance from parent).
/// - `OICI`    — object-inherit + container-inherit so contents of a
///   directory inherit the same DACL.
/// - `FA`      — file-all rights.
/// - `OW`      — file owner (the current user, who created the file).
/// - `BA`      — Built-in Administrators (so an admin can recover the
///   file even if the user account is later disabled — matches the
///   posture Windows applies to per-user `%USERPROFILE%` files).
/// - `SY`      — `LocalSystem` (so backup / volume-shadow services
///   that run as `SYSTEM` can read the files; without this entry,
///   restic / VSS-based backups silently fail).
///
/// No `Everyone`, no `Users`, no `Authenticated Users` entry. A
/// second non-admin user on the same machine cannot read the file
/// even though the parent directory may grant them traversal.
#[cfg(windows)]
const LOCAL_ADMIN_DACL_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

/// Apply the protected owner+admin+system DACL to a file or
/// directory at `path`. Three principals only (Owner / BA / SY).
///
/// On Windows: replaces the object's DACL with
/// [`LOCAL_ADMIN_DACL_SDDL`] via `SetNamedSecurityInfoW`. The DACL
/// is `protected` so it does not inherit any permissive ACEs from
/// the parent (e.g. a `Users:Read` entry on the user's profile root
/// would otherwise leak into a fresh secret file).
///
/// **Path-based API note:** `SetNamedSecurityInfoW` resolves `path`
/// at call time. Callers that have just created a file via
/// `OpenOptions::create_new(...).open(...)` and then immediately
/// invoke this helper close the TOCTOU window in practice (the
/// kernel inode is already published under the path; the only race
/// is rename-during-call which is fast). For higher-assurance call
/// sites the handle-based `SetSecurityInfo` would be marginally
/// safer; this is documented as a known residual path-API exposure.
///
/// On non-Windows: no-op. Unix call sites set `mode(0o600)` /
/// `mode(0o700)` atomically at create-time; this function is only
/// invoked on the Windows branch.
///
/// # Errors
///
/// Returns [`CoreError::Internal`] when the SDDL fails to parse
/// (programmer error — the constant is fixed) or when
/// `SetNamedSecurityInfoW` rejects the call (typical: target path
/// does not exist, or the calling process lacks `WRITE_DAC`).
#[allow(unused_variables)] // path is unused on non-Windows
pub fn set_local_admin_dacl(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::str::FromStr;
        use windows_permissions::{
            LocalBox, SecurityDescriptor,
            constants::{SeObjectType, SecurityInformation},
            wrappers::SetNamedSecurityInfo,
        };

        // Parse the SDDL constant once per call. The crate caches the
        // parsed object via `LocalBox<SecurityDescriptor>`, which is
        // dropped at the end of this scope; SetNamedSecurityInfoW
        // copies what it needs internally.
        let sd: LocalBox<SecurityDescriptor> =
            LocalBox::<SecurityDescriptor>::from_str(LOCAL_ADMIN_DACL_SDDL).map_err(|e| {
                CoreError::Internal(format!(
                    "win_acl: failed to parse owner-only SDDL ({}): {}",
                    LOCAL_ADMIN_DACL_SDDL, e
                ))
            })?;

        let dacl = sd.dacl().ok_or_else(|| {
            CoreError::Internal(
                "win_acl: parsed SecurityDescriptor had no DACL (SDDL constant is malformed)"
                    .to_string(),
            )
        })?;

        // `Dacl | ProtectedDacl` so the assignment also CLEARS the
        // inheritance bit — without `ProtectedDacl` the new DACL is
        // merged with whatever the parent inherits, which can re-add
        // permissive ACEs.
        SetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
        .map_err(|e| {
            CoreError::Internal(format!(
                "win_acl: SetNamedSecurityInfoW failed for {}: {}",
                path.display(),
                e
            ))
        })?;
    }
    #[cfg(not(windows))]
    {
        // Unix call sites set mode(0o600)/mode(0o700) atomically at
        // create-time. This function is only invoked from the Windows
        // branch of those call sites, so the non-Windows arm is a
        // pure no-op rather than a fallback that could mask a missing
        // mode-call on Unix.
        let _ = path;
    }
    Ok(())
}
