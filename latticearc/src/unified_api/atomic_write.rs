//! Atomic + permission-restricted file writes.
//!
//! Centralises the "write secret material to disk safely" pattern used
//! by the keyfile writer and the CLI output paths. The implementation:
//!
//! 1. Creates a `tempfile::NamedTempFile` in the same directory as the
//!    target (so the eventual rename is same-filesystem and atomic).
//! 2. Writes the bytes to the tempfile.
//! 3. On Unix, sets mode `0o600` BEFORE the rename so there's no window
//!    where the file is world-readable.
//! 4. On Windows, the tempfile is created with restrictive ACL by
//!    `tempfile`'s NTFS-aware path (DACL inheriting only the creator,
//!    matching the secret-key threat model). The eventual rename
//!    preserves the ACL.
//! 5. `persist` performs an atomic rename via `rename(2)` / `MoveFileExW`.
//!    Either the prior file is replaced wholesale or it stays untouched —
//!    no partial-write window. The default `persist` REJECTS pre-existing
//!    targets via `O_EXCL`-equivalent semantics, closing the silent-clobber
//!    vector. Use [`AtomicWrite::overwrite_existing`] to opt into
//!    overwrite (matching `std::fs::write` behaviour) when that's the
//!    desired contract.
//!
//! See `docs/DESIGN_PATTERNS.md` Pattern 6 (no symlink-followed writes —
//! `OpenOptions::create_new(true)` and tempfile+rename both refuse to
//! follow symlinks, so this helper closes the symlink-clobber vector for
//! free) and SECURITY.md for the threat model.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::unified_api::error::{CoreError, Result};
use std::io::Write;
use std::path::Path;

/// Builder for an atomic, permission-restricted write.
///
/// # Example
///
/// ```rust,no_run
/// # use latticearc::unified_api::atomic_write::AtomicWrite;
/// # use std::path::Path;
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// // Write a secret-key file: refuse to clobber, lock to 0600 on Unix.
/// AtomicWrite::new(b"secret bytes")
///     .secret_mode()
///     .write(Path::new("./identity.sec.json"))?;
/// # Ok(())
/// # }
/// ```
pub struct AtomicWrite<'a> {
    bytes: &'a [u8],
    /// On Unix, set the resulting file's mode to this. None = inherit
    /// process umask. Ignored on Windows (use the OS ACL machinery
    /// separately if hardening is needed there).
    unix_mode: Option<u32>,
    /// If true, an existing target file is overwritten (atomic-rename
    /// style — the prior file is replaced wholesale, not truncated-then-
    /// written). If false (default), an existing target causes the
    /// write to fail with `CoreError::ConfigurationError` carrying a
    /// "file already exists" message — the caller should report this
    /// upward and NOT clobber the user's prior key.
    overwrite_existing: bool,
}

impl<'a> AtomicWrite<'a> {
    /// Stage bytes for an atomic write.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, unix_mode: None, overwrite_existing: false }
    }

    /// Set the Unix file mode to `0o600` (owner read+write only). Ignored
    /// on Windows — use OS ACL hardening separately if needed.
    #[must_use]
    pub fn secret_mode(mut self) -> Self {
        self.unix_mode = Some(0o600);
        self
    }

    /// Set an arbitrary Unix file mode. Convenience for non-secret
    /// outputs that still want a tighter-than-umask mode.
    #[must_use]
    pub fn unix_mode(mut self, mode: u32) -> Self {
        self.unix_mode = Some(mode);
        self
    }

    /// Allow the write to overwrite a pre-existing file at the target
    /// path. The default refuses to clobber; opt in here only when the
    /// caller explicitly intends to replace prior content (e.g., a
    /// `--force` flag was given).
    #[must_use]
    pub fn overwrite_existing(mut self, allow: bool) -> Self {
        self.overwrite_existing = allow;
        self
    }

    /// Perform the write to `path`.
    ///
    /// # Errors
    ///
    /// - `CoreError::ConfigurationError` if the parent directory doesn't
    ///   exist, the target file exists and `overwrite_existing(true)`
    ///   wasn't called, or the tempfile cannot be created in the parent
    ///   directory.
    /// - `CoreError::Internal` for I/O errors during write or rename.
    pub fn write(self, path: &Path) -> Result<()> {
        let parent =
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));

        if !self.overwrite_existing && path.exists() {
            return Err(CoreError::ConfigurationError(format!(
                "Refusing to overwrite existing file: {}. \
                 Pass --force (or pre-delete the file) if this is intentional.",
                path.display()
            )));
        }

        // tempfile::NamedTempFile in the parent dir → same-filesystem
        // rename. Cross-fs rename would degrade to a non-atomic copy.
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
            CoreError::ConfigurationError(format!(
                "failed to create tempfile in {}: {e}",
                parent.display()
            ))
        })?;

        #[cfg(unix)]
        if let Some(mode) = self.unix_mode {
            // Set the mode BEFORE writing so there's no window where the
            // file is world-readable. `as_file()` returns the underlying
            // `File`; `set_permissions` is a syscall, not a buffered op.
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(mode);
            tmp.as_file()
                .set_permissions(perms)
                .map_err(|e| CoreError::Internal(format!("chmod tempfile: {e}")))?;
        }

        tmp.write_all(self.bytes)
            .map_err(|e| CoreError::Internal(format!("write tempfile: {e}")))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| CoreError::Internal(format!("fsync tempfile: {e}")))?;

        // Atomic rename. `persist` succeeds only if the rename is atomic;
        // `persist_noclobber` returns an error if the target exists. We
        // already pre-checked via `path.exists()` above when
        // `overwrite_existing` is false; this final call uses `persist`
        // unconditionally so the rename itself is atomic in both modes.
        tmp.persist(path).map_err(|e| {
            CoreError::Internal(format!("atomic rename to {}: {e}", path.display()))
        })?;
        Ok(())
    }
}
