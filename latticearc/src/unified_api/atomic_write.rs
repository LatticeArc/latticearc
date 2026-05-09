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
    /// process umask. Set by [`AtomicWrite::secret_mode`] to `0o600`.
    unix_mode: Option<u32>,
    /// On Windows, replace the post-rename file's DACL with the
    /// workspace owner-only policy. Set by
    /// [`AtomicWrite::secret_mode`]. The Unix counterpart is
    /// `unix_mode = Some(0o600)`; both are populated by `secret_mode`
    /// so callers don't have to remember a cross-platform pair.
    harden_windows_acl: bool,
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
        Self { bytes, unix_mode: None, harden_windows_acl: false, overwrite_existing: false }
    }

    /// Convenience for the most common case: write secret bytes to
    /// `path` with mode `0o600`, refusing to clobber. Equivalent to
    /// `AtomicWrite::new(bytes).secret_mode().write(path)`.
    ///
    /// # Errors
    ///
    /// Same as [`write`](Self::write).
    pub fn write_secret(bytes: &[u8], path: &Path) -> Result<()> {
        AtomicWrite::new(bytes).secret_mode().write(path)
    }

    /// Convenience for "overwrite an existing file atomically" — used
    /// for non-secret CLI output (encrypted blobs, signatures) where
    /// the user reasonably expects re-running the command to replace
    /// prior output. Mode left at process umask.
    ///
    /// # Errors
    ///
    /// Same as [`write`](Self::write).
    pub fn write_overwrite(bytes: &[u8], path: &Path) -> Result<()> {
        AtomicWrite::new(bytes).overwrite_existing(true).write(path)
    }

    /// Mark this write as a secret-bearing file.
    ///
    /// On Unix this sets the mode to `0o600` (owner read+write only)
    /// atomically before any bytes are written — the file is never
    /// world-readable, even briefly.
    ///
    /// On Windows this sets `harden_windows_acl = true`; after the
    /// rename completes, [`set_local_admin_dacl`] replaces the file's
    /// inherited DACL with the workspace's owner-only policy. The
    /// rename target inherits the parent directory's ACL on creation,
    /// which on a default user profile typically grants `Users:Read`
    /// — without this hardening every secret key file would lose its
    /// confidentiality protection on Windows.
    #[must_use]
    pub fn secret_mode(mut self) -> Self {
        self.unix_mode = Some(0o600);
        self.harden_windows_acl = true;
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

        // Windows DACL hardening — apply BEFORE the atomic rename so
        // there's no window where the post-rename file at `path`
        // exists with the parent dir's permissive default DACL (round-
        // 39 H2 race). NTFS object security descriptors travel with
        // the inode/MFT entry, so a same-volume rename is just a
        // directory-entry update — the hardened DACL we apply to the
        // tempfile here persists across `tmp.persist()` to the final
        // path. A failure here is fatal: silently leaving the secret-
        // key file world-readable is worse than failing the write.
        if self.harden_windows_acl
            && let Err(e) = crate::unified_api::set_local_admin_dacl(tmp.path())
        {
            // Best-effort secret-bytes scrub before `tmp` drops and
            // unlinks. The plaintext bytes were already written above;
            // if we return the error directly, NamedTempFile's drop
            // just unlinks — which on NTFS releases cluster runs
            // without zeroizing them, leaving the secret recoverable
            // from raw disk until those clusters get reallocated.
            //
            // Sequence:
            //   1. seek-to-start (MUST succeed — see below)
            //   2. write zeros for the active length (NTFS resident-
            //      data files <~700 B are truly zeroed; for cluster-
            //      resident files the currently-mapped clusters are
            //      zeroed before release)
            //   3. sync_all so the zeros hit disk before truncate
            //   4. set_len(0) releases the now-zeroed clusters
            //
            // Steps 2-4 are best-effort (`let _ =`) — if zero-write or
            // sync fails partway, the active clusters still hold a mix
            // of zeros and original bytes, which is strictly better
            // than the no-scrub baseline. Only the seek MUST succeed:
            // without rewinding, write_all would APPEND zeros after the
            // already-written secret bytes (extending the file from N
            // to 2N), then `set_len(0)` would release the original N
            // bytes of plaintext to the free-cluster pool. That is
            // worse than returning early without scrubbing — a silent
            // failure that claims to scrub. So a seek failure aborts
            // the scrub and surfaces in the returned error.
            use std::io::{Seek, SeekFrom, Write};
            const ZERO_CHUNK: [u8; 4096] = [0u8; 4096];
            let f = tmp.as_file_mut();
            if let Err(seek_err) = f.seek(SeekFrom::Start(0)) {
                // Don't fall through to write_all + set_len(0) — that
                // would propagate the secret without zeroing it. tmp's
                // drop still unlinks, releasing the original clusters
                // un-scrubbed; surface the seek failure with the
                // *parent dir* (so the operator can decide whether to
                // wipe the volume's free-cluster pool) but NOT the
                // tempfile's full path — the per-file path is a
                // forensic-recovery oracle for whatever consumes
                // `CoreError::Internal` (tracing aggregators, error-
                // reporting sinks). The path itself isn't secret, but
                // it points to the file that just had plaintext
                // secrets written into it.
                return Err(CoreError::Internal(format!(
                    "windows DACL hardening on tempfile in {} failed: {e}; \
                     plaintext-scrub aborted because seek-to-start failed: {seek_err}",
                    parent.display()
                )));
            }
            let mut remaining = self.bytes.len();
            while remaining > 0 {
                let n = remaining.min(ZERO_CHUNK.len());
                #[expect(
                    clippy::indexing_slicing,
                    reason = "indexing into a slice whose length is known at this site"
                )]
                // SAFETY: `n = remaining.min(ZERO_CHUNK.len())`
                // ⇒ `n ≤ ZERO_CHUNK.len()` ⇒ `&ZERO_CHUNK[..n]` is
                // in-bounds. (no possible panic)
                let chunk = &ZERO_CHUNK[..n];
                if f.write_all(chunk).is_err() {
                    break;
                }
                remaining = remaining.saturating_sub(n);
            }
            let _ = f.sync_all();
            let _ = f.set_len(0);
            return Err(CoreError::Internal(format!(
                "windows DACL hardening on tempfile in {} failed: {e}",
                parent.display()
            )));
        }

        // Atomic rename — the choice between `persist` and `persist_noclobber`
        // is the difference between "atomic but clobber-OK" and "atomic AND
        // refuse to clobber via link(2)+unlink(2)". The earlier shape used
        // `path.exists()` + `persist`, which had a TOCTOU window: another
        // process could create `path` between the check and the rename and
        // get silently overwritten. `persist_noclobber` collapses both
        // into a single syscall, so the exclusive-create guarantee is real,
        // not best-effort.
        if self.overwrite_existing {
            tmp.persist(path).map_err(|e| {
                CoreError::Internal(format!("atomic rename to {}: {e}", path.display()))
            })?;
        } else {
            tmp.persist_noclobber(path).map_err(|e| {
                // tempfile's `PersistError` carries the source io::Error;
                // surface AlreadyExists as the user-facing
                // ConfigurationError ("refusing to overwrite") and wrap any
                // other I/O failure as Internal.
                if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                    CoreError::ConfigurationError(format!(
                        "Refusing to overwrite existing file: {}. \
                         Pass --force (or pre-delete the file) if this is intentional.",
                        path.display()
                    ))
                } else {
                    CoreError::Internal(format!("atomic rename to {}: {e}", path.display()))
                }
            })?;
        }

        // fsync the parent directory so the rename is durable across a
        // power-loss event. Without this step, on ext4/XFS with the
        // default `data=ordered` the directory entry can be flushed after
        // the file inode but before the rename, leaving the file
        // unrecoverable. Best-effort on non-Unix platforms (Windows
        // doesn't expose a parent-fsync primitive in the same way).
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        // Windows DACL hardening was applied to the tempfile above,
        // BEFORE persist, so the rename preserves the hardened DACL.
        // No post-rename DACL apply is needed — a post-rename apply
        // would have a race window where the file at `path` exists
        // with the parent dir's permissive default DACL.
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test scaffolding: source-shape regression assertions")]
mod regression_tests {
    //! Source-text regression for the Windows DACL-failure
    //! plaintext-scrub sequence. The current logic at the
    //! `set_local_admin_dacl` failure block calls `seek(SeekFrom::Start(0))`
    //! BEFORE the `write_all(zero)` loop and `set_len(0)` truncate. A
    //! future refactor that reorders seek and write_all would silently
    //! regress the "don't append zeros to plaintext" invariant —
    //! `write_all` from the current cursor position would extend the
    //! file from N to 2N bytes, then `set_len(0)` would release the
    //! ORIGINAL N bytes of plaintext to the free-cluster pool.
    //!
    //! This isn't a behavioural test — it's a source-shape assertion
    //! that runs on every `cargo test`. The cost is one `include_str!`
    //! and a substring-position comparison. The benefit is a loud
    //! signal if the ordering ever drifts.

    const SRC: &str = include_str!("atomic_write.rs");

    /// The seek-to-start MUST appear before the zero-write loop in the
    /// DACL-failure scrub block. Without this ordering, plaintext is
    /// appended to (not overwritten) before the truncate releases
    /// clusters back to the free pool.
    #[test]
    fn test_dacl_failure_scrub_seeks_before_writing_zeros() {
        // Anchor on the unique block-opening comment so we don't match
        // unrelated `seek(SeekFrom::Start(0))` calls elsewhere.
        let block_anchor = "Best-effort secret-bytes scrub before `tmp` drops and";
        let block_start = SRC.find(block_anchor).expect(
            "scrub-block anchor comment moved or removed — update this test \
             to anchor on the new comment OR review the change for the \
             ordering invariant before adjusting the anchor.",
        );

        let block = &SRC[block_start..];
        let seek_pos = block
            .find("f.seek(SeekFrom::Start(0))")
            .expect("seek-to-start call missing from scrub block");
        let write_pos =
            block.find("f.write_all(chunk)").expect("zero-write loop missing from scrub block");

        assert!(
            seek_pos < write_pos,
            "DACL-scrub ordering regressed: seek(SeekFrom::Start(0)) MUST appear \
             before write_all(chunk) so plaintext is overwritten, not appended. \
             seek_pos={seek_pos}, write_pos={write_pos}"
        );
    }
}
