//! Shared orchestration that gates every backend identically. Written once here
//! so a backend only implements `detect` / `is_already_compressed` /
//! `apply_inplace` and inherits all the safety invariants.

use std::path::Path;

use super::{verify, Backend, Error, Outcome, SkipReason};

/// Reached only when the backend reported `Supported`. Fail-soft: a permission,
/// read-only, or busy failure is a `Skipped` Outcome, never a hard `Err`. And if a
/// (broken) backend ever leaves the file no longer loadable, roll back to the
/// pre-apply bytes so a corrupt addon is never stranded.
pub(crate) fn apply_guarded<B: Backend>(backend: &B, path: &Path) -> Result<Outcome, Error> {
    // INV-idempotent.
    if backend.is_already_compressed(path)? {
        return Ok(Outcome::AlreadyCompressed {
            before: verify::on_disk_bytes(path)?,
        });
    }

    let before = verify::on_disk_bytes(path)?;

    // INV-loadable + INV-rollback: keep the FULL pre-apply bytes. A native read decompresses
    // transparently, so reading the file back and comparing it to this snapshot is the
    // authoritative post-apply oracle (NOT vacuous — it is exactly the check the one-pass
    // write path uses, and it catches a deep corruption a 4-byte magic prefix would miss).
    // The snapshot doubles as the rollback source if a broken backend wrecked the file.
    let snapshot = read_snapshot(path)?;

    // INV-fail-soft: EACCES/EPERM/EROFS -> Skipped(PermissionDenied); EBUSY/ETXTBSY
    // -> Skipped(Busy). A genuine, unclassifiable I/O error still propagates.
    if let Err(err) = backend.apply_inplace(path, &snapshot) {
        if let Error::Io { source, .. } = &err {
            if let Some(reason) = classify_skip(source) {
                return Ok(Outcome::Skipped { reason });
            }
        }
        return Err(err);
    }

    verify_loadable_or_restore(backend, path, before, &snapshot)
}

/// Read the whole file for the rollback snapshot. Extracted + `coverage(off)`: a read
/// failing HERE — immediately after `is_already_compressed` and `on_disk_bytes` already
/// opened/stat'd the same file — is a defensive I/O-race arm with no deterministic
/// in-process trigger.
#[cfg_attr(coverage_nightly, coverage(off))]
fn read_snapshot(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|source| Error::Io {
        context: "snapshot",
        source,
    })
}

/// Post-apply gate for the in-place path: read the file back and compare it to the full
/// pre-apply `snapshot`. If the kernel does not hand back byte-identical content the backend
/// broke it (a deep corruption past the 4-byte magic included), so restore the snapshot and
/// report `Skipped(NotLoadable)`; otherwise classify the win. This mirrors the one-pass
/// twin's `readback_matches` oracle. Split out so the not-loadable rollback is unit-testable
/// without a backend that corrupts a file (point it at on-disk bytes that differ from
/// `snapshot`).
fn verify_loadable_or_restore<B: Backend>(
    backend: &B,
    path: &Path,
    before: u64,
    snapshot: &[u8],
) -> Result<Outcome, Error> {
    if !verify::readback_matches(path, snapshot)? {
        restore(path, snapshot)?;
        return Ok(classify_outcome(false, before, before, None));
    }

    // INV-verify: prefer the backend's authoritative signal (btrfs FIEMAP ENCODED —
    // st_blocks reports the logical size there, so a real win is invisible to it).
    // Where the backend has no special signal (APFS/NTFS), fall back to the generic
    // allocated-bytes drop.
    let after = verify::on_disk_bytes(path)?;
    Ok(classify_outcome(
        true,
        before,
        after,
        backend.compressed_on_disk(path)?,
    ))
}

/// Map the post-apply facts to an Outcome. Pure (no I/O) so every branch is unit
/// testable: not loadable → Skipped(NotLoadable); else the backend's compression
/// signal (or, absent one, an allocated-bytes drop) decides Compressed vs NoGain.
fn classify_outcome(loadable: bool, before: u64, after: u64, signal: Option<bool>) -> Outcome {
    if !loadable {
        return Outcome::Skipped {
            reason: SkipReason::NotLoadable,
        };
    }
    if signal.unwrap_or(after < before) {
        Outcome::Compressed { before, after }
    } else {
        Outcome::NoGain { before, after }
    }
}

/// Map a backend I/O failure to a non-fatal `Skipped` reason, or `None` to let it
/// propagate as a hard error. Uses both `ErrorKind` (cross-platform, esp. Windows)
/// and the POSIX errno (stable across Linux/macOS), so it needs no newer-than-1.0
/// `ErrorKind` variants.
fn classify_skip(err: &std::io::Error) -> Option<SkipReason> {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return Some(SkipReason::PermissionDenied);
    }
    classify_errno(err.raw_os_error()?)
}

// Per-platform errno classification. Windows `raw_os_error()` is the Win32 space,
// which does NOT coincide with POSIX (e.g. 32 = SHARING_VIOLATION on Windows but
// EPIPE on unix), so the two maps are mutually exclusive by cfg.
#[cfg(not(windows))]
fn classify_errno(code: i32) -> Option<SkipReason> {
    match code {
        1 | 13 | 30 => Some(SkipReason::PermissionDenied), // EPERM/EACCES/EROFS
        16 | 26 => Some(SkipReason::Busy),                 // EBUSY/ETXTBSY
        27 => Some(SkipReason::TooLarge),                  // EFBIG
        _ => None,
    }
}
#[cfg(windows)]
fn classify_errno(code: i32) -> Option<SkipReason> {
    match code {
        5 | 19 => Some(SkipReason::PermissionDenied), // ACCESS_DENIED / WRITE_PROTECT
        32 | 33 => Some(SkipReason::Busy),            // SHARING_VIOLATION / LOCK_VIOLATION
        _ => None,
    }
}

/// One-pass guarded write of `content` to `path` as an OS-compressed file. Reached
/// only when the backend reported `Supported`. The backend writes the bytes AS the
/// file is created (decmpfs built from `content`, btrfs codec-then-write, NTFS
/// FSCTL-then-write) — no write-then-read-back. Fail-soft mirrors `apply_guarded`:
/// a permission/busy/too-large failure becomes a `Skipped` Outcome and the caller
/// is expected to fall back to a plain write; an unclassifiable I/O error
/// propagates. After a successful apply the kernel read-back is verified
/// byte-identical to `content` (the transparent-compression oracle), and the file
/// is restored to a plain write of `content` if it somehow doesn't match.
pub(crate) fn compress_bytes_guarded<B: Backend>(
    backend: &B,
    path: &Path,
    content: &[u8],
) -> Result<Outcome, Error> {
    if let Err(err) = backend.apply_bytes(path, content, None) {
        if let Error::Io { source, .. } = &err {
            if let Some(reason) = classify_skip(source) {
                return Ok(Outcome::Skipped { reason });
            }
        }
        return Err(err);
    }

    // Oracle: a normal read must hand back the exact bytes we asked to store.
    verify_readback_or_restore(backend, path, content)
}

/// Post-apply oracle for the one-pass path: a normal read must hand back exactly
/// `content`. If the backend produced something that doesn't decode identically,
/// restore a plain write of `content` and report `Skipped(IntegrityRevert)` so an
/// install is never left with a corrupt file; otherwise classify the win. Split
/// out so the mismatch-rollback is unit-testable without a backend that corrupts
/// the read-back (point it at a file whose bytes differ from `content`).
fn verify_readback_or_restore<B: Backend>(
    backend: &B,
    path: &Path,
    content: &[u8],
) -> Result<Outcome, Error> {
    let after = verify::on_disk_bytes(path)?;
    if !verify::readback_matches(path, content)? {
        restore(path, content)?;
        return Ok(Outcome::Skipped {
            reason: SkipReason::IntegrityRevert,
        });
    }

    let before = content.len() as u64;
    Ok(classify_outcome(
        true,
        before,
        after,
        backend.compressed_on_disk(path)?,
    ))
}

/// Atomic restore of the pre-apply bytes (sibling temp + rename). Returns `Err`
/// when the rollback itself fails (e.g. `ENOSPC`, a read-only dir) — the caller
/// MUST surface that as a hard error rather than a benign `Skipped`, else a
/// corrupted file is left on disk while the outcome reads as non-fatal.
fn restore(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| Error::Io {
        context: "rollback restore: path has no parent",
        source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
    })?;
    let name = path.file_name().map_or_else(
        || std::borrow::Cow::Borrowed("addon"),
        |n| n.to_string_lossy(),
    );
    let tmp = unique_tmp(dir, &name);
    // `create_new` (O_EXCL): with the collision-resistant name below, two concurrent
    // rollbacks in the same directory never share a temp and a stale same-pid temp is never
    // silently truncated through — a collision errors instead.
    let wrote = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    wrote.map_err(|source| {
        let _ = std::fs::remove_file(&tmp);
        Error::Io {
            context: "rollback restore",
            source,
        }
    })
}

/// A collision-resistant sibling temp path for the rollback write: PID + wall-clock nanos +
/// a process-local counter, so two concurrent rollbacks in the same directory (or a crashed
/// same-pid run's stale temp) never derive the same name. Paired with `create_new`, a
/// collision errors rather than truncating through. Mirrors the backends' `unique_tmp`
/// discipline (macos.rs / linux.rs / windows.rs), which the PID-only name here did not.
fn unique_tmp(dir: &Path, name: &str) -> std::path::PathBuf {
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(format!(
        ".{name}.decmpfs-restore-{}-{nanos}-{seq}.tmp",
        std::process::id()
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::fscompress::{FakeBackend, Os, Support};

    fn err(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::from(kind)
    }

    #[test]
    fn apply_guarded_propagates_an_unclassifiable_apply_error() {
        // A fake backend reports a compressible FS but its in-place apply fails with an
        // unclassifiable error (ENOENT) — apply_guarded propagates it rather than
        // swallowing it. A real backend reaches this only on a true I/O fault.
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-broken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin");
        std::fs::write(&path, b"\x7fELF readable original").unwrap();
        let backend = FakeBackend {
            detect: Support::Supported,
            apply_errno: Some(2),
            apply_not_found: false,
        };
        let out = apply_guarded(&backend, &path);
        assert!(matches!(out, Err(Error::Io { .. })), "got {out:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_guarded_propagates_a_non_io_error() {
        // A backend whose in-place apply fails with a NON-`Io` error (Error::NotFound)
        // exercises the fall-through past the `if let Error::Io` classifier at L42: the
        // error is neither classified as a skip nor swallowed — apply_guarded returns it
        // verbatim. A real backend reaches this only on a genuine NotFound fault.
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-nonio-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin");
        std::fs::write(&path, b"\x7fELF readable original").unwrap();
        let backend = FakeBackend {
            detect: Support::Supported,
            apply_errno: None,
            apply_not_found: true,
        };
        let out = apply_guarded(&backend, &path);
        assert!(matches!(out, Err(Error::NotFound(_))), "got {out:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compress_bytes_guarded_propagates_a_non_io_error() {
        // The one-pass twin at L146: a non-`Io` apply_bytes failure (Error::NotFound) falls
        // through the skip classifier in compress_bytes_guarded and is returned verbatim,
        // never misreported as a benign Skipped outcome.
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-nonio2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin");
        let backend = FakeBackend {
            detect: Support::Supported,
            apply_errno: None,
            apply_not_found: true,
        };
        let out = compress_bytes_guarded(&backend, &path, b"content bytes");
        assert!(matches!(out, Err(Error::NotFound(_))), "got {out:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn permission_errors_become_skipped() {
        assert_eq!(
            classify_skip(&err(std::io::ErrorKind::PermissionDenied)),
            Some(SkipReason::PermissionDenied)
        );
        for errno in [1, 13, 30] {
            assert_eq!(
                classify_skip(&std::io::Error::from_raw_os_error(errno)),
                Some(SkipReason::PermissionDenied),
                "errno {errno}"
            );
        }
    }

    #[test]
    fn busy_errors_become_skipped() {
        for errno in [16, 26] {
            assert_eq!(
                classify_skip(&std::io::Error::from_raw_os_error(errno)),
                Some(SkipReason::Busy),
                "errno {errno}"
            );
        }
    }

    #[test]
    fn efbig_becomes_too_large() {
        assert_eq!(
            classify_skip(&std::io::Error::from_raw_os_error(27)), // EFBIG
            Some(SkipReason::TooLarge)
        );
    }

    #[test]
    fn classify_outcome_covers_every_branch() {
        use super::Outcome;
        assert!(matches!(
            classify_outcome(false, 100, 50, None),
            Outcome::Skipped {
                reason: SkipReason::NotLoadable
            }
        ));
        // Allocated-bytes fallback (no backend signal).
        assert!(matches!(
            classify_outcome(true, 100, 40, None),
            Outcome::Compressed {
                before: 100,
                after: 40
            }
        ));
        assert!(matches!(
            classify_outcome(true, 100, 100, None),
            Outcome::NoGain { .. }
        ));
        // Backend signal overrides the size comparison both ways.
        assert!(matches!(
            classify_outcome(true, 100, 100, Some(true)),
            Outcome::Compressed { .. }
        ));
        assert!(matches!(
            classify_outcome(true, 100, 40, Some(false)),
            Outcome::NoGain { .. }
        ));
    }

    #[test]
    fn restore_writes_the_snapshot_back() {
        let dir = std::env::temp_dir().join(format!(
            "abitious-fscompress-restore-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        std::fs::write(&path, b"corrupted-by-a-broken-backend").unwrap();
        restore(&path, b"the original loadable bytes").unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"the original loadable bytes"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // A target whose parent directory does not exist: the backend's temp create
    // fails with ENOENT — not a permission/busy/too-large skip — so the guarded
    // one-pass write propagates it as a hard Err rather than swallowing it.
    #[cfg(target_os = "macos")]
    #[test]
    fn compress_bytes_guarded_propagates_an_unclassifiable_error() {
        let out = compress_bytes_guarded(
            &Os,
            std::path::Path::new("/no/such/decmpfs/dir/x.node"),
            b"data",
        );
        assert!(matches!(out, Err(Error::Io { .. })));
    }

    #[test]
    fn compress_bytes_guarded_success_classifies_via_the_backend_signal() {
        // A faked successful apply over a file pre-seeded with `content`: the read-back
        // oracle matches, so the backend's compressed_on_disk signal classifies the win.
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin");
        let content = b"the stored content bytes, pre-seeded";
        std::fs::write(&path, content).unwrap();
        let backend = FakeBackend {
            detect: Support::Supported,
            apply_errno: None,
            apply_not_found: false,
        };
        let out = compress_bytes_guarded(&backend, &path, content).unwrap();
        assert!(matches!(out, Outcome::NoGain { .. }), "got {out:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unrelated_errors_propagate() {
        assert_eq!(classify_skip(&err(std::io::ErrorKind::NotFound)), None);
        assert_eq!(classify_skip(&std::io::Error::from_raw_os_error(2)), None); // ENOENT
    }

    #[test]
    fn restore_errors_when_the_path_has_no_parent() {
        // "/" has no parent → the rollback can't write a sibling temp, so it must
        // surface an Err (a silent no-op would report a corrupt file as benign).
        assert!(restore(std::path::Path::new("/"), b"x").is_err());
    }

    #[test]
    fn not_loadable_result_is_restored_and_skipped() {
        // Drive the in-place rollback without a corrupting backend: the on-disk file differs
        // from the snapshot, so the readback oracle sees "not loadable", restores the
        // snapshot, and reports NotLoadable.
        let dir = std::env::temp_dir().join(format!(
            "abitious-fscompress-notload-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        std::fs::write(&path, b"\x7fELF garbage the backend supposedly produced").unwrap();
        let out = verify_loadable_or_restore(&Os, &path, 100, b"the original bytes").unwrap();
        assert!(matches!(
            out,
            Outcome::Skipped {
                reason: SkipReason::NotLoadable
            }
        ));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"the original bytes",
            "snapshot restored"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn in_place_verify_catches_deep_corruption_past_the_magic() {
        // FINDING #6: the in-place verify used to compare only the 4-byte magic, which a
        // deep corruption LEAVES INTACT. Here the on-disk file shares the snapshot's 4-byte
        // magic but differs at byte 10 — a magic-only check would have PASSED it; the full
        // readback oracle catches it, rolls back, and reports NotLoadable.
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-deep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        let snapshot = b"\x7fELF the original good tail bytes here, all intact.".to_vec();
        let mut corrupt = snapshot.clone();
        corrupt[10] ^= 0xff; // same magic (bytes 0..4), differs deep in the body
        assert_eq!(
            corrupt[..4],
            snapshot[..4],
            "the 4-byte magic still matches"
        );
        std::fs::write(&path, &corrupt).unwrap();
        let out = verify_loadable_or_restore(&Os, &path, 100, &snapshot).unwrap();
        assert!(
            matches!(
                out,
                Outcome::Skipped {
                    reason: SkipReason::NotLoadable
                }
            ),
            "deep corruption past the magic must trip the readback rollback: {out:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            snapshot,
            "the snapshot was restored over the deep corruption"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_back_mismatch_is_restored_and_skipped() {
        // Drive the one-pass oracle rollback: the file on disk differs from the bytes
        // we claim to have stored, so the read-back mismatches, the content is
        // restored, and IntegrityRevert is reported.
        let dir = std::env::temp_dir().join(format!(
            "abitious-fscompress-mismatch-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        std::fs::write(&path, b"what the broken backend actually wrote").unwrap();
        let intended = b"the bytes the caller asked to store";
        let out = verify_readback_or_restore(&Os, &path, intended).unwrap();
        assert!(matches!(
            out,
            Outcome::Skipped {
                reason: SkipReason::IntegrityRevert
            }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), intended, "content restored");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_cleans_up_its_temp_when_the_rename_fails() {
        // Renaming a temp file over an existing DIRECTORY fails → the temp is removed.
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-rr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("a-dir");
        std::fs::create_dir_all(&target).unwrap();
        assert!(
            restore(&target, b"bytes").is_err(),
            "rename-over-dir must Err"
        );
        // The temp name is pid+nanos+seq now, so scan for ANY leftover restore temp.
        let leftover = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("decmpfs-restore"));
        assert!(!leftover, "a restore temp was left behind");
        assert!(target.is_dir(), "directory target untouched");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rollback_temp_names_are_unique_and_dont_collide() {
        // FINDING #5: the rollback temp was `.decmpfs-restore-<pid>.tmp` (PID only), so two
        // concurrent rollbacks in the same dir/process collided. The name now carries
        // pid+nanos+seq, so successive derivations differ...
        let dir = Path::new("/tmp/abitious-rollback-unique");
        let a = unique_tmp(dir, "addon.node");
        let b = unique_tmp(dir, "addon.node");
        assert_ne!(a, b, "two temps in the same dir must differ");
        assert!(a.to_string_lossy().contains("decmpfs-restore"));

        // ...and two real rollbacks to different targets in the SAME directory both succeed
        // (the old PID-only + truncating-create scheme could interleave them).
        let scratch =
            std::env::temp_dir().join(format!("abitious-fscompress-two-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let p1 = scratch.join("one");
        let p2 = scratch.join("two");
        std::fs::write(&p1, b"corrupt-1").unwrap();
        std::fs::write(&p2, b"corrupt-2").unwrap();
        restore(&p1, b"original-one").unwrap();
        restore(&p2, b"original-two").unwrap();
        assert_eq!(std::fs::read(&p1).unwrap(), b"original-one");
        assert_eq!(std::fs::read(&p2).unwrap(), b"original-two");
        std::fs::remove_dir_all(&scratch).ok();
    }
}
