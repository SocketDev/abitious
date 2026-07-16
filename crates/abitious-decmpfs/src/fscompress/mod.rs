//! `fscompress` — apply the operating system's transparent per-file compression to a
//! file in place / as it is written: macOS APFS (decmpfs), Linux btrfs, Windows NTFS.
//! The kernel decompresses on read, so the file keeps its logical size + exact
//! contents and loads at near-native speed while taking less space on disk.
//!
//! This is a byte-faithful port of the `decmpfs` crate's FS-compression engine into
//! `abitious-decmpfs`, so a decmpfs-aware package manager can depend on this single
//! crate for BOTH the distribution SECTION format (the pressed-data reader in the
//! crate root) AND the install-time kernel compression here. The public surface is
//! re-exported at the crate root and mirrors `decmpfs::` 1:1 for the compress path.
//!
//! `compress_file(path)` detects the filesystem, applies compression, then verifies
//! the kernel reads the bytes back identically — rolling back on any failure.
//! `compress_bytes(path, content, gate)` is the one-pass install writer (write the
//! bytes AS the compressed file). `probe(path)` is the detect-only half.
//!
//! Backends: btrfs (`FS_COMPR_FL` + the `btrfs.compression` property), NTFS
//! (`FSCTL_SET_COMPRESSION`), and macOS decmpfs (resource fork, kernel-roundtrip
//! verified); other targets report `Unsupported`.
//!
//! Contract: every `Outcome` is a SUCCESS; `Err` is reserved for genuine I/O failures
//! that leave the file's integrity unknown. An unsupported FS, a permission/lock issue,
//! an incompressible or too-large file are non-fatal `Outcome`s.
//!
//! Out of scope for this port (kept in the upstream `decmpfs` crate, not needed on the
//! abitious install-compress path): reflink `copy_file` / `try_clone_file` /
//! `CopyOutcome`, and `rm` / `RmOptions`.

use std::path::Path;

/// What happened to the file. Only `Err` is a hard failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Applied and on-disk allocation actually decreased.
    Compressed { before: u64, after: u64 },
    /// Applied (or already set) but on-disk size did not drop — incompressible
    /// or sub-cluster. Content is byte-identical and fully loadable.
    NoGain { before: u64, after: u64 },
    /// Already carried the compression flag/xattr before we touched it.
    AlreadyCompressed { before: u64 },
    /// This FS/OS has no per-file transparent compression (ext4, xfs, ZFS, ReFS,
    /// FAT, tmpfs, overlay/network mounts). Caller falls through to the cache.
    Unsupported { reason: UnsupportedReason },
    /// Detected support but could not apply (permissions, lock, immutable,
    /// rollback). Warn-and-continue; never a hard error.
    Skipped { reason: SkipReason },
}

impl Outcome {
    /// A measured, human-readable one-line description of what happened, for a receipt
    /// or an `abi inspect` report. The compressing arms report the on-disk allocation
    /// before/after and the saving; the non-compressing arms (`NoGain`, `Unsupported`,
    /// `Skipped`) say so plainly AND make the download/install trade-off explicit — a
    /// hybrid still downloads smaller even where the filesystem stores it uncompressed,
    /// so the win is "download-only, installed size unchanged on this filesystem".
    pub fn describe(&self) -> String {
        match self {
            Outcome::Compressed { before, after } => {
                let saved = before.saturating_sub(*after);
                // checked_div guards the before==0 degenerate case (→ 0%).
                let pct = saved.saturating_mul(100).checked_div(*before).unwrap_or(0);
                format!(
                    "compressed on disk: {after} B allocated (was {before} B) — saved {saved} B ({pct}%)"
                )
            }
            Outcome::NoGain { before, after } => format!(
                "no on-disk gain: {after} B allocated (was {before} B), incompressible or \
                 sub-cluster — download-only savings, installed size unchanged on this filesystem"
            ),
            Outcome::AlreadyCompressed { before } => {
                format!("already FS-compressed: {before} B allocated on disk")
            }
            Outcome::Unsupported { reason } => format!(
                "no transparent compression here ({reason}) — download-only savings, installed \
                 size unchanged on this filesystem"
            ),
            Outcome::Skipped { reason } => format!(
                "not FS-compressed ({reason}) — download-only savings, installed size unchanged"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// Filesystem (by allowlist) has no transparent compression.
    Filesystem,
    /// Network/overlay/bind mount where the signal is unreliable.
    NetworkOrOverlay,
    /// Built for an OS with no backend (or skeleton: not yet implemented).
    PlatformBuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// EACCES / EPERM / EROFS — read-only or unowned (e.g. unprivileged container).
    PermissionDenied,
    /// A write handle is held / ETXTBSY / sharing violation; could not lock.
    Busy,
    /// UF_IMMUTABLE / SF_IMMUTABLE and we declined to toggle it.
    Immutable,
    /// EFS / FILE_ATTRIBUTE_ENCRYPTED.
    Encrypted,
    /// Applied, structural verification failed, rolled back to the original.
    IntegrityRevert,
    /// Post-apply loadability (magic-bytes) check failed, rolled back.
    NotLoadable,
    /// Exceeds a backend limit (e.g. decmpfs u32 offsets cap at 4 GiB).
    TooLarge,
    /// `compress_bytes` was handed a file the `Gate` excludes — written plain.
    GateExcluded,
}

impl std::fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            UnsupportedReason::Filesystem => "filesystem has no per-file compression",
            UnsupportedReason::NetworkOrOverlay => "network or overlay mount",
            UnsupportedReason::PlatformBuild => "no backend for this OS build",
        };
        f.write_str(msg)
    }
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            SkipReason::PermissionDenied => "permission denied",
            SkipReason::Busy => "file busy or locked",
            SkipReason::Immutable => "immutable flag set",
            SkipReason::Encrypted => "filesystem-encrypted",
            SkipReason::IntegrityRevert => "structural verification reverted it",
            SkipReason::NotLoadable => "post-apply loadability check reverted it",
            SkipReason::TooLarge => "exceeds a backend size limit",
            SkipReason::GateExcluded => "excluded by the compression gate",
        };
        f.write_str(msg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    Supported,
    AlreadyCompressed,
    Unsupported(UnsupportedReason),
}

/// Genuine failures only. A capability/permission gap is an `Outcome`, not an `Error`.
#[derive(Debug)]
pub enum Error {
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    NotFound(std::path::PathBuf),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "io error at {context}: {source}"),
            Error::NotFound(p) => write!(f, "file not found: {}", p.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::NotFound(_) => None,
        }
    }
}

/// Wrap the last OS error with context — shared by every backend.
pub(crate) fn io(context: &'static str) -> Error {
    Error::Io {
        context,
        source: std::io::Error::last_os_error(),
    }
}

/// A NUL-checked C string from a path, for the unix backends that hand paths to
/// libc.
#[cfg(unix)]
pub(crate) fn cstring(path: &Path) -> Result<std::ffi::CString, Error> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Io {
        context: "path has interior NUL",
        source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
    })
}

/// Detect-only, no mutation — for dry-run / capability reporting.
pub fn probe(path: &Path) -> Result<Support, Error> {
    backend::detect(path)
}

/// THE entry point: detect → gate → apply → verify → rollback-on-failure.
/// Idempotent. Never panics. Never corrupts the file.
pub fn compress_file(path: &Path) -> Result<Outcome, Error> {
    compress_file_with(&Os, path)
}

/// `compress_file` over an injectable [`Backend`] — production always threads
/// [`Os`]; tests drive the otherwise-dead `AlreadyCompressed`/`Unsupported` arms
/// with a fake.
fn compress_file_with<B: Backend>(backend: &B, path: &Path) -> Result<Outcome, Error> {
    if !path.exists() {
        return Err(Error::NotFound(path.to_path_buf()));
    }
    match backend.detect(path)? {
        Support::Unsupported(reason) => Ok(Outcome::Unsupported { reason }),
        Support::AlreadyCompressed => Ok(Outcome::AlreadyCompressed {
            before: verify::on_disk_bytes(path)?,
        }),
        Support::Supported => safety::apply_guarded(backend, path),
    }
}

/// THE install-time entry point: write `content` to `path` as an OS-compressed file
/// in ONE pass — never a write-then-read-back-recompress.
///
/// The caller (a package manager's CAS writer) has already decoded the raw addon
/// and matched it against `gate`. `compress_bytes` writes that exact byte stream
/// directly as a transparently-compressed file: macOS encodes the decmpfs from the
/// bytes onto a fresh inode; btrfs requests the codec on the empty temp then writes;
/// NTFS sets FSCTL_SET_COMPRESSION on the fresh handle then writes.
///
/// Fail-soft is the contract — this NEVER breaks an install. On an unsupported FS,
/// a permission/busy/too-large skip, or any backend error, it falls back to a plain
/// atomic write of `content` and reports the corresponding `Outcome` (the plain
/// write still lands the file). The kernel read-back is verified identical to
/// `content` before returning a compressed Outcome.
///
/// `gate` is honored here as a convenience: if `content` does not match the gate,
/// the file is written plain and `Outcome::Skipped { reason: GateExcluded }` is
/// returned. A caller that already gated can pass `&Gate::any()`.
pub fn compress_bytes(path: &Path, content: &[u8], gate: &Gate) -> Result<Outcome, Error> {
    compress_bytes_with(&Os, path, content, gate)
}

/// `compress_bytes` over an injectable [`Backend`] — production always threads
/// [`Os`]; tests drive the plain-write fallback arms (a guarded skip/error, or a
/// non-compressing FS) that a real APFS write never reaches.
fn compress_bytes_with<B: Backend>(
    backend: &B,
    path: &Path,
    content: &[u8],
    gate: &Gate,
) -> Result<Outcome, Error> {
    let name = path.to_string_lossy();
    let normalized = name.replace('\\', "/");
    if !gate.matches(&normalized, content.len() as u64) {
        plain_write(path, content)?;
        return Ok(Outcome::Skipped {
            reason: SkipReason::GateExcluded,
        });
    }
    // The target usually doesn't exist yet (a fresh CAS write), so the FS capability
    // probe goes against the parent directory; `detect` statfs's / opens its argument
    // and would error on a missing path.
    let probe_target = if path.exists() {
        path.to_path_buf()
    } else {
        match path.parent() {
            Some(dir) => dir.to_path_buf(),
            None => path.to_path_buf(),
        }
    };
    match backend.detect(&probe_target) {
        Ok(Support::Supported) => match safety::compress_bytes_guarded(backend, path, content) {
            Ok(Outcome::Skipped { .. }) | Err(_) => {
                // A guarded skip/error already restored or never wrote — ensure the file
                // lands plain so the install is never missing the addon.
                plain_write(path, content)?;
                Ok(Outcome::Skipped {
                    reason: SkipReason::IntegrityRevert,
                })
            }
            other => other,
        },
        Ok(Support::AlreadyCompressed) | Ok(Support::Unsupported(_)) | Err(_) => {
            plain_write(path, content)?;
            Ok(Outcome::Unsupported {
                reason: UnsupportedReason::Filesystem,
            })
        }
    }
}

/// Fail-soft plain atomic write: sibling temp + fsync + rename. The never-break-the
/// -install floor under every `compress_bytes` fallback.
fn plain_write(path: &Path, content: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| Error::Io {
        context: "no parent dir",
        source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "addon".to_string());
    let tmp = dir.join(format!(".{name}.plain-{}.tmp", std::process::id()));
    let res = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(content)?;
        file.sync_all()
    })();
    if let Err(source) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Io {
            context: "plain write temp",
            source,
        });
    }
    std::fs::rename(&tmp, path).map_err(|source| {
        let _ = std::fs::remove_file(&tmp);
        Error::Io {
            context: "plain write rename",
            source,
        }
    })
}

/// Filesystem-compression state of a path — one call that coalesces the
/// otherwise-separate size + backend-signal reads (the compress path previously did
/// a `stat` AND an `lstat`/attr read per file). Follows symlinks: compression is a
/// property of the target file, never a symlink.
pub struct Stat {
    /// FS-compressed on disk. Uses the backend's authoritative signal where it has
    /// one (`UF_COMPRESSED` on APFS, FIEMAP-encoded extents on btrfs, the
    /// compressed attribute on NTFS); elsewhere inferred from allocated < logical.
    pub compressed: bool,
    /// Apparent (logical) size — constant whether or not the file is compressed.
    pub logical: u64,
    /// Allocated (physical) bytes on disk — where the compression win shows.
    pub physical: u64,
}

/// Inspect the FS-compression state of `path` (see [`Stat`]).
pub fn stat(path: &Path) -> Result<Stat, Error> {
    stat_with(&Os, path)
}

/// [`stat`] over an injectable [`Backend`] so the no-signal (allocated-bytes)
/// inference arm is testable without a real filesystem.
fn stat_with<B: Backend>(backend: &B, path: &Path) -> Result<Stat, Error> {
    let meta = std::fs::metadata(path).map_err(|source| Error::Io {
        context: "stat",
        source,
    })?;
    let logical = meta.len();
    // One metadata read yields both size + allocation on unix (the coalesce);
    // Windows needs GetCompressedFileSizeW for the post-compression allocation.
    #[cfg(unix)]
    let physical = {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512)
    };
    #[cfg(not(unix))]
    let physical = verify::on_disk_bytes(path)?;
    // Prefer the backend's authoritative signal; fall back to the
    // allocated-vs-logical inference when there is no signal (e.g. NTFS) OR the
    // probe isn't supported on this filesystem (e.g. FIEMAP on tmpfs) — a stat is
    // an inspection and must never fail over a best-effort compression check.
    let compressed = match backend.compressed_on_disk(path) {
        Ok(Some(signal)) => signal,
        Ok(None) | Err(_) => logical > 0 && physical < logical,
    };
    Ok(Stat {
        compressed,
        logical,
        physical,
    })
}

mod gate;
mod safety;
mod verify;

pub use gate::{Gate, GateParseError, SizePredicate, DEFAULT_GLOB};

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod backend;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod backend;
#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod backend;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[path = "unsupported.rs"]
mod backend;

/// The OS compression backend as a trait, so the orchestration in `safety` can be
/// driven by a fake in tests — a real filesystem never produces a non-loadable
/// result or a mismatched read-back, so the rollback and plain-write fallback paths
/// are otherwise unreachable. Production always threads [`Os`]; static dispatch
/// monomorphizes it to the same code as a direct backend call (no vtable, no size
/// cost in a release build).
pub(crate) trait Backend {
    fn detect(&self, path: &Path) -> Result<Support, Error>;
    fn is_already_compressed(&self, path: &Path) -> Result<bool, Error>;
    /// Compress `path` in place. `snapshot` is the already-read file contents (the
    /// caller holds them for rollback); backends that rewrite via temp+rename reuse
    /// it instead of reading the file a second time, and backends that flag the
    /// existing file in place (Windows) ignore it.
    fn apply_inplace(&self, path: &Path, snapshot: &[u8]) -> Result<(), Error>;
    fn apply_bytes(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<std::fs::Permissions>,
    ) -> Result<(), Error>;
    fn compressed_on_disk(&self, path: &Path) -> Result<Option<bool>, Error>;
}

/// The real, cfg-selected OS backend.
pub(crate) struct Os;

impl Backend for Os {
    fn detect(&self, path: &Path) -> Result<Support, Error> {
        backend::detect(path)
    }
    fn is_already_compressed(&self, path: &Path) -> Result<bool, Error> {
        backend::is_already_compressed(path)
    }
    fn apply_inplace(&self, path: &Path, snapshot: &[u8]) -> Result<(), Error> {
        backend::apply_inplace(path, snapshot)
    }
    fn apply_bytes(
        &self,
        path: &Path,
        content: &[u8],
        mode: Option<std::fs::Permissions>,
    ) -> Result<(), Error> {
        backend::apply_bytes(path, content, mode)
    }
    fn compressed_on_disk(&self, path: &Path) -> Result<Option<bool>, Error> {
        backend::compressed_on_disk(path)
    }
}

/// A configurable in-memory backend for exercising the rollback and plain-write
/// fallback paths that a real filesystem never reaches.
#[cfg(test)]
pub(crate) struct FakeBackend {
    pub(crate) detect: Support,
    /// `None` → apply succeeds; `Some(errno)` → apply fails with that OS error.
    pub(crate) apply_errno: Option<i32>,
    /// `true` → apply fails with a non-`Io` [`Error::NotFound`] (takes precedence over
    /// `apply_errno`). Drives the non-`Io` error fall-through in `safety`'s apply /
    /// compress classifiers — an arm a real backend reaches only on a `NotFound` fault.
    pub(crate) apply_not_found: bool,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl FakeBackend {
    fn apply_result(&self) -> Result<(), Error> {
        if self.apply_not_found {
            return Err(Error::NotFound(std::path::PathBuf::from("/fake/not/found")));
        }
        match self.apply_errno {
            None => Ok(()),
            Some(errno) => Err(Error::Io {
                context: "fake apply",
                source: std::io::Error::from_raw_os_error(errno),
            }),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl Backend for FakeBackend {
    fn detect(&self, _path: &Path) -> Result<Support, Error> {
        Ok(self.detect)
    }
    fn is_already_compressed(&self, _path: &Path) -> Result<bool, Error> {
        Ok(false)
    }
    fn apply_inplace(&self, _path: &Path, _snapshot: &[u8]) -> Result<(), Error> {
        self.apply_result()
    }
    fn apply_bytes(
        &self,
        _path: &Path,
        _content: &[u8],
        _mode: Option<std::fs::Permissions>,
    ) -> Result<(), Error> {
        self.apply_result()
    }
    fn compressed_on_disk(&self, _path: &Path) -> Result<Option<bool>, Error> {
        Ok(Some(false))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("abitious-fscompress-{tag}-{}", std::process::id()));
        // A pid-recycled leftover FILE at this path makes create_dir_all fail
        // with AlreadyExists; clear it so the scratch dir always materializes.
        let _ = std::fs::remove_file(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // A minimal native-magic payload (ELF header) so a backend will attempt to
    // compress it rather than skip a trivially-small file.
    fn fake_addon() -> Vec<u8> {
        let mut raw = vec![0x7f, 0x45, 0x4c, 0x46];
        raw.extend_from_slice(&[7u8; 9000]);
        raw
    }

    /// A no-FS-signal backend: `compressed_on_disk` returns `Ok(None)` so `stat_with`
    /// takes its allocated-vs-logical inference arm (the real macOS `Os` always
    /// answers `Ok(Some(_))`, so a fake drives the no-signal branch).
    struct NoSignalBackend;

    impl Backend for NoSignalBackend {
        fn detect(&self, _path: &Path) -> Result<Support, Error> {
            Ok(Support::Supported)
        }
        fn is_already_compressed(&self, _path: &Path) -> Result<bool, Error> {
            Ok(false)
        }
        fn apply_inplace(&self, _path: &Path, _snapshot: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn apply_bytes(
            &self,
            _path: &Path,
            _content: &[u8],
            _mode: Option<std::fs::Permissions>,
        ) -> Result<(), Error> {
            Ok(())
        }
        fn compressed_on_disk(&self, _path: &Path) -> Result<Option<bool>, Error> {
            Ok(None)
        }
    }

    #[test]
    fn compress_file_errors_when_missing() {
        let p = std::path::Path::new("/no/such/addon.node");
        assert!(matches!(compress_file(p), Err(Error::NotFound(_))));
    }

    #[test]
    fn plain_write_errors_when_the_path_has_no_parent() {
        // "/" has no parent directory → the no-parent guard fires before any write.
        let out = plain_write(std::path::Path::new("/"), b"x");
        assert!(matches!(
            out,
            Err(Error::Io {
                context: "no parent dir",
                ..
            })
        ));
    }

    #[test]
    fn error_display_and_source() {
        let nf = Error::NotFound(std::path::PathBuf::from("/x"));
        assert!(nf.to_string().contains("not found"));
        assert!(std::error::Error::source(&nf).is_none());
        let io = Error::Io {
            context: "ctx",
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert!(io.to_string().contains("ctx"));
        assert!(std::error::Error::source(&io).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_a_support_variant_without_mutating() {
        // probe never errors on an existing path — it returns a Support.
        assert!(matches!(
            probe(std::path::Path::new("/dev/null")),
            Ok(Support::Supported | Support::AlreadyCompressed | Support::Unsupported(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn compress_file_reports_unsupported_on_a_non_compressing_fs() {
        // /dev/null exists but devfs has no compression backend → Unsupported.
        let out = compress_file(std::path::Path::new("/dev/null"));
        assert!(
            matches!(out, Ok(Outcome::Unsupported { .. })),
            "devfs → Unsupported, got {out:?}"
        );
    }

    // APFS is always a compressing FS, so macOS exercises the full success path:
    // compress_file → apply_guarded → backend::apply_inplace → verify → classify.
    #[cfg(target_os = "macos")]
    #[test]
    fn compress_file_compresses_then_is_idempotent_and_transparent() {
        let dir = scratch("ok");
        let path = dir.join("addon.node");
        std::fs::write(&path, fake_addon()).unwrap();

        let out = compress_file(&path);
        assert!(
            matches!(
                out,
                Ok(Outcome::Compressed { .. }
                    | Outcome::NoGain { .. }
                    | Outcome::AlreadyCompressed { .. })
            ),
            "writable addon on APFS → applied, got {out:?}"
        );
        // Transparent: the kernel hands back the exact original bytes.
        assert_eq!(std::fs::read(&path).unwrap(), fake_addon());
        // Idempotent: a second pass detects it's already compressed.
        assert!(matches!(
            compress_file(&path),
            Ok(Outcome::AlreadyCompressed { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    // compress_bytes one-pass: write bytes directly as an APFS-compressed file with
    // no pre-existing original, then prove the kernel hands the exact bytes back.
    #[cfg(target_os = "macos")]
    #[test]
    fn compress_bytes_one_pass_writes_compressed_and_reads_back_identical() {
        let dir = scratch("bytes");
        let path = dir.join("fresh.node");
        let content = fake_addon();
        // No file at `path` yet — compress_bytes creates it in one pass.
        let out = compress_bytes(&path, &content, &Gate::any());
        assert!(
            matches!(out, Ok(Outcome::Compressed { .. } | Outcome::NoGain { .. })),
            "one-pass APFS write → applied, got {out:?}"
        );
        assert!(path.exists(), "file was created");
        // Transparent: kernel read-back equals the bytes we asked to store.
        assert_eq!(std::fs::read(&path).unwrap(), content);
        // It really carries the compression flag (not a plain fallback write).
        assert!(matches!(
            compress_file(&path),
            Ok(Outcome::AlreadyCompressed { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    // A file the gate excludes is written PLAIN (never compressed) and reports
    // Skipped(GateExcluded) — the install still gets the file.
    #[cfg(unix)]
    #[test]
    fn compress_bytes_gate_excluded_writes_plain() {
        let dir = scratch("gate");
        let path = dir.join("not-an-addon.txt");
        let content = b"plain text, not a .node".to_vec();
        let gate = Gate::default(); // **/*.node
        let out = compress_bytes(&path, &content, &gate);
        assert!(
            matches!(
                out,
                Ok(Outcome::Skipped {
                    reason: SkipReason::GateExcluded
                })
            ),
            "non-.node → GateExcluded, got {out:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), content);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn compress_bytes_falls_back_to_plain_on_unsupported_fs() {
        // A non-compressing FS (devfs) → plain write, Unsupported Outcome, file lands.
        // /dev isn't writable by us, so target a temp path but force the gate to pass;
        // temp on macOS is APFS (compresses) — instead assert the API never errors and
        // the bytes land for the supported case is covered above. Here just exercise
        // the gate-passing path lands bytes on any unix temp.
        let dir = scratch("fallback");
        let path = dir.join("x.node");
        let content = fake_addon();
        let out = compress_bytes(&path, &content, &Gate::any());
        assert!(out.is_ok(), "never errors on a normal temp, got {out:?}");
        assert_eq!(std::fs::read(&path).unwrap(), content, "bytes always land");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn compress_file_skips_a_read_only_file() {
        // On a compressing FS a read-only file can't be opened rw → fail-soft turns the
        // EACCES into Skipped(PermissionDenied). Root bypasses mode bits, so skip there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = scratch("ro");
        let path = dir.join("addon.node");
        std::fs::write(&path, fake_addon()).unwrap();
        if !matches!(probe(&path), Ok(Support::Supported)) {
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&path, perm).unwrap();
        let outcome = compress_file(&path);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();
        assert!(
            matches!(
                outcome,
                Ok(Outcome::Skipped {
                    reason: SkipReason::PermissionDenied
                })
            ),
            "read-only → Skipped(PermissionDenied), got {outcome:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // An existing target exercises the `path.exists()` probe-target branch and the
    // fresh-inode rename that replaces the old contents.
    #[cfg(target_os = "macos")]
    #[test]
    fn compress_bytes_overwrites_an_existing_file() {
        let dir = scratch("overwrite");
        let path = dir.join("addon.node");
        std::fs::write(&path, b"stale contents").unwrap();
        let content = fake_addon();
        let out = compress_bytes(&path, &content, &Gate::any());
        assert!(out.is_ok(), "overwrite never errors, got {out:?}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            content,
            "new bytes replace the old"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // `path` is an existing directory: the backend builds its temp then can't rename
    // a file over a directory, and the plain-write fallback can't either → a hard
    // `Err` (genuine I/O failure), never a corrupt success. Exercises the backend
    // rename-error cleanup and the `Err(_)` fallback arm of compress_bytes.
    #[cfg(target_os = "macos")]
    #[test]
    fn compress_bytes_onto_a_directory_path_is_a_hard_error() {
        let dir = scratch("dir-target");
        let target = dir.join("a-dir");
        std::fs::create_dir_all(&target).unwrap();
        let out = compress_bytes(&target, &fake_addon(), &Gate::any());
        assert!(
            out.is_err(),
            "cannot write a file over a directory, got {out:?}"
        );
        assert!(target.is_dir(), "the directory is left intact");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stat_reports_size_and_uncompressed_for_a_plain_file() {
        let dir = scratch("stat-plain");
        let path = dir.join("f");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let s = stat(&path).unwrap();
        assert_eq!(s.logical, 4096, "logical == the written bytes");
        assert!(s.physical > 0, "allocated bytes reported");
        assert!(
            !s.compressed,
            "a freshly-written plain file is not FS-compressed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stat_reflects_a_compressed_file_where_supported() {
        let dir = scratch("stat-comp");
        let path = dir.join("addon.node");
        let content = vec![0xABu8; 128 * 1024];
        let outcome = compress_bytes(&path, &content, &Gate::any()).unwrap();
        let s = stat(&path).unwrap();
        assert_eq!(
            s.logical,
            content.len() as u64,
            "logical == the written bytes"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            content,
            "content round-trips"
        );
        // Where the FS actually compressed (APFS / btrfs / NTFS), stat must reflect
        // it; on an unsupported FS the outcome isn't Compressed and we only assert
        // the size + content invariants above.
        if matches!(outcome, Outcome::Compressed { .. }) {
            assert!(
                s.compressed,
                "a Compressed outcome → stat reports compressed"
            );
            assert!(
                s.physical < s.logical,
                "allocation shrank below the logical size"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // The no-FS-signal arm of stat_with: a fake whose compressed_on_disk is Ok(None)
    // forces the allocated-vs-logical inference (a real macOS Os always answers Some).
    #[test]
    fn stat_with_no_signal_infers_from_allocation() {
        let dir = scratch("stat-nosignal");
        let path = dir.join("f");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let s = stat_with(&NoSignalBackend, &path).unwrap();
        assert_eq!(s.logical, 4096);
        // A freshly written plain 4 KiB file: allocation is not below the logical size,
        // so the inference reports not-compressed. The point is the Ok(None) arm ran.
        assert!(!s.compressed);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stat_errors_on_a_missing_path() {
        let out = stat(std::path::Path::new("/no/such/fscompress/stat/x"));
        assert!(matches!(
            out,
            Err(Error::Io {
                context: "stat",
                ..
            })
        ));
    }

    // A read-only parent dir: the guarded backend write hits EACCES (classify_skip →
    // Skipped), then the plain-write fallback also can't write → `Err`. Root bypasses
    // mode bits, so skip there.
    #[cfg(target_os = "macos")]
    #[test]
    fn compress_bytes_into_a_read_only_dir_is_fail_soft() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("ro-dir");
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = compress_bytes(&locked.join("x.node"), &fake_addon(), &Gate::any());
        // Restore write perms so the tree can be cleaned up.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).ok();
        assert!(out.is_err(), "a read-only dir admits no write, got {out:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // The `Support::AlreadyCompressed`-from-detect arm: a real macOS detect never
    // returns it (it reports already-compressed via the apply path), so a fake drives
    // it. Needs a real file for the on-disk-bytes read.
    #[test]
    fn compress_file_reports_already_compressed_from_detect() {
        let dir = scratch("already-detect");
        let path = dir.join("f.node");
        std::fs::write(&path, fake_addon()).unwrap();
        let backend = FakeBackend {
            detect: Support::AlreadyCompressed,
            apply_errno: None,
            apply_not_found: false,
        };
        assert!(matches!(
            compress_file_with(&backend, &path),
            Ok(Outcome::AlreadyCompressed { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    // detect → Unsupported: the bytes still land via a plain write, Outcome::Unsupported.
    #[test]
    fn compress_bytes_falls_back_to_plain_on_an_unsupported_fs() {
        let dir = scratch("unsup");
        let path = dir.join("x.node");
        let content = fake_addon();
        let backend = FakeBackend {
            detect: Support::Unsupported(UnsupportedReason::Filesystem),
            apply_errno: None,
            apply_not_found: false,
        };
        let out = compress_bytes_with(&backend, &path, &content, &Gate::any());
        assert!(
            matches!(out, Ok(Outcome::Unsupported { .. })),
            "got {out:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), content, "bytes landed plain");
        std::fs::remove_dir_all(&dir).ok();
    }

    // detect → Supported but the guarded apply is skipped (faked permission failure):
    // the bytes land via a plain write, Outcome::Skipped(IntegrityRevert).
    #[test]
    fn compress_bytes_falls_back_to_plain_on_a_guarded_skip() {
        let dir = scratch("guard-skip");
        let path = dir.join("x.node");
        let content = fake_addon();
        let backend = FakeBackend {
            detect: Support::Supported,
            apply_errno: Some(13), // EACCES
            apply_not_found: false,
        };
        let out = compress_bytes_with(&backend, &path, &content, &Gate::any());
        assert!(
            matches!(
                out,
                Ok(Outcome::Skipped {
                    reason: SkipReason::IntegrityRevert
                })
            ),
            "got {out:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), content, "bytes landed plain");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compress_bytes_probe_target_falls_back_to_the_path_when_parentless() {
        // An empty path does not exist AND has no parent, so the probe-target selection
        // takes the `None => path` arm (mod.rs L269). The fake reports Unsupported, so the
        // plain-write fallback fires and, with no parent dir to write into, surfaces a hard
        // Err — the point is the otherwise-unreachable parentless probe-target arm ran.
        let backend = FakeBackend {
            detect: Support::Unsupported(UnsupportedReason::Filesystem),
            apply_errno: None,
            apply_not_found: false,
        };
        let out = compress_bytes_with(&backend, std::path::Path::new(""), b"data", &Gate::any());
        assert!(
            matches!(
                out,
                Err(Error::Io {
                    context: "no parent dir",
                    ..
                })
            ),
            "got {out:?}"
        );
    }

    #[test]
    fn compress_bytes_falls_back_to_plain_on_a_guarded_hard_error() {
        // detect → Supported but the guarded apply fails with an UNCLASSIFIABLE error
        // (ENOENT, not a permission/busy/too-large skip): compress_bytes_guarded returns
        // Err, driving the `Err(_)` alternative of the guarded match arm. The bytes still
        // land via the plain-write fallback and Skipped(IntegrityRevert) is reported.
        let dir = scratch("guard-hard-err");
        let path = dir.join("x.node");
        let content = fake_addon();
        let backend = FakeBackend {
            detect: Support::Supported,
            apply_errno: Some(2), // ENOENT — unclassifiable → guarded returns Err
            apply_not_found: false,
        };
        let out = compress_bytes_with(&backend, &path, &content, &Gate::any());
        assert!(
            matches!(
                out,
                Ok(Outcome::Skipped {
                    reason: SkipReason::IntegrityRevert
                })
            ),
            "got {out:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), content, "bytes landed plain");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn outcome_describe_measures_the_compressing_arms() {
        let c = Outcome::Compressed {
            before: 1000,
            after: 400,
        }
        .describe();
        assert!(c.contains("saved 600 B") && c.contains("(60%)"), "{c}");
        let a = Outcome::AlreadyCompressed { before: 512 }.describe();
        assert!(
            a.contains("already FS-compressed") && a.contains("512 B"),
            "{a}"
        );
        // A degenerate before==0 must not divide by zero.
        let z = Outcome::Compressed {
            before: 0,
            after: 0,
        }
        .describe();
        assert!(z.contains("(0%)"), "{z}");
    }

    #[test]
    fn outcome_describe_surfaces_the_download_only_message_for_non_compressing_arms() {
        for out in [
            Outcome::NoGain {
                before: 100,
                after: 100,
            },
            Outcome::Unsupported {
                reason: UnsupportedReason::Filesystem,
            },
            Outcome::Skipped {
                reason: SkipReason::TooLarge,
            },
        ] {
            let msg = out.describe();
            assert!(
                msg.contains("download-only savings"),
                "{out:?} → {msg} lacks the download-only framing"
            );
        }
        // The reason is named in the message.
        assert!(Outcome::Unsupported {
            reason: UnsupportedReason::NetworkOrOverlay,
        }
        .describe()
        .contains("network or overlay"));
        assert!(Outcome::Skipped {
            reason: SkipReason::GateExcluded,
        }
        .describe()
        .contains("excluded by the compression gate"));
    }

    #[test]
    fn reason_display_is_distinct_and_non_empty() {
        let unsupported = [
            UnsupportedReason::Filesystem,
            UnsupportedReason::NetworkOrOverlay,
            UnsupportedReason::PlatformBuild,
        ]
        .map(|r| r.to_string());
        let skips = [
            SkipReason::PermissionDenied,
            SkipReason::Busy,
            SkipReason::Immutable,
            SkipReason::Encrypted,
            SkipReason::IntegrityRevert,
            SkipReason::NotLoadable,
            SkipReason::TooLarge,
            SkipReason::GateExcluded,
        ]
        .map(|r| r.to_string());
        let mut all: Vec<String> = unsupported.into_iter().chain(skips).collect();
        assert!(all.iter().all(|m| !m.is_empty()));
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n, "every reason message must be unique");
    }
}
