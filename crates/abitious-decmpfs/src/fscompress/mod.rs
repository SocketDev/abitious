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
      Outcome::Skipped { reason } => {
        format!("not FS-compressed ({reason}) — download-only savings, installed size unchanged")
      }
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
mod tests;
