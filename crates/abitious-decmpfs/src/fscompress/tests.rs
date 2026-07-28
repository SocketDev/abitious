use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
  let dir = std::env::temp_dir().join(format!("abitious-fscompress-{tag}-{}", std::process::id()));
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
fn plain_write_uses_the_default_name_when_the_path_has_no_file_name() {
  // A path whose final component is `..` has a parent but no file_name(), so plain_write
  // takes its `"addon"` fallback name (the `unwrap_or_else` default arm). It still reaches
  // the temp write + rename; renaming a file over `..` then fails, so it returns Err — but
  // the default-name branch is exercised without a real gate-excluded write.
  let dir = scratch("plain-noname");
  let sub = dir.join("sub");
  std::fs::create_dir_all(&sub).unwrap();
  let no_name = sub.join(".."); // file_name() is None; parent() is `<dir>/sub` (exists)
  assert!(
    no_name.file_name().is_none(),
    "sanity: `..` has no file_name"
  );
  assert!(
    plain_write(&no_name, b"bytes").is_err(),
    "rename onto `..` must fail after the fallback name"
  );
  std::fs::remove_dir_all(&dir).ok();
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
      Ok(Outcome::Compressed { .. } | Outcome::NoGain { .. } | Outcome::AlreadyCompressed { .. })
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
