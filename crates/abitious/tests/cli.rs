//! Lightweight `abi` binary smoke tests — always run (no cc/node/cargo-build needed).
//!
//! These drive the real `abi` binary for its fast, no-side-effect paths (usage, arg
//! errors, and a deterministic build failure) so `main`'s dispatch arms and the LOUD error
//! plumbing are exercised on every host, complementing the heavier gated e2e in `e2e.rs`.

#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn abi(args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_abi"))
    .args(args)
    .output()
    .expect("run abi")
}

/// Run `abi` with `cwd` set — used to exercise the stub auto-resolver from an isolated
/// directory with no `node_modules/@abitious` ancestry.
fn abi_in(cwd: &Path, args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_abi"))
    .args(args)
    .current_dir(cwd)
    .output()
    .expect("run abi")
}

#[test]
fn help_prints_usage_and_succeeds() {
  for args in [&["--help"][..], &["-h"][..], &[][..]] {
    let out = abi(args);
    assert!(out.status.success(), "abi {args:?} should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
      stdout.contains("usage: abi build"),
      "unexpected help: {stdout}"
    );
  }
}

#[test]
fn unknown_subcommand_fails_loud() {
  let out = abi(&["frobnicate"]);
  assert!(!out.status.success());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(stderr.contains("unknown subcommand"), "stderr: {stderr}");
}

#[test]
fn compress_without_stub_auto_resolve_fails_loud_naming_the_package() {
  // M6: `--compress` with no `--stub` auto-resolves from an installed @abitious/<triple>.
  // From an isolated temp dir (no node_modules/@abitious ancestry), resolution fails fast —
  // BEFORE any cargo build — with an actionable error naming the exact package to install.
  let dir: PathBuf =
    std::env::temp_dir().join(format!("abitious-cli-noresolve-{}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");

  let out = abi_in(&dir, &["build", "--compress"]);
  assert!(!out.status.success());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("could not auto-resolve a prebuilt stub"),
    "stderr: {stderr}"
  );
  assert!(
    stderr.contains("@abitious/"),
    "stderr should name the package: {stderr}"
  );
  assert!(
    stderr.contains("--stub"),
    "stderr should mention the override: {stderr}"
  );

  std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn bad_compress_level_fails_loud() {
  let out = abi(&["build", "--compress-level", "not-a-number"]);
  assert!(!out.status.success());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(stderr.contains("not an integer"), "stderr: {stderr}");
}

#[test]
fn build_with_unknown_package_fails_loud() {
  // `cargo build -p <bogus>` fails fast (no compilation), driving the build-error arm of
  // both `build::run` and `main`. Runs from the crate dir (a real cargo workspace).
  let out = abi(&["build", "-p", "__abi_no_such_package__"]);
  assert!(
    !out.status.success(),
    "building a nonexistent package must fail"
  );
  // Either cargo's own error (cargo build failed) or abi's resolution error surfaces.
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(!stderr.is_empty(), "expected a LOUD error on stderr");
}

// --- `abi inspect` (lightweight, always-run: synthetic hybrid, no cc/node needed) ---

/// A minimal valid ELF64 stub with a `.shstrtab` + 2-entry section table — the shape
/// `inject_pressed_data` grows a `.PRESSED_DATA` section onto. Duplicated from the crate's
/// test helpers (an integration test cannot reach them).
fn minimal_elf64() -> Vec<u8> {
  fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
  }
  fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
  }
  fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
  }
  let shstr: &[u8] = b"\0.shstrtab\0";
  let shoff = 80usize;
  let mut e = vec![0u8; shoff + 2 * 64];
  e[0..4].copy_from_slice(b"\x7fELF");
  e[4] = 2; // 64-bit
  e[5] = 1; // little-endian
  e[6] = 1; // version
  put_u64(&mut e, 40, shoff as u64);
  put_u16(&mut e, 58, 64);
  put_u16(&mut e, 60, 2);
  put_u16(&mut e, 62, 1);
  e[64..64 + shstr.len()].copy_from_slice(shstr);
  let sh1 = shoff + 64;
  put_u32(&mut e, sh1, 1);
  put_u32(&mut e, sh1 + 4, 3);
  put_u64(&mut e, sh1 + 24, 64);
  put_u64(&mut e, sh1 + 32, shstr.len() as u64);
  e
}

/// Build a synthetic hybrid `.node` (an ELF carrying `raw` in a `.PRESSED_DATA` section)
/// and write it to a fresh temp path; returns (dir, hybrid_path, raw_bytes).
fn planted_hybrid(tag: &str) -> (PathBuf, PathBuf, Vec<u8>) {
  use abitious_decmpfs::{build_section_payload, inject_pressed_data, Arch, Libc, Platform};
  let dir = std::env::temp_dir().join(format!("abitious-inspect-{tag}-{}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");
  let raw = b"\x7fELF the real abitious addon, compressible payload text here! ".repeat(40);
  let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
  let hybrid = inject_pressed_data(&minimal_elf64(), &section).expect("inject");
  let path = dir.join("hybrid.node");
  std::fs::write(&path, &hybrid).expect("write hybrid");
  (dir, path, raw)
}

#[test]
fn inspect_reports_a_plain_node_clearly() {
  let dir = std::env::temp_dir().join(format!("abitious-inspect-plain-{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  let plain = dir.join("plain.node");
  std::fs::write(&plain, b"not a hybrid, just raw addon bytes").unwrap();
  let out = abi(&["inspect", plain.to_str().unwrap()]);
  assert!(out.status.success(), "inspect of a plain file exits 0");
  let stdout = String::from_utf8_lossy(&out.stdout);
  assert!(
    stdout.contains("plain .node (no pressed-data section)"),
    "stdout: {stdout}"
  );
  std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_reports_a_hybrid_human_and_json() {
  let (dir, path, raw) = planted_hybrid("report");

  let human = abi(&["inspect", path.to_str().unwrap()]);
  assert!(human.status.success());
  let h = String::from_utf8_lossy(&human.stdout);
  assert!(h.contains("abitious hybrid .node"), "{h}");
  assert!(h.contains("platform=linux arch=x64 libc=glibc"), "{h}");
  assert!(
    h.contains(&format!("uncompressed addon:  {} B", raw.len())),
    "{h}"
  );
  assert!(h.contains("verified (SHA-512 matches)"), "{h}");

  let json = abi(&["inspect", "--json", path.to_str().unwrap()]);
  assert!(json.status.success());
  let j = String::from_utf8_lossy(&json.stdout);
  assert!(j.contains("\"hybrid\":true"), "{j}");
  assert!(j.contains("\"integrityVerified\":true"), "{j}");
  assert!(j.contains("\"platform\":\"linux\""), "{j}");

  std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_decompress_round_trips_to_the_raw_addon() {
  let (dir, path, raw) = planted_hybrid("decomp");

  // To a file (-o): byte-identical to the raw addon.
  let out_path = dir.join("extracted.node");
  let to_file = abi(&[
    "inspect",
    "--decompress",
    path.to_str().unwrap(),
    "-o",
    out_path.to_str().unwrap(),
  ]);
  assert!(
    to_file.status.success(),
    "decompress -o failed:\n{}",
    String::from_utf8_lossy(&to_file.stderr)
  );
  assert_eq!(
    std::fs::read(&out_path).unwrap(),
    raw,
    "extracted -o bytes match"
  );

  // To stdout: the raw addon bytes are streamed verbatim.
  let to_stdout = abi(&["inspect", "--decompress", path.to_str().unwrap()]);
  assert!(to_stdout.status.success());
  assert_eq!(to_stdout.stdout, raw, "extracted stdout bytes match");

  std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_decompress_of_a_plain_file_reports_and_does_not_error() {
  let dir = std::env::temp_dir().join(format!("abitious-inspect-dp-{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  let plain = dir.join("plain.node");
  std::fs::write(&plain, b"already a raw addon").unwrap();
  let out = abi(&["inspect", "--decompress", plain.to_str().unwrap()]);
  assert!(
    out.status.success(),
    "plain --decompress must not error hard"
  );
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(stderr.contains("nothing to decompress"), "stderr: {stderr}");
  std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inspect_missing_file_fails_loud() {
  let out = abi(&["inspect", "/no/such/abi-inspect/missing.node"]);
  assert!(!out.status.success());
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("cannot read the .node file"),
    "stderr: {stderr}"
  );
  assert!(
    stderr.contains("Where:") && stderr.contains("Fix:"),
    "stderr: {stderr}"
  );
}

#[test]
fn inspect_decompress_to_an_unwritable_out_fails_loud() {
  // -o into a directory that does not exist → the extracted-addon write fails LOUD,
  // exercising the `--decompress -o` write-error arm.
  let (dir, path, _raw) = planted_hybrid("badout");
  let bad = dir.join("no-such-subdir").join("x.node");
  let out = abi(&[
    "inspect",
    "--decompress",
    path.to_str().unwrap(),
    "-o",
    bad.to_str().unwrap(),
  ]);
  assert!(!out.status.success(), "an unwritable -o must fail");
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(
    stderr.contains("cannot write the extracted addon"),
    "stderr: {stderr}"
  );
  std::fs::remove_dir_all(&dir).ok();
}
