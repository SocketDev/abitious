//! Lightweight `abitious-producer` binary smoke tests — always run (no cc/node needed).
//!
//! Drives the real producer BINARY for its fast paths — a minimal-stub success (the stdout
//! receipt + exit 0) and the arg-error / read-error failures (exit 1, LOUD stderr) — so
//! `main`'s success AND failure arms are exercised on every host, complementing the heavier
//! gated `e2e.rs`. The success path needs only a minimal ELF stub, so it runs without a C
//! compiler or Node.

#![allow(clippy::print_stderr)]

use std::process::{Command, Output};

fn producer(args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_abitious-producer"))
    .args(args)
    .output()
    .expect("run abitious-producer")
}

/// A minimal valid ELF64 stub with a `.shstrtab` + 2-entry section table — enough for
/// section injection to grow onto; no signing needed. Duplicated from the crate's test
/// helpers (an integration test cannot reach them).
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
  e[4] = 2;
  e[5] = 1;
  e[6] = 1;
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

#[test]
fn success_prints_a_receipt_and_exits_zero() {
  let dir = std::env::temp_dir().join(format!("abitious-producer-cli-ok-{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  let raw = dir.join("addon.node");
  std::fs::write(&raw, b"\x7fELF addon payload text ".repeat(16)).unwrap();
  let stub = dir.join("stub.node");
  std::fs::write(&stub, minimal_elf64()).unwrap();
  let out = dir.join("hybrid.node");

  let o = producer(&[
    raw.to_str().unwrap(),
    stub.to_str().unwrap(),
    "-o",
    out.to_str().unwrap(),
  ]);
  assert!(
    o.status.success(),
    "producer failed:\n{}",
    String::from_utf8_lossy(&o.stderr)
  );
  let stdout = String::from_utf8_lossy(&o.stdout);
  assert!(
    stdout.contains("\"cacheKey\":\"") && stdout.contains("\"rawSize\":"),
    "receipt missing fields: {stdout}"
  );
  assert!(out.exists(), "the hybrid was written");
  std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_output_flag_fails_loud() {
  let o = producer(&["raw.node", "stub.node"]);
  assert!(!o.status.success());
  let stderr = String::from_utf8_lossy(&o.stderr);
  assert!(stderr.contains("missing -o"), "stderr: {stderr}");
}

#[test]
fn bad_level_fails_loud() {
  let o = producer(&["r", "s", "-o", "o", "--level", "not-a-number"]);
  assert!(!o.status.success());
  let stderr = String::from_utf8_lossy(&o.stderr);
  assert!(stderr.contains("not an integer"), "stderr: {stderr}");
}

#[test]
fn missing_addon_fails_loud() {
  let dir = std::env::temp_dir().join(format!("abitious-producer-cli-miss-{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  let stub = dir.join("stub.node");
  std::fs::write(&stub, b"stub").unwrap();
  let out = dir.join("out.node");
  let missing = dir.join("nope.node");

  let o = producer(&[
    missing.to_str().unwrap(),
    stub.to_str().unwrap(),
    "-o",
    out.to_str().unwrap(),
  ]);
  assert!(!o.status.success());
  let stderr = String::from_utf8_lossy(&o.stderr);
  assert!(
    stderr.contains("cannot read the raw addon"),
    "stderr: {stderr}"
  );
  std::fs::remove_dir_all(&dir).ok();
}
