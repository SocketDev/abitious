//! **M3 end-to-end proof** — the self-extracting `dlopen` path, on darwin-arm64.
//!
//! Drives the real producer BINARY and the real stub cdylib, then proves the whole hybrid
//! flow works when Node loads it:
//!
//! 1. build the generic stub (`cargo build -p abitious-stub --release`) → `stub.node`;
//! 2. `cc`-build a minimal REAL addon whose `napi_register_module_v1` writes a marker file
//!    (a detectable side effect proving IT ran, not the stub);
//! 3. run `abitious-producer <fixture.node> <stub.node> -o <hybrid.node>`;
//! 4. ORACLE — `unwrap_if_hybrid(<hybrid>)` recovers the fixture bytes byte-for-byte;
//!    `codesign -v <hybrid>` is clean (the injected section is signature-covered); and
//!    `node process.dlopen(<hybrid>)` loads WITHOUT error AND the marker file exists —
//!    i.e. the stub self-extracted the section, `dlopen`ed the cache, and forwarded
//!    `napi_register_module_v1` into the real addon, which ran.
//!
//! macOS-only (`#![cfg(target_os = "macos")]`); skip-with-message (never fail) when `cc`,
//! `codesign`, or `node` is absent. Never touches the network.

#![cfg(target_os = "macos")]
// Skip-with-message diagnostics + producer receipt inspection print to stderr; the
// established integration-test pattern.
#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;

use abitious_decmpfs::unwrap_if_hybrid;

/// Repo root: crates/abitious-producer/ → up two.
fn repo_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .ancestors()
    .nth(2)
    .expect("repo root")
    .to_path_buf()
}

/// The cargo target directory (honors `CARGO_TARGET_DIR`, else `<root>/target`).
fn target_dir(root: &Path) -> PathBuf {
  std::env::var_os("CARGO_TARGET_DIR")
    .map(PathBuf::from)
    .unwrap_or_else(|| root.join("target"))
}

/// Build the generic stub cdylib and return the `libabitious_stub.dylib` path.
fn build_stub(root: &Path) -> Option<PathBuf> {
  let status = Command::new(env!("CARGO"))
    .args(["build", "-p", "abitious-stub", "--release"])
    .current_dir(root)
    .status()
    .ok()?;
  if !status.success() {
    return None;
  }
  let dylib = target_dir(root).join("release/libabitious_stub.dylib");
  dylib.exists().then_some(dylib)
}

/// A minimal REAL addon whose register writes `$ABITIOUS_E2E_MARKER` and returns the
/// `exports` it was handed — a detectable side effect that proves the real addon's
/// register actually ran (via the stub's self-extract → dlopen → forward), and a valid
/// napi return so Node's `dlopen` succeeds. No headerpad needed: the fixture is carried as
/// compressed PAYLOAD, never surgically injected.
fn build_fixture_addon(dir: &Path) -> Option<PathBuf> {
  let src = dir.join("fixture.c");
  std::fs::write(
    &src,
    r#"#include <stdio.h>
#include <stdlib.h>
void *napi_register_module_v1(void *env, void *exports) {
    const char *marker = getenv("ABITIOUS_E2E_MARKER");
    if (marker != NULL) {
        FILE *f = fopen(marker, "w");
        if (f != NULL) { fputs("registered", f); fclose(f); }
    }
    (void)env;
    return exports;
}
"#,
  )
  .ok()?;
  let out = dir.join("fixture.node");
  let status = Command::new("cc")
    .args(["-bundle", "-undefined", "dynamic_lookup", "-o"])
    .arg(&out)
    .arg(&src)
    .status()
    .ok()?;
  status.success().then_some(out)
}

#[test]
fn hybrid_self_extracts_and_forwards_registration_under_node() {
  let dir = std::env::temp_dir().join(format!("abitious-e2e-{}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");

  let root = repo_root();

  // Step 1: the generic stub → stub.node.
  let Some(stub_dylib) = build_stub(&root) else {
    eprintln!("skip: could not build abitious-stub (needed for the M3 proof)");
    std::fs::remove_dir_all(&dir).ok();
    return;
  };
  let stub_node = dir.join("stub.node");
  std::fs::copy(&stub_dylib, &stub_node).expect("copy stub -> stub.node");

  // Step 2: the real fixture addon.
  let Some(fixture) = build_fixture_addon(&dir) else {
    eprintln!("skip: no C compiler (cc) to build the fixture addon");
    std::fs::remove_dir_all(&dir).ok();
    return;
  };
  let fixture_bytes = std::fs::read(&fixture).expect("read fixture");

  // Step 3: run the producer to build the hybrid.
  let hybrid = dir.join("hybrid.node");
  let producer = env!("CARGO_BIN_EXE_abitious-producer");
  let out = Command::new(producer)
    .arg(&fixture)
    .arg(&stub_node)
    .arg("-o")
    .arg(&hybrid)
    .output()
    .expect("run abitious-producer");
  assert!(
    out.status.success(),
    "producer failed:\n{}",
    String::from_utf8_lossy(&out.stderr)
  );
  let receipt = String::from_utf8_lossy(&out.stdout);
  eprintln!("producer receipt: {}", receipt.trim());
  assert!(
    receipt.contains("\"cacheKey\":\"") && receipt.contains("\"rawSize\":"),
    "receipt missing expected JSON fields: {receipt}"
  );

  // Oracle (a): the section round-trips back to the exact fixture bytes.
  let hybrid_bytes = std::fs::read(&hybrid).expect("read hybrid");
  assert_eq!(
    unwrap_if_hybrid(&hybrid_bytes).as_deref(),
    Some(fixture_bytes.as_slice()),
    "the hybrid's SMOL/__PRESSED_DATA section must decode back to the fixture addon",
  );

  // Oracle (b): the injected section is code-signature-covered.
  match Command::new("codesign").arg("-v").arg(&hybrid).status() {
    Ok(cs) => assert!(cs.success(), "codesign -v must pass on the hybrid .node"),
    Err(_) => eprintln!("note: `codesign` not found — skipped the signature oracle"),
  }

  // Oracle (c): node dlopens the hybrid AND the fixture's register ran. The marker file
  // is written by the fixture's register — its existence proves the self-extract →
  // dlopen → forward path executed the REAL addon.
  let marker = dir.join("register-ran.marker");
  let _ = std::fs::remove_file(&marker);
  let probe = format!(
    "process.dlopen({{exports:{{}}}},{:?})",
    hybrid.to_string_lossy()
  );
  match Command::new("node")
    .args(["-e", &probe])
    .env("ABITIOUS_E2E_MARKER", &marker)
    .output()
  {
    Ok(node) => {
      assert!(
        node.status.success(),
        "node dlopen of the hybrid failed:\n{}",
        String::from_utf8_lossy(&node.stderr)
      );
      assert!(
        marker.exists(),
        "node loaded the hybrid but the fixture's napi_register_module_v1 did not \
                 run (no marker) — the self-extract/forward path did not reach the real addon",
      );
      eprintln!("M3 proof: node dlopened the hybrid and the fixture register ran.");
    }
    Err(_) => eprintln!("note: `node` not found — skipped the dlopen + forward oracle"),
  }

  std::fs::remove_dir_all(&dir).ok();
}
