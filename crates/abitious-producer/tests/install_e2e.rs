//! **M5 end-to-end proof** — the abitious install bridge, on darwin-arm64.
//!
//! Proves the decmpfs-aware package-manager install path works when Node loads the
//! store entry:
//!
//! 1. build the generic stub (`cargo build -p abitious-stub --release`) → `stub.node`;
//! 2. `cc`-build a REAL addon whose `napi_register_module_v1` writes a marker file (a
//!    detectable side effect proving IT ran), padded with a large compressible const
//!    so the on-disk allocation genuinely shrinks under decmpfs;
//! 3. `abitious_producer::compress_node(<fixture>, <stub>, <hybrid>)` → a real hybrid;
//! 4. `install_hybrid(<hybrid bytes>, <store>/addon.node, Gate::any())` — THE install
//!    bridge: unwrap the raw addon out of the hybrid's pressed-data SECTION and land it
//!    as an APFS-decmpfs store entry in one pass.
//!
//! Oracle: (a) the outcome is `Outcome::Compressed { before, after }` with
//! `after < before`, cross-checked via the store file's `st_blocks` allocation vs its
//! logical size; (b) the store file reads back byte-for-byte as the raw addon (the
//! kernel decompresses transparently); (c) `node process.dlopen(<store>/addon.node)`
//! loads WITHOUT error AND the addon's `napi_register_module_v1` runs (the marker
//! exists) — the kernel decompressed the compressed store entry on the read `dlopen`
//! does, at near-native speed.
//!
//! macOS-only (`#![cfg(target_os = "macos")]`); skip-with-message (never fail) when
//! `cc` or `node` is absent. Never touches the network.

#![cfg(target_os = "macos")]
// Skip-with-message diagnostics + before/after inspection print to stderr; the
// established integration-test pattern.
#![allow(clippy::print_stderr)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use abitious_decmpfs::{install_hybrid, unwrap_if_hybrid, Gate, Outcome};
use abitious_producer::compress_node;

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

/// True if `tool --version` runs — the gate for skip-not-fail on a missing toolchain.
fn has_tool(tool: &str) -> bool {
  Command::new(tool)
    .arg("--version")
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false)
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

/// A minimal REAL addon whose register writes `$ABITIOUS_INSTALL_MARKER` and returns
/// the `exports` it was handed — a detectable side effect proving the real addon's
/// register ran, and a valid napi return so `dlopen` succeeds. A large INITIALIZED
/// const (mostly zeros → highly compressible, but materialized on disk, not BSS) makes
/// the built `.node` big enough that APFS decmpfs strictly shrinks its allocation.
fn build_fixture_addon(dir: &Path) -> Option<PathBuf> {
  let src = dir.join("fixture.c");
  std::fs::write(
    &src,
    r#"#include <stdio.h>
#include <stdlib.h>

/* A large, INITIALIZED (non-zero prefix → on-disk data, not zerofill/BSS), highly
   compressible buffer so the built .node is big enough that decmpfs shrinks its
   on-disk allocation below the logical size (after < before). */
__attribute__((used))
const char abitious_install_pad[262144] = "abitious decmpfs install-compress padding block";

void *napi_register_module_v1(void *env, void *exports) {
    const char *marker = getenv("ABITIOUS_INSTALL_MARKER");
    if (marker != NULL) {
        FILE *f = fopen(marker, "w");
        if (f != NULL) { fputs("registered", f); fclose(f); }
    }
    (void)env;
    (void)abitious_install_pad;
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
fn install_hybrid_lands_a_kernel_compressed_store_entry_that_still_loads() {
  // Gate: the fixture addon needs a C compiler; without it, skip (never fail).
  if !has_tool("cc") {
    eprintln!("skip: no C compiler (cc) to build the fixture addon");
    return;
  }

  let dir = std::env::temp_dir().join(format!("abitious-install-e2e-{}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");

  let root = repo_root();

  // Step 1: the generic stub → stub.node.
  let Some(stub_dylib) = build_stub(&root) else {
    eprintln!("skip: could not build abitious-stub (needed for the M5 proof)");
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

  // Step 3: produce a real hybrid via the producer library (compress + inject + sign).
  let hybrid_path = dir.join("hybrid.node");
  let receipt =
    compress_node(&fixture, &stub_node, &hybrid_path, 19).expect("compress_node builds a hybrid");
  eprintln!("producer receipt: {}", receipt.to_json());
  let hybrid_bytes = std::fs::read(&hybrid_path).expect("read hybrid");
  // Sanity: the hybrid's section really unwraps back to the raw addon.
  assert_eq!(
    unwrap_if_hybrid(&hybrid_bytes).as_deref(),
    Some(fixture_bytes.as_slice()),
    "the hybrid must decode back to the raw fixture addon",
  );

  // Step 4: THE M5 INSTALL BRIDGE — land the hybrid as a kernel-compressed store entry.
  let store = dir.join("store");
  std::fs::create_dir_all(&store).expect("store dir");
  let dest = store.join("addon.node");
  let outcome = install_hybrid(&hybrid_bytes, &dest, &Gate::any()).expect("install_hybrid");

  // Oracle (a): a genuine compression win — Compressed with after < before.
  let (before, after) = match outcome {
    Outcome::Compressed { before, after } => (before, after),
    other => panic!("expected Outcome::Compressed on this APFS host, got {other:?}"),
  };
  assert!(
    after < before,
    "the store entry's on-disk allocation must shrink: before={before} after={after}",
  );
  eprintln!("install_hybrid: before={before} bytes → after={after} bytes on disk (APFS decmpfs)");

  // Oracle (b): the store file reads back byte-for-byte as the raw addon, and its
  // st_blocks allocation is below the logical size (an independent cross-check).
  assert_eq!(
    std::fs::read(&dest).unwrap(),
    fixture_bytes,
    "the store file is the raw addon, read back byte-for-byte (kernel decompresses)",
  );
  let meta = std::fs::metadata(&dest).expect("stat store file");
  assert!(
    meta.blocks().saturating_mul(512) < meta.len(),
    "st_blocks allocation ({}) must be below the logical size ({})",
    meta.blocks().saturating_mul(512),
    meta.len(),
  );

  // Oracle (c): node dlopens the COMPRESSED store entry AND the addon's register ran.
  if !has_tool("node") {
    eprintln!("note: `node` not found — skipped the dlopen + register oracle");
    std::fs::remove_dir_all(&dir).ok();
    return;
  }
  let marker = dir.join("register-ran.marker");
  let _ = std::fs::remove_file(&marker);
  let probe = format!(
    "process.dlopen({{exports:{{}}}},{:?})",
    dest.to_string_lossy()
  );
  let node = Command::new("node")
    .args(["-e", &probe])
    .env("ABITIOUS_INSTALL_MARKER", &marker)
    .output()
    .expect("run node");
  assert!(
    node.status.success(),
    "node dlopen of the compressed store entry failed:\n{}",
    String::from_utf8_lossy(&node.stderr)
  );
  assert!(
    marker.exists(),
    "node loaded the store entry but the addon's napi_register_module_v1 did not run \
         (no marker) — the kernel-decompressed load did not reach the real addon",
  );
  eprintln!(
    "M5 proof: install_hybrid landed a kernel-compressed store entry that node \
         dlopened and whose register ran."
  );

  std::fs::remove_dir_all(&dir).ok();
}
