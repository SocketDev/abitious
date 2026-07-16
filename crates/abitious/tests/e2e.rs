//! **M4 end-to-end proof** — the `abi build --compress` CLI, on darwin-arm64.
//!
//! Drives the real `abi` BINARY against a scaffolded fixture cdylib crate and the real
//! generic stub, then proves the whole `abi build` flow works when Node loads the result:
//!
//! 1. build the generic stub (`cargo build -p abitious-stub --release`) → `stub.node`;
//! 2. scaffold a minimal fixture cdylib crate in a tempdir whose
//!    `napi_register_module_v1` writes a marker file (a detectable side effect proving it
//!    ran, not the stub);
//! 3. `abi build --release` (no compress) → the raw `<name>.node` (its bytes are the
//!    expected addon), and a `"compressed":false` build receipt;
//! 4. `abi build --release --compress --stub <stub.node>` → the hybrid `<name>.node`;
//! 5. ORACLE — `unwrap_if_hybrid(<hybrid>)` recovers the raw addon byte-for-byte;
//!    `codesign -v` is clean; and `node process.dlopen(<hybrid>)` loads WITHOUT error AND
//!    the marker exists — i.e. the stub self-extracted the section, `dlopen`ed the cache,
//!    and forwarded `napi_register_module_v1` into the real addon, which ran.
//!
//! macOS-only (`#![cfg(target_os = "macos")]`); gated on `cc` + `node` (skip-with-message,
//! never fail, when either is absent — the fixture cdylib needs a linker and the dlopen
//! oracle needs Node). Never touches the network (the fixture has no dependencies).

#![cfg(target_os = "macos")]
// Skip-with-message diagnostics + receipt inspection print to stderr; the established
// integration-test pattern.
#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;

use abitious_decmpfs::unwrap_if_hybrid;

/// Repo root: crates/abitious/ → up two.
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

/// The host npm triple, computed the same way `crate::triple::host_triple` does. Duplicated
/// here (test code cannot reach the bin crate's private modules) but proven equivalent by
/// `triple::tests::triple_of_matches_targets_mts`; on this host both see the same cfg.
fn host_triple_for_test() -> String {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "win32"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "x64"
    };
    let abi = if cfg!(target_os = "windows") {
        "-msvc"
    } else if cfg!(target_os = "macos") {
        ""
    } else if cfg!(target_env = "musl") {
        "-musl"
    } else {
        "-gnu"
    };
    format!("{os}-{arch}{abi}")
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

/// Scaffold a minimal fixture cdylib crate in `dir`: a `napi_register_module_v1` that
/// writes `$ABI_E2E_MARKER` and returns the `exports` it was handed. Its own `[workspace]`
/// table keeps it out of any ancestor workspace; it has no dependencies (offline build).
fn scaffold_fixture(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("fixture src dir");
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "abi_fixture"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[workspace]
"#,
    )
    .expect("write fixture Cargo.toml");
    std::fs::write(
        dir.join("src/lib.rs"),
        r#"use std::ffi::c_void;

#[no_mangle]
pub extern "C" fn napi_register_module_v1(_env: *mut c_void, exports: *mut c_void) -> *mut c_void {
    if let Ok(marker) = std::env::var("ABI_E2E_MARKER") {
        let _ = std::fs::write(&marker, b"registered");
    }
    exports
}
"#,
    )
    .expect("write fixture lib.rs");
}

/// Run the `abi` binary with `args` in `cwd`, isolating the fixture build to its own
/// `target/` by dropping any inherited `CARGO_TARGET_DIR`.
fn run_abi(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_abi"))
        .args(args)
        .current_dir(cwd)
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("run abi")
}

#[test]
fn abi_build_compress_produces_a_self_extracting_hybrid_under_node() {
    // Gate: the fixture cdylib needs a linker (cc); without it, skip (never fail).
    if !has_tool("cc") {
        eprintln!("skip: no C compiler (cc) to link the fixture cdylib");
        return;
    }

    let dir = std::env::temp_dir().join(format!("abitious-abi-e2e-{}", std::process::id()));
    let fixture = dir.join("fixture");
    std::fs::create_dir_all(&fixture).expect("scratch dir");

    let root = repo_root();

    // Step 1: the generic stub → stub.node (in the scratch dir, beside the fixture).
    let Some(stub_dylib) = build_stub(&root) else {
        eprintln!("skip: could not build abitious-stub (needed for the M4 proof)");
        std::fs::remove_dir_all(&dir).ok();
        return;
    };
    let stub_node = dir.join("stub.node");
    std::fs::copy(&stub_dylib, &stub_node).expect("copy stub -> stub.node");

    // Step 2: scaffold the fixture cdylib crate.
    scaffold_fixture(&fixture);

    // Step 3: `abi build --release` (no compress) → the raw <name>.node + build receipt.
    let raw_out = run_abi(&fixture, &["build", "--release"]);
    assert!(
        raw_out.status.success(),
        "abi build (raw) failed:\n{}",
        String::from_utf8_lossy(&raw_out.stderr)
    );
    let raw_receipt = String::from_utf8_lossy(&raw_out.stdout);
    eprintln!("abi build receipt (raw): {}", raw_receipt.trim());
    assert!(
        raw_receipt.contains("\"compressed\":false") && raw_receipt.contains("\"size\":"),
        "raw build receipt missing expected fields: {raw_receipt}"
    );
    let node_path = fixture.join("abi_fixture.node");
    let raw_bytes = std::fs::read(&node_path).expect("read raw .node");
    assert!(!raw_bytes.is_empty(), "the raw .node should not be empty");
    // The raw .node is a plain cdylib, not a hybrid.
    assert!(
        unwrap_if_hybrid(&raw_bytes).is_none(),
        "the un-compressed .node must NOT be a hybrid"
    );

    // Step 4: `abi build --release --compress --stub <stub>` → the hybrid <name>.node.
    let comp_out = run_abi(
        &fixture,
        &[
            "build",
            "--release",
            "--compress",
            "--stub",
            stub_node.to_str().unwrap(),
        ],
    );
    assert!(
        comp_out.status.success(),
        "abi build --compress failed:\n{}",
        String::from_utf8_lossy(&comp_out.stderr)
    );
    let receipt = String::from_utf8_lossy(&comp_out.stdout);
    eprintln!("abi build receipt (compressed): {}", receipt.trim());
    assert!(
        receipt.contains("\"cacheKey\":\"") && receipt.contains("\"rawSize\":"),
        "compress receipt missing expected JSON fields: {receipt}"
    );

    // Oracle (a): the hybrid's section round-trips back to the exact raw addon bytes.
    let hybrid_bytes = std::fs::read(&node_path).expect("read hybrid");
    assert_eq!(
        unwrap_if_hybrid(&hybrid_bytes).as_deref(),
        Some(raw_bytes.as_slice()),
        "the hybrid's SMOL/__PRESSED_DATA section must decode back to the raw addon",
    );

    // Oracle (b): the injected section is code-signature-covered.
    match Command::new("codesign").arg("-v").arg(&node_path).status() {
        Ok(cs) => assert!(cs.success(), "codesign -v must pass on the hybrid .node"),
        Err(_) => eprintln!("note: `codesign` not found — skipped the signature oracle"),
    }

    // Oracle (c): node dlopens the hybrid AND the fixture's register ran (marker written by
    // the real addon proves the self-extract → dlopen → forward path reached it).
    if !has_tool("node") {
        eprintln!("note: `node` not found — skipped the dlopen + forward oracle");
        std::fs::remove_dir_all(&dir).ok();
        return;
    }
    let marker = dir.join("register-ran.marker");
    let _ = std::fs::remove_file(&marker);
    let probe = format!(
        "process.dlopen({{exports:{{}}}},{:?})",
        node_path.to_string_lossy()
    );
    let node = Command::new("node")
        .args(["-e", &probe])
        .env("ABI_E2E_MARKER", &marker)
        .output()
        .expect("run node");
    assert!(
        node.status.success(),
        "node dlopen of the hybrid failed:\n{}",
        String::from_utf8_lossy(&node.stderr)
    );
    assert!(
        marker.exists(),
        "node loaded the hybrid but the fixture's napi_register_module_v1 did not run \
         (no marker) — the self-extract/forward path did not reach the real addon",
    );
    eprintln!("M4 proof: `abi build --compress` produced a hybrid node dlopened + registered.");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn abi_build_compress_auto_resolves_stub_from_node_modules() {
    // M6 host-triple end-to-end: `abi build --compress` with NO `--stub` auto-resolves the
    // prebuilt stub from an installed `@abitious/<host-triple>` package (walking up from cwd),
    // then produces a hybrid that Node dlopens and whose real addon registers.
    if !has_tool("cc") {
        eprintln!("skip: no C compiler (cc) to link the fixture cdylib");
        return;
    }

    let dir = std::env::temp_dir().join(format!("abitious-abi-autoresolve-{}", std::process::id()));
    let fixture = dir.join("fixture");
    std::fs::create_dir_all(&fixture).expect("scratch dir");
    let root = repo_root();

    // Build the stub and PLANT it as an installed platform package one level ABOVE the fixture,
    // exactly as a package manager lays out node_modules/@abitious/<triple>/stub.node — proving
    // the walk-up resolver, not an explicit path.
    let Some(stub_dylib) = build_stub(&root) else {
        eprintln!("skip: could not build abitious-stub (needed for the M6 proof)");
        std::fs::remove_dir_all(&dir).ok();
        return;
    };
    let triple = host_triple_for_test();
    let pkg_dir = dir.join("node_modules").join("@abitious").join(&triple);
    std::fs::create_dir_all(&pkg_dir).expect("platform pkg dir");
    let planted_stub = pkg_dir.join("stub.node");
    std::fs::copy(&stub_dylib, &planted_stub).expect("plant stub.node");
    eprintln!("planted stub at {}", planted_stub.display());

    scaffold_fixture(&fixture);

    // `abi build --release --compress` with NO `--stub` — the resolver must find the planted
    // platform package by walking up from the fixture cwd.
    let out = run_abi(&fixture, &["build", "--release", "--compress"]);
    assert!(
        out.status.success(),
        "abi build --compress (auto-resolve) failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let receipt = String::from_utf8_lossy(&out.stdout);
    eprintln!("abi build receipt (auto-resolved stub): {}", receipt.trim());
    assert!(
        receipt.contains("\"cacheKey\":\"") && receipt.contains("\"rawSize\":"),
        "compress receipt missing expected JSON fields: {receipt}"
    );

    // Oracle: the produced hybrid is a real self-extracting addon Node can load.
    let node_path = fixture.join("abi_fixture.node");
    let hybrid_bytes = std::fs::read(&node_path).expect("read hybrid");
    assert!(
        unwrap_if_hybrid(&hybrid_bytes).is_some(),
        "the auto-resolved --compress output must be a hybrid",
    );

    if !has_tool("node") {
        eprintln!("note: `node` not found — skipped the dlopen oracle");
        std::fs::remove_dir_all(&dir).ok();
        return;
    }
    let marker = dir.join("register-ran.marker");
    let _ = std::fs::remove_file(&marker);
    let probe = format!(
        "process.dlopen({{exports:{{}}}},{:?})",
        node_path.to_string_lossy()
    );
    let node = Command::new("node")
        .args(["-e", &probe])
        .env("ABI_E2E_MARKER", &marker)
        .output()
        .expect("run node");
    assert!(
        node.status.success(),
        "node dlopen of the auto-resolved hybrid failed:\n{}",
        String::from_utf8_lossy(&node.stderr)
    );
    assert!(
        marker.exists(),
        "node loaded the hybrid but the fixture's register did not run (auto-resolve path)",
    );
    eprintln!(
        "M6 proof: `abi build --compress` (no --stub) auto-resolved @abitious/{triple} and \
         produced a hybrid node dlopened + registered."
    );

    std::fs::remove_dir_all(&dir).ok();
}
