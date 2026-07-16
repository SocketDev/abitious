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
