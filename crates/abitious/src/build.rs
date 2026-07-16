//! `abi build` orchestration — the impure half that drives cargo and the producer.
//!
//! The flow ports napi-rs `build.ts` for the HOST triple (no cross matrix, no JS fallback):
//!
//! 1. `cargo build [--release] [-p <pkg>]` (inherit stderr, LOUD-fail on non-zero);
//! 2. `cargo metadata --format-version 1 --no-deps` → resolve the cdylib artifact path
//!    ([`crate::metadata::cdylib_artifact_path`], a pure fn);
//! 3. copy/rename the cdylib to `<name>.node` (or `--out`) — napi-rs `copyArtifact`;
//! 4. `--compress`: compress the `.node` in place into a self-loading hybrid via
//!    [`abitious_producer::compress_node`], printing its JSON receipt; else leave the raw
//!    `.node` and print a small build receipt (path + size).
//!
//! The path-decision helpers ([`artifact_path`], [`output_path`], [`build_receipt`]) are
//! pure and unit-tested against fixture metadata; the process spawning and file copy are
//! covered by the gated integration test.

use std::path::{Path, PathBuf};
use std::process::Command;

use abitious_producer::compress_node;

use crate::args::BuildArgs;
use crate::metadata::{cdylib_artifact_path, cdylib_target_name, node_output_name};
use crate::resolve::{resolve_stub as resolve_stub_in, stub_not_found_error};
use crate::triple::host_triple;

/// The stub to inject when compressing: the explicit `--stub` if given, else the prebuilt
/// stub auto-resolved from an installed `@abitious/<host-triple>` package (walking up from
/// `cwd`). LOUD-fails naming the exact package when neither is available.
fn resolve_stub(args: &BuildArgs, cwd: &Path) -> Result<PathBuf, String> {
    if let Some(stub) = &args.stub {
        return Ok(stub.clone());
    }
    let triple = host_triple();
    resolve_stub_in(cwd, &triple).ok_or_else(|| stub_not_found_error(&triple, cwd))
}

/// Run `abi build` in `cwd`. On success returns the line to print (the producer's JSON
/// receipt when compressing, else a small build receipt); on failure a LOUD error string.
pub fn run(args: &BuildArgs, cwd: &Path) -> Result<String, String> {
    // Resolve the stub UP FRONT when compressing — before the expensive cargo build — so a
    // missing stub fails fast with an actionable message rather than after a full compile.
    let resolved_stub = if args.compress {
        Some(resolve_stub(args, cwd)?)
    } else {
        None
    };

    let cargo = cargo_bin();
    cargo_build(&cargo, args, cwd)?;

    let meta_json = cargo_metadata(&cargo, cwd)?;
    let artifact = artifact_path(&meta_json, args)?;
    if !artifact.exists() {
        return Err(fail(
            "the built cdylib artifact is missing",
            &artifact.display().to_string(),
            "cargo build reported success but the expected artifact is not there",
            "confirm the crate declares `crate-type = [\"cdylib\"]` and check the \
             --release / -p flags match the build.",
        ));
    }
    let dest = output_path(&meta_json, args, cwd)?;

    copy_artifact(&artifact, &dest)?;

    if args.compress {
        // Resolved above (explicit `--stub` or auto-resolved `@abitious/<triple>`).
        let stub = resolved_stub
            .as_ref()
            .expect("stub resolved above whenever compress is set");
        let receipt =
            compress_node(&dest, stub, &dest, args.compress_level).map_err(|e| e.to_string())?;
        Ok(receipt.to_json())
    } else {
        let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        Ok(build_receipt(&dest, size))
    }
}

/// Resolve the cdylib artifact path from the metadata, or a LOUD error naming the fix.
/// Pure: the caller does the on-disk existence check.
pub fn artifact_path(meta_json: &str, args: &BuildArgs) -> Result<PathBuf, String> {
    cdylib_artifact_path(meta_json, args.package.as_deref(), args.release).ok_or_else(|| {
        fail(
            "could not resolve a cdylib artifact to build",
            "cargo metadata",
            "no package with a `crate-type = [\"cdylib\"]` target was found (or the choice \
             was ambiguous)",
            "run in a napi crate dir, or pass -p <package> to pick one in a workspace.",
        )
    })
}

/// The output `.node` path: `--out` if given, else `<cdylib name>.node` in `cwd`. Pure.
pub fn output_path(meta_json: &str, args: &BuildArgs, cwd: &Path) -> Result<PathBuf, String> {
    if let Some(out) = &args.out {
        return Ok(out.clone());
    }
    let name = cdylib_target_name(meta_json, args.package.as_deref()).ok_or_else(|| {
        fail(
            "could not name the output .node",
            "cargo metadata",
            "no cdylib target name was found for the selected package",
            "pass --out <path>, or -p <package> to select the cdylib crate.",
        )
    })?;
    Ok(cwd.join(node_output_name(&name)))
}

/// A small one-line JSON build receipt for the non-compress path: the output path, its
/// size, and `compressed:false`. Pure.
pub fn build_receipt(path: &Path, size: u64) -> String {
    format!(
        "{{\"output\":{output},\"size\":{size},\"compressed\":false}}",
        output = json_string(&path.display().to_string()),
    )
}

/// The cargo binary: honor `CARGO` (set when a cargo subprocess spawns us), else `cargo`.
fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

/// `cargo build [--release] [-p <pkg>]` in `cwd`, inheriting stdout/stderr so cargo's own
/// diagnostics reach the user. LOUD-fails on a non-zero exit or a spawn error.
fn cargo_build(cargo: &str, args: &BuildArgs, cwd: &Path) -> Result<(), String> {
    let mut cmd = Command::new(cargo);
    cmd.arg("build").current_dir(cwd);
    if args.release {
        cmd.arg("--release");
    }
    if let Some(pkg) = &args.package {
        cmd.arg("-p").arg(pkg);
    }
    let status = cmd.status().map_err(|e| {
        fail(
            "could not run `cargo build`",
            cargo,
            &e.to_string(),
            "ensure cargo is installed and on PATH.",
        )
    })?;
    if !status.success() {
        return Err(fail(
            "`cargo build` failed",
            cargo,
            &format!("exit {status}"),
            "fix the compile errors cargo printed above, then re-run `abi build`.",
        ));
    }
    Ok(())
}

/// `cargo metadata --format-version 1 --no-deps` in `cwd`, capturing stdout (the JSON).
/// LOUD-fails on a spawn error or a non-zero exit (stderr echoed into the error).
fn cargo_metadata(cargo: &str, cwd: &Path) -> Result<String, String> {
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(cwd)
        .output()
        .map_err(|e| {
            fail(
                "could not run `cargo metadata`",
                cargo,
                &e.to_string(),
                "ensure cargo is installed and on PATH.",
            )
        })?;
    if !out.status.success() {
        return Err(fail(
            "`cargo metadata` failed",
            cargo,
            &String::from_utf8_lossy(&out.stderr),
            "run `cargo metadata` manually to see the error.",
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| {
        fail(
            "`cargo metadata` produced non-UTF-8 output",
            cargo,
            &e.to_string(),
            "this should not happen; report it.",
        )
    })
}

/// Copy `src` over `dest`, removing a stale `dest` first (napi-rs `copyArtifact`).
fn copy_artifact(src: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() {
        std::fs::remove_file(dest).map_err(|e| {
            fail(
                "could not remove the stale output",
                &dest.display().to_string(),
                &e.to_string(),
                "check the output path is writable.",
            )
        })?;
    }
    std::fs::copy(src, dest).map_err(|e| {
        fail(
            "could not copy the cdylib artifact",
            &format!("{} -> {}", src.display(), dest.display()),
            &e.to_string(),
            "check the source artifact exists and the output dir is writable.",
        )
    })?;
    Ok(())
}

/// A four-ingredient LOUD error: What / Where / Saw / Fix.
fn fail(what: &str, where_: &str, saw: &str, fix: &str) -> String {
    format!(
        "abi: {what}.\n  \
         Where: {where_}\n  \
         Saw:   {saw}\n  \
         Fix:   {fix}"
    )
}

/// Minimal JSON string encoding for a path in a receipt (quotes + the escapes a path can
/// contain).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::BuildArgs;

    fn fixture() -> &'static str {
        r#"{
            "target_directory": "/work/target",
            "packages": [
                { "name": "my-addon", "targets": [
                    { "name": "my_addon", "crate_types": ["cdylib"] }
                ] }
            ]
        }"#
    }

    #[test]
    fn artifact_path_resolves_from_metadata() {
        let args = BuildArgs {
            release: true,
            ..BuildArgs::default()
        };
        let p = artifact_path(fixture(), &args).expect("resolves");
        assert!(p.starts_with("/work/target/release"));
        assert!(p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("my_addon"));
    }

    #[test]
    fn artifact_path_errors_loud_when_absent() {
        let json = r#"{ "target_directory": "/t", "packages": [] }"#;
        let err = artifact_path(json, &BuildArgs::default()).unwrap_err();
        assert!(err.contains("could not resolve a cdylib artifact"));
        assert!(err.contains("Where:") && err.contains("Fix:"));
    }

    #[test]
    fn output_path_prefers_explicit_out() {
        let args = BuildArgs {
            out: Some(PathBuf::from("/somewhere/custom.node")),
            ..BuildArgs::default()
        };
        assert_eq!(
            output_path(fixture(), &args, Path::new("/cwd")).unwrap(),
            PathBuf::from("/somewhere/custom.node")
        );
    }

    #[test]
    fn output_path_defaults_to_cwd_node_name() {
        let out = output_path(fixture(), &BuildArgs::default(), Path::new("/cwd")).unwrap();
        assert_eq!(out, PathBuf::from("/cwd/my_addon.node"));
    }

    #[test]
    fn output_path_errors_when_name_unresolvable() {
        let json = r#"{ "target_directory": "/t", "packages": [] }"#;
        let err = output_path(json, &BuildArgs::default(), Path::new("/cwd")).unwrap_err();
        assert!(err.contains("could not name the output .node"));
    }

    #[test]
    fn build_receipt_is_json_with_path_and_size() {
        let r = build_receipt(Path::new("/out/my_addon.node"), 4096);
        assert!(r.contains("\"output\":\"/out/my_addon.node\""));
        assert!(r.contains("\"size\":4096"));
        assert!(r.contains("\"compressed\":false"));
    }

    #[test]
    fn json_string_escapes_specials() {
        assert_eq!(json_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_string("tab\there"), "\"tab\\there\"");
    }
}
