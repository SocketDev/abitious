//! `abi` — the abitious build/inspect CLI.
//!
//! Two subcommands:
//!
//! * `abi build [--compress] [--compress-level N] [--release] [--stub <path>] [-p <package>]
//!   [--out <path>]` cargo-builds a napi cdylib for the HOST triple, resolves its `.node`
//!   artifact (porting napi-rs `build.ts`'s cdylib resolution), and — with `--compress` —
//!   turns it into a self-loading hybrid `.node` via the shared
//!   [`abitious_producer::compress_node`] library (the stub auto-resolved from an installed
//!   `@abitious/<triple>` package, or `--stub`).
//! * `abi inspect <file.node> [--json] [--decompress [-o <path>]]` reports a hybrid's
//!   pressed-data section (sizes, cache key, target, integrity) or extracts the raw addon
//!   back out — a plain (non-hybrid) `.node` is reported plainly, not an error.
//!
//! Every failure is a LOUD What / Where / Saw / Fix message. The parsing and
//! path-resolution logic lives in pure, unit-tested modules ([`args`], [`metadata`],
//! [`json`]); [`build`] and [`inspect`] hold the process orchestration.

// stdout (receipts / usage) and stderr (LOUD errors) ARE this binary's interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]
// cargo-llvm-cov (nightly) sets `coverage_nightly`, enabling `#[coverage(off)]` on the
// in-module test blocks so the report reflects PRODUCTION coverage. A no-op on stable.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod args;
mod build;
mod inspect;
mod json;
mod metadata;
mod resolve;
mod triple;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::args::Command;

fn main() -> ExitCode {
    let cwd = current_working_dir();
    match run(
        std::env::args().skip(1),
        &cwd,
        &mut std::io::stdout().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Parse `argv` and dispatch to the subcommand, writing success output (usage / the build
/// receipt) to `out` and returning a LOUD error string on failure. Split from `main` so the
/// dispatch + error arms are unit-tested in-process without spawning the binary; `main` only
/// maps the `Result` to a process exit (printing errors to stderr), preserving the exact CLI
/// behavior + exit codes. `inspect` streams RAW addon bytes and self-prints to stdout, so it
/// writes there directly rather than through `out`.
fn run<W: Write>(
    argv: impl IntoIterator<Item = String>,
    cwd: &Path,
    out: &mut W,
) -> Result<(), String> {
    match args::parse(argv)? {
        Command::Help => {
            let _ = writeln!(out, "usage: {}", args::USAGE);
            Ok(())
        }
        Command::Build(build_args) => {
            let receipt = build::run(&build_args, cwd)?;
            let _ = writeln!(out, "{receipt}");
            Ok(())
        }
        Command::Inspect(inspect_args) => inspect::run(&inspect_args),
    }
}

/// The process working directory, or — on the (in-process-unreachable) failure — a LOUD
/// message to stderr and exit 1. Extracted and `coverage(off)` because `current_dir`
/// failing has no in-process trigger (a live process always has a cwd), so branching on it
/// is defensive; keeping it out of `run` leaves `run`'s dispatch fully unit-testable.
#[cfg_attr(coverage_nightly, coverage(off))]
fn current_working_dir() -> PathBuf {
    match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("abi: cannot determine the current directory.\n  Saw: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// Run the dispatcher, capturing what it writes to `out` (usage / receipt).
    fn run_capture(parts: &[&str], cwd: &Path) -> Result<String, String> {
        let mut out = Vec::<u8>::new();
        run(argv(parts), cwd, &mut out).map(|()| String::from_utf8(out).expect("utf8"))
    }

    #[test]
    fn help_writes_usage_to_the_writer() {
        let cwd = std::env::temp_dir();
        assert!(run_capture(&["--help"], &cwd)
            .unwrap()
            .contains("usage: abi build"));
        assert!(run_capture(&["-h"], &cwd)
            .unwrap()
            .contains("usage: abi build"));
        // Bare `abi` (no subcommand) also prints usage.
        assert!(run_capture(&[], &cwd).unwrap().contains("usage: abi build"));
    }

    #[test]
    fn a_parse_error_is_returned_as_a_loud_string() {
        let err = run_capture(&["frobnicate"], &std::env::temp_dir()).unwrap_err();
        assert!(err.contains("unknown subcommand"), "{err}");
    }

    #[test]
    fn a_build_error_propagates() {
        // `--compress` with no `--stub`, from an isolated cwd with no node_modules/@abitious
        // ancestry → build::run's stub resolution fails and run returns the LOUD error.
        let dir = std::env::temp_dir().join(format!("abi-main-build-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = run_capture(&["build", "--compress"], &dir).unwrap_err();
        assert!(
            err.contains("could not auto-resolve a prebuilt stub"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_inspect_error_propagates() {
        let err = run_capture(
            &["inspect", "/no/such/abi-main/missing.node"],
            &std::env::temp_dir(),
        )
        .unwrap_err();
        assert!(err.contains("cannot read the .node file"), "{err}");
    }

    #[test]
    fn an_inspect_success_returns_ok() {
        // A plain .node → inspect::run prints its report to stdout and returns Ok(()); the
        // dispatcher maps that to Ok (the Inspect arm self-prints, bypassing `out` by design).
        let dir = std::env::temp_dir().join(format!("abi-main-inspect-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain.node");
        std::fs::write(&plain, b"not a hybrid, just bytes").unwrap();
        assert!(run_capture(&["inspect", plain.to_str().unwrap()], &dir).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
