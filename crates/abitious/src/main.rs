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

use std::process::ExitCode;

use crate::args::Command;

fn main() -> ExitCode {
    let command = match args::parse(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };

    match command {
        Command::Help => {
            println!("usage: {}", args::USAGE);
            ExitCode::SUCCESS
        }
        Command::Build(build_args) => {
            let cwd = match std::env::current_dir() {
                Ok(cwd) => cwd,
                Err(e) => {
                    eprintln!("abi: cannot determine the current directory.\n  Saw: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match build::run(&build_args, &cwd) {
                Ok(receipt) => {
                    println!("{receipt}");
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Inspect(inspect_args) => match inspect::run(&inspect_args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
    }
}
