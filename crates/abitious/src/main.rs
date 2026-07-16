//! `abi` — the abitious build CLI.
//!
//! `abi build [--compress] [--compress-level N] [--release] [--stub <path>] [-p <package>]
//! [--out <path>]` cargo-builds a napi cdylib for the HOST triple, resolves its `.node`
//! artifact (porting napi-rs `build.ts`'s cdylib resolution), and — with `--compress` —
//! turns it into a self-loading hybrid `.node` via the shared
//! [`abitious_producer::compress_node`] library. No JS fallback, no cross matrix (that is
//! M6); every failure is a LOUD What / Where / Saw / Fix message.
//!
//! The parsing and path-resolution logic lives in pure, unit-tested modules ([`args`],
//! [`metadata`], [`json`]); [`build`] holds the process orchestration.

// stdout (receipts / usage) and stderr (LOUD errors) ARE this binary's interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod args;
mod build;
mod json;
mod metadata;

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
    }
}
