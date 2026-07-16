//! `abitious-producer` — the host build-time producer BINARY.
//!
//! A thin wrapper over [`abitious_producer::compress_node`]: parses
//! `abitious-producer <raw-addon.node> <stub.node> -o <out.node> [--level N]`, calls the
//! shared library to compress + inject + (macOS) ad-hoc re-sign + atomically write the
//! hybrid, and prints the resulting one-line JSON [`Receipt`](abitious_producer::Receipt)
//! on stdout. Fails LOUD (What / Where / Saw / Fix) on stderr, never leaving a partial or
//! unsigned output at the final path.
//!
//! The `abi` CLI (`crates/abitious`) drives the same `compress_node` library directly, so
//! this bin and the CLI never duplicate the compress/inject/sign logic.

// stdout (the JSON receipt) and stderr (the LOUD error) ARE this binary's interface — the
// producer is the one crate that opts into printing.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use abitious_producer::{compress_node, DEFAULT_LEVEL, MAX_LEVEL, MIN_LEVEL};

struct Args {
    raw: PathBuf,
    stub: PathBuf,
    out: PathBuf,
    level: i32,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    match compress_node(&args.raw, &args.stub, &args.out, args.level) {
        Ok(receipt) => {
            println!("{}", receipt.to_json());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

/// Positional `<raw-addon> <stub>` plus `-o/--output <out>` and an optional `--level <n>`.
/// Hand-rolled (no clap) — the invocation shape is fixed and validated here.
fn parse_args() -> Result<Args, String> {
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut level = DEFAULT_LEVEL;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-o" | "--output" => {
                let value = argv
                    .next()
                    .ok_or_else(|| usage(&format!("{arg} needs a value")))?;
                out = Some(PathBuf::from(value));
            }
            "--level" => {
                let value = argv.next().ok_or_else(|| usage("--level needs a value"))?;
                let parsed: i32 = value
                    .parse()
                    .map_err(|_| usage(&format!("--level value {value:?} is not an integer")))?;
                level = parsed.clamp(MIN_LEVEL, MAX_LEVEL);
            }
            "-h" | "--help" => return Err(usage("help requested")),
            other if other.starts_with('-') && other != "-" => {
                return Err(usage(&format!("unknown flag {other:?}")));
            }
            _ => positional.push(PathBuf::from(arg)),
        }
    }
    let out = out.ok_or_else(|| usage("missing -o <out.node>"))?;
    let [raw, stub] = <[PathBuf; 2]>::try_from(positional)
        .map_err(|got| usage(&format!("expected 2 positional paths, got {}", got.len())))?;
    Ok(Args {
        raw,
        stub,
        out,
        level,
    })
}

fn usage(detail: &str) -> String {
    format!(
        "abitious-producer: bad arguments.\n  \
         What:  {detail}\n  \
         Where: abitious-producer <raw-addon.node> <stub.node> -o <out.node> \
         [--level <{MIN_LEVEL}..={MAX_LEVEL}>]\n  \
         Fix:   pass the real addon, the prebuilt stub, and the output path."
    )
}
