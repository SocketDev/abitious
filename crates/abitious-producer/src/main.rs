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
// cargo-llvm-cov (nightly) sets `coverage_nightly`, enabling `#[coverage(off)]` on the
// in-module test block so the report reflects PRODUCTION coverage. A no-op on stable.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::path::PathBuf;
use std::process::ExitCode;

use abitious_producer::{compress_node, DEFAULT_LEVEL, MAX_LEVEL, MIN_LEVEL};

#[derive(Debug)]
struct Args {
    raw: PathBuf,
    stub: PathBuf,
    out: PathBuf,
    level: i32,
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
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

/// Parse `argv`, compress the addon into a hybrid, and return the one-line JSON receipt — or
/// a LOUD error string. Split from `main` so the arg-parse / dispatch / compress-error arms
/// are unit-tested in-process without spawning the binary; `main` only maps the `Result` to
/// a process exit (and prints), preserving the exact CLI behavior + exit codes.
fn run<I: IntoIterator<Item = String>>(argv: I) -> Result<String, String> {
    let args = parse_args(argv)?;
    let receipt =
        compress_node(&args.raw, &args.stub, &args.out, args.level).map_err(|e| e.to_string())?;
    Ok(receipt.to_json())
}

/// Positional `<raw-addon> <stub>` plus `-o/--output <out>` and an optional `--level <n>`.
/// Hand-rolled (no clap) — the invocation shape is fixed and validated here.
fn parse_args<I: IntoIterator<Item = String>>(argv: I) -> Result<Args, String> {
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut level = DEFAULT_LEVEL;
    let mut argv = argv.into_iter();
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn parse(parts: &[&str]) -> Result<Args, String> {
        parse_args(argv(parts))
    }

    #[test]
    fn parses_positionals_out_and_level() {
        let a = parse(&["raw.node", "stub.node", "-o", "out.node", "--level", "19"]).unwrap();
        assert_eq!(a.raw, PathBuf::from("raw.node"));
        assert_eq!(a.stub, PathBuf::from("stub.node"));
        assert_eq!(a.out, PathBuf::from("out.node"));
        assert_eq!(a.level, 19);
    }

    #[test]
    fn output_long_flag_and_default_level() {
        let a = parse(&["raw.node", "stub.node", "--output", "out.node"]).unwrap();
        assert_eq!(a.out, PathBuf::from("out.node"));
        assert_eq!(a.level, DEFAULT_LEVEL);
    }

    #[test]
    fn level_is_clamped_into_the_producer_range() {
        assert_eq!(
            parse(&["r", "s", "-o", "o", "--level", "100"])
                .unwrap()
                .level,
            MAX_LEVEL
        );
        assert_eq!(
            parse(&["r", "s", "-o", "o", "--level", "-5"])
                .unwrap()
                .level,
            MIN_LEVEL
        );
    }

    #[test]
    fn missing_output_is_an_error() {
        let err = parse(&["raw.node", "stub.node"]).unwrap_err();
        assert!(err.contains("missing -o"), "{err}");
    }

    #[test]
    fn output_flag_without_value_is_an_error() {
        let err = parse(&["raw.node", "stub.node", "-o"]).unwrap_err();
        assert!(err.contains("-o needs a value"), "{err}");
    }

    #[test]
    fn level_without_value_is_an_error() {
        let err = parse(&["r", "s", "-o", "o", "--level"]).unwrap_err();
        assert!(err.contains("--level needs a value"), "{err}");
    }

    #[test]
    fn non_integer_level_is_an_error() {
        let err = parse(&["r", "s", "-o", "o", "--level", "abc"]).unwrap_err();
        assert!(err.contains("not an integer"), "{err}");
    }

    #[test]
    fn unknown_flag_is_an_error() {
        let err = parse(&["r", "s", "-o", "o", "--nope"]).unwrap_err();
        assert!(err.contains("unknown flag"), "{err}");
    }

    #[test]
    fn help_flag_is_reported_as_usage() {
        for flag in ["-h", "--help"] {
            let err = parse(&[flag]).unwrap_err();
            assert!(
                err.contains("abitious-producer") && err.contains("Where:"),
                "{err}"
            );
        }
    }

    #[test]
    fn wrong_positional_count_is_an_error() {
        // Too few and too many positionals both fail the exactly-2-path requirement.
        assert!(parse(&["only-one", "-o", "o"])
            .unwrap_err()
            .contains("expected 2 positional"));
        assert!(parse(&["a", "b", "c", "-o", "o"])
            .unwrap_err()
            .contains("expected 2 positional"));
    }

    #[test]
    fn a_lone_dash_is_treated_as_a_positional() {
        // `-` is not a flag (the `other != "-"` guard) → it counts as a positional path.
        let a = parse(&["-", "stub.node", "-o", "out.node"]).unwrap();
        assert_eq!(a.raw, PathBuf::from("-"));
        assert_eq!(a.stub, PathBuf::from("stub.node"));
    }

    #[test]
    fn run_surfaces_a_compress_error_for_a_missing_addon() {
        // parse succeeds; compress_node fails to read the nonexistent raw addon → run maps it
        // to a LOUD error string (the ProducerError Display), never a panic.
        let dir = std::env::temp_dir().join(format!(
            "abitious-producer-bin-run-err-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("nope.node");
        let stub = dir.join("stub.node");
        std::fs::write(&stub, b"stub").unwrap();
        let out = dir.join("out.node");
        let err = run(argv(&[
            raw.to_str().unwrap(),
            stub.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ]))
        .unwrap_err();
        assert!(err.contains("cannot read the raw addon"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_compresses_a_minimal_stub_and_returns_a_receipt() {
        // A full happy path in-process: a minimal ELF stub + a raw addon compress into a
        // hybrid; run returns the JSON receipt. No cc/node needed (see the lib tests).
        let dir = std::env::temp_dir().join(format!(
            "abitious-producer-bin-run-ok-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("addon.node");
        std::fs::write(&raw, b"\x7fELF the raw addon payload".repeat(20)).unwrap();
        let stub = dir.join("stub.node");
        std::fs::write(&stub, minimal_elf64()).unwrap();
        let out = dir.join("hybrid.node");
        let receipt = run(argv(&[
            raw.to_str().unwrap(),
            stub.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--level",
            "9",
        ]))
        .expect("run compresses a minimal stub");
        assert!(
            receipt.contains("\"cacheKey\":\"") && receipt.contains("\"rawSize\":"),
            "{receipt}"
        );
        assert!(out.exists(), "the hybrid was written");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A minimal valid ELF64 stub (matching the producer lib's test helper) — enough for
    /// `inject_pressed_data` to grow a section onto; no signing needed.
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
}
