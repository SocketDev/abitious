//! Hand-rolled argument parsing for the `abi` CLI (no clap — dep budget).
//!
//! Two subcommands:
//!
//! ```text
//! abi build   [--compress] [--compress-level N] [--release]
//!             [--stub <path>] [-p <package>] [--out <path>]
//! abi inspect <file.node> [--decompress] [--json] [-o <path>]
//! ```
//!
//! [`parse`] is a pure transform from an argument iterator to a [`Command`], so every flag
//! path — including the rejection of a non-integer `--compress-level` — is covered by unit
//! tests without spawning anything. As of M6, `--compress` no longer requires `--stub`: when
//! `--stub` is omitted the stub is auto-resolved from an installed `@abitious/<triple>`
//! package at build time ([`crate::resolve`]); `--stub` still overrides.

use std::path::PathBuf;

use abitious_producer::DEFAULT_LEVEL;

/// A parsed CLI invocation.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// `abi build …` with its resolved options.
    Build(BuildArgs),
    /// `abi inspect …` with its resolved options.
    Inspect(InspectArgs),
    /// `-h` / `--help` (or `abi` with no subcommand): print usage and exit 0.
    Help,
}

/// The options for `abi inspect`.
#[derive(Clone, Debug, PartialEq)]
pub struct InspectArgs {
    /// The `.node` file to inspect (hybrid or plain).
    pub file: PathBuf,
    /// Extract the raw addon out of the pressed-data section (via `unwrap_if_hybrid`).
    pub decompress: bool,
    /// Where `--decompress` writes the raw addon; `None` = stdout.
    pub out: Option<PathBuf>,
    /// Emit a machine-readable JSON report instead of the human report.
    pub json: bool,
}

/// The options for `abi build`.
#[derive(Clone, Debug, PartialEq)]
pub struct BuildArgs {
    /// Compress the built `.node` into a self-loading hybrid (requires [`Self::stub`]).
    pub compress: bool,
    /// zstd level for `--compress` (clamped to the producer's range when compressing).
    pub compress_level: i32,
    /// Build with `--release` (artifact under `target/release`).
    pub release: bool,
    /// The prebuilt generic stub `.node`. Optional: when omitted and `--compress` is set, it
    /// is auto-resolved from an installed `@abitious/<triple>` package ([`crate::resolve`]).
    pub stub: Option<PathBuf>,
    /// `cargo`/`-p` package to build in a workspace.
    pub package: Option<String>,
    /// Explicit output path for the `.node` (defaults to `<cdylib>.node`).
    pub out: Option<PathBuf>,
}

impl Default for BuildArgs {
    fn default() -> Self {
        BuildArgs {
            compress: false,
            compress_level: DEFAULT_LEVEL,
            release: false,
            stub: None,
            package: None,
            out: None,
        }
    }
}

/// The `abi` usage banner (the `Where:` line of every arg error, and `--help` output).
pub const USAGE: &str = "abi build [--compress] [--compress-level N] [--release] \
                         [--stub <path>] [-p <package>] [--out <path>]\n       \
                         abi inspect <file.node> [--decompress] [--json] [-o <path>]";

/// Parse `argv` (the arguments AFTER the program name) into a [`Command`]. Returns a LOUD
/// What / Where / Fix error string on any malformed invocation.
pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Command, String> {
    let mut it = argv.into_iter();
    let sub = match it.next() {
        Some(s) => s,
        None => return Ok(Command::Help),
    };
    match sub.as_str() {
        "-h" | "--help" => Ok(Command::Help),
        "build" => parse_build(it),
        "inspect" => parse_inspect(it),
        other => Err(usage(&format!(
            "unknown subcommand {other:?} (expected `build` or `inspect`)"
        ))),
    }
}

/// Parse the arguments after `abi build` into a [`Command::Build`].
fn parse_build<I: Iterator<Item = String>>(mut it: I) -> Result<Command, String> {
    let mut args = BuildArgs::default();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--compress" => args.compress = true,
            "--release" => args.release = true,
            "--compress-level" => {
                let value = it
                    .next()
                    .ok_or_else(|| usage("--compress-level needs a value"))?;
                args.compress_level = value.parse().map_err(|_| {
                    usage(&format!(
                        "--compress-level value {value:?} is not an integer"
                    ))
                })?;
            }
            "--stub" => {
                let value = it.next().ok_or_else(|| usage("--stub needs a value"))?;
                args.stub = Some(PathBuf::from(value));
            }
            "-p" | "--package" => {
                let value = it
                    .next()
                    .ok_or_else(|| usage(&format!("{arg} needs a value")))?;
                args.package = Some(value);
            }
            "--out" | "-o" => {
                let value = it
                    .next()
                    .ok_or_else(|| usage(&format!("{arg} needs a value")))?;
                args.out = Some(PathBuf::from(value));
            }
            "-h" | "--help" => return Ok(Command::Help),
            other => return Err(usage(&format!("unexpected argument {other:?}"))),
        }
    }

    // M6: `--compress` no longer requires `--stub` at parse time. When omitted, the stub is
    // auto-resolved from an installed `@abitious/<triple>` package during `build::run` (which
    // LOUD-fails there, naming the exact package, if none is found).
    Ok(Command::Build(args))
}

/// Parse the arguments after `abi inspect` into a [`Command::Inspect`]. Exactly one
/// positional `<file.node>` is required; `--decompress`/`-d`, `--json`, and `-o`/`--out`
/// are optional flags.
fn parse_inspect<I: Iterator<Item = String>>(mut it: I) -> Result<Command, String> {
    let mut file: Option<PathBuf> = None;
    let mut decompress = false;
    let mut out: Option<PathBuf> = None;
    let mut json = false;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--decompress" | "-d" => decompress = true,
            "--json" => json = true,
            "--out" | "-o" => {
                let value = it
                    .next()
                    .ok_or_else(|| usage(&format!("{arg} needs a value")))?;
                out = Some(PathBuf::from(value));
            }
            "-h" | "--help" => return Ok(Command::Help),
            other if other.starts_with('-') && other != "-" => {
                return Err(usage(&format!("unexpected argument {other:?}")));
            }
            _ => {
                if file.is_some() {
                    return Err(usage(&format!("unexpected extra path {arg:?}")));
                }
                file = Some(PathBuf::from(arg));
            }
        }
    }
    let file = file.ok_or_else(|| usage("inspect needs a <file.node> path"))?;
    Ok(Command::Inspect(InspectArgs {
        file,
        decompress,
        out,
        json,
    }))
}

/// A LOUD `What / Where / Fix` argument error anchored on the usage banner.
fn usage(detail: &str) -> String {
    format!(
        "abi: bad arguments.\n  \
         What:  {detail}\n  \
         Where: {USAGE}\n  \
         Fix:   check the flags above."
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn build(parts: &[&str]) -> BuildArgs {
        match parse(args(parts)) {
            Ok(Command::Build(b)) => b,
            other => panic!("expected Build, got {other:?}"),
        }
    }

    #[test]
    fn no_args_is_help() {
        assert_eq!(parse(args(&[])).unwrap(), Command::Help);
        assert_eq!(parse(args(&["-h"])).unwrap(), Command::Help);
        assert_eq!(parse(args(&["--help"])).unwrap(), Command::Help);
    }

    #[test]
    fn bare_build_uses_defaults() {
        assert_eq!(build(&["build"]), BuildArgs::default());
    }

    #[test]
    fn parses_every_flag() {
        let b = build(&[
            "build",
            "--release",
            "--compress",
            "--compress-level",
            "19",
            "--stub",
            "/tmp/stub.node",
            "-p",
            "my-addon",
            "--out",
            "/tmp/out.node",
        ]);
        assert!(b.release);
        assert!(b.compress);
        assert_eq!(b.compress_level, 19);
        assert_eq!(b.stub, Some(PathBuf::from("/tmp/stub.node")));
        assert_eq!(b.package, Some("my-addon".to_string()));
        assert_eq!(b.out, Some(PathBuf::from("/tmp/out.node")));
    }

    #[test]
    fn package_and_out_aliases() {
        assert_eq!(
            build(&["build", "--package", "x"]).package,
            Some("x".to_string())
        );
        assert_eq!(build(&["build", "-p", "y"]).package, Some("y".to_string()));
        assert_eq!(
            build(&["build", "-o", "a.node"]).out,
            Some(PathBuf::from("a.node"))
        );
        assert_eq!(
            build(&["build", "--out", "b.node"]).out,
            Some(PathBuf::from("b.node"))
        );
    }

    #[test]
    fn help_flag_after_build() {
        assert_eq!(parse(args(&["build", "--help"])).unwrap(), Command::Help);
    }

    #[test]
    fn compress_without_stub_is_allowed_at_parse_time() {
        // M6: parsing no longer rejects `--compress` without `--stub`; the stub is
        // auto-resolved (or LOUD-failed) at build time. Parse yields compress=true, stub=None.
        let b = build(&["build", "--compress"]);
        assert!(b.compress);
        assert_eq!(b.stub, None);
    }

    #[test]
    fn compress_with_stub_is_ok() {
        let b = build(&["build", "--compress", "--stub", "s.node"]);
        assert!(b.compress);
        assert_eq!(b.stub, Some(PathBuf::from("s.node")));
    }

    #[test]
    fn bad_compress_level_errors() {
        let err = parse(args(&["build", "--compress-level", "abc"])).unwrap_err();
        assert!(err.contains("not an integer"));
    }

    #[test]
    fn missing_flag_values_error() {
        assert!(parse(args(&["build", "--compress-level"])).is_err());
        assert!(parse(args(&["build", "--stub"])).is_err());
        assert!(parse(args(&["build", "-p"])).is_err());
        assert!(parse(args(&["build", "--out"])).is_err());
    }

    #[test]
    fn unknown_subcommand_and_flags_error() {
        assert!(parse(args(&["frobnicate"]))
            .unwrap_err()
            .contains("unknown subcommand"));
        let err = parse(args(&["build", "--nope"])).unwrap_err();
        assert!(err.contains("unexpected argument"));
    }

    #[test]
    fn stray_positional_errors() {
        assert!(parse(args(&["build", "extra"])).is_err());
    }

    #[test]
    fn negative_compress_level_parses_as_integer() {
        // Range clamping is the producer's job; parsing only rejects non-integers.
        assert_eq!(
            build(&["build", "--compress-level", "-5"]).compress_level,
            -5
        );
    }

    fn inspect(parts: &[&str]) -> InspectArgs {
        match parse(args(parts)) {
            Ok(Command::Inspect(i)) => i,
            other => panic!("expected Inspect, got {other:?}"),
        }
    }

    #[test]
    fn inspect_requires_a_file() {
        let err = parse(args(&["inspect"])).unwrap_err();
        assert!(err.contains("needs a <file.node>"), "{err}");
    }

    #[test]
    fn inspect_parses_the_file_and_flags() {
        let i = inspect(&["inspect", "hybrid.node"]);
        assert_eq!(i.file, PathBuf::from("hybrid.node"));
        assert!(!i.decompress && !i.json && i.out.is_none());

        let full = inspect(&[
            "inspect",
            "--decompress",
            "--json",
            "-o",
            "raw.node",
            "hybrid.node",
        ]);
        assert!(full.decompress && full.json);
        assert_eq!(full.out, Some(PathBuf::from("raw.node")));
        assert_eq!(full.file, PathBuf::from("hybrid.node"));

        // `-d` is the short alias for `--decompress`; the path can precede the flags.
        let short = inspect(&["inspect", "hybrid.node", "-d"]);
        assert!(short.decompress);
        assert_eq!(short.file, PathBuf::from("hybrid.node"));
    }

    #[test]
    fn inspect_rejects_extra_paths_unknown_flags_and_missing_values() {
        assert!(parse(args(&["inspect", "a.node", "b.node"]))
            .unwrap_err()
            .contains("unexpected extra path"));
        assert!(parse(args(&["inspect", "--nope", "a.node"]))
            .unwrap_err()
            .contains("unexpected argument"));
        assert!(parse(args(&["inspect", "a.node", "-o"])).is_err());
    }

    #[test]
    fn inspect_help_flag_returns_help() {
        assert_eq!(parse(args(&["inspect", "--help"])).unwrap(), Command::Help);
    }

    #[test]
    fn usage_names_both_subcommands() {
        assert!(USAGE.contains("abi build") && USAGE.contains("abi inspect"));
    }
}
