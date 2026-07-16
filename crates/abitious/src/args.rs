//! Hand-rolled argument parsing for the `abi` CLI (no clap — dep budget).
//!
//! The one subcommand is `build`:
//!
//! ```text
//! abi build [--compress] [--compress-level N] [--release]
//!           [--stub <path>] [-p <package>] [--out <path>]
//! ```
//!
//! [`parse`] is a pure transform from an argument iterator to a [`Command`], so every flag
//! path — including the M4 rule that `--compress` requires `--stub` and the rejection of a
//! non-integer `--compress-level` — is covered by unit tests without spawning anything.

use std::path::PathBuf;

use abitious_producer::DEFAULT_LEVEL;

/// A parsed CLI invocation.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// `abi build …` with its resolved options.
    Build(BuildArgs),
    /// `-h` / `--help` (or `abi` with no subcommand): print usage and exit 0.
    Help,
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
    /// The prebuilt generic stub `.node`; REQUIRED when `--compress` is set (M4).
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
                         [--stub <path>] [-p <package>] [--out <path>]";

/// Parse `argv` (the arguments AFTER the program name) into a [`Command`]. Returns a LOUD
/// What / Where / Fix error string on any malformed invocation.
pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Command, String> {
    let mut it = argv.into_iter();
    let sub = match it.next() {
        Some(s) => s,
        None => return Ok(Command::Help),
    };
    match sub.as_str() {
        "-h" | "--help" => return Ok(Command::Help),
        "build" => {}
        other => {
            return Err(usage(&format!(
                "unknown subcommand {other:?} (expected `build`)"
            )));
        }
    }

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

    // M4: compressing needs an explicit stub. Auto `@abitious/<triple>` resolution is M6.
    if args.compress && args.stub.is_none() {
        return Err(fail(
            "`--compress` needs a stub",
            "auto stub resolution (@abitious/<triple>) is not implemented yet",
            "pass --stub <path> to the prebuilt stub .node for this host \
             (e.g. `cargo build -p abitious-stub --release`).",
        ));
    }

    Ok(Command::Build(args))
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

/// A LOUD `What / Where / Fix` error for a semantic (not syntactic) problem.
fn fail(what: &str, where_: &str, fix: &str) -> String {
    format!(
        "abi: {what}.\n  \
         Where: {where_}\n  \
         Fix:   {fix}"
    )
}

#[cfg(test)]
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
    fn compress_without_stub_errors() {
        let err = parse(args(&["build", "--compress"])).unwrap_err();
        assert!(err.contains("`--compress` needs a stub"));
        assert!(err.contains("--stub"));
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
}
