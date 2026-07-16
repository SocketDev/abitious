//! `abitious-producer` — the host build-time producer.
//!
//! Reads a real built `.node` addon and a prebuilt generic stub `.node`, compresses the
//! addon into a frozen pressed-data section, injects it into the stub's signable
//! `SMOL/__PRESSED_DATA` section (ad-hoc re-signed on macOS so the section stays
//! signature-covered), and writes a single self-loading hybrid `.node`. Node `dlopen`s
//! the hybrid, the stub self-extracts the real addon, and forwards registration to it.
//!
//! Usage: `abitious-producer <raw-addon.node> <stub.node> -o <out.node> [--level N]`.
//!
//! Emits a one-line JSON receipt on stdout and fails LOUD (What / Where / Saw / Fix) on
//! stderr, never leaving a partial or unsigned output at the final path.

// stdout (the JSON receipt) and stderr (the LOUD error) ARE this binary's interface — the
// producer is the one crate that opts into printing.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use abitious_decmpfs::{
    build_section_payload, inject_pressed_data, pressed_data_cache_key, Arch, Libc, Platform,
    HEADER_LEN,
};

/// zstd level knob. 16 is a fast, high-ratio default; 22 is the smallest blob when build
/// time does not matter. Clamped to this inclusive range.
const DEFAULT_LEVEL: i32 = 16;
const MIN_LEVEL: i32 = 1;
const MAX_LEVEL: i32 = 22;

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
    match run(&args) {
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

/// Read raw + stub → compress into a pressed-data section → inject (+ re-sign on macOS)
/// → atomic write → JSON receipt. Fails LOUD at the first step that cannot complete and
/// never leaves a partial output at `out`.
fn run(args: &Args) -> Result<String, String> {
    let raw = std::fs::read(&args.raw).map_err(|e| {
        fail(
            "cannot read the raw addon",
            &args.raw.display().to_string(),
            &e.to_string(),
            "pass the path to the built .node addon.",
        )
    })?;
    let stub = std::fs::read(&args.stub).map_err(|e| {
        fail(
            "cannot read the prebuilt stub",
            &args.stub.display().to_string(),
            &e.to_string(),
            "build it with `cargo build -p abitious-stub --release` and pass the .dylib/.node.",
        )
    })?;

    let (platform, arch, libc) = (Platform::detect(), Arch::detect(), Libc::detect());
    let section = build_section_payload(&raw, platform, arch, libc, args.level);

    // inject_pressed_data dispatches on the stub's format; the Mach-O arm ad-hoc re-signs
    // internally (the `resign` feature), so the injected section stays signature-covered.
    let hybrid = inject_pressed_data(&stub, &section).map_err(|e| {
        fail(
            "section injection failed",
            &args.stub.display().to_string(),
            &e.to_string(),
            "the stub must be a 64-bit Mach-O/ELF/PE with header slack \
             (abitious-stub is built with -headerpad,0x1000).",
        )
    })?;

    write_atomic(&args.out, &hybrid).map_err(|e| {
        fail(
            "cannot write the output",
            &args.out.display().to_string(),
            &e.to_string(),
            "check the output directory exists and is writable.",
        )
    })?;

    // The section is `HEADER_LEN` framing + the zstd payload (abitious always emits
    // has_config = 0), so the compressed size is the tail past the fixed header.
    let compressed = section.len().saturating_sub(HEADER_LEN);
    let cache_key = pressed_data_cache_key(&section)
        .map(hex)
        .unwrap_or_default();
    Ok(receipt(
        args,
        raw.len(),
        compressed,
        &cache_key,
        platform,
        arch,
        libc,
    ))
}

/// A one-line JSON receipt: inputs, sizes, the content-address, and the stamped target.
#[allow(clippy::too_many_arguments)]
fn receipt(
    args: &Args,
    raw_size: usize,
    compressed_size: usize,
    cache_key: &str,
    platform: Platform,
    arch: Arch,
    libc: Libc,
) -> String {
    format!(
        "{{\"input\":{input},\"stub\":{stub},\"output\":{output},\
         \"rawSize\":{raw_size},\"compressedSize\":{compressed_size},\
         \"cacheKey\":\"{cache_key}\",\"platform\":\"{plat}\",\"arch\":\"{arch}\",\
         \"libc\":\"{libc}\"}}",
        input = json_str(&args.raw.display().to_string()),
        stub = json_str(&args.stub.display().to_string()),
        output = json_str(&args.out.display().to_string()),
        plat = platform_name(platform),
        arch = arch_name(arch),
        libc = libc_name(libc),
    )
}

fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::Linux => "linux",
        Platform::Darwin => "darwin",
        Platform::Win32 => "win32",
    }
}

fn arch_name(a: Arch) -> &'static str {
    match a {
        Arch::X64 => "x64",
        Arch::Arm64 => "arm64",
        Arch::Ia32 => "ia32",
        Arch::Arm => "arm",
    }
}

fn libc_name(l: Libc) -> &'static str {
    match l {
        Libc::Glibc => "glibc",
        Libc::Musl => "musl",
        Libc::Na => "na",
    }
}

/// Lowercase hex of a byte slice — the cache-key content-address for the receipt.
fn hex(bytes: [u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Minimal JSON string encoding for a path — quotes plus the escapes a filesystem path
/// can plausibly contain (`\`, `"`, control chars). Enough for a machine-readable receipt.
fn json_str(s: &str) -> String {
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

/// A four-ingredient LOUD error: What / Where / Saw / Fix.
fn fail(what: &str, where_: &str, saw: &str, fix: &str) -> String {
    format!(
        "abitious-producer: {what}.\n  \
         Where: {where_}\n  \
         Saw:   {saw}\n  \
         Fix:   {fix}"
    )
}

/// Write to a sibling temp then rename over `out`, so a crash never leaves a half-written
/// (unsigned / unloadable) `.node` at the final path.
fn write_atomic(out: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = out.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let name = out
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out.node".to_string());
    let tmp = dir.join(format!(
        ".{name}.abitious-producer-{}.tmp",
        std::process::id()
    ));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, out)
}
