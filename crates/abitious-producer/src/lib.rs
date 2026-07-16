//! `abitious-producer` — the host build-time producer LIBRARY.
//!
//! [`compress_node`] reads a real built `.node` addon and a prebuilt generic stub `.node`,
//! compresses the addon into a frozen pressed-data section, injects it into the stub's
//! signable `SMOL/__PRESSED_DATA` section (ad-hoc re-signed on macOS so the section stays
//! signature-covered), and atomically writes a single self-loading hybrid `.node`,
//! returning a [`Receipt`]. Node `dlopen`s the hybrid, the stub self-extracts the real
//! addon, and forwards registration to it.
//!
//! Both the `abitious-producer` BIN and the `abi` CLI (`crates/abitious`) drive this one
//! function, so the compress/inject/sign/write logic lives here once and never diverges.
//! Every failure is a [`ProducerError`] whose `Display` is a LOUD What / Where / Saw / Fix
//! message; the write is atomic (temp + rename) so a crash never leaves a partial or
//! unsigned output at the final path.

// cargo-llvm-cov (nightly) sets `coverage_nightly`, enabling `#[coverage(off)]` on the
// in-module test block so the report reflects PRODUCTION coverage. A no-op on stable.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::fmt;
use std::path::{Path, PathBuf};

use abitious_decmpfs::{
    build_section_payload, inject_pressed_data, pressed_data_cache_key, Arch, InjectError, Libc,
    Platform, HEADER_LEN,
};

/// zstd level knob. 16 is a fast, high-ratio default; 22 is the smallest blob when build
/// time does not matter. [`compress_node`] clamps its `level` to this inclusive range.
pub const DEFAULT_LEVEL: i32 = 16;
/// Minimum accepted zstd level (inclusive).
pub const MIN_LEVEL: i32 = 1;
/// Maximum accepted zstd level (inclusive).
pub const MAX_LEVEL: i32 = 22;

/// A machine-readable record of one `compress_node` run: the inputs, the raw/compressed
/// sizes, the content-address, and the stamped target triple. [`Receipt::to_json`] renders
/// the one-line JSON the `abitious-producer` bin and the `abi` CLI print to stdout.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// The raw `.node` addon that was compressed.
    pub input: PathBuf,
    /// The prebuilt generic stub the section was injected into.
    pub stub: PathBuf,
    /// The self-loading hybrid `.node` that was written.
    pub output: PathBuf,
    /// The raw addon's size in bytes.
    pub raw_size: usize,
    /// The zstd payload's size in bytes (the section tail past the fixed header).
    pub compressed_size: usize,
    /// Lowercase hex of the 16-byte cache key (first 16 bytes of SHA-256 over the addon).
    pub cache_key: String,
    /// The host OS the addon targets.
    pub platform: Platform,
    /// The host CPU the addon targets.
    pub arch: Arch,
    /// The host libc the addon targets (`na` off Linux).
    pub libc: Libc,
}

impl Receipt {
    /// A one-line JSON receipt: inputs, sizes, the content-address, and the stamped target.
    /// Field names are camelCase (`rawSize`, `compressedSize`, `cacheKey`) so the output
    /// matches the `napi-compress` producer's receipt shape.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"input\":{input},\"stub\":{stub},\"output\":{output},\
             \"rawSize\":{raw_size},\"compressedSize\":{compressed_size},\
             \"cacheKey\":\"{cache_key}\",\"platform\":\"{plat}\",\"arch\":\"{arch}\",\
             \"libc\":\"{libc}\"}}",
            input = json_str(&self.input.display().to_string()),
            stub = json_str(&self.stub.display().to_string()),
            output = json_str(&self.output.display().to_string()),
            raw_size = self.raw_size,
            compressed_size = self.compressed_size,
            cache_key = self.cache_key,
            plat = platform_name(self.platform),
            arch = arch_name(self.arch),
            libc = libc_name(self.libc),
        )
    }
}

impl fmt::Display for Receipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json())
    }
}

/// Everything `compress_node` can fail at, in step order. Each variant carries the path it
/// was working on plus the underlying cause; `Display` renders the LOUD What / Where / Saw
/// / Fix message both the bin and the `abi` CLI print on stderr.
#[derive(Debug)]
pub enum ProducerError {
    /// The raw `.node` addon could not be read.
    ReadRaw {
        /// The addon path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The prebuilt stub could not be read.
    ReadStub {
        /// The stub path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Injecting the pressed-data section into the stub failed.
    Inject {
        /// The stub the section could not be injected into.
        stub: PathBuf,
        /// The underlying injection error.
        source: InjectError,
    },
    /// The hybrid output could not be written.
    Write {
        /// The output path that failed to write.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

impl fmt::Display for ProducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProducerError::ReadRaw { path, source } => fail(
                f,
                "cannot read the raw addon",
                &path.display().to_string(),
                &source.to_string(),
                "pass the path to the built .node addon.",
            ),
            ProducerError::ReadStub { path, source } => fail(
                f,
                "cannot read the prebuilt stub",
                &path.display().to_string(),
                &source.to_string(),
                "build it with `cargo build -p abitious-stub --release` and pass the .dylib/.node.",
            ),
            ProducerError::Inject { stub, source } => fail(
                f,
                "section injection failed",
                &stub.display().to_string(),
                &source.to_string(),
                "the stub must be a 64-bit Mach-O/ELF/PE with header slack \
                 (abitious-stub is built with -headerpad,0x1000).",
            ),
            ProducerError::Write { path, source } => fail(
                f,
                "cannot write the output",
                &path.display().to_string(),
                &source.to_string(),
                "check the output directory exists and is writable.",
            ),
        }
    }
}

impl std::error::Error for ProducerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProducerError::ReadRaw { source, .. } | ProducerError::ReadStub { source, .. } => {
                Some(source)
            }
            ProducerError::Inject { source, .. } => Some(source),
            ProducerError::Write { source, .. } => Some(source),
        }
    }
}

/// Read `raw_node` + `stub` → compress the addon into a pressed-data section → inject it
/// (+ ad-hoc re-sign on macOS) → atomically write the hybrid to `out` → return a
/// [`Receipt`]. `level` is clamped to `[MIN_LEVEL, MAX_LEVEL]`. Fails LOUD (via
/// [`ProducerError`]) at the first step that cannot complete and never leaves a partial
/// output at `out`.
pub fn compress_node(
    raw_node: &Path,
    stub: &Path,
    out: &Path,
    level: i32,
) -> Result<Receipt, ProducerError> {
    let raw = std::fs::read(raw_node).map_err(|source| ProducerError::ReadRaw {
        path: raw_node.to_path_buf(),
        source,
    })?;
    let stub_bytes = std::fs::read(stub).map_err(|source| ProducerError::ReadStub {
        path: stub.to_path_buf(),
        source,
    })?;

    let (platform, arch, libc) = (Platform::detect(), Arch::detect(), Libc::detect());
    let level = level.clamp(MIN_LEVEL, MAX_LEVEL);
    let section = build_section_payload(&raw, platform, arch, libc, level);

    // inject_pressed_data dispatches on the stub's format; the Mach-O arm ad-hoc re-signs
    // internally (the `resign` feature), so the injected section stays signature-covered.
    let hybrid =
        inject_pressed_data(&stub_bytes, &section).map_err(|source| ProducerError::Inject {
            stub: stub.to_path_buf(),
            source,
        })?;

    write_atomic(out, &hybrid).map_err(|source| ProducerError::Write {
        path: out.to_path_buf(),
        source,
    })?;

    // The section is `HEADER_LEN` framing + the zstd payload (abitious always emits
    // has_config = 0), so the compressed size is the tail past the fixed header.
    let compressed_size = section.len().saturating_sub(HEADER_LEN);
    let cache_key = pressed_data_cache_key(&section)
        .map(hex)
        .unwrap_or_default();
    Ok(Receipt {
        input: raw_node.to_path_buf(),
        stub: stub.to_path_buf(),
        output: out.to_path_buf(),
        raw_size: raw.len(),
        compressed_size,
        cache_key,
        platform,
        arch,
        libc,
    })
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

/// Render a four-ingredient LOUD error: What / Where / Saw / Fix.
fn fail(f: &mut fmt::Formatter<'_>, what: &str, where_: &str, saw: &str, fix: &str) -> fmt::Result {
    write!(
        f,
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use abitious_decmpfs::{unwrap_if_hybrid, MAGIC_MARKER};

    /// A minimal valid ELF64 LE stub with a `.shstrtab` + 2-entry section table — enough
    /// for `inject_elf` (dispatched by `inject_pressed_data`) to grow. No signing needed.
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
        e[4] = 2; // 64-bit
        e[5] = 1; // little-endian
        e[6] = 1; // version
        put_u64(&mut e, 40, shoff as u64); // e_shoff
        put_u16(&mut e, 58, 64); // e_shentsize
        put_u16(&mut e, 60, 2); // e_shnum
        put_u16(&mut e, 62, 1); // e_shstrndx
        e[64..64 + shstr.len()].copy_from_slice(shstr);
        let sh1 = shoff + 64;
        put_u32(&mut e, sh1, 1); // sh_name -> ".shstrtab"
        put_u32(&mut e, sh1 + 4, 3); // sh_type = SHT_STRTAB
        put_u64(&mut e, sh1 + 24, 64); // sh_offset
        put_u64(&mut e, sh1 + 32, shstr.len() as u64); // sh_size
        e
    }

    /// A scratch dir unique to one test; the test removes exactly this named dir.
    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "abitious-producer-lib-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn compress_node_writes_a_round_tripping_hybrid_and_receipt() {
        let dir = scratch_dir("roundtrip");
        let raw_bytes = b"\x7fELF the real abitious addon payload!".repeat(50);
        let raw = dir.join("addon.node");
        std::fs::write(&raw, &raw_bytes).expect("write raw");
        let stub = dir.join("stub.node");
        std::fs::write(&stub, minimal_elf64()).expect("write stub");
        let out = dir.join("hybrid.node");

        let receipt = compress_node(&raw, &stub, &out, 9).expect("compress_node");

        // The receipt reports the inputs, the true raw size, and a 32-hex cache key.
        assert_eq!(receipt.input, raw);
        assert_eq!(receipt.stub, stub);
        assert_eq!(receipt.output, out);
        assert_eq!(receipt.raw_size, raw_bytes.len());
        assert!(receipt.compressed_size > 0);
        assert_eq!(receipt.cache_key.len(), 32);
        assert!(receipt.cache_key.chars().all(|c| c.is_ascii_hexdigit()));

        // The written hybrid round-trips back to the exact addon bytes.
        let hybrid = std::fs::read(&out).expect("read hybrid");
        assert_eq!(
            unwrap_if_hybrid(&hybrid).as_deref(),
            Some(raw_bytes.as_slice())
        );

        // The JSON receipt carries the expected fields.
        let json = receipt.to_json();
        assert!(json.contains("\"rawSize\":"));
        assert!(json.contains("\"compressedSize\":"));
        assert!(json.contains(&format!("\"cacheKey\":\"{}\"", receipt.cache_key)));
        assert_eq!(receipt.to_string(), json);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn level_is_clamped_into_range() {
        let dir = scratch_dir("clamp");
        let raw = dir.join("addon.node");
        std::fs::write(&raw, b"payload bytes to compress".repeat(10)).expect("write raw");
        let stub = dir.join("stub.node");
        std::fs::write(&stub, minimal_elf64()).expect("write stub");

        // Both an over-max and a below-min level produce a valid hybrid (clamped, no panic).
        for level in [i32::MIN, 0, MAX_LEVEL + 100, i32::MAX] {
            let out = dir.join(format!("hybrid-{level}.node"));
            let receipt = compress_node(&raw, &stub, &out, level).expect("compress_node clamps");
            let hybrid = std::fs::read(&out).expect("read hybrid");
            assert!(unwrap_if_hybrid(&hybrid).is_some());
            assert!(receipt.compressed_size > 0);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_raw_addon_is_a_loud_read_error() {
        let dir = scratch_dir("missing-raw");
        let missing = dir.join("nope.node");
        let stub = dir.join("stub.node");
        std::fs::write(&stub, minimal_elf64()).expect("write stub");
        let out = dir.join("hybrid.node");

        let err = compress_node(&missing, &stub, &out, 16).expect_err("missing raw must fail");
        assert!(matches!(err, ProducerError::ReadRaw { .. }));
        let msg = err.to_string();
        assert!(msg.contains("cannot read the raw addon"));
        assert!(msg.contains("Where:") && msg.contains("Saw:") && msg.contains("Fix:"));
        assert!(
            !out.exists(),
            "no output should be written on a read failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_stub_is_a_loud_read_error() {
        let dir = scratch_dir("missing-stub");
        let raw = dir.join("addon.node");
        std::fs::write(&raw, b"addon").expect("write raw");
        let missing_stub = dir.join("nope-stub.node");
        let out = dir.join("hybrid.node");

        let err = compress_node(&raw, &missing_stub, &out, 16).expect_err("missing stub fails");
        assert!(matches!(err, ProducerError::ReadStub { .. }));
        assert!(err.to_string().contains("cannot read the prebuilt stub"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_object_stub_is_a_loud_inject_error() {
        let dir = scratch_dir("bad-stub");
        let raw = dir.join("addon.node");
        std::fs::write(&raw, b"addon bytes").expect("write raw");
        let stub = dir.join("stub.node");
        std::fs::write(&stub, b"not an object file at all").expect("write junk stub");
        let out = dir.join("hybrid.node");

        let err = compress_node(&raw, &stub, &out, 16).expect_err("junk stub fails to inject");
        assert!(matches!(err, ProducerError::Inject { .. }));
        assert!(err.to_string().contains("section injection failed"));
        assert!(
            !out.exists(),
            "no output should be written on an inject failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_error_when_output_dir_is_missing() {
        let dir = scratch_dir("bad-out");
        let raw = dir.join("addon.node");
        std::fs::write(&raw, b"addon bytes").expect("write raw");
        let stub = dir.join("stub.node");
        std::fs::write(&stub, minimal_elf64()).expect("write stub");
        // A path whose parent directory does not exist → the atomic temp write fails.
        let out = dir.join("no-such-subdir").join("hybrid.node");

        let err = compress_node(&raw, &stub, &out, 16).expect_err("missing out dir fails");
        assert!(matches!(err, ProducerError::Write { .. }));
        assert!(err.to_string().contains("cannot write the output"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_uses_the_default_name_when_the_dest_has_no_file_name() {
        // A dest whose final component is `..` has a parent but no file_name(), so write_atomic
        // takes its `"out.node"` fallback name (the `unwrap_or_else` default arm). It still
        // reaches the temp write + rename; renaming over `..` then fails, so it returns Err —
        // the point is the otherwise-untaken default-name branch runs.
        let dir = scratch_dir("wa-noname");
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let no_name = sub.join(".."); // file_name() is None; parent() is `<dir>/sub` (non-empty)
        assert!(no_name.file_name().is_none(), "sanity: `..` has no file_name");
        assert!(
            write_atomic(&no_name, b"data").is_err(),
            "rename onto `..` must fail after the fallback name"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_json_escapes_paths_and_names_the_triple() {
        let receipt = Receipt {
            input: PathBuf::from("in put\".node"),
            stub: PathBuf::from("stub.node"),
            output: PathBuf::from("out.node"),
            raw_size: 100,
            compressed_size: 42,
            cache_key: "abc123".to_string(),
            platform: Platform::Linux,
            arch: Arch::X64,
            libc: Libc::Musl,
        };
        let json = receipt.to_json();
        assert!(json.contains("\\\"")); // the quote in the input path is escaped
        assert!(json.contains("\"rawSize\":100"));
        assert!(json.contains("\"compressedSize\":42"));
        assert!(json.contains("\"platform\":\"linux\""));
        assert!(json.contains("\"arch\":\"x64\""));
        assert!(json.contains("\"libc\":\"musl\""));
    }

    #[test]
    fn to_json_names_every_platform_arch_and_libc() {
        // Cover every name-mapping arm (the host e2e only exercises darwin/arm64/na).
        let cases = [
            (
                Platform::Linux,
                Arch::X64,
                Libc::Glibc,
                "linux",
                "x64",
                "glibc",
            ),
            (
                Platform::Linux,
                Arch::Ia32,
                Libc::Musl,
                "linux",
                "ia32",
                "musl",
            ),
            (
                Platform::Darwin,
                Arch::Arm64,
                Libc::Na,
                "darwin",
                "arm64",
                "na",
            ),
            (Platform::Win32, Arch::Arm, Libc::Na, "win32", "arm", "na"),
        ];
        for (platform, arch, libc, pname, aname, lname) in cases {
            let receipt = Receipt {
                input: PathBuf::from("in.node"),
                stub: PathBuf::from("stub.node"),
                output: PathBuf::from("out.node"),
                raw_size: 1,
                compressed_size: 1,
                cache_key: "00".to_string(),
                platform,
                arch,
                libc,
            };
            let json = receipt.to_json();
            assert!(
                json.contains(&format!("\"platform\":\"{pname}\"")),
                "{json}"
            );
            assert!(json.contains(&format!("\"arch\":\"{aname}\"")), "{json}");
            assert!(json.contains(&format!("\"libc\":\"{lname}\"")), "{json}");
        }
    }

    #[test]
    fn to_json_escapes_every_special_character() {
        // Drive every arm of the private json_str escaper via a path with each special.
        let receipt = Receipt {
            input: PathBuf::from("a\\b\nc\rd\te\u{0001}f\"g"),
            stub: PathBuf::from("s"),
            output: PathBuf::from("o"),
            raw_size: 0,
            compressed_size: 0,
            cache_key: String::new(),
            platform: Platform::Darwin,
            arch: Arch::Arm64,
            libc: Libc::Na,
        };
        let json = receipt.to_json();
        assert!(json.contains("a\\\\b")); // backslash
        assert!(json.contains("\\n")); // newline
        assert!(json.contains("\\r")); // carriage return
        assert!(json.contains("\\t")); // tab
        assert!(json.contains("\\u0001")); // control char
        assert!(json.contains("\\\"g")); // quote
    }

    #[test]
    fn producer_error_source_is_the_underlying_cause() {
        use std::error::Error as _;
        let io = || std::io::Error::other("x");
        assert!(ProducerError::ReadRaw {
            path: PathBuf::from("p"),
            source: io(),
        }
        .source()
        .is_some());
        assert!(ProducerError::ReadStub {
            path: PathBuf::from("p"),
            source: io(),
        }
        .source()
        .is_some());
        assert!(ProducerError::Write {
            path: PathBuf::from("p"),
            source: io(),
        }
        .source()
        .is_some());
        // An Inject error's source is the InjectError (obtained from a real junk-stub run).
        let dir = scratch_dir("source-inject");
        let raw = dir.join("a.node");
        std::fs::write(&raw, b"x").unwrap();
        let stub = dir.join("s.node");
        std::fs::write(&stub, b"not an object").unwrap();
        let err = compress_node(&raw, &stub, &dir.join("o.node"), 16).unwrap_err();
        assert!(err.source().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_only_section_has_empty_cache_key_never_panics() {
        // pressed_data_cache_key returns None on a too-short/garbage blob; hex().unwrap_or_default
        // must yield an empty key rather than panic. Exercised indirectly: a real run always has
        // the marker, but assert the helper contract here for the receipt's `.unwrap_or_default()`.
        assert!(pressed_data_cache_key(&MAGIC_MARKER[..4]).is_none());
    }
}
