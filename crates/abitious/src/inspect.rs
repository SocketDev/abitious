//! `abi inspect` — report a hybrid `.node`'s pressed-data section, or extract its raw addon.
//!
//! `abi inspect <file.node>` finds and parses the pressed-data section
//! ([`abitious_decmpfs::inspect_hybrid`]) WITHOUT decompressing, then prints a human report
//! (or `--json`): magic present, compressed/uncompressed sizes + download savings, the
//! 16-byte cache key, the target platform/arch/libc, `has_config`, and whether the section's
//! SHA-512 integrity verifies. A plain (non-hybrid) `.node` is reported plainly rather than
//! erroring hard.
//!
//! `abi inspect --decompress <file.node> [-o <out>]` extracts the raw addon out of the
//! section (via [`abitious_decmpfs::unwrap_if_hybrid`], integrity-checked) to a file or
//! stdout. A plain `.node` is already the raw addon, so there is nothing to extract — that
//! is reported, not treated as an error.
//!
//! Output goes straight to stdout/stderr here (rather than returning a string like
//! `build::run`) because `--decompress` streams RAW addon BYTES to stdout, which are not a
//! `String`.

use std::io::Write;
use std::path::Path;

use abitious_decmpfs::{inspect_hybrid, unwrap_if_hybrid, Arch, Libc, Platform, SectionInfo};

use crate::args::InspectArgs;

/// Run `abi inspect`. Writes the report (or the extracted addon) to stdout / a file and
/// returns `Ok(())`; on failure returns a LOUD What / Where / Saw / Fix error string.
pub fn run(args: &InspectArgs) -> Result<(), String> {
    let bytes = std::fs::read(&args.file).map_err(|e| {
        fail(
            "cannot read the .node file",
            &args.file.display().to_string(),
            &e.to_string(),
            "pass the path to a .node file (a hybrid or a plain addon).",
        )
    })?;

    if args.decompress {
        return decompress(args, &bytes);
    }

    let report = match inspect_hybrid(&bytes) {
        Some(info) => {
            if args.json {
                json_report(&args.file, bytes.len(), &info)
            } else {
                human_report(&args.file, bytes.len(), &info)
            }
        }
        None => plain_report(&args.file, bytes.len(), args.json),
    };
    println!("{report}");
    Ok(())
}

/// `--decompress`: recover the raw addon and write it to `-o <out>` (or stdout). A plain
/// `.node` (or an integrity failure) yields no section to unwrap — reported clearly, exit 0.
fn decompress(args: &InspectArgs, bytes: &[u8]) -> Result<(), String> {
    let Some(raw) = unwrap_if_hybrid(bytes) else {
        // Not a hybrid (or the section failed its integrity check): a plain .node is already
        // the raw addon, so there is nothing to extract. Report clearly, do not error hard.
        eprintln!(
            "abi: {} is a plain .node (no valid pressed-data section) — it is already the raw \
             addon; nothing to decompress.",
            args.file.display()
        );
        return Ok(());
    };

    match &args.out {
        Some(out) => {
            std::fs::write(out, &raw).map_err(|e| {
                fail(
                    "cannot write the extracted addon",
                    &out.display().to_string(),
                    &e.to_string(),
                    "check the output directory exists and is writable.",
                )
            })?;
            eprintln!("abi: extracted {} bytes -> {}", raw.len(), out.display());
            Ok(())
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&raw)
                .and_then(|()| stdout.flush())
                .map_err(|e| {
                    fail(
                        "cannot write the extracted addon to stdout",
                        "<stdout>",
                        &e.to_string(),
                        "redirect stdout to a file, or pass -o <path>.",
                    )
                })
        }
    }
}

/// The human-readable report for a hybrid `.node`.
fn human_report(file: &Path, file_size: usize, info: &SectionInfo) -> String {
    let saved = info.uncompressed_size.saturating_sub(info.compressed_size);
    let pct_saved = if info.uncompressed_size > 0 {
        saved as f64 / info.uncompressed_size as f64 * 100.0
    } else {
        0.0
    };
    let integrity = if info.integrity_verified {
        "verified (SHA-512 matches)"
    } else {
        "MISMATCH — payload corrupt or tampered"
    };
    format!(
        "abitious hybrid .node: {file}\n  \
         file size:           {file_size} B\n  \
         pressed section:     present (magic OK)\n  \
         compressed addon:    {comp} B   (the download cost)\n  \
         uncompressed addon:  {uncomp} B   (self-extracted / installed size)\n  \
         download savings:    {saved} B   ({pct_saved:.1}% smaller to download)\n  \
         target:              platform={plat} arch={arch} libc={libc}\n  \
         cache key:           {key}\n  \
         has_config:          {cfg}\n  \
         integrity:           {integrity}",
        file = file.display(),
        comp = info.compressed_size,
        uncomp = info.uncompressed_size,
        plat = platform_name(info.platform, info.platform_byte),
        arch = arch_name(info.arch, info.arch_byte),
        libc = libc_name(info.libc, info.libc_byte),
        key = hex(&info.cache_key),
        cfg = info.has_config,
    )
}

/// The JSON report for a hybrid `.node`.
fn json_report(file: &Path, file_size: usize, info: &SectionInfo) -> String {
    format!(
        "{{\"file\":{file},\"fileSize\":{file_size},\"hybrid\":true,\"magic\":true,\
         \"compressedSize\":{comp},\"uncompressedSize\":{uncomp},\"cacheKey\":\"{key}\",\
         \"platform\":{plat},\"arch\":{arch},\"libc\":{libc},\
         \"platformByte\":{pb},\"archByte\":{ab},\"libcByte\":{lb},\
         \"hasConfig\":{cfg},\"integrityVerified\":{integ}}}",
        file = json_str(&file.display().to_string()),
        comp = info.compressed_size,
        uncomp = info.uncompressed_size,
        key = hex(&info.cache_key),
        plat = json_opt_name(
            info.platform
                .map(|_| platform_name(info.platform, info.platform_byte))
        ),
        arch = json_opt_name(info.arch.map(|_| arch_name(info.arch, info.arch_byte))),
        libc = json_opt_name(info.libc.map(|_| libc_name(info.libc, info.libc_byte))),
        pb = info.platform_byte,
        ab = info.arch_byte,
        lb = info.libc_byte,
        cfg = info.has_config,
        integ = info.integrity_verified,
    )
}

/// The report for a plain (non-hybrid) `.node`.
fn plain_report(file: &Path, file_size: usize, json: bool) -> String {
    if json {
        format!(
            "{{\"file\":{file},\"fileSize\":{file_size},\"hybrid\":false}}",
            file = json_str(&file.display().to_string()),
        )
    } else {
        format!(
            "plain .node (no pressed-data section): {file}\n  \
             file size:  {file_size} B\n  \
             This is a raw addon, not an abitious hybrid — `abi build --compress` wraps it.",
            file = file.display(),
        )
    }
}

fn platform_name(p: Option<Platform>, byte: u8) -> String {
    match p {
        Some(Platform::Linux) => "linux".to_string(),
        Some(Platform::Darwin) => "darwin".to_string(),
        Some(Platform::Win32) => "win32".to_string(),
        None => format!("unknown(0x{byte:02x})"),
    }
}

fn arch_name(a: Option<Arch>, byte: u8) -> String {
    match a {
        Some(Arch::X64) => "x64".to_string(),
        Some(Arch::Arm64) => "arm64".to_string(),
        Some(Arch::Ia32) => "ia32".to_string(),
        Some(Arch::Arm) => "arm".to_string(),
        None => format!("unknown(0x{byte:02x})"),
    }
}

fn libc_name(l: Option<Libc>, byte: u8) -> String {
    match l {
        Some(Libc::Glibc) => "glibc".to_string(),
        Some(Libc::Musl) => "musl".to_string(),
        Some(Libc::Na) => "na".to_string(),
        None => format!("unknown(0x{byte:02x})"),
    }
}

/// A recognized enum name becomes a JSON string; an unrecognized byte becomes `null`.
fn json_opt_name(name: Option<String>) -> String {
    match name {
        Some(n) => json_str(&n),
        None => "null".to_string(),
    }
}

/// A four-ingredient LOUD error: What / Where / Saw / Fix (matches `build::fail`).
fn fail(what: &str, where_: &str, saw: &str, fix: &str) -> String {
    format!(
        "abi: {what}.\n  \
         Where: {where_}\n  \
         Saw:   {saw}\n  \
         Fix:   {fix}"
    )
}

/// Lowercase hex of a byte slice — the cache-key content-address for the report.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Minimal JSON string encoding — quotes plus the escapes a path can contain (matches the
/// hand-rolled encoders in `build.rs` / the producer; dep budget rules out `serde_json`).
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use abitious_decmpfs::{build_section_payload, Arch, Libc, Platform};

    fn info_for(raw: &[u8], platform: Platform, arch: Arch, libc: Libc) -> SectionInfo {
        let section = build_section_payload(raw, platform, arch, libc, 16);
        abitious_decmpfs::read_section_info(&section).expect("valid section")
    }

    #[test]
    fn human_report_names_the_target_and_verifies_integrity() {
        let raw = vec![0x7bu8; 4000];
        let info = info_for(&raw, Platform::Darwin, Arch::Arm64, Libc::Na);
        let r = human_report(Path::new("addon.node"), 9000, &info);
        assert!(r.contains("abitious hybrid .node: addon.node"));
        assert!(r.contains("platform=darwin arch=arm64 libc=na"), "{r}");
        assert!(r.contains("uncompressed addon:  4000 B"), "{r}");
        assert!(r.contains("download savings:"), "{r}");
        assert!(r.contains("verified (SHA-512 matches)"), "{r}");
        assert!(r.contains("has_config:          false"), "{r}");
    }

    #[test]
    fn json_report_is_machine_readable_with_every_field() {
        let raw = vec![0x11u8; 2000];
        let info = info_for(&raw, Platform::Linux, Arch::X64, Libc::Musl);
        let j = json_report(Path::new("a.node"), 5000, &info);
        assert!(j.contains("\"hybrid\":true"));
        assert!(j.contains("\"magic\":true"));
        assert!(j.contains("\"uncompressedSize\":2000"));
        assert!(j.contains("\"platform\":\"linux\""));
        assert!(j.contains("\"arch\":\"x64\""));
        assert!(j.contains("\"libc\":\"musl\""));
        assert!(j.contains("\"integrityVerified\":true"));
        assert!(j.contains(&format!("\"cacheKey\":\"{}\"", hex(&info.cache_key))));
    }

    #[test]
    fn report_flags_a_tampered_section_and_unknown_enums() {
        let raw = vec![0x22u8; 1500];
        let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 9);
        let mut section = section;
        // Corrupt the payload tail → integrity fails; also bogus platform byte.
        let last = section.len() - 1;
        section[last] ^= 0xff;
        // Platform byte sits after magic(32)+sizes(16)+cache(16).
        section[64] = 250;
        let info = abitious_decmpfs::read_section_info(&section).unwrap();
        let human = human_report(Path::new("t.node"), 100, &info);
        assert!(human.contains("MISMATCH"), "{human}");
        assert!(human.contains("unknown(0xfa)"), "{human}");
        let json = json_report(Path::new("t.node"), 100, &info);
        assert!(json.contains("\"integrityVerified\":false"));
        assert!(json.contains("\"platform\":null"), "{json}");
        assert!(json.contains("\"platformByte\":250"));
    }

    #[test]
    fn plain_report_human_and_json() {
        let h = plain_report(Path::new("raw.node"), 4096, false);
        assert!(h.contains("plain .node (no pressed-data section): raw.node"));
        assert!(h.contains("4096 B"));
        let j = plain_report(Path::new("raw.node"), 4096, true);
        assert!(j.contains("\"hybrid\":false"));
        assert!(j.contains("\"fileSize\":4096"));
    }

    #[test]
    fn json_str_escapes_and_hex_is_lowercase() {
        // Every escape arm: quote, backslash, \n, \r, \t, and the generic control-char \u.
        assert_eq!(
            json_str("q\"b\\c\n\r\t\u{01}"),
            "\"q\\\"b\\\\c\\n\\r\\t\\u0001\""
        );
        assert_eq!(hex(&[0x0f, 0xa0, 0xff]), "0fa0ff");
        assert_eq!(json_opt_name(None), "null");
        assert_eq!(json_opt_name(Some("x".to_string())), "\"x\"");
    }

    /// Hand-build a `SectionInfo` to drive every platform/arch/libc name arm (incl. the
    /// unknown-byte fallbacks, which a real `build_section_payload` never emits) and the
    /// `uncompressed_size == 0` path of `human_report`.
    fn mk(pb: u8, ab: u8, lb: u8) -> SectionInfo {
        SectionInfo {
            compressed_size: 10,
            uncompressed_size: 0,
            cache_key: [0u8; 16],
            platform_byte: pb,
            platform: Platform::from_u8(pb),
            arch_byte: ab,
            arch: Arch::from_u8(ab),
            libc_byte: lb,
            libc: Libc::from_u8(lb),
            has_config: false,
            integrity_verified: false,
        }
    }

    #[test]
    fn name_helpers_cover_every_enum_arm_and_unknown() {
        let win = human_report(Path::new("x"), 0, &mk(2, 2, 255));
        assert!(win.contains("platform=win32 arch=ia32 libc=na"), "{win}");
        let arm = human_report(Path::new("x"), 0, &mk(0, 3, 1));
        assert!(arm.contains("platform=linux arch=arm libc=musl"), "{arm}");
        // Unknown bytes → the `unknown(0x..)` fallbacks (human) and JSON `null`.
        let unknown = human_report(Path::new("x"), 0, &mk(9, 9, 9));
        assert!(
            unknown.contains("platform=unknown(0x09) arch=unknown(0x09) libc=unknown(0x09)"),
            "{unknown}"
        );
        let j = json_report(Path::new("x"), 0, &mk(9, 9, 9));
        assert!(
            j.contains("\"platform\":null")
                && j.contains("\"arch\":null")
                && j.contains("\"libc\":null"),
            "{j}"
        );
    }

    #[test]
    fn human_report_handles_a_zero_length_addon() {
        // uncompressed_size == 0 → the pct_saved fallback (no divide-by-zero) and a 0-byte
        // download-savings line.
        let r = human_report(Path::new("empty.node"), 132, &mk(1, 1, 255));
        assert!(r.contains("download savings:    0 B"), "{r}");
        assert!(r.contains("(0.0% smaller to download)"), "{r}");
    }
}
