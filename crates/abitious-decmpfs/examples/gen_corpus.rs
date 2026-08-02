//! Regenerate the frozen interop-corpus vectors printed as hex, for pasting into
//! `tests/interop_corpus.rs`. Run: `cargo run --example gen_corpus`. Only re-run
//! on a DELIBERATE format bump — the committed vectors are the frozen tripwire.

use abitious_decmpfs::{build_section_payload, Arch, Libc, Platform};

/// (name, raw addon bytes, platform, arch, libc, zstd level)
type Vector = (&'static str, Vec<u8>, Platform, Arch, Libc, i32);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let vectors: [Vector; 3] = [
        (
            "v1_darwin_arm64",
            b"abitious pressed-data interop vector \x7fELF one".to_vec(),
            Platform::Darwin,
            Arch::Arm64,
            Libc::Na,
            19,
        ),
        (
            "v1_linux_x64_musl",
            vec![0x9au8; 4096],
            Platform::Linux,
            Arch::X64,
            Libc::Musl,
            16,
        ),
        (
            "v1_win32_x64",
            (0..1000u32).map(|i| (i % 256) as u8).collect(),
            Platform::Win32,
            Arch::X64,
            Libc::Na,
            12,
        ),
    ];
    for (name, raw, platform, arch, libc, level) in &vectors {
        let section = build_section_payload(raw, *platform, *arch, *libc, *level);
        println!("{name}|{}|{}", hex(raw), hex(&section));
    }
}
