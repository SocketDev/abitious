use super::*;

/// Build a valid pressed-data section blob directly (bypassing the producer)
/// so a reader test does not depend on `build_section_payload`.
fn synth_section(raw: &[u8], has_config: bool) -> Vec<u8> {
    let payload = zstd::stream::encode_all(raw, 3).unwrap();
    let hash = Sha512::digest(&payload);
    let mut s = Vec::new();
    s.extend_from_slice(MAGIC_MARKER);
    s.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    s.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    s.extend_from_slice(&[b'a'; CACHE_KEY_LEN]);
    s.extend_from_slice(&[1u8, 1u8, 255u8]);
    s.extend_from_slice(&hash);
    s.push(u8::from(has_config));
    if has_config {
        s.extend_from_slice(&[0u8; SMOL_CONFIG_BINARY_LEN]);
    }
    s.extend_from_slice(&payload);
    s
}

#[test]
fn producer_round_trips_through_reader() {
    for (size, level) in [(1usize, 1), (64, 9), (4096, 16), (200_000, 19)] {
        let raw: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let section = build_section_payload(&raw, Platform::Darwin, Arch::Arm64, Libc::Na, level);
        assert_eq!(
            decode_pressed_data(&section).as_deref(),
            Some(raw.as_slice())
        );
    }
}

#[test]
fn producer_stamps_the_platform_bytes_and_cache_key() {
    let raw = vec![0x5au8; 1000];
    let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Musl, 16);
    // Platform bytes sit right after magic(32) + sizes(16) + cache(16).
    let p = MAGIC_MARKER.len() + SIZE_HEADER_LEN + CACHE_KEY_LEN;
    assert_eq!(&section[p..p + 3], &[0u8, 0u8, 1u8]); // linux/x64/musl
                                                      // Cache key = first 16 bytes of SHA-256(raw).
    let key_at = MAGIC_MARKER.len() + SIZE_HEADER_LEN;
    assert_eq!(
        &section[key_at..key_at + CACHE_KEY_LEN],
        &Sha256::digest(&raw)[..CACHE_KEY_LEN]
    );
}

#[test]
fn pressed_data_round_trips() {
    let raw = b"\x7fELF this is the original addon payload, repeated.".repeat(40);
    assert_eq!(
        decode_pressed_data(&synth_section(&raw, false)).as_deref(),
        Some(raw.as_slice())
    );
}

#[test]
fn pressed_data_round_trips_with_config() {
    let raw = vec![0xABu8; 5000];
    assert_eq!(
        decode_pressed_data(&synth_section(&raw, true)).as_deref(),
        Some(raw.as_slice())
    );
}

#[test]
fn rejects_a_non_hybrid() {
    assert!(unwrap_if_hybrid(b"not a binary at all").is_none());
    assert!(decode_pressed_data(MAGIC_MARKER.as_slice()).is_none());
    assert!(decode_pressed_data(&[0u8; HEADER_LEN + 10]).is_none());
}

#[test]
fn decode_capped_rejects_a_zstd_bomb_without_allocating_it() {
    // A tiny payload that expands FAR beyond a small cap (highly compressible zeros):
    // the bounded decoder must reject it after reading at most cap + 1 bytes — never
    // allocating the full multi-MiB (in production, multi-GiB) expansion. Tested here
    // with a small cap so the proof is fast and deterministic; `decode_pressed_data`
    // wires this exact helper to the real 512 MiB `MAX_DECOMPRESSED`.
    let bomb = zstd::stream::encode_all(&vec![0u8; 4 * 1024 * 1024][..], 19).unwrap();
    assert!(
        bomb.len() < 64 * 1024,
        "the bomb payload is tiny ({} B) yet expands to 4 MiB",
        bomb.len()
    );
    assert!(
        decode_capped(&bomb, 64 * 1024).is_none(),
        "an over-cap expansion is rejected (no OOM), not decoded"
    );
    // Within the cap, the very same frame decodes fully — a normal payload still works.
    let raw = decode_capped(&bomb, 8 * 1024 * 1024).expect("a within-cap frame decodes");
    assert_eq!(raw.len(), 4 * 1024 * 1024);
    assert!(raw.iter().all(|&b| b == 0));
    // A non-zstd payload is a codec error → None (never a panic).
    assert!(decode_capped(b"not a zstd frame", 1024).is_none());
}

#[test]
fn normal_hybrid_still_decodes_through_the_capped_path() {
    // The bounded decode does not regress the happy path: a real producer section still
    // round-trips through `decode_pressed_data` (which now calls `decode_capped`).
    let raw = b"\x7fELF a perfectly normal, well-behaved addon payload. ".repeat(64);
    let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 19);
    assert_eq!(
        decode_pressed_data(&section).as_deref(),
        Some(raw.as_slice())
    );
}

#[test]
fn rejects_a_tampered_payload() {
    let mut section = synth_section(&vec![0x11u8; 2000], false);
    let last = section.len() - 1;
    section[last] ^= 0xff;
    assert!(decode_pressed_data(&section).is_none());
}

#[test]
fn rejects_a_wrong_uncompressed_size() {
    let mut section = synth_section(&vec![0x22u8; 2000], false);
    section[40] = section[40].wrapping_add(1); // uncompressed-size field (32 + 8)
    assert!(decode_pressed_data(&section).is_none());
}

#[test]
fn finds_pressed_data_in_a_synthetic_macho() {
    let raw = vec![0x42u8; 3000];
    let blob = build_section_payload(&raw, Platform::Darwin, Arch::Arm64, Libc::Na, 16);
    const LC_SEGMENT_64: u32 = 0x19;
    let seg_cmd_len = 72 + 80;
    let blob_off = 32 + seg_cmd_len;
    let mut bin = vec![0u8; blob_off];
    bin[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bin[16..20].copy_from_slice(&1u32.to_le_bytes());
    let seg = 32;
    bin[seg..seg + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    bin[seg + 4..seg + 8].copy_from_slice(&(seg_cmd_len as u32).to_le_bytes());
    bin[seg + 8..seg + 12].copy_from_slice(b"SMOL");
    bin[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes());
    let sect = seg + 72;
    bin[sect..sect + 14].copy_from_slice(b"__PRESSED_DATA");
    bin[sect + 40..sect + 48].copy_from_slice(&(blob.len() as u64).to_le_bytes());
    bin[sect + 48..sect + 52].copy_from_slice(&(blob_off as u32).to_le_bytes());
    bin.extend_from_slice(&blob);
    assert_eq!(unwrap_if_hybrid(&bin).as_deref(), Some(raw.as_slice()));
}

#[test]
fn finds_pressed_data_in_a_synthetic_pe() {
    let raw = vec![0x55u8; 1500];
    let blob = build_section_payload(&raw, Platform::Win32, Arch::X64, Libc::Na, 16);
    let pe_off = 64usize;
    let sect_table = pe_off + 24;
    let blob_off = sect_table + 40;
    let mut bin = vec![0u8; blob_off];
    bin[0] = b'M';
    bin[1] = b'Z';
    bin[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    bin[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    bin[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    bin[pe_off + 20..pe_off + 22].copy_from_slice(&0u16.to_le_bytes());
    bin[sect_table..sect_table + 8].copy_from_slice(b".PRESSED");
    bin[sect_table + 16..sect_table + 20].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    bin[sect_table + 20..sect_table + 24].copy_from_slice(&(blob_off as u32).to_le_bytes());
    bin.extend_from_slice(&blob);
    assert_eq!(unwrap_if_hybrid(&bin).as_deref(), Some(raw.as_slice()));
}

#[test]
fn finds_pressed_data_in_a_synthetic_elf() {
    let raw = vec![0x66u8; 2200];
    let blob = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
    let shentsize = 64usize;
    let mut strtab = vec![0u8];
    let shstrtab_name = strtab.len() as u32;
    strtab.extend_from_slice(b".shstrtab\0");
    let pressed_name = strtab.len() as u32;
    strtab.extend_from_slice(b".PRESSED_DATA\0");
    let strtab_off = 64usize;
    let shoff = strtab_off + strtab.len();
    let blob_off = shoff + 2 * shentsize;
    let mut bin = vec![0u8; blob_off];
    bin[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bin[4] = 2;
    bin[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    bin[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    bin[60..62].copy_from_slice(&2u16.to_le_bytes());
    bin[62..64].copy_from_slice(&0u16.to_le_bytes());
    bin[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
    let sh0 = shoff;
    bin[sh0..sh0 + 4].copy_from_slice(&shstrtab_name.to_le_bytes());
    bin[sh0 + 24..sh0 + 32].copy_from_slice(&(strtab_off as u64).to_le_bytes());
    bin[sh0 + 32..sh0 + 40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
    let sh1 = shoff + shentsize;
    bin[sh1..sh1 + 4].copy_from_slice(&pressed_name.to_le_bytes());
    bin[sh1 + 24..sh1 + 32].copy_from_slice(&(blob_off as u64).to_le_bytes());
    bin[sh1 + 32..sh1 + 40].copy_from_slice(&(blob.len() as u64).to_le_bytes());
    bin.extend_from_slice(&blob);
    assert_eq!(unwrap_if_hybrid(&bin).as_deref(), Some(raw.as_slice()));
}

#[test]
fn name_eq_is_exact_with_nul_padding() {
    assert!(name_eq(b"SMOL\0\0\0\0\0\0\0\0\0\0\0\0", b"SMOL"));
    assert!(!name_eq(b"SMOLX\0\0\0\0\0\0\0\0\0\0\0", b"SMOL"));
    assert!(!name_eq(b"SMO\0", b"SMOL"));
}

/// A synthetic ELF64 that carries `raw` in a `.PRESSED_DATA` section, so
/// `unwrap_if_hybrid` recovers `raw` — a self-contained hybrid fixture for the
/// install-bridge tests (no producer crate, no `cc`). Mirrors the section layout
/// exercised by `finds_pressed_data_in_a_synthetic_elf`.
fn synth_elf_hybrid(raw: &[u8]) -> Vec<u8> {
    let blob = build_section_payload(raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
    let shentsize = 64usize;
    let mut strtab = vec![0u8];
    let shstrtab_name = strtab.len() as u32;
    strtab.extend_from_slice(b".shstrtab\0");
    let pressed_name = strtab.len() as u32;
    strtab.extend_from_slice(b".PRESSED_DATA\0");
    let strtab_off = 64usize;
    let shoff = strtab_off + strtab.len();
    let blob_off = shoff + 2 * shentsize;
    let mut bin = vec![0u8; blob_off];
    bin[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bin[4] = 2;
    bin[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    bin[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    bin[60..62].copy_from_slice(&2u16.to_le_bytes());
    bin[62..64].copy_from_slice(&0u16.to_le_bytes());
    bin[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
    let sh0 = shoff;
    bin[sh0..sh0 + 4].copy_from_slice(&shstrtab_name.to_le_bytes());
    bin[sh0 + 24..sh0 + 32].copy_from_slice(&(strtab_off as u64).to_le_bytes());
    bin[sh0 + 32..sh0 + 40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
    let sh1 = shoff + shentsize;
    bin[sh1..sh1 + 4].copy_from_slice(&pressed_name.to_le_bytes());
    bin[sh1 + 24..sh1 + 32].copy_from_slice(&(blob_off as u64).to_le_bytes());
    bin[sh1 + 32..sh1 + 40].copy_from_slice(&(blob.len() as u64).to_le_bytes());
    bin.extend_from_slice(&blob);
    bin
}

fn install_scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("abitious-install-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// install_hybrid on a hybrid: recover the raw addon from the section and land it
// as a (kernel-compressed, verified) store file. The store bytes must equal the
// raw addon (the kernel decompresses transparently on read).
#[test]
fn install_hybrid_unwraps_the_section_and_lands_the_raw_addon() {
    let dir = install_scratch("hybrid");
    let raw = b"\x7fELF the real abitious addon .text payload, compressible. ".repeat(400);
    let hybrid = synth_elf_hybrid(&raw);
    // Sanity: the fixture really is a hybrid.
    assert_eq!(unwrap_if_hybrid(&hybrid).as_deref(), Some(raw.as_slice()));

    let dest = dir.join("addon.node");
    let out = install_hybrid(&hybrid, &dest, &Gate::any()).expect("install never errors");
    assert!(
        matches!(
            out,
            Outcome::Compressed { .. } | Outcome::NoGain { .. } | Outcome::Unsupported { .. }
        ),
        "got {out:?}"
    );
    assert!(dest.exists(), "the store file was created");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        raw,
        "the store file is the raw addon, read back byte-for-byte"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// install_hybrid on a plain (non-hybrid) addon: `unwrap_if_hybrid` returns None,
// so the input is written as-is (still kernel-compressed where supported).
#[test]
fn install_hybrid_writes_a_plain_addon_as_is() {
    let dir = install_scratch("plain");
    // Not a hybrid: no recognized object magic → unwrap_if_hybrid returns None.
    let raw = b"a plain raw addon with no PRESSED_DATA section here. ".repeat(400);
    assert!(unwrap_if_hybrid(&raw).is_none(), "fixture is not a hybrid");

    let dest = dir.join("addon.node");
    let out = install_hybrid(&raw, &dest, &Gate::any()).expect("install never errors");
    assert!(
        matches!(
            out,
            Outcome::Compressed { .. } | Outcome::NoGain { .. } | Outcome::Unsupported { .. }
        ),
        "got {out:?}"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        raw,
        "plain addon landed as-is"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn read_section_info_reports_the_header_and_verifies_integrity() {
    let raw = vec![0x7bu8; 5000];
    let section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Musl, 16);
    let info = read_section_info(&section).expect("a valid section parses");
    assert_eq!(info.uncompressed_size, raw.len() as u64);
    assert_eq!(
        info.compressed_size,
        section.len() as u64 - HEADER_LEN as u64
    );
    assert_eq!(info.cache_key, &Sha256::digest(&raw)[..CACHE_KEY_LEN]);
    assert_eq!(info.platform, Some(Platform::Linux));
    assert_eq!(info.arch, Some(Arch::X64));
    assert_eq!(info.libc, Some(Libc::Musl));
    assert_eq!(
        (info.platform_byte, info.arch_byte, info.libc_byte),
        (0, 0, 1)
    );
    assert!(!info.has_config);
    assert!(info.integrity_verified, "a producer section verifies");
}

#[test]
fn read_section_info_flags_a_tampered_payload_as_unverified() {
    let raw = vec![0x33u8; 3000];
    let mut section = build_section_payload(&raw, Platform::Darwin, Arch::Arm64, Libc::Na, 9);
    // Flip a payload byte: the header still parses, but SHA-512 no longer matches.
    let last = section.len() - 1;
    section[last] ^= 0xff;
    let info = read_section_info(&section).expect("header still parses");
    assert!(
        !info.integrity_verified,
        "a tampered payload must read as unverified"
    );
    // And it does NOT decode — the inspector's verdict matches the decoder's.
    assert!(decode_pressed_data(&section).is_none());
}

#[test]
fn read_section_info_none_on_too_short_or_unmarked() {
    assert!(read_section_info(&[0u8; 8]).is_none());
    assert!(read_section_info(&[0u8; HEADER_LEN]).is_none()); // right length, no magic
    assert!(inspect_hybrid(b"not a binary").is_none());
}

#[test]
fn inspect_hybrid_reads_a_synthetic_macho_section() {
    // Reuse the synthetic Mach-O the decode test builds; inspect_hybrid must find and
    // parse the same section it decodes.
    let raw = vec![0x42u8; 3000];
    let blob = build_section_payload(&raw, Platform::Darwin, Arch::Arm64, Libc::Na, 16);
    const LC_SEGMENT_64: u32 = 0x19;
    let seg_cmd_len = 72 + 80;
    let blob_off = 32 + seg_cmd_len;
    let mut bin = vec![0u8; blob_off];
    bin[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bin[16..20].copy_from_slice(&1u32.to_le_bytes());
    let seg = 32;
    bin[seg..seg + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    bin[seg + 4..seg + 8].copy_from_slice(&(seg_cmd_len as u32).to_le_bytes());
    bin[seg + 8..seg + 12].copy_from_slice(b"SMOL");
    bin[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes());
    let sect = seg + 72;
    bin[sect..sect + 14].copy_from_slice(b"__PRESSED_DATA");
    bin[sect + 40..sect + 48].copy_from_slice(&(blob.len() as u64).to_le_bytes());
    bin[sect + 48..sect + 52].copy_from_slice(&(blob_off as u32).to_le_bytes());
    bin.extend_from_slice(&blob);
    let info = inspect_hybrid(&bin).expect("finds + parses the section");
    assert_eq!(info.platform, Some(Platform::Darwin));
    assert_eq!(info.uncompressed_size, raw.len() as u64);
    assert!(info.integrity_verified);
}

#[test]
fn read_section_info_keeps_raw_bytes_for_unknown_enums() {
    // A section whose platform/arch/libc bytes are unrecognized: the decoded enums
    // are None but the raw bytes are preserved for a report.
    let raw = vec![0x01u8; 200];
    let mut section = build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 3);
    let p = MAGIC_MARKER.len() + SIZE_HEADER_LEN + CACHE_KEY_LEN;
    section[p] = 200; // bogus platform
    section[p + 1] = 201; // bogus arch
    section[p + 2] = 202; // bogus libc
    let info = read_section_info(&section).unwrap();
    assert_eq!((info.platform, info.arch, info.libc), (None, None, None));
    assert_eq!(
        (info.platform_byte, info.arch_byte, info.libc_byte),
        (200, 201, 202)
    );
}

#[test]
fn enum_from_u8_round_trips_and_rejects_unknown() {
    // Every arm of each from_u8 (the reverse of the frozen enum bytes).
    assert_eq!(Platform::from_u8(0), Some(Platform::Linux));
    assert_eq!(Platform::from_u8(1), Some(Platform::Darwin));
    assert_eq!(Platform::from_u8(2), Some(Platform::Win32));
    assert_eq!(Platform::from_u8(9), None);
    assert_eq!(Arch::from_u8(0), Some(Arch::X64));
    assert_eq!(Arch::from_u8(1), Some(Arch::Arm64));
    assert_eq!(Arch::from_u8(2), Some(Arch::Ia32));
    assert_eq!(Arch::from_u8(3), Some(Arch::Arm));
    assert_eq!(Arch::from_u8(9), None);
    assert_eq!(Libc::from_u8(0), Some(Libc::Glibc));
    assert_eq!(Libc::from_u8(1), Some(Libc::Musl));
    assert_eq!(Libc::from_u8(255), Some(Libc::Na));
    assert_eq!(Libc::from_u8(9), None);
}

#[test]
fn decode_rejects_zero_and_oversized_sizes() {
    // Magic present, all-zero header → the size gate (not the magic gate) rejects it,
    // and the inspector reports it unverified (zero compressed size, no payload).
    let mut s = MAGIC_MARKER.to_vec();
    s.extend(std::iter::repeat_n(0u8, HEADER_LEN - MAGIC_MARKER.len()));
    assert_eq!(s.len(), HEADER_LEN);
    assert!(decode_pressed_data(&s).is_none());
    let info = read_section_info(&s).expect("the header still parses");
    assert!(!info.integrity_verified);
}

#[test]
fn decode_rejects_a_truncated_payload() {
    // A header claiming a 100-byte payload with NO payload bytes present → the payload
    // slice is out of range, so both the decoder and the inspector reject it.
    let mut s = MAGIC_MARKER.to_vec();
    s.extend_from_slice(&100u64.to_le_bytes()); // compressed_size
    s.extend_from_slice(&100u64.to_le_bytes()); // uncompressed_size
    s.extend_from_slice(&[0u8; CACHE_KEY_LEN]);
    s.extend_from_slice(&[0u8, 1u8, 255u8]); // platform bytes
    s.extend_from_slice(&[0u8; INTEGRITY_HASH_LEN]);
    s.push(0); // has_config
    assert_eq!(s.len(), HEADER_LEN);
    assert!(decode_pressed_data(&s).is_none());
    assert!(!read_section_info(&s).unwrap().integrity_verified);
}

#[test]
fn detect_from_cfg_covers_every_platform_arch_and_libc_arm() {
    // The host-dispatch policy split from `cfg!` — every arm is pinned here regardless of
    // the host, so the platform matrix is covered without a per-OS test run.
    assert_eq!(Platform::from_cfg(true, false), Platform::Darwin);
    assert_eq!(Platform::from_cfg(false, true), Platform::Win32);
    assert_eq!(Platform::from_cfg(false, false), Platform::Linux);

    assert_eq!(Arch::from_cfg(true, false, false), Arch::Arm64);
    assert_eq!(Arch::from_cfg(false, true, false), Arch::Ia32);
    assert_eq!(Arch::from_cfg(false, false, true), Arch::Arm);
    assert_eq!(Arch::from_cfg(false, false, false), Arch::X64);

    assert_eq!(Libc::from_cfg(false, false), Libc::Na); // non-Linux → Na
    assert_eq!(Libc::from_cfg(true, true), Libc::Musl);
    assert_eq!(Libc::from_cfg(true, false), Libc::Glibc);

    // And `detect()` returns one of those on this host (exercises the `cfg!` wrapper).
    let _ = (Platform::detect(), Arch::detect(), Libc::detect());
}

#[test]
fn name_eq_rejects_a_want_longer_than_the_field() {
    // The early-out when `want` is longer than the fixed-width slot (line-guarded so the
    // slice index below never panics).
    assert!(!name_eq(b"AB", b"ABCD"));
    assert!(name_eq(b"AB\0\0", b"AB"));
}

// --- Reader defensive parse arms: crafted malformed Mach-O / ELF / PE (inline bytes).
// find_pressed_data_section dispatches on the leading magic; each fixture drives one
// otherwise-untaken guard in find_macho / find_elf / find_pe.

#[test]
fn find_macho_rejects_a_zero_length_load_command() {
    // magic + ncmds=1, then a load command whose cmdsize is 0 → the zero-cmdsize guard.
    let mut m = vec![0u8; 40];
    m[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    m[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
                                                    // cmd @32, cmdsize @36 both left 0.
    assert!(unwrap_if_hybrid(&m).is_none());
}

#[test]
fn find_macho_walks_past_a_non_pressed_section_in_the_smol_segment() {
    // A SMOL LC_SEGMENT_64 with one section that is NOT __PRESSED_DATA → the section loop
    // advances past it and the command loop then falls through to None.
    const LC_SEGMENT_64: u32 = 0x19;
    let cmdsize = 72 + 80usize;
    let mut m = vec![0u8; 32 + cmdsize];
    m[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    m[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
    let seg = 32;
    m[seg..seg + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    m[seg + 4..seg + 8].copy_from_slice(&(cmdsize as u32).to_le_bytes());
    m[seg + 8..seg + 12].copy_from_slice(b"SMOL");
    m[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects = 1
    let sect = seg + 72;
    m[sect..sect + 7].copy_from_slice(b"__OTHER"); // not __PRESSED_DATA
    assert!(unwrap_if_hybrid(&m).is_none());
}

#[test]
fn find_elf_rejects_32_bit_and_a_bad_section_header_table() {
    // EI_CLASS != 2 (32-bit) → refused up front.
    let mut e = vec![0u8; 8];
    e[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    e[4] = 1; // 32-bit
    assert!(unwrap_if_hybrid(&e).is_none());

    // 64-bit but a zero e_shentsize → the unusable-SHT guard.
    let mut e = vec![0u8; 64];
    e[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    e[4] = 2; // 64-bit
    e[58..60].copy_from_slice(&0u16.to_le_bytes()); // e_shentsize = 0 (< 64)
    e[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum = 1
    assert!(unwrap_if_hybrid(&e).is_none());
}

#[test]
fn find_elf_returns_none_when_no_pressed_section_is_present() {
    // A well-formed ELF64 whose only section is `.shstrtab` (no `.PRESSED_DATA`) → the
    // section-name loop runs to completion and returns None.
    let shentsize = 64usize;
    let mut strtab = vec![0u8];
    let shstrtab_name = strtab.len() as u32;
    strtab.extend_from_slice(b".shstrtab\0");
    let strtab_off = 64usize;
    let shoff = strtab_off + strtab.len();
    let mut e = vec![0u8; shoff + shentsize];
    e[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    e[4] = 2;
    e[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    e[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    e[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum = 1
    e[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx = 0
    e[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
    let sh0 = shoff;
    e[sh0..sh0 + 4].copy_from_slice(&shstrtab_name.to_le_bytes());
    e[sh0 + 24..sh0 + 32].copy_from_slice(&(strtab_off as u64).to_le_bytes());
    e[sh0 + 32..sh0 + 40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
    assert!(unwrap_if_hybrid(&e).is_none());
}

#[test]
fn find_pe_rejects_a_bad_nt_signature_and_too_many_sections() {
    let pe_off = 0x40usize;
    // Bad NT signature at e_lfanew.
    let mut p = vec![0u8; pe_off + 24];
    p[0..2].copy_from_slice(b"MZ");
    p[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    p[pe_off..pe_off + 4].copy_from_slice(b"XX\0\0"); // not "PE\0\0"
    assert!(unwrap_if_hybrid(&p).is_none());

    // Valid "PE\0\0" but an absurd NumberOfSections → refused.
    let mut p = vec![0u8; pe_off + 24];
    p[0..2].copy_from_slice(b"MZ");
    p[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    p[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    p[pe_off + 6..pe_off + 8].copy_from_slice(&201u16.to_le_bytes()); // NumberOfSections
    assert!(unwrap_if_hybrid(&p).is_none());
}

#[test]
fn find_pe_returns_none_when_no_pressed_section_is_present() {
    // A PE with a single `.text` section (not `.PRESSED`) → the section loop advances
    // past it and returns None.
    let pe_off = 0x40usize;
    let coff = pe_off + 4;
    let size_of_optional = 0usize;
    let sect_table = coff + 20 + size_of_optional;
    let mut p = vec![0u8; sect_table + 40];
    p[0..2].copy_from_slice(b"MZ");
    p[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    p[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    p[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
    p[coff + 16..coff + 18].copy_from_slice(&(size_of_optional as u16).to_le_bytes());
    p[sect_table..sect_table + 5].copy_from_slice(b".text"); // not ".PRESSED"
    assert!(unwrap_if_hybrid(&p).is_none());
}

// --- "Oh shit" cases: catastrophic / malicious inputs against the frozen-format decode
// path. Each test crafts a real disaster input, drives the real defensive arm, and asserts
// graceful rejection (None, never a panic or a giant allocation). The valid fixtures below
// (synth_macho_hybrid / synth_pe_hybrid, plus the existing synth_elf_hybrid) are chopped or
// mutated at the exact byte the guard fires on.

/// A synthetic Mach-O 64 carrying `raw` in a `SMOL`/`__PRESSED_DATA` section at the fixed
/// offsets `find_macho` walks (mirrors `finds_pressed_data_in_a_synthetic_macho`). A valid
/// hybrid the truncation/overflow tests below chop up.
fn synth_macho_hybrid(raw: &[u8]) -> Vec<u8> {
    let blob = build_section_payload(raw, Platform::Darwin, Arch::Arm64, Libc::Na, 3);
    const LC_SEGMENT_64: u32 = 0x19;
    let seg_cmd_len = 72 + 80;
    let blob_off = 32 + seg_cmd_len;
    let mut bin = vec![0u8; blob_off];
    bin[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    bin[16..20].copy_from_slice(&1u32.to_le_bytes());
    let seg = 32;
    bin[seg..seg + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    bin[seg + 4..seg + 8].copy_from_slice(&(seg_cmd_len as u32).to_le_bytes());
    bin[seg + 8..seg + 12].copy_from_slice(b"SMOL");
    bin[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes());
    let sect = seg + 72;
    bin[sect..sect + 14].copy_from_slice(b"__PRESSED_DATA");
    bin[sect + 40..sect + 48].copy_from_slice(&(blob.len() as u64).to_le_bytes());
    bin[sect + 48..sect + 52].copy_from_slice(&(blob_off as u32).to_le_bytes());
    bin.extend_from_slice(&blob);
    bin
}

/// A synthetic PE carrying `raw` in a `.PRESSED` section at the fixed offsets `find_pe`
/// parses (mirrors `finds_pressed_data_in_a_synthetic_pe`). A valid hybrid the
/// truncation/overflow tests below chop up.
fn synth_pe_hybrid(raw: &[u8]) -> Vec<u8> {
    let blob = build_section_payload(raw, Platform::Win32, Arch::X64, Libc::Na, 3);
    let pe_off = 64usize;
    let sect_table = pe_off + 24;
    let blob_off = sect_table + 40;
    let mut bin = vec![0u8; blob_off];
    bin[0] = b'M';
    bin[1] = b'Z';
    bin[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    bin[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    bin[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    bin[pe_off + 20..pe_off + 22].copy_from_slice(&0u16.to_le_bytes());
    bin[sect_table..sect_table + 8].copy_from_slice(b".PRESSED");
    bin[sect_table + 16..sect_table + 20].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    bin[sect_table + 20..sect_table + 24].copy_from_slice(&(blob_off as u32).to_le_bytes());
    bin.extend_from_slice(&blob);
    bin
}

#[test]
fn decode_rejects_an_oversized_size_claim_without_allocating_the_claim() {
    // oh-shit: bomb-by-size-claim. A header CLAIMING a decompressed (or compressed) size
    // past the 512 MiB `MAX_DECOMPRESSED` cap must be refused by the size gate BEFORE any
    // payload slice or decode runs — so a 600 MiB claim never drives a 600 MiB allocation.
    // The section is a bare 132-byte header with NO payload bytes, so a large allocation is
    // physically impossible: the guard (not the buffer) does the rejecting.
    let over = MAX_DECOMPRESSED + 1;
    let header = |compressed: u64, uncompressed: u64| -> Vec<u8> {
        let mut s = MAGIC_MARKER.to_vec();
        s.extend_from_slice(&compressed.to_le_bytes());
        s.extend_from_slice(&uncompressed.to_le_bytes());
        s.extend_from_slice(&[0u8; CACHE_KEY_LEN]);
        s.extend_from_slice(&[0u8, 1u8, 255u8]); // platform bytes
        s.extend_from_slice(&[0u8; INTEGRITY_HASH_LEN]);
        s.push(0); // has_config
        assert_eq!(s.len(), HEADER_LEN);
        s
    };
    // Oversized UNCOMPRESSED claim (with a small, in-cap compressed claim).
    assert!(decode_pressed_data(&header(64, over)).is_none());
    // Oversized COMPRESSED claim (with a small, in-cap uncompressed claim).
    assert!(decode_pressed_data(&header(over, 64)).is_none());
}

#[test]
fn decode_rejects_a_frame_that_passes_integrity_but_will_not_decompress() {
    // oh-shit: SHA-512 vouches for the bytes, but they are not a decodable zstd frame. The
    // publisher-controlled integrity hash CANNOT guarantee decode safety, so the capped
    // streaming decode still has to reject (None). Proves `decode_pressed_data` does not
    // trust a passing hash to skip the decode — it exercises the `decode_capped(...)?`
    // propagation arm with a frame that hashes fine yet is un-decodable.
    let payload = b"\xde\xad\xbe\xef these bytes hash fine but are not a zstd frame".repeat(4);
    let mut s = MAGIC_MARKER.to_vec();
    s.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // compressed_size (in-cap)
    s.extend_from_slice(&64u64.to_le_bytes()); // uncompressed_size (in-cap, non-zero)
    s.extend_from_slice(&[0u8; CACHE_KEY_LEN]);
    s.extend_from_slice(&[0u8, 1u8, 255u8]);
    s.extend_from_slice(&Sha512::digest(&payload)); // integrity: matches the payload exactly
    s.push(0); // has_config
    s.extend_from_slice(&payload);
    // The oh-shit precondition: the integrity check PASSES on this garbage frame ...
    assert!(read_section_info(&s).unwrap().integrity_verified);
    // ... yet the decode still refuses it, because the hash can't vouch for decodability.
    assert!(decode_pressed_data(&s).is_none());
}

#[test]
fn find_pressed_data_section_rejects_a_runt_shorter_than_the_magic() {
    // oh-shit: a file too short to even hold the 4-byte object magic. The leading
    // `content.get(..4)?` must bail (None), never index past the end.
    for runt in [&b""[..], &b"M"[..], &b"MZ"[..], &b"\x7fEL"[..]] {
        assert!(unwrap_if_hybrid(runt).is_none());
    }
}

#[test]
fn find_macho_rejects_a_header_truncated_at_each_guarded_read() {
    // oh-shit: truncated-Mach-O. A valid hybrid chopped at each successive header/section
    // read must degrade to None, never panic. Each length lands exactly on one guarded read.
    let raw = vec![0x42u8; 64];
    let full = synth_macho_hybrid(&raw);
    assert_eq!(unwrap_if_hybrid(&full).as_deref(), Some(raw.as_slice()));
    for len in [
        16,  // ncmds read (offset 16)
        34,  // load-command `cmd` read (offset 32)
        38,  // `cmdsize` read (offset 36)
        50,  // SMOL segname slice (offset 40..56)
        98,  // nsects read (offset 96)
        110, // section-name slice (offset 104..120)
        148, // section `size` read (offset 144)
        154, // section `offset` read (offset 152)
    ] {
        assert!(
            unwrap_if_hybrid(&full[..len]).is_none(),
            "a Mach-O truncated to {len} B must be rejected, not decoded"
        );
    }
}

#[test]
fn find_macho_rejects_a_pressed_data_section_whose_offset_plus_size_overflows() {
    // oh-shit: offset overflow. A __PRESSED_DATA section header claiming size == u64::MAX
    // with offset 1 would overflow `offset + size`; the `offset.checked_add(size)?` must
    // bail to None rather than wrap and slice out of bounds.
    let mut bin = synth_macho_hybrid(&[0x42u8; 64]);
    let sect = 32 + 72; // section_64 record start (segment command header is 72 B)
    bin[sect + 40..sect + 48].copy_from_slice(&u64::MAX.to_le_bytes()); // size = u64::MAX
    bin[sect + 48..sect + 52].copy_from_slice(&1u32.to_le_bytes()); // offset = 1
    assert!(unwrap_if_hybrid(&bin).is_none());
}

#[test]
fn find_elf_rejects_a_header_truncated_at_each_guarded_read() {
    // oh-shit: truncated-ELF. Chop a valid ELF64 hybrid at each header/section-table read.
    let raw = vec![0x66u8; 64];
    let full = synth_elf_hybrid(&raw);
    assert_eq!(unwrap_if_hybrid(&full).as_deref(), Some(raw.as_slice()));
    for len in [
        4,   // EI_CLASS read (offset 4)
        10,  // e_shoff read (offset 40)
        50,  // e_shentsize read (offset 58)
        61,  // e_shnum read (offset 60)
        63,  // e_shstrndx read (offset 62)
        115, // string-table sh_offset read (strtab_hdr + 24 == 113)
        125, // string-table sh_size read (strtab_hdr + 32 == 121)
        155, // section-header sh_name read mid-walk (section 1 header @ 153)
        160, // matched .PRESSED_DATA sh_offset read (153 + 24 == 177)
        188, // matched .PRESSED_DATA sh_size read (153 + 32 == 185)
    ] {
        assert!(
            unwrap_if_hybrid(&full[..len]).is_none(),
            "an ELF truncated to {len} B must be rejected, not decoded"
        );
    }
}

#[test]
fn find_elf_rejects_offsets_that_overflow_or_slice_out_of_bounds() {
    // oh-shit: attacker-chosen u64 offsets in the ELF section-header table. Every
    // `checked_add` / `.get(..)` on the frozen layout must bail to None, never wrap or
    // read past the end. (`synth_elf_hybrid` lays strtab @ 64, e_shoff @ 89, second
    // section-header record @ 153.)
    let strtab_hdr = 89usize;
    let sect1 = 153usize;

    // (a) e_shoff so large that strtab_hdr = e_shoff + e_shstrndx * e_shentsize overflows.
    let mut bin = synth_elf_hybrid(&[0x66u8; 64]);
    bin[40..48].copy_from_slice(&u64::MAX.to_le_bytes()); // e_shoff = usize::MAX
    bin[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx = 1 (< e_shnum = 2)
    assert!(unwrap_if_hybrid(&bin).is_none());

    // (b) string-table (offset, size) whose offset + size overflows.
    let mut bin = synth_elf_hybrid(&[0x66u8; 64]);
    bin[strtab_hdr + 24..strtab_hdr + 32].copy_from_slice(&u64::MAX.to_le_bytes()); // strtab_off
    bin[strtab_hdr + 32..strtab_hdr + 40].copy_from_slice(&1u64.to_le_bytes()); // strtab_size
    assert!(unwrap_if_hybrid(&bin).is_none());

    // (c) string-table with an in-range offset but a size running off the end of the file.
    let mut bin = synth_elf_hybrid(&[0x66u8; 64]);
    bin[strtab_hdr + 24..strtab_hdr + 32].copy_from_slice(&0u64.to_le_bytes()); // strtab_off = 0
    bin[strtab_hdr + 32..strtab_hdr + 40].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // 4 GiB
    assert!(unwrap_if_hybrid(&bin).is_none());

    // (d) a matched .PRESSED_DATA section whose (sh_offset, sh_size) runs off the end.
    let mut bin = synth_elf_hybrid(&[0x66u8; 64]);
    bin[sect1 + 24..sect1 + 32].copy_from_slice(&0u64.to_le_bytes()); // sh_offset = 0
    bin[sect1 + 32..sect1 + 40].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // sh_size 4 GiB
    assert!(unwrap_if_hybrid(&bin).is_none());

    // (e) a matched .PRESSED_DATA section whose sh_offset + sh_size overflows usize.
    let mut bin = synth_elf_hybrid(&[0x66u8; 64]);
    bin[sect1 + 24..sect1 + 32].copy_from_slice(&u64::MAX.to_le_bytes()); // sh_offset = usize::MAX
    bin[sect1 + 32..sect1 + 40].copy_from_slice(&1u64.to_le_bytes()); // sh_size = 1
    assert!(unwrap_if_hybrid(&bin).is_none());
}

#[test]
fn find_elf_rejects_a_section_name_offset_past_the_string_table() {
    // oh-shit: a section header whose sh_name points beyond the string table. `cstr_at`'s
    // `strtab.get(off..)?` must bail (None), so the name simply never matches — no panic.
    let sect1 = 153usize; // second section-header record (synth_elf_hybrid layout)
    let mut bin = synth_elf_hybrid(&[0x66u8; 64]);
    bin[sect1..sect1 + 4].copy_from_slice(&9999u32.to_le_bytes()); // sh_name past strtab end
    assert!(unwrap_if_hybrid(&bin).is_none());
}

#[test]
fn find_pe_rejects_a_header_truncated_at_each_guarded_read() {
    // oh-shit: truncated-PE. Chop a valid PE hybrid at each successive header/section read.
    let raw = vec![0x55u8; 64];
    let full = synth_pe_hybrid(&raw);
    assert_eq!(unwrap_if_hybrid(&full).as_deref(), Some(raw.as_slice()));
    for len in [
        4,   // e_lfanew read (offset 0x3c)
        66,  // "PE\0\0" signature slice (pe_off 64..68)
        70,  // NumberOfSections read (coff + 2 == 70)
        84,  // SizeOfOptionalHeader read (coff + 16 == 84)
        90,  // section-name slice (section table @ 88)
        106, // matched .PRESSED SizeOfRawData read (sect + 16 == 104)
        110, // matched .PRESSED PointerToRawData read (sect + 20 == 108)
    ] {
        assert!(
            unwrap_if_hybrid(&full[..len]).is_none(),
            "a PE truncated to {len} B must be rejected, not decoded"
        );
    }
}

#[test]
fn find_pe_rejects_a_pressed_section_slice_out_of_bounds() {
    // oh-shit: a .PRESSED section header whose (PointerToRawData, SizeOfRawData) runs off
    // the end of the file. `content.get(ptr_raw..ptr_raw + size_of_raw)?` must bail to None.
    let sect = 64 + 24; // section-table start (pe_off + 24)
    let mut bin = synth_pe_hybrid(&[0x55u8; 64]);
    bin[sect + 16..sect + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // SizeOfRawData 4 GiB
    bin[sect + 20..sect + 24].copy_from_slice(&0u32.to_le_bytes()); // PointerToRawData = 0
    assert!(unwrap_if_hybrid(&bin).is_none());
}

// --- Tier-1 property tests (fleet property-and-fuzz spec) -----------------
//
// Round-trip + never-panic + oracle properties over the frozen pressed-data
// section ABI and the object-file readers. The equivalent adversarial-bytes
// surface is covered by the cargo-fuzz targets (fuzz/fuzz_targets/), which run
// under ASan with an inverted (assertions + overflow-checks ON) profile; these
// proptests give a fast, deterministic in-tree signal on every `cargo test`.
mod props {
    use super::*;
    use proptest::prelude::*;

    /// The three enum families, as (`Strategy`, byte) generators for the section
    /// producer's platform/arch/libc slots.
    fn platform() -> impl Strategy<Value = Platform> {
        prop_oneof![
            Just(Platform::Linux),
            Just(Platform::Darwin),
            Just(Platform::Win32),
        ]
    }
    fn arch() -> impl Strategy<Value = Arch> {
        prop_oneof![
            Just(Arch::X64),
            Just(Arch::Arm64),
            Just(Arch::Ia32),
            Just(Arch::Arm),
        ]
    }
    fn libc() -> impl Strategy<Value = Libc> {
        prop_oneof![Just(Libc::Glibc), Just(Libc::Musl), Just(Libc::Na)]
    }

    proptest! {
      /// ROUND-TRIP: a freshly framed section always decodes back to the exact
      /// input, for any raw addon, any platform/arch/libc, any valid zstd level.
      #[test]
      fn build_then_decode_is_the_identity(
        raw in proptest::collection::vec(any::<u8>(), 1..4096),
        p in platform(),
        a in arch(),
        l in libc(),
        level in 1i32..=19,
      ) {
        let section = build_section_payload(&raw, p, a, l, level);
        let decoded = decode_pressed_data(&section);
        prop_assert_eq!(decoded.as_deref(), Some(raw.as_slice()));
      }

      /// ORACLE: a freshly framed section's stamped header agrees with the decoder
      /// — the inspector reports the true sizes/cache key and verifies integrity
      /// WITHOUT decompressing, matching what `decode_pressed_data` accepts.
      #[test]
      fn inspector_agrees_with_the_producer(
        raw in proptest::collection::vec(any::<u8>(), 1..4096),
        p in platform(),
        a in arch(),
        l in libc(),
        level in 1i32..=19,
      ) {
        let section = build_section_payload(&raw, p, a, l, level);
        let info = read_section_info(&section).expect("a producer section parses");
        prop_assert_eq!(info.uncompressed_size, raw.len() as u64);
        prop_assert_eq!(info.cache_key, pressed_data_cache_key(&section).unwrap());
        prop_assert!(info.integrity_verified);
        prop_assert_eq!(info.platform, Some(p));
        prop_assert_eq!(info.arch, Some(a));
        prop_assert_eq!(info.libc, Some(l));
      }

      /// NEVER-PANIC: every reader/decoder/producer entry tolerates arbitrary
      /// bytes without panicking, overflowing, or exceeding the DoS cap. This is
      /// the proptest mirror of the `read_hybrid_node` / `decode_pressed_data` /
      /// `inject_pressed_data` fuzz targets.
      #[test]
      fn readers_never_panic_on_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..8192),
      ) {
        if let Some(raw) = unwrap_if_hybrid(&data) {
          prop_assert!(raw.len() as u64 <= MAX_DECOMPRESSED);
        }
        if let Some(raw) = decode_pressed_data(&data) {
          prop_assert!(raw.len() as u64 <= MAX_DECOMPRESSED);
        }
        let _ = read_section_info(&data);
        let _ = inspect_hybrid(&data);
        let _ = pressed_data_cache_key(&data);
        // The producer-side object injector must also survive arbitrary `binary`
        // bytes (a Result either way, never a panic/overflow).
        let section = build_section_payload(b"x", Platform::Linux, Arch::X64, Libc::Glibc, 1);
        let _ = inject_pressed_data(&data, &section);
      }

      /// ORACLE: a decode that SUCCEEDS implies the inspector marks the same bytes
      /// integrity-verified — the two readers can never disagree on a good section.
      #[test]
      fn decode_success_implies_integrity_verified(
        data in proptest::collection::vec(any::<u8>(), 0..8192),
      ) {
        if decode_pressed_data(&data).is_some() {
          let info = read_section_info(&data).expect("a decodable section has a parseable header");
          prop_assert!(info.integrity_verified);
        }
      }

      /// NEVER-PANIC + ROUND-TRIP: the frozen enum byte decoders accept every u8,
      /// and any recognized byte round-trips through `variant as u8`.
      #[test]
      fn enum_from_u8_roundtrips_for_every_byte(byte in any::<u8>()) {
        if let Some(p) = Platform::from_u8(byte) {
          prop_assert_eq!(p as u8, byte);
        }
        if let Some(a) = Arch::from_u8(byte) {
          prop_assert_eq!(a as u8, byte);
        }
        if let Some(l) = Libc::from_u8(byte) {
          prop_assert_eq!(l as u8, byte);
        }
      }
    }
}
