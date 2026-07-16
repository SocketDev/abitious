//! The abitious **pressed-data section ABI** — one frozen format for shipping a
//! native `.node` addon compressed inside a signable object-file section.
//!
//! A hybrid `.node` carries the original addon, zstd-compressed, inside a
//! `PRESSED_DATA` **section** (Mach-O `__PRESSED_DATA` in segment `SMOL`, ELF
//! `.PRESSED_DATA`, PE `.PRESSED` — read from the binary's SECTION HEADERS, never
//! an EOF footer, so the file stays code-signable). The section content is the
//! pressed-data blob:
//!
//! ```text
//! [magic marker  32B]  "__SMOL_PRESSED_DATA_MAGIC_MARKER"
//! [compressed    u64 LE]  zstd payload length
//! [uncompressed  u64 LE]  raw addon length
//! [cache key     16B]  first 16 bytes of SHA-256(raw addon)
//! [platform      3B ]  platform / arch / libc enum bytes
//! [integrity     64B]  SHA-512 of the zstd payload
//! [has_config    1B ]  0 = none (abitious always emits 0)
//! [config        1192B] only if has_config == 1 (parsed-past, never emitted)
//! [payload       compressed bytes]  zstd frame
//! ```
//!
//! This is the **mirror-image ABI** of `decmpfs`'s reader (`unwrap_if_hybrid` in
//! `decmpfs/crates/decmpfs/src/addon.rs`) and `socket-btm`'s producer
//! (`compressed-binary-format-constants.mts` / `smol_segment_reader.c`). The
//! format is **frozen** — see `docs/PRESSED-DATA-FORMAT.md`. abitious is the
//! producer half decmpfs never had (`build_section_payload`) plus a byte-faithful
//! copy of the reader so both live in one crate.

mod inject;
pub mod selfextract;

pub use inject::{inject_elf, inject_macho, inject_pe, inject_pressed_data, resign, InjectError};

use sha2::{Digest, Sha256, Sha512};

/// "__SMOL_PRESSED_DATA_MAGIC_MARKER" — the 32-byte section-start marker.
pub const MAGIC_MARKER: &[u8; 32] = b"__SMOL_PRESSED_DATA_MAGIC_MARKER";

const SIZE_HEADER_LEN: usize = 16; // compressed u64 + uncompressed u64
const CACHE_KEY_LEN: usize = 16;
const PLATFORM_METADATA_LEN: usize = 3;
const INTEGRITY_HASH_LEN: usize = 64; // SHA-512
const SMOL_CONFIG_FLAG_LEN: usize = 1;
const SMOL_CONFIG_BINARY_LEN: usize = 1192;

/// Fixed header length up to and including the has-config flag (before any config
/// block or the zstd payload). marker(32) + sizes(16) + cache(16) + platform(3) +
/// integrity(64) + flag(1) = 132 bytes.
pub const HEADER_LEN: usize = MAGIC_MARKER.len()
    + SIZE_HEADER_LEN
    + CACHE_KEY_LEN
    + PLATFORM_METADATA_LEN
    + INTEGRITY_HASH_LEN
    + SMOL_CONFIG_FLAG_LEN;

/// Refuse a decompressed-size claim past this — a DoS guard matching the socket-btm
/// / decmpfs 512 MiB cap.
pub const MAX_DECOMPRESSED: u64 = 512 * 1024 * 1024;

/// Target OS enum byte (matches socket-btm `PLATFORM_VALUES`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Platform {
    Linux = 0,
    Darwin = 1,
    Win32 = 2,
}

/// Target CPU enum byte (matches socket-btm `ARCH_VALUES`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Arch {
    X64 = 0,
    Arm64 = 1,
    Ia32 = 2,
    Arm = 3,
}

/// Target libc enum byte (matches socket-btm `LIBC_VALUES`). `Na` (255) is used
/// on every non-Linux target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Libc {
    Glibc = 0,
    Musl = 1,
    Na = 255,
}

impl Platform {
    /// The host OS the running binary was built for.
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") {
            Platform::Darwin
        } else if cfg!(target_os = "windows") {
            Platform::Win32
        } else {
            Platform::Linux
        }
    }
}

impl Arch {
    /// The host CPU the running binary was built for.
    pub fn detect() -> Self {
        if cfg!(target_arch = "aarch64") {
            Arch::Arm64
        } else if cfg!(target_arch = "x86") {
            Arch::Ia32
        } else if cfg!(target_arch = "arm") {
            Arch::Arm
        } else {
            Arch::X64
        }
    }
}

impl Libc {
    /// The host libc — `Musl`/`Glibc` on Linux, `Na` everywhere else.
    pub fn detect() -> Self {
        if !cfg!(target_os = "linux") {
            Libc::Na
        } else if cfg!(target_env = "musl") {
            Libc::Musl
        } else {
            Libc::Glibc
        }
    }
}

/// Build a pressed-data section blob from a raw `.node` addon: zstd-encode it at
/// `level`, then frame it with the frozen header (magic, sizes, the SHA-256-prefix
/// cache key, the platform/arch/libc bytes, the SHA-512 payload integrity, and
/// `has_config = 0`). The result round-trips through [`decode_pressed_data`] and is
/// what a producer injects into the target's `PRESSED_DATA` section.
///
/// zstd in-memory encoding of an in-memory slice is infallible; a codec failure
/// here is a programmer error, so it panics rather than returning `Result`.
pub fn build_section_payload(
    raw: &[u8],
    platform: Platform,
    arch: Arch,
    libc: Libc,
    level: i32,
) -> Vec<u8> {
    let payload = zstd::stream::encode_all(raw, level).expect("zstd encode of an in-memory slice");

    let cache_key = {
        let digest = Sha256::digest(raw);
        let mut key = [0u8; CACHE_KEY_LEN];
        key.copy_from_slice(&digest[..CACHE_KEY_LEN]);
        key
    };
    let integrity = Sha512::digest(&payload);

    let mut section = Vec::with_capacity(HEADER_LEN + payload.len());
    section.extend_from_slice(MAGIC_MARKER);
    section.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    section.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    section.extend_from_slice(&cache_key);
    section.extend_from_slice(&[platform as u8, arch as u8, libc as u8]);
    section.extend_from_slice(&integrity);
    section.push(0u8); // has_config = 0 — abitious never emits the SMFG config block.
    section.extend_from_slice(&payload);
    section
}

/// If `content` is a pressed-data hybrid, locate its section and decode the raw
/// addon; otherwise `None`. Integrity-checked — a hybrid that fails the SHA-512 or
/// size checks returns `None`, never partial bytes.
pub fn unwrap_if_hybrid(content: &[u8]) -> Option<Vec<u8>> {
    let section = find_pressed_data_section(content)?;
    decode_pressed_data(section)
}

/// Parse a pressed-data blob (magic + header + zstd payload) into the raw addon.
/// Split from section-finding so the format round-trips in a unit test without
/// synthesizing a whole Mach-O/ELF/PE. Byte-faithful to decmpfs's reader.
pub fn decode_pressed_data(section: &[u8]) -> Option<Vec<u8>> {
    if section.len() < HEADER_LEN {
        return None;
    }
    if &section[..MAGIC_MARKER.len()] != MAGIC_MARKER.as_slice() {
        return None;
    }
    let mut at = MAGIC_MARKER.len();
    let compressed_size = read_u64_le(section, at)?;
    at += 8;
    let uncompressed_size = read_u64_le(section, at)?;
    at += 8;
    // Skip the cache key + platform metadata (not needed to decode).
    at += CACHE_KEY_LEN + PLATFORM_METADATA_LEN;
    let integrity = section.get(at..at + INTEGRITY_HASH_LEN)?;
    let mut hash = [0u8; INTEGRITY_HASH_LEN];
    hash.copy_from_slice(integrity);
    at += INTEGRITY_HASH_LEN;
    let has_config = *section.get(at)?;
    at += SMOL_CONFIG_FLAG_LEN;
    if has_config != 0 {
        at = at.checked_add(SMOL_CONFIG_BINARY_LEN)?;
    }

    if compressed_size == 0
        || uncompressed_size == 0
        || uncompressed_size > MAX_DECOMPRESSED
        || compressed_size > MAX_DECOMPRESSED
    {
        return None;
    }
    let payload = section.get(at..at.checked_add(compressed_size as usize)?)?;

    // Integrity: SHA-512 of the zstd payload, BEFORE decompressing (reject a
    // tampered frame up front).
    if Sha512::digest(payload).as_slice() != hash {
        return None;
    }

    let raw = zstd::stream::decode_all(payload).ok()?;
    if raw.len() as u64 != uncompressed_size {
        return None;
    }
    Some(raw)
}

/// Read the 16-byte cache key stamped into a pressed-data section blob (the first 16
/// bytes of SHA-256 over the raw addon, written by [`build_section_payload`]). The key
/// sits right after the magic marker and the two size fields. Returns `None` if `section`
/// is too short or lacks the magic marker. This is the content-address the self-extract
/// cache path is keyed on — a producer reads it back for its receipt without decoding.
pub fn pressed_data_cache_key(section: &[u8]) -> Option<[u8; CACHE_KEY_LEN]> {
    if section.len() < HEADER_LEN || &section[..MAGIC_MARKER.len()] != MAGIC_MARKER.as_slice() {
        return None;
    }
    let at = MAGIC_MARKER.len() + SIZE_HEADER_LEN;
    let mut key = [0u8; CACHE_KEY_LEN];
    key.copy_from_slice(section.get(at..at + CACHE_KEY_LEN)?);
    Some(key)
}

fn read_u64_le(buf: &[u8], at: usize) -> Option<u64> {
    let bytes = buf.get(at..at + 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Some(u64::from_le_bytes(arr))
}

fn read_u32_le(buf: &[u8], at: usize) -> Option<u32> {
    let bytes = buf.get(at..at + 4)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Some(u32::from_le_bytes(arr))
}

fn read_u16_le(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Locate the PRESSED_DATA section's raw bytes by walking the binary's section /
/// load-command table — never an EOF footer. Dispatches on the leading magic.
fn find_pressed_data_section(content: &[u8]) -> Option<&[u8]> {
    match content.get(..4)? {
        // Mach-O 64-bit, both endiannesses.
        [0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf] => find_macho(content),
        [0x7f, b'E', b'L', b'F'] => find_elf(content),
        [b'M', b'Z', ..] => find_pe(content),
        _ => None,
    }
}

/// Mach-O 64-bit (little-endian host): segment `SMOL` → section `__PRESSED_DATA` →
/// its (offset, size) slice.
fn find_macho(content: &[u8]) -> Option<&[u8]> {
    const LC_SEGMENT_64: u32 = 0x19;
    // mach_header_64: magic(4) cputype(4) cpusubtype(4) filetype(4) ncmds(4) ...
    let ncmds = read_u32_le(content, 16)?;
    let mut cmd_off = 32usize; // sizeof(mach_header_64)
    for _ in 0..ncmds.min(10_000) {
        let cmd = read_u32_le(content, cmd_off)?;
        let cmdsize = read_u32_le(content, cmd_off + 4)? as usize;
        if cmdsize == 0 {
            return None;
        }
        if cmd == LC_SEGMENT_64 {
            // segment_command_64: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8)
            //   fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4)
            let segname = content.get(cmd_off + 8..cmd_off + 24)?;
            if name_eq(segname, b"SMOL") {
                let nsects = read_u32_le(content, cmd_off + 64)?;
                let mut sect_off = cmd_off + 72; // start of section_64 array
                for _ in 0..nsects.min(1000) {
                    // section_64: sectname(16) segname(16) addr(8) size(8) offset(4) ...
                    let sectname = content.get(sect_off..sect_off + 16)?;
                    if name_eq(sectname, b"__PRESSED_DATA") {
                        let size = read_u64_le(content, sect_off + 40)? as usize;
                        let offset = read_u32_le(content, sect_off + 48)? as usize;
                        return content.get(offset..offset.checked_add(size)?);
                    }
                    sect_off += 80; // sizeof(section_64)
                }
            }
        }
        cmd_off = cmd_off.checked_add(cmdsize)?;
    }
    None
}

/// ELF 64-bit: walk the section-header table, match `.PRESSED_DATA` against the
/// section-header string table, return its (sh_offset, sh_size) slice.
fn find_elf(content: &[u8]) -> Option<&[u8]> {
    // EI_CLASS at offset 4: 2 == 64-bit. Only 64-bit addons ship.
    if *content.get(4)? != 2 {
        return None;
    }
    let e_shoff = read_u64_le(content, 40)? as usize;
    let e_shentsize = read_u16_le(content, 58)? as usize;
    let e_shnum = read_u16_le(content, 60)? as usize;
    let e_shstrndx = read_u16_le(content, 62)? as usize;
    if e_shentsize < 64 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return None;
    }
    // String-table section header → its (offset, size).
    let strtab_hdr = e_shoff.checked_add(e_shstrndx.checked_mul(e_shentsize)?)?;
    let strtab_off = read_u64_le(content, strtab_hdr + 24)? as usize;
    let strtab_size = read_u64_le(content, strtab_hdr + 32)? as usize;
    let strtab = content.get(strtab_off..strtab_off.checked_add(strtab_size)?)?;

    for i in 0..e_shnum {
        let shdr = e_shoff.checked_add(i.checked_mul(e_shentsize)?)?;
        let sh_name = read_u32_le(content, shdr)? as usize;
        if cstr_at(strtab, sh_name) == Some(b".PRESSED_DATA".as_slice()) {
            let sh_offset = read_u64_le(content, shdr + 24)? as usize;
            let sh_size = read_u64_le(content, shdr + 32)? as usize;
            return content.get(sh_offset..sh_offset.checked_add(sh_size)?);
        }
    }
    None
}

/// PE: parse the section table for `.PRESSED` (the 8-byte-name truncation of
/// `.PRESSED_DATA`) and return its (PointerToRawData, SizeOfRawData) slice.
fn find_pe(content: &[u8]) -> Option<&[u8]> {
    let pe_off = read_u32_le(content, 0x3c)? as usize;
    if content.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_off + 4;
    let number_of_sections = read_u16_le(content, coff + 2)? as usize;
    let size_of_optional = read_u16_le(content, coff + 16)? as usize;
    if number_of_sections > 200 {
        return None;
    }
    let mut sect = coff + 20 + size_of_optional; // section table start
    for _ in 0..number_of_sections {
        let name = content.get(sect..sect + 8)?;
        if name == b".PRESSED" {
            let size_of_raw = read_u32_le(content, sect + 16)? as usize;
            let ptr_raw = read_u32_le(content, sect + 20)? as usize;
            return content.get(ptr_raw..ptr_raw.checked_add(size_of_raw)?);
        }
        sect += 40; // sizeof(IMAGE_SECTION_HEADER)
    }
    None
}

/// Compare a fixed-width, NUL-padded name field against a logical name.
fn name_eq(field: &[u8], want: &[u8]) -> bool {
    if want.len() > field.len() {
        return false;
    }
    field[..want.len()] == *want && field[want.len()..].iter().all(|&b| b == 0)
}

/// The NUL-terminated string at `off` within a string table.
fn cstr_at(strtab: &[u8], off: usize) -> Option<&[u8]> {
    let rest = strtab.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
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
            let section =
                build_section_payload(&raw, Platform::Darwin, Arch::Arm64, Libc::Na, level);
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
}
