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
//! format is **frozen** — see `docs/pressed-data-format.md`. abitious is the
//! producer half decmpfs never had (`build_section_payload`) plus a byte-faithful
//! copy of the reader so both live in one crate.
//!
//! ## The FS-compression engine
//!
//! Transparent filesystem compression (macOS APFS decmpfs, Linux btrfs, Windows
//! NTFS) comes from the [`decmpfs`] crate, which owns that engine. The store-write
//! surface a package manager needs is re-exported at this crate's root
//! ([`compress_bytes`], [`probe`], [`stat`], [`Outcome`], [`Gate`], …), so a
//! decmpfs-aware package manager gets BOTH the distribution SECTION format AND
//! install-time kernel compression from one dependency, at one pinned engine
//! version. [`install_hybrid`] is the abitious install bridge that ties the two
//! halves together: unwrap a downloaded hybrid's raw addon and land it as a
//! kernel-compressed store entry in one pass. [`OutcomeExt::describe`] renders the
//! result as a receipt line.
//!
//! The in-place [`decmpfs::compress_file`] is deliberately NOT re-exported flat —
//! see the note on the re-export block below.

// The deny keeps non-test code free of the obvious panic sources; all slice indexing
// in the section reader is already length-guarded. `build_section_payload` carries a
// single justified `#[allow]` for its infallible in-memory zstd encode.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// On a nightly `cargo llvm-cov` run, cargo-llvm-cov sets `coverage_nightly`,
// enabling `#[coverage(off)]` so test-only code is dropped from the report and it
// reflects PRODUCTION coverage. A no-op on stable (the cfg is unset), so ordinary
// builds and `cargo test` are unaffected.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod inject;
mod outcome;
pub mod selfextract;

pub use inject::{inject_elf, inject_macho, inject_pe, inject_pressed_data, resign, InjectError};
pub use outcome::{skip_reason_text, unsupported_reason_text, OutcomeExt};

// The engine itself, re-exported under its own name. Anything not named flat below
// is reached as `abitious_decmpfs::decmpfs::…`, which keeps upstream semantics
// explicit at the call site and spares a caller a second dependency that could skew
// against the version this crate pins.
pub use decmpfs;

// The store-write surface, flattened to the crate root: what a package manager
// needs to land a downloaded addon as a kernel-compressed store entry.
//
// `compress_file` is intentionally absent. It compresses an existing file IN PLACE,
// which is not the store-write path abitious exists to serve, and upstream verifies
// that path by comparing only a 4-byte magic prefix before/after — where
// `compress_bytes` (and so [`install_hybrid`]) compares the FULL content read back
// through the kernel. Flattening a weaker in-place check next to these names would
// imply a guarantee this crate does not make, and re-implementing the strong check
// here would fork the safety layer and let the upstream gap sit unfixed. A caller
// that genuinely wants in-place compression reaches `decmpfs::compress_file`
// directly, where the semantics are upstream's and read as upstream's.
pub use decmpfs::{
    compress_bytes, probe, stat, Error, Gate, GateParseError, Outcome, SizePredicate, SkipReason,
    Stat, Support, UnsupportedReason, DEFAULT_GLOB,
};

use std::path::Path;

use sha2::{Digest, Sha256, Sha512};

/// Install a (possibly hybrid) `.node` into the store as an OS-transparently-compressed
/// file in one pass — THE decmpfs-aware package-manager install path.
///
/// If `input` is an abitious hybrid, its raw addon is recovered from the pressed-data
/// SECTION ([`unwrap_if_hybrid`]) first; a plain addon (not a hybrid) is written as-is.
/// The raw addon bytes are then written to `dest` via [`compress_bytes`]
/// (kernel-compressed, kernel-roundtrip verified, fail-soft to a plain atomic write on
/// any unsupported FS / permission / integrity issue). Returns the resulting
/// [`Outcome`].
///
/// This is exactly what a PM's content-addressed store writer does: it downloaded the
/// published hybrid and lands a kernel-compressed, natively-loadable store entry that
/// `dlopen` reads at near-native speed (the kernel decompresses transparently). The
/// `gate` gates the write as a convenience; a caller that already selected the file can
/// pass [`Gate::any()`].
pub fn install_hybrid(input: &[u8], dest: &Path, gate: &Gate) -> Result<Outcome, Error> {
    match unwrap_if_hybrid(input) {
        Some(raw) => compress_bytes(dest, &raw, gate),
        None => compress_bytes(dest, input, gate),
    }
}

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
        Self::from_cfg(cfg!(target_os = "macos"), cfg!(target_os = "windows"))
    }

    /// The pure host-dispatch policy, split from the `cfg!` evaluation so every platform arm
    /// is unit-tested regardless of the host running the tests (mirrors `decmpfs`'s
    /// `classify_fs` split and `triple::triple_of`; no single host can execute all arms).
    fn from_cfg(is_macos: bool, is_windows: bool) -> Self {
        if is_macos {
            Platform::Darwin
        } else if is_windows {
            Platform::Win32
        } else {
            Platform::Linux
        }
    }
}

impl Arch {
    /// The host CPU the running binary was built for.
    pub fn detect() -> Self {
        Self::from_cfg(
            cfg!(target_arch = "aarch64"),
            cfg!(target_arch = "x86"),
            cfg!(target_arch = "arm"),
        )
    }

    /// Pure host-dispatch policy, split from `cfg!` so every arch arm is testable on any host.
    fn from_cfg(is_aarch64: bool, is_x86: bool, is_arm: bool) -> Self {
        if is_aarch64 {
            Arch::Arm64
        } else if is_x86 {
            Arch::Ia32
        } else if is_arm {
            Arch::Arm
        } else {
            Arch::X64
        }
    }
}

impl Libc {
    /// The host libc — `Musl`/`Glibc` on Linux, `Na` everywhere else.
    pub fn detect() -> Self {
        Self::from_cfg(cfg!(target_os = "linux"), cfg!(target_env = "musl"))
    }

    /// Pure host-dispatch policy, split from `cfg!` so every libc arm is testable on any host.
    fn from_cfg(is_linux: bool, is_musl: bool) -> Self {
        if !is_linux {
            Libc::Na
        } else if is_musl {
            Libc::Musl
        } else {
            Libc::Glibc
        }
    }
}

impl Platform {
    /// Map a stored platform enum byte back to a [`Platform`], or `None` for an
    /// unrecognized value (a tool inspecting a hybrid keeps the raw byte in that case).
    pub fn from_u8(byte: u8) -> Option<Platform> {
        match byte {
            0 => Some(Platform::Linux),
            1 => Some(Platform::Darwin),
            2 => Some(Platform::Win32),
            _ => None,
        }
    }
}

impl Arch {
    /// Map a stored arch enum byte back to an [`Arch`], or `None` for an unrecognized value.
    pub fn from_u8(byte: u8) -> Option<Arch> {
        match byte {
            0 => Some(Arch::X64),
            1 => Some(Arch::Arm64),
            2 => Some(Arch::Ia32),
            3 => Some(Arch::Arm),
            _ => None,
        }
    }
}

impl Libc {
    /// Map a stored libc enum byte back to a [`Libc`], or `None` for an unrecognized value.
    pub fn from_u8(byte: u8) -> Option<Libc> {
        match byte {
            0 => Some(Libc::Glibc),
            1 => Some(Libc::Musl),
            255 => Some(Libc::Na),
            _ => None,
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
// zstd in-memory encoding of an in-memory slice is infallible; the deny on
// expect_used is waived here for that single justified, documented panic.
#[allow(clippy::expect_used)]
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

/// The parsed fixed header of a pressed-data section (every field before the zstd
/// payload) plus `payload_at`, the byte offset the payload begins at. The frozen
/// field offsets live here in exactly ONE place, shared by [`decode_pressed_data`]
/// (which then decompresses) and [`read_section_info`] (which never does), so the two
/// readers can never drift from the layout in `docs/pressed-data-format.md`.
struct ParsedHeader {
    compressed_size: u64,
    uncompressed_size: u64,
    cache_key: [u8; CACHE_KEY_LEN],
    platform: u8,
    arch: u8,
    libc: u8,
    integrity: [u8; INTEGRITY_HASH_LEN],
    has_config: bool,
    payload_at: usize,
}

/// Parse the frozen fixed header out of a pressed-data blob (magic, sizes, cache key,
/// platform bytes, integrity, has_config), returning the fields and the offset the zstd
/// payload starts at. `None` if the buffer is too short or lacks the magic marker. Never
/// touches the payload — no decompression, no size/DoS gating (the callers apply those
/// where they matter).
fn parse_header(section: &[u8]) -> Option<ParsedHeader> {
    if section.len() < HEADER_LEN || &section[..MAGIC_MARKER.len()] != MAGIC_MARKER.as_slice() {
        return None;
    }
    let mut at = MAGIC_MARKER.len();
    let compressed_size = read_u64_le(section, at)?;
    at += 8;
    let uncompressed_size = read_u64_le(section, at)?;
    at += 8;
    let mut cache_key = [0u8; CACHE_KEY_LEN];
    cache_key.copy_from_slice(section.get(at..at + CACHE_KEY_LEN)?);
    at += CACHE_KEY_LEN;
    let platform = *section.get(at)?;
    let arch = *section.get(at + 1)?;
    let libc = *section.get(at + 2)?;
    at += PLATFORM_METADATA_LEN;
    let mut integrity = [0u8; INTEGRITY_HASH_LEN];
    integrity.copy_from_slice(section.get(at..at + INTEGRITY_HASH_LEN)?);
    at += INTEGRITY_HASH_LEN;
    let has_config = *section.get(at)? != 0;
    at += SMOL_CONFIG_FLAG_LEN;
    let payload_at = if has_config {
        at.checked_add(SMOL_CONFIG_BINARY_LEN)?
    } else {
        at
    };
    Some(ParsedHeader {
        compressed_size,
        uncompressed_size,
        cache_key,
        platform,
        arch,
        libc,
        integrity,
        has_config,
        payload_at,
    })
}

/// Parse a pressed-data blob (magic + header + zstd payload) into the raw addon.
/// Split from section-finding so the format round-trips in a unit test without
/// synthesizing a whole Mach-O/ELF/PE. Byte-faithful to decmpfs's reader.
pub fn decode_pressed_data(section: &[u8]) -> Option<Vec<u8>> {
    let header = parse_header(section)?;

    if header.compressed_size == 0
        || header.uncompressed_size == 0
        || header.uncompressed_size > MAX_DECOMPRESSED
        || header.compressed_size > MAX_DECOMPRESSED
    {
        return None;
    }
    let payload = section.get(
        header.payload_at
            ..header
                .payload_at
                .checked_add(header.compressed_size as usize)?,
    )?;

    // Integrity: SHA-512 of the zstd payload, BEFORE decompressing (reject a
    // tampered frame up front).
    if Sha512::digest(payload).as_slice() != header.integrity {
        return None;
    }

    // Bound the ACTUAL decompression to MAX_DECOMPRESSED: the header's size claims and the
    // publisher-controlled SHA-512 cannot stop a zstd bomb — a tiny payload that expands to
    // many GiB — so decode through a capped streaming decoder rather than an unbounded
    // `decode_all` (which would OOM the reader before this size check ever ran).
    let raw = decode_capped(payload, MAX_DECOMPRESSED)?;
    if raw.len() as u64 != header.uncompressed_size {
        return None;
    }
    Some(raw)
}

/// Decompress a zstd frame while never allocating more than `cap` bytes of output. A tiny
/// payload can claim a small `uncompressed_size` in the (attacker-controlled) header yet
/// expand to many GiB — a zstd bomb — so neither the header sizes nor the
/// publisher-controlled SHA-512 can bound the decode. Stream through a `Decoder` capped at
/// `cap + 1` bytes and reject a frame whose output would exceed `cap` BEFORE the oversized
/// buffer is ever materialized. `None` on any codec error or an over-cap frame.
fn decode_capped(payload: &[u8], cap: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    // Read at most cap + 1 bytes: pulling that many proves the frame is over the cap, and
    // the `Take` guarantees the buffer never grows past cap + 1 no matter how big the frame.
    let mut limited = zstd::stream::read::Decoder::new(payload)
        .ok()?
        .take(cap.saturating_add(1));
    let mut raw = Vec::new();
    limited.read_to_end(&mut raw).ok()?;
    if raw.len() as u64 > cap {
        return None;
    }
    Some(raw)
}

/// A non-decoding view of a pressed-data section's fixed header + integrity status —
/// what `abi inspect` reports without paying to decompress the payload. Produced by
/// [`inspect_hybrid`] (from a whole binary) or [`read_section_info`] (from a bare
/// section blob).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionInfo {
    /// The zstd payload length claimed by the header.
    pub compressed_size: u64,
    /// The raw addon length claimed by the header.
    pub uncompressed_size: u64,
    /// The 16-byte content-address (first 16 bytes of `SHA-256(raw addon)`).
    pub cache_key: [u8; CACHE_KEY_LEN],
    /// The raw platform enum byte, and its decoded [`Platform`] when recognized.
    pub platform_byte: u8,
    /// Decoded platform, or `None` for an unrecognized byte.
    pub platform: Option<Platform>,
    /// The raw arch enum byte.
    pub arch_byte: u8,
    /// Decoded arch, or `None` for an unrecognized byte.
    pub arch: Option<Arch>,
    /// The raw libc enum byte.
    pub libc_byte: u8,
    /// Decoded libc, or `None` for an unrecognized byte.
    pub libc: Option<Libc>,
    /// The `has_config` flag (abitious always emits `false`).
    pub has_config: bool,
    /// `true` when `SHA-512(payload)` matches the stored integrity hash — the same
    /// check [`decode_pressed_data`] gates on, computed here WITHOUT decompressing.
    /// `false` if the payload is missing/out-of-range or the hash differs.
    pub integrity_verified: bool,
}

/// If `content` is a pressed-data hybrid, locate its section and read its header +
/// integrity status ([`SectionInfo`]) WITHOUT decompressing the payload; otherwise
/// `None` (a plain, non-hybrid file). The inspection counterpart of
/// [`unwrap_if_hybrid`].
pub fn inspect_hybrid(content: &[u8]) -> Option<SectionInfo> {
    read_section_info(find_pressed_data_section(content)?)
}

/// Parse a bare pressed-data section blob into a [`SectionInfo`] — the header fields
/// plus whether `SHA-512(payload)` matches the stored integrity hash — without
/// decompressing. `None` if the blob is too short or lacks the magic marker.
pub fn read_section_info(section: &[u8]) -> Option<SectionInfo> {
    let header = parse_header(section)?;
    // Verify integrity exactly as the decoder does (SHA-512 of the zstd payload),
    // but stop there — no decompression, so inspecting a huge hybrid stays cheap.
    let integrity_verified = header.compressed_size > 0
        && header.compressed_size <= MAX_DECOMPRESSED
        && header
            .payload_at
            .checked_add(header.compressed_size as usize)
            .and_then(|end| section.get(header.payload_at..end))
            .is_some_and(|payload| Sha512::digest(payload).as_slice() == header.integrity);
    Some(SectionInfo {
        compressed_size: header.compressed_size,
        uncompressed_size: header.uncompressed_size,
        cache_key: header.cache_key,
        platform_byte: header.platform,
        platform: Platform::from_u8(header.platform),
        arch_byte: header.arch,
        arch: Arch::from_u8(header.arch),
        libc_byte: header.libc,
        libc: Libc::from_u8(header.libc),
        has_config: header.has_config,
        integrity_verified,
    })
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
