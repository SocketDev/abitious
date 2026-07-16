//! Producer-side section injection + ad-hoc re-sign — the mirror of the reader in
//! [`crate`]. Splices the pressed-data blob (what [`crate::build_section_payload`]
//! returns) into a target binary's SIGNABLE section so [`crate::unwrap_if_hybrid`]
//! recovers it:
//!
//! | format | injected as |
//! | --- | --- |
//! | Mach-O 64-bit | a READ-only `LC_SEGMENT_64` `SMOL` / section `__PRESSED_DATA` |
//! | ELF 64-bit | a non-alloc `SHT_PROGBITS` section `.PRESSED_DATA` |
//! | PE / COFF | a read-only section `.PRESSED` (the 8-char section-name limit) |
//!
//! The Mach-O path splices the new segment command into the header slack immediately
//! before `__LINKEDIT`, shifts `__LINKEDIT` and every linkedit-pointing file offset
//! down by the page-rounded section size, strips the stale `LC_CODE_SIGNATURE`, then
//! ad-hoc re-signs so the injected section is signature-covered. Every structural
//! offset is walked at runtime from the load commands. The byte layout matches a
//! binject(LIEF)-produced reference (segment `filesize` = unpadded body, `vmsize` =
//! page-rounded; section `size` = body, `offset` = `fileoff` = the old `__LINKEDIT`
//! fileoff; W^X `initprot` = `maxprot` = `VM_PROT_READ`).
//!
//! Adapted from napi-rs `napi-compress`'s `inject.rs`, which injected `SMOL/__DECMPFS`;
//! abitious injects `SMOL/__PRESSED_DATA` (ELF `.PRESSED_DATA`, PE `.PRESSED`) so the
//! names agree with the M1 reader's `find_macho` / `find_elf` / `find_pe`.

use std::fmt;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;

const CPU_TYPE_ARM64: u32 = 0x0100_000c;

const MACH_HEADER_64_SIZE: usize = 32;
/// `cmd,cmdsize,segname[16],vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,flags`.
const SEGMENT_COMMAND_64_SIZE: usize = 72;
/// `sectname[16],segname[16],addr,size,offset,align,reloff,nreloc,flags,reserved1..3`.
const SECTION_64_SIZE: usize = 80;
const NEW_LC_SIZE: usize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE; // 152

/// `VM_PROT_READ` only. An injected segment MUST be read-only: RWX (0x07) makes
/// dyld refuse to mmap the bundle on dlopen (EACCES) even with a valid signature.
const VM_PROT_READ: u32 = 0x01;

/// The ad-hoc code-signing identifier stamped when the (stripped) Mach-O carries
/// none — a stable non-empty string is all an ad-hoc signature needs.
#[cfg(all(target_os = "macos", feature = "resign"))]
const DEFAULT_BINARY_IDENTIFIER: &str = "abitious-hybrid-addon";

/// Everything that can go wrong injecting a pressed-data section or re-signing the
/// result. Hand-rolled (no `thiserror`) to keep the dependency budget minimal.
pub enum InjectError {
    /// The binary's leading magic matched no supported object format.
    UnknownFormat,
    /// A structural field lay outside the binary, or a header field held an
    /// unsupported / malformed value. Carries a human-readable description.
    Malformed(String),
    /// Not enough Mach-O header slack to splice the new segment command.
    InsufficientSlack { have: usize, need: usize },
    /// apple-codesign failed to ad-hoc re-sign the injected Mach-O (macOS producer).
    Resign(String),
}

impl fmt::Display for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectError::UnknownFormat => {
                f.write_str("unrecognized binary format: not a 64-bit LE Mach-O, ELF, or PE")
            }
            InjectError::Malformed(msg) => write!(f, "malformed object file: {msg}"),
            InjectError::InsufficientSlack { have, need } => write!(
                f,
                "insufficient Mach-O header slack: have {have} bytes, need {need} for the \
                 injected segment command; rebuild with -headerpad,0x1000"
            ),
            InjectError::Resign(msg) => write!(f, "ad-hoc re-sign failed: {msg}"),
        }
    }
}

impl fmt::Debug for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectError::UnknownFormat => f.write_str("UnknownFormat"),
            InjectError::Malformed(msg) => write!(f, "Malformed({msg:?})"),
            InjectError::InsufficientSlack { have, need } => f
                .debug_struct("InsufficientSlack")
                .field("have", have)
                .field("need", need)
                .finish(),
            InjectError::Resign(msg) => write!(f, "Resign({msg:?})"),
        }
    }
}

impl std::error::Error for InjectError {}

fn malformed(msg: impl Into<String>) -> InjectError {
    InjectError::Malformed(msg.into())
}

fn u16_le(bytes: &[u8], off: usize) -> Result<u16, InjectError> {
    bytes
        .get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| malformed(format!("truncated u16 at offset {off}")))
}

fn u32_le(bytes: &[u8], off: usize) -> Result<u32, InjectError> {
    bytes
        .get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| malformed(format!("truncated u32 at offset {off}")))
}

fn u64_le(bytes: &[u8], off: usize) -> Result<u64, InjectError> {
    bytes
        .get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| malformed(format!("truncated u64 at offset {off}")))
}

fn put_u16(bytes: &mut [u8], off: usize, value: u16) {
    bytes[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], off: usize, value: u64) {
    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn round_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

/// A NUL-padded fixed-width name slot equals `want`.
fn name_eq(slot: &[u8], want: &[u8]) -> bool {
    slot.len() >= want.len()
        && &slot[..want.len()] == want
        && slot[want.len()..].iter().all(|&b| b == 0)
}

/// Inject the pressed-data blob `section` (exactly what [`crate::build_section_payload`]
/// returns) into `binary`, dispatching on the leading magic. Mach-O is injected +
/// ad-hoc re-signed (see [`resign`]); ELF and PE need no signature (their loaders
/// enforce none on `dlopen`). The result round-trips through [`crate::unwrap_if_hybrid`].
pub fn inject_pressed_data(binary: &[u8], section: &[u8]) -> Result<Vec<u8>, InjectError> {
    match binary.get(..4) {
        // Mach-O 64-bit, both endiannesses (the injector supports only LE; a BE
        // header is recognized here but rejected by `inject_macho`'s magic check).
        Some([0xcf, 0xfa, 0xed, 0xfe]) | Some([0xfe, 0xed, 0xfa, 0xcf]) => {
            inject_macho(binary, section)
        }
        Some([0x7f, b'E', b'L', b'F']) => inject_elf(binary, section),
        Some([b'M', b'Z', ..]) => inject_pe(binary, section),
        _ => Err(InjectError::UnknownFormat),
    }
}

/// One linkedit-pointing field to bump: the absolute byte offset of a `u32`
/// file-offset field within the (post-splice) command stream.
struct OffsetField {
    at: usize,
}

/// The structural anchors found by walking the load commands once.
struct Layout {
    page_size: u64,
    /// Byte offset of the `__LINKEDIT` segment command (splice point).
    linkedit_lc_off: usize,
    linkedit_fileoff: u64,
    linkedit_vmaddr: u64,
    /// `LC_CODE_SIGNATURE`, if present: (command byte offset, sig dataoff).
    code_sig: Option<CodeSig>,
    /// First mapped section file offset — the slack boundary the new LC must fit
    /// under (everything before it is header + load commands).
    first_section_offset: u64,
    end_of_lc: usize,
    /// Linkedit-pointing `u32` file-offset fields, by their byte offset in the
    /// ORIGINAL command stream (caller re-bases by +NEW_LC after the splice).
    linkedit_pointers: Vec<OffsetField>,
}

struct CodeSig {
    lc_off: usize,
    dataoff: u64,
}

/// Walk the mach_header_64 + load commands once, recording every anchor the
/// surgery touches. Refuses anything but a single-arch 64-bit LE Mach-O.
fn read_layout(bytes: &[u8]) -> Result<Layout, InjectError> {
    if u32_le(bytes, 0)? != MH_MAGIC_64 {
        return Err(malformed("not a 64-bit little-endian Mach-O (bad magic)"));
    }
    let cputype = u32_le(bytes, 4)?;
    let page_size: u64 = if cputype == CPU_TYPE_ARM64 {
        0x4000
    } else {
        0x1000
    };
    let ncmds = u32_le(bytes, 16)?;

    let mut linkedit_lc_off: Option<usize> = None;
    let mut linkedit_fileoff = 0u64;
    let mut linkedit_vmaddr = 0u64;
    let mut code_sig: Option<CodeSig> = None;
    let mut first_section_offset = u64::MAX;
    let mut linkedit_pointers: Vec<OffsetField> = Vec::new();

    let mut off = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let cmd = u32_le(bytes, off)?;
        let cmdsize = u32_le(bytes, off + 4)? as usize;
        if cmdsize < 8 || off + cmdsize > bytes.len() {
            return Err(malformed(format!(
                "malformed load command at {off} (cmdsize {cmdsize})"
            )));
        }
        match cmd {
            LC_SEGMENT_64 => {
                // An LC_SEGMENT_64 is always >= 72 bytes; the generic `cmdsize >= 8` guard
                // above is not enough to make the fixed segment_command_64 fields (segname,
                // fileoff@40, nsects@64) in-range. Require the real minimum so a truncated
                // segment command (cmdsize in [8,71] at EOF) is a Malformed error, never a
                // slice-index panic — and so the post-splice __LINKEDIT field writes stay
                // within the copied command bytes.
                if cmdsize < SEGMENT_COMMAND_64_SIZE {
                    return Err(malformed(format!(
                        "LC_SEGMENT_64 at {off} has cmdsize {cmdsize} < {SEGMENT_COMMAND_64_SIZE}"
                    )));
                }
                let segname = bytes.get(off + 8..off + 24).ok_or_else(|| {
                    malformed(format!("truncated LC_SEGMENT_64 segname at {off}"))
                })?;
                let fileoff = u64_le(bytes, off + 40)?;
                let nsects = u32_le(bytes, off + 64)?;
                if name_eq(segname, b"__LINKEDIT") {
                    linkedit_lc_off = Some(off);
                    linkedit_fileoff = fileoff;
                    linkedit_vmaddr = u64_le(bytes, off + 24)?;
                }
                // Track the smallest section file offset across every segment — the
                // header-slack ceiling (load commands must not overrun the first
                // mapped section's bytes).
                let mut soff = off + SEGMENT_COMMAND_64_SIZE;
                for _ in 0..nsects {
                    let sect_off = u32_le(bytes, soff + 48)? as u64;
                    // offset == 0 marks a zero-fill section (__bss/__thread_bss); skip it.
                    if sect_off != 0 && sect_off < first_section_offset {
                        first_section_offset = sect_off;
                    }
                    soff += SECTION_64_SIZE;
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                // rebase_off@8, bind_off@16, weak_bind_off@24, lazy_bind_off@32, export_off@40.
                for field in [8, 16, 24, 32, 40] {
                    linkedit_pointers.push(OffsetField { at: off + field });
                }
            }
            LC_SYMTAB => {
                // symoff@8, stroff@16.
                linkedit_pointers.push(OffsetField { at: off + 8 });
                linkedit_pointers.push(OffsetField { at: off + 16 });
            }
            LC_DYSYMTAB => {
                // tocoff@32, modtaboff@40, extrefsymoff@48, indirectsymoff@56,
                // extreloff@64, locreloff@72 — all linkedit-relative file offsets.
                for field in [32, 40, 48, 56, 64, 72] {
                    linkedit_pointers.push(OffsetField { at: off + field });
                }
            }
            LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_DYLD_EXPORTS_TRIE => {
                // linkedit_data_command: dataoff@8.
                linkedit_pointers.push(OffsetField { at: off + 8 });
            }
            LC_CODE_SIGNATURE => {
                // linkedit_data_command: dataoff is a u32 file offset at +8 (NOT a u64).
                code_sig = Some(CodeSig {
                    lc_off: off,
                    dataoff: u32_le(bytes, off + 8)? as u64,
                });
            }
            _ => {}
        }
        off += cmdsize;
    }

    let linkedit_lc_off = linkedit_lc_off
        .ok_or_else(|| malformed("no __LINKEDIT segment to anchor the new section"))?;
    if first_section_offset == u64::MAX {
        return Err(malformed("no mapped section to bound the header slack"));
    }
    Ok(Layout {
        page_size,
        linkedit_lc_off,
        linkedit_fileoff,
        linkedit_vmaddr,
        code_sig,
        first_section_offset,
        end_of_lc: off,
        linkedit_pointers,
    })
}

/// Build the 152-byte `LC_SEGMENT_64` + one `section_64` for `SMOL/__PRESSED_DATA`.
fn build_segment_lc(body_len: u64, delta: u64, fileoff: u64, vmaddr: u64) -> Vec<u8> {
    let mut lc = vec![0u8; NEW_LC_SIZE];
    // segment_command_64
    put_u32(&mut lc, 0, LC_SEGMENT_64);
    put_u32(&mut lc, 4, NEW_LC_SIZE as u32);
    lc[8..12].copy_from_slice(b"SMOL"); // segname (NUL-padded)
    put_u64(&mut lc, 24, vmaddr); // vmaddr
    put_u64(&mut lc, 32, delta); // vmsize (page-rounded)
    put_u64(&mut lc, 40, fileoff); // fileoff
    put_u64(&mut lc, 48, body_len); // filesize (unpadded body)
    put_u32(&mut lc, 56, VM_PROT_READ); // maxprot
    put_u32(&mut lc, 60, VM_PROT_READ); // initprot (W^X)
    put_u32(&mut lc, 64, 1); // nsects
    put_u32(&mut lc, 68, 0); // flags
    let s = SEGMENT_COMMAND_64_SIZE; // the section_64 begins at +72
    lc[s..s + 14].copy_from_slice(b"__PRESSED_DATA"); // sectname (14B, NUL-padded to 16)
    lc[s + 16..s + 20].copy_from_slice(b"SMOL"); // segname
    put_u64(&mut lc, s + 32, vmaddr); // addr
    put_u64(&mut lc, s + 40, body_len); // size (unpadded body)
    put_u32(&mut lc, s + 48, fileoff as u32); // offset
    put_u32(&mut lc, s + 52, 2); // align 2^2 = 4; reloff/nreloc/flags/reserved1..3 stay 0
    lc
}

/// Mach-O: splice a READ-only `SMOL/__PRESSED_DATA` `LC_SEGMENT_64`, strip the stale
/// `LC_CODE_SIGNATURE`, then ad-hoc re-sign via [`resign`] so the injected section is
/// signature-covered. On non-macOS (or without the `resign` feature) [`resign`] is a
/// no-op and the returned bytes are unsigned.
pub fn inject_macho(binary: &[u8], section: &[u8]) -> Result<Vec<u8>, InjectError> {
    let spliced = splice_macho_segment(binary, section)?;
    resign(&spliced)
}

/// The pure Mach-O surgery: returns the injected (still UNSIGNED) bytes.
fn splice_macho_segment(stub: &[u8], section_body: &[u8]) -> Result<Vec<u8>, InjectError> {
    let layout = read_layout(stub)?;

    // 1. Slack guard: the new 152-byte LC must fit between END_OF_LC and the first
    //    mapped section. The stub must be linked with -headerpad,0x1000 to guarantee it.
    //    `checked_sub` (release builds run with overflow-checks OFF, so a bare `-` would
    //    WRAP): a first mapped section that precedes the load commands is a corrupt layout.
    let first_section_offset = usize::try_from(layout.first_section_offset)
        .map_err(|_| malformed("first mapped section offset out of range"))?;
    let slack = first_section_offset
        .checked_sub(layout.end_of_lc)
        .ok_or_else(|| malformed("first mapped section precedes the end of the load commands"))?;
    if slack < NEW_LC_SIZE {
        return Err(InjectError::InsufficientSlack {
            have: slack,
            need: NEW_LC_SIZE,
        });
    }

    let body_len = section_body.len() as u64;
    let delta = round_up(body_len, layout.page_size);
    let new_fileoff = layout.linkedit_fileoff;
    let new_vmaddr = layout.linkedit_vmaddr;
    let linkedit_start = layout.linkedit_fileoff as usize;
    // Exclude the old signature bytes — they trail __LINKEDIT and the signer
    // regenerates them. Without a signature, __LINKEDIT runs to EOF.
    let linkedit_end = match &layout.code_sig {
        Some(sig) => sig.dataoff as usize,
        None => stub.len(),
    };
    // Range guard for EVERY splice slice below (each must be start <= end <= len, and in
    // file order). A malformed / out-of-order layout — __LINKEDIT fileoff inside the load
    // commands, a code-signature dataoff before __LINKEDIT or past EOF — must be a Malformed
    // error, never a slice-index panic (which a bare `stub[a..b]` with a > b would be).
    let lc_end_after_splice = layout
        .end_of_lc
        .checked_add(NEW_LC_SIZE)
        .ok_or_else(|| malformed("load-command region overflows"))?;
    if layout.linkedit_lc_off > layout.end_of_lc
        || lc_end_after_splice > linkedit_start
        || linkedit_start > linkedit_end
        || linkedit_end > stub.len()
    {
        return Err(malformed(
            "out-of-order or out-of-range Mach-O layout for the splice",
        ));
    }

    // 2. Assemble the new file so NOTHING before __LINKEDIT moves its file offset.
    //    The new 152-byte LC is written into the header slack: the load-command
    //    bytes [linkedit_lc_off, END_OF_LC) shift forward by 152, consuming 152 of
    //    the headerpad gap; the first mapped section and every byte up to
    //    __LINKEDIT keep their original file offset. __LINKEDIT's body then slides
    //    down by DELTA only (the page-rounded section content occupies the old
    //    __LINKEDIT file region).
    //
    //    [0, linkedit_lc_off)              header + LCs before __LINKEDIT's LC
    //    new_lc (152)                      the SMOL/__PRESSED_DATA segment command
    //    [linkedit_lc_off, END_OF_LC)      __LINKEDIT's LC + the LCs after it
    //    [END_OF_LC+152, linkedit_start)   remaining headerpad + all mapped bytes
    //    section_body + zero-pad to DELTA  the injected section content
    //    [linkedit_start, linkedit_end)    __LINKEDIT body (sans old signature)
    let new_lc = build_segment_lc(body_len, delta, new_fileoff, new_vmaddr);
    let mut out: Vec<u8> = Vec::with_capacity(stub.len() + delta as usize);
    out.extend_from_slice(&stub[..layout.linkedit_lc_off]);
    out.extend_from_slice(&new_lc);
    out.extend_from_slice(&stub[layout.linkedit_lc_off..layout.end_of_lc]);
    // Headerpad after the (now-larger) command stream, shrunk by the 152 bytes the
    // new LC consumed, so the first mapped section stays at its original offset.
    out.extend_from_slice(&stub[layout.end_of_lc + NEW_LC_SIZE..linkedit_start]);
    out.extend_from_slice(section_body);
    out.resize(out.len() + (delta - body_len) as usize, 0);
    out.extend_from_slice(&stub[linkedit_start..linkedit_end]);

    // 3. Header: ncmds += 1, sizeofcmds += NEW_LC. (The strip below nets these back
    //    down by the code-signature command.)
    let ncmds = u32_le(&out, 16)?;
    put_u32(&mut out, 16, ncmds + 1);
    let sizeofcmds = u32_le(&out, 20)?;
    put_u32(&mut out, 20, sizeofcmds + NEW_LC_SIZE as u32);

    // 4. Shift __LINKEDIT's own fileoff + vmaddr by DELTA (its LC now sits at
    //    linkedit_lc_off + NEW_LC, after the new segment command). When the old
    //    signature was excluded, shrink filesize/vmsize to the bytes that remain on
    //    disk (up to where the signature began) — else the segment claims more than
    //    the file holds and the signer's parser rejects it; the signer re-extends.
    let le_lc = layout.linkedit_lc_off + NEW_LC_SIZE;
    let le_fileoff = u64_le(&out, le_lc + 40)?;
    put_u64(&mut out, le_lc + 40, le_fileoff + delta);
    let le_vmaddr = u64_le(&out, le_lc + 24)?;
    put_u64(&mut out, le_lc + 24, le_vmaddr + delta);
    if let Some(sig) = &layout.code_sig {
        let remaining = sig.dataoff - layout.linkedit_fileoff;
        put_u64(&mut out, le_lc + 48, remaining); // filesize
        put_u64(&mut out, le_lc + 32, round_up(remaining, layout.page_size)); // vmsize
    }

    // 5. Bump every linkedit-pointing file offset by DELTA. A field whose command
    //    sits at/after __LINKEDIT's LC had its byte position shifted +NEW_LC when the
    //    new LC was written before __LINKEDIT; a field before it keeps its position.
    //    Skip zeros (an absent table).
    for field in &layout.linkedit_pointers {
        let at = if field.at >= layout.linkedit_lc_off {
            field.at + NEW_LC_SIZE
        } else {
            field.at
        };
        let current = u32_le(&out, at)?;
        if current != 0 {
            put_u32(&mut out, at, current + delta as u32);
        }
    }

    // 6. Strip LC_CODE_SIGNATURE in place (it is the LAST command, so zeroing its
    //    bytes + decrementing the header counts removes it WITHOUT shifting any file
    //    offset — a splice here would move __LINKEDIT and re-break step 5). Its
    //    trailing __LINKEDIT bytes were already excluded in step 2; the signer
    //    re-adds a correct command into the freed command-stream slack.
    if let Some(sig) = &layout.code_sig {
        let sig_lc = sig.lc_off + NEW_LC_SIZE;
        let sig_cmdsize = u32_le(&out, sig_lc + 4)? as usize;
        let ncmds = u32_le(&out, 16)?;
        put_u32(&mut out, 16, ncmds - 1);
        let sizeofcmds = u32_le(&out, 20)?;
        put_u32(&mut out, 20, sizeofcmds - sig_cmdsize as u32);
        for b in out.iter_mut().skip(sig_lc).take(sig_cmdsize) {
            *b = 0;
        }
    }

    Ok(out)
}

/// ELF: add a non-alloc `SHT_PROGBITS` section named `.PRESSED_DATA`. The loader maps
/// from PROGRAM headers and ignores the section table, so this is pure append + a
/// repointed `e_shoff` — nothing the loader maps moves. New section data, a grown
/// `.shstrtab` (old strings + the name), and a fresh section-header table are all
/// appended at EOF; the `.shstrtab` header is repointed and one entry added. No
/// signing — no ELF loader enforces a code signature on `dlopen`.
pub fn inject_elf(binary: &[u8], section: &[u8]) -> Result<Vec<u8>, InjectError> {
    let stub = binary;
    let body = section;
    if stub.get(4).copied() != Some(2) {
        return Err(malformed(
            "only 64-bit ELF is supported (32-bit producer is a follow-up)",
        ));
    }
    if stub.get(5).copied() != Some(1) {
        return Err(malformed("only little-endian ELF is supported"));
    }
    let shentsize = u16_le(stub, 58)? as usize;
    if shentsize != 64 {
        return Err(malformed(format!(
            "unexpected ELF64 e_shentsize {shentsize} (want 64)"
        )));
    }
    let shoff = u64_le(stub, 40)? as usize;
    let shnum = u16_le(stub, 60)? as usize;
    let shstrndx = u16_le(stub, 62)? as usize;
    if shnum == 0 || shstrndx >= shnum {
        return Err(malformed("ELF has no usable section header table"));
    }
    let old_sht = stub
        .get(shoff..shoff + shnum * 64)
        .ok_or_else(|| malformed("section header table out of range"))?
        .to_vec();
    // The existing .shstrtab (named by e_shstrndx).
    let str_hdr = shoff + shstrndx * 64;
    let strtab_off = u64_le(stub, str_hdr + 24)? as usize;
    let strtab_size = u64_le(stub, str_hdr + 32)? as usize;
    let old_strtab = stub
        .get(strtab_off..strtab_off + strtab_size)
        .ok_or_else(|| malformed(".shstrtab out of range"))?
        .to_vec();

    let mut out = stub.to_vec();
    // Section data.
    let data_off = align_up(out.len(), 8);
    out.resize(data_off, 0);
    out.extend_from_slice(body);
    // Grown .shstrtab = old strings + ".PRESSED_DATA\0"; the new name sits at the old size.
    let name_off = strtab_size;
    let shstr_off = align_up(out.len(), 8);
    out.resize(shstr_off, 0);
    out.extend_from_slice(&old_strtab);
    out.extend_from_slice(b".PRESSED_DATA\0");
    let new_strtab_size = strtab_size + b".PRESSED_DATA\0".len();
    // Fresh section-header table: the old entries (with .shstrtab repointed) + one new.
    let new_shoff = align_up(out.len(), 8);
    out.resize(new_shoff, 0);
    out.extend_from_slice(&old_sht);
    put_u64(&mut out, new_shoff + shstrndx * 64 + 24, shstr_off as u64); // .shstrtab sh_offset
    put_u64(
        &mut out,
        new_shoff + shstrndx * 64 + 32,
        new_strtab_size as u64,
    ); // sh_size
    let mut entry = vec![0u8; 64];
    put_u32(&mut entry, 0, name_off as u32); // sh_name
    put_u32(&mut entry, 4, 1); // sh_type = SHT_PROGBITS
    put_u64(&mut entry, 24, data_off as u64); // sh_offset
    put_u64(&mut entry, 32, body.len() as u64); // sh_size
    put_u64(&mut entry, 48, 1); // sh_addralign
    out.extend_from_slice(&entry);
    // Repoint the header at the new table; one more section.
    put_u64(&mut out, 40, new_shoff as u64);
    put_u16(&mut out, 60, (shnum + 1) as u16);
    Ok(out)
}

/// PE: add a `.PRESSED` section — a 40-byte header into the header slack + raw data
/// at EOF. No signing (napi PE addons are unsigned; the loader enforces none on
/// load). The reader uses SizeOfRawData; the header framing self-delimits the payload.
pub fn inject_pe(binary: &[u8], section: &[u8]) -> Result<Vec<u8>, InjectError> {
    let stub = binary;
    let body = section;
    let pe_off = u32_le(stub, 0x3c)? as usize;
    if stub.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err(malformed("not a PE (bad NT signature)"));
    }
    let coff = pe_off + 4;
    let num_sections = u16_le(stub, coff + 2)? as usize;
    let opt_size = u16_le(stub, coff + 16)? as usize;
    let opt_off = coff + 20;
    // SectionAlignment@32, FileAlignment@36, SizeOfImage@56, SizeOfHeaders@60 — same
    // offsets in PE32 and PE32+ (they sit past the ImageBase divergence).
    let section_align = u32_le(stub, opt_off + 32)? as usize;
    let file_align = u32_le(stub, opt_off + 36)? as usize;
    if section_align == 0 || file_align == 0 {
        return Err(malformed("zero PE Section/FileAlignment"));
    }
    let size_of_headers = u32_le(stub, opt_off + 60)? as usize;
    let sect_table = opt_off + opt_size;
    let new_hdr = sect_table + num_sections * 40;
    if new_hdr + 40 > size_of_headers {
        return Err(malformed(
            "no PE header slack for a new section header (needs SizeOfHeaders room)",
        ));
    }
    // Next free RVA, after the highest existing section.
    let mut max_va_end = 0usize;
    for i in 0..num_sections {
        let sh = sect_table + i * 40;
        let va = u32_le(stub, sh + 12)? as usize;
        let vsize = u32_le(stub, sh + 8)? as usize;
        max_va_end = max_va_end.max(va + vsize);
    }
    let new_va = align_up(max_va_end, section_align);
    let raw_size = align_up(body.len(), file_align);

    let mut out = stub.to_vec();
    let raw_ptr = align_up(out.len(), file_align);
    out.resize(raw_ptr, 0);
    out.extend_from_slice(body);
    out.resize(raw_ptr + raw_size, 0); // pad raw data to FileAlignment

    out[new_hdr..new_hdr + 8].copy_from_slice(b".PRESSED"); // Name (exactly 8 bytes)
    put_u32(&mut out, new_hdr + 8, body.len() as u32); // VirtualSize (true length)
    put_u32(&mut out, new_hdr + 12, new_va as u32); // VirtualAddress
    put_u32(&mut out, new_hdr + 16, raw_size as u32); // SizeOfRawData
    put_u32(&mut out, new_hdr + 20, raw_ptr as u32); // PointerToRawData
    put_u32(&mut out, new_hdr + 36, 0x4000_0040); // IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ
    put_u16(&mut out, coff + 2, (num_sections + 1) as u16); // NumberOfSections
    let size_of_image = align_up(new_va + body.len(), section_align);
    put_u32(&mut out, opt_off + 56, size_of_image as u32); // SizeOfImage
    Ok(out)
}

/// Ad-hoc re-sign the injected Mach-O so the new section is signature-covered
/// (macOS + the `resign` feature). Non-Mach-O input passes through unchanged — ELF/PE
/// loaders enforce no signature. `codesign -s -` equivalent: no signing key ⇒ ad-hoc.
#[cfg(all(target_os = "macos", feature = "resign"))]
pub fn resign(macho: &[u8]) -> Result<Vec<u8>, InjectError> {
    use apple_codesign::{MachOSigner, SettingsScope, SigningSettings};

    if macho.get(0..4) != Some(&MH_MAGIC_64.to_le_bytes()) {
        return Ok(macho.to_vec());
    }

    let mut settings = SigningSettings::default();
    settings
        .import_settings_from_macho(macho)
        .map_err(|e| InjectError::Resign(format!("import_settings_from_macho: {e}")))?;
    if settings.binary_identifier(SettingsScope::Main).is_none() {
        settings.set_binary_identifier(SettingsScope::Main, DEFAULT_BINARY_IDENTIFIER);
    }
    // No signing key set → ad-hoc signature (exactly what `codesign -s -` produces).
    let signer = MachOSigner::new(macho)
        .map_err(|e| InjectError::Resign(format!("MachOSigner::new: {e}")))?;
    let mut out: Vec<u8> = Vec::with_capacity(macho.len() + 0x4000);
    signer
        .write_signed_binary(&settings, &mut out)
        .map_err(|e| InjectError::Resign(format!("write_signed_binary: {e}")))?;
    Ok(out)
}

/// Off-macOS or without the `resign` feature: only Mach-O needs a signature and this
/// build cannot produce one, so the bytes pass through unchanged. ELF/PE always load
/// as-is; a darwin cross-build must enable the `resign` feature on a macOS host.
#[cfg(not(all(target_os = "macos", feature = "resign")))]
pub fn resign(macho: &[u8]) -> Result<Vec<u8>, InjectError> {
    Ok(macho.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{unwrap_if_hybrid, Arch, Libc, Platform};

    // A minimal valid ELF64 LE: header + ".shstrtab" + a 2-entry section table
    // (NULL, .shstrtab) — enough for inject_elf to grow.
    fn minimal_elf64() -> Vec<u8> {
        let shstr: &[u8] = b"\0.shstrtab\0"; // ".shstrtab" at name offset 1
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
        let sh1 = shoff + 64; // section header [1] = .shstrtab
        put_u32(&mut e, sh1, 1); // sh_name -> ".shstrtab"
        put_u32(&mut e, sh1 + 4, 3); // sh_type = SHT_STRTAB
        put_u64(&mut e, sh1 + 24, 64); // sh_offset
        put_u64(&mut e, sh1 + 32, shstr.len() as u64); // sh_size
        e
    }

    // A minimal PE32+ with one section and header slack for a second header.
    fn minimal_pe() -> Vec<u8> {
        let pe = 0x40usize;
        let coff = pe + 4;
        let opt_off = coff + 20;
        let opt_size = 0x70usize;
        let sect_table = opt_off + opt_size;
        let size_of_headers = 0x200usize;
        let mut p = vec![0u8; size_of_headers];
        p[0..2].copy_from_slice(b"MZ");
        put_u32(&mut p, 0x3c, pe as u32);
        p[pe..pe + 4].copy_from_slice(b"PE\0\0");
        put_u16(&mut p, coff + 2, 1); // NumberOfSections
        put_u16(&mut p, coff + 16, opt_size as u16); // SizeOfOptionalHeader
        put_u16(&mut p, opt_off, 0x20b); // PE32+ magic
        put_u32(&mut p, opt_off + 32, 0x1000); // SectionAlignment
        put_u32(&mut p, opt_off + 36, 0x200); // FileAlignment
        put_u32(&mut p, opt_off + 56, 0x1000); // SizeOfImage
        put_u32(&mut p, opt_off + 60, size_of_headers as u32); // SizeOfHeaders
        p[sect_table..sect_table + 5].copy_from_slice(b".text");
        put_u32(&mut p, sect_table + 8, 0x10); // VirtualSize
        put_u32(&mut p, sect_table + 12, 0x1000); // VirtualAddress
        put_u32(&mut p, sect_table + 16, 0x200); // SizeOfRawData
        put_u32(&mut p, sect_table + 20, 0x200); // PointerToRawData
        p
    }

    #[test]
    fn elf_injection_round_trips_through_the_reader() {
        let raw = b"\x7fELF abitious elf addon payload bytes, repeated.".repeat(20);
        let section =
            crate::build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
        let out = inject_elf(&minimal_elf64(), &section).expect("inject elf");
        // The pre-existing string table survives; the new section round-trips.
        assert_eq!(unwrap_if_hybrid(&out).as_deref(), Some(raw.as_slice()));
    }

    #[test]
    fn pe_injection_round_trips_through_the_reader() {
        let raw = vec![0x5au8; 1500];
        let section = crate::build_section_payload(&raw, Platform::Win32, Arch::X64, Libc::Na, 12);
        let out = inject_pe(&minimal_pe(), &section).expect("inject pe");
        // find_pe returns the FileAlignment-padded slice; decode_pressed_data slices
        // exactly compressed_size, so trailing zero-fill is ignored — round-trip holds.
        assert_eq!(unwrap_if_hybrid(&out).as_deref(), Some(raw.as_slice()));
    }

    #[test]
    fn dispatch_via_inject_pressed_data_round_trips_elf_and_pe() {
        let raw = vec![0x33u8; 777];
        let elf_section =
            crate::build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Musl, 9);
        let elf = inject_pressed_data(&minimal_elf64(), &elf_section).expect("dispatch elf");
        assert_eq!(unwrap_if_hybrid(&elf).as_deref(), Some(raw.as_slice()));

        let pe_section =
            crate::build_section_payload(&raw, Platform::Win32, Arch::X64, Libc::Na, 9);
        let pe = inject_pressed_data(&minimal_pe(), &pe_section).expect("dispatch pe");
        assert_eq!(unwrap_if_hybrid(&pe).as_deref(), Some(raw.as_slice()));
    }

    #[test]
    fn dispatch_rejects_unknown_format() {
        assert!(matches!(
            inject_pressed_data(b"not an object file", b"x"),
            Err(InjectError::UnknownFormat)
        ));
    }

    #[test]
    fn resign_passes_through_non_macho() {
        // Non-Mach-O input is returned unchanged by resign on every build.
        let elf = minimal_elf64();
        assert_eq!(resign(&elf).expect("resign passthrough"), elf);
    }

    #[test]
    fn insufficient_slack_is_reported() {
        // A minimal Mach-O whose one mapped section sits at the very end of the load
        // commands (no headerpad) — zero slack for the 152-byte segment command.
        let text = MACH_HEADER_64_SIZE; // __TEXT LC
        let text_cmdsize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE; // seg + 1 section
        let sect = text + SEGMENT_COMMAND_64_SIZE; // the section_64
        let le = text + text_cmdsize; // __LINKEDIT LC
        let end_of_lc = le + SEGMENT_COMMAND_64_SIZE;
        let mut m = vec![0u8; end_of_lc];
        put_u32(&mut m, 0, MH_MAGIC_64);
        put_u32(&mut m, 4, CPU_TYPE_ARM64);
        put_u32(&mut m, 16, 2); // ncmds = 2
                                // __TEXT with one section whose file offset == end_of_lc (⇒ zero slack).
        put_u32(&mut m, text, LC_SEGMENT_64);
        put_u32(&mut m, text + 4, text_cmdsize as u32);
        m[text + 8..text + 14].copy_from_slice(b"__TEXT");
        put_u32(&mut m, text + 64, 1); // nsects = 1
        m[sect..sect + 6].copy_from_slice(b"__text");
        put_u32(&mut m, sect + 48, end_of_lc as u32); // section file offset
                                                      // __LINKEDIT immediately after.
        put_u32(&mut m, le, LC_SEGMENT_64);
        put_u32(&mut m, le + 4, SEGMENT_COMMAND_64_SIZE as u32);
        m[le + 8..le + 18].copy_from_slice(b"__LINKEDIT");
        put_u64(&mut m, le + 40, end_of_lc as u64); // fileoff
        assert!(matches!(
            splice_macho_segment(&m, b"body"),
            Err(InjectError::InsufficientSlack { .. })
        ));
    }

    #[test]
    fn inject_error_display_and_debug_cover_every_variant() {
        let cases = [
            InjectError::UnknownFormat,
            InjectError::Malformed("bad header".to_string()),
            InjectError::InsufficientSlack { have: 8, need: 152 },
            InjectError::Resign("signer blew up".to_string()),
        ];
        // Display: each variant renders a distinct, non-empty message naming its cause.
        assert!(cases[0].to_string().contains("unrecognized binary format"));
        assert!(cases[1]
            .to_string()
            .contains("malformed object file: bad header"));
        let slack = cases[2].to_string();
        assert!(slack.contains("insufficient Mach-O header slack") && slack.contains("152"));
        assert!(cases[3]
            .to_string()
            .contains("ad-hoc re-sign failed: signer blew up"));
        // Debug: mirrors the variant shape (used in test assertions / logs).
        assert_eq!(format!("{:?}", cases[0]), "UnknownFormat");
        assert!(format!("{:?}", cases[1]).starts_with("Malformed("));
        assert!(format!("{:?}", cases[2]).contains("InsufficientSlack"));
        assert!(format!("{:?}", cases[3]).starts_with("Resign("));
        // The Error trait is implemented (source is None for all variants).
        let _: &dyn std::error::Error = &cases[0];
    }

    #[test]
    fn round_up_and_align_up_handle_a_zero_alignment() {
        // A zero alignment is a no-op guard (page_size / file_align are never 0 in a real
        // object, but the helpers stay total).
        assert_eq!(round_up(5, 0), 5);
        assert_eq!(round_up(5, 4), 8);
        assert_eq!(align_up(5, 0), 5);
        assert_eq!(align_up(5, 4), 8);
    }

    #[test]
    fn inject_macho_rejects_a_big_endian_header() {
        // A BE Mach-O is recognized by the dispatch magic but rejected by read_layout's
        // little-endian magic check.
        let be = [0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = inject_pressed_data(&be, b"x").unwrap_err();
        assert!(matches!(err, InjectError::Malformed(_)), "{err:?}");
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn read_layout_rejects_a_zero_size_load_command() {
        // magic + cputype + ncmds=1, then a load command with cmdsize < 8 → malformed.
        let mut m = vec![0u8; 48];
        put_u32(&mut m, 0, MH_MAGIC_64);
        put_u32(&mut m, 4, CPU_TYPE_ARM64);
        put_u32(&mut m, 16, 1); // ncmds
        put_u32(&mut m, 32, LC_SEGMENT_64);
        put_u32(&mut m, 36, 4); // cmdsize < 8
        let err = splice_macho_segment(&m, b"x").unwrap_err();
        assert!(
            err.to_string().contains("malformed load command"),
            "{err:?}"
        );
    }

    #[test]
    fn read_layout_rejects_a_truncated_lc_segment_64_at_eof() {
        // An LC_SEGMENT_64 whose cmdsize is in [8, 71] sitting flush at EOF: the generic
        // `cmdsize >= 8 && off + cmdsize <= len` guard passes, but the fixed segment fields
        // (segname@8..24, fileoff@40, nsects@64) run past the buffer. This used to panic on
        // the raw `&bytes[off + 8..off + 24]` slice; now it is a Malformed error, no panic.
        let mut m = vec![0u8; 48];
        put_u32(&mut m, 0, MH_MAGIC_64);
        put_u32(&mut m, 4, CPU_TYPE_ARM64);
        put_u32(&mut m, 16, 1); // ncmds = 1
        put_u32(&mut m, 32, LC_SEGMENT_64);
        put_u32(&mut m, 36, 16); // cmdsize = 16: >= 8 and off(32)+16 == len(48), but < 72
        let err = splice_macho_segment(&m, b"x").unwrap_err();
        assert!(matches!(err, InjectError::Malformed(_)), "{err:?}");
        assert!(err.to_string().contains("cmdsize"), "{err}");
    }

    #[test]
    fn read_layout_rejects_a_macho_with_no_mapped_section() {
        // A Mach-O carrying only a __LINKEDIT segment with zero sections: read_layout finds
        // the __LINKEDIT anchor but never lowers first_section_offset from u64::MAX, so it
        // must reject ("no mapped section to bound the header slack") rather than splice past
        // a phantom section — the post-loop guard that keeps the header-slack ceiling sound.
        let le = MACH_HEADER_64_SIZE; // the sole load command
        let end = le + SEGMENT_COMMAND_64_SIZE;
        let mut m = vec![0u8; end];
        put_u32(&mut m, 0, MH_MAGIC_64);
        put_u32(&mut m, 4, CPU_TYPE_ARM64);
        put_u32(&mut m, 16, 1); // ncmds = 1
        put_u32(&mut m, le, LC_SEGMENT_64);
        put_u32(&mut m, le + 4, SEGMENT_COMMAND_64_SIZE as u32); // cmdsize = 72
        m[le + 8..le + 18].copy_from_slice(b"__LINKEDIT");
        put_u64(&mut m, le + 40, end as u64); // fileoff
        put_u32(&mut m, le + 64, 0); // nsects = 0 → no section file offset is ever tracked
        let err = splice_macho_segment(&m, b"x").unwrap_err();
        assert!(matches!(err, InjectError::Malformed(_)), "{err:?}");
        assert!(err.to_string().contains("no mapped section"), "{err}");
    }

    #[test]
    fn splice_rejects_out_of_order_layouts_without_panicking() {
        // Two corrupt layouts that would underflow a bare subtraction / panic a bare slice
        // in release (overflow-checks off): both must be Malformed errors, never a panic.
        const FIRST_SECT_OFFSET: u32 = 0x4000; // ample slack past end_of_lc
        let build = |section_offset: u32, linkedit_fileoff: u64| -> Vec<u8> {
            let text = MACH_HEADER_64_SIZE; // 32
            let text_cmdsize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE; // 152
            let le = text + text_cmdsize; // __LINKEDIT LC
            let end_of_lc = le + SEGMENT_COMMAND_64_SIZE; // 256
            let mut m = vec![0u8; end_of_lc];
            put_u32(&mut m, 0, MH_MAGIC_64);
            put_u32(&mut m, 4, CPU_TYPE_ARM64);
            put_u32(&mut m, 16, 2); // ncmds = 2
            put_u32(&mut m, text, LC_SEGMENT_64);
            put_u32(&mut m, text + 4, text_cmdsize as u32);
            m[text + 8..text + 14].copy_from_slice(b"__TEXT");
            put_u32(&mut m, text + 64, 1); // nsects = 1
            let sect = text + SEGMENT_COMMAND_64_SIZE;
            m[sect..sect + 6].copy_from_slice(b"__text");
            put_u32(&mut m, sect + 48, section_offset);
            put_u32(&mut m, le, LC_SEGMENT_64);
            put_u32(&mut m, le + 4, SEGMENT_COMMAND_64_SIZE as u32);
            m[le + 8..le + 18].copy_from_slice(b"__LINKEDIT");
            put_u64(&mut m, le + 40, linkedit_fileoff); // fileoff
            m
        };

        // (a) A mapped section whose file offset PRECEDES the end of the load commands →
        //     the slack `checked_sub` underflows → Malformed (was a wrapping subtraction).
        let section_inside_lcs = build(8, 0x8000);
        let err = splice_macho_segment(&section_inside_lcs, b"body").unwrap_err();
        assert!(matches!(err, InjectError::Malformed(_)), "{err:?}");

        // (b) __LINKEDIT's fileoff lands INSIDE the (post-splice) command region → the
        //     splice range guard rejects it before any `stub[a..b]` with a > b panics.
        let linkedit_before_body = build(FIRST_SECT_OFFSET, 64);
        let err = splice_macho_segment(&linkedit_before_body, b"body").unwrap_err();
        assert!(matches!(err, InjectError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn read_layout_rejects_a_macho_without_linkedit() {
        // A single __TEXT segment with a mapped section but NO __LINKEDIT → no anchor.
        let cmdsize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE;
        let mut m = vec![0u8; MACH_HEADER_64_SIZE + cmdsize];
        put_u32(&mut m, 0, MH_MAGIC_64);
        put_u32(&mut m, 4, CPU_TYPE_ARM64);
        put_u32(&mut m, 16, 1); // ncmds
        let text = MACH_HEADER_64_SIZE;
        put_u32(&mut m, text, LC_SEGMENT_64);
        put_u32(&mut m, text + 4, cmdsize as u32);
        m[text + 8..text + 14].copy_from_slice(b"__TEXT");
        put_u32(&mut m, text + 64, 1); // nsects = 1
        let sect = text + SEGMENT_COMMAND_64_SIZE;
        m[sect..sect + 6].copy_from_slice(b"__text");
        put_u32(&mut m, sect + 48, 0x1000); // a mapped section offset (nonzero)
        let err = splice_macho_segment(&m, b"x").unwrap_err();
        assert!(err.to_string().contains("no __LINKEDIT segment"), "{err:?}");
    }

    /// A synthetic, splice-able Mach-O with NO code signature and a linkedit-pointing
    /// command (`LC_SYMTAB`) placed BEFORE the `__LINKEDIT` segment command — so
    /// `splice_macho_segment` exercises the no-signature `linkedit_end` arm, the
    /// pointer-before-`__LINKEDIT` (`field.at` unchanged) rebase branch, the nonzero-offset
    /// bump, and the non-ARM64 page-size branch. Built as x86_64 to hit the 0x1000 page.
    /// Returns a stub whose splice round-trips a real pressed-data section back to `raw`.
    #[test]
    fn splice_macho_round_trips_without_a_signature_and_bumps_prior_pointers() {
        const CPU_TYPE_X86_64: u32 = 0x0100_0007;
        const LINKEDIT_FILEOFF: usize = 0x2000;
        const FIRST_SECT_OFFSET: u32 = 0x1000;
        const LINKEDIT_BODY: usize = 64;

        let text = MACH_HEADER_64_SIZE; // 32
        let text_cmdsize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE; // 152
        let symtab = text + text_cmdsize; // 184
        let symtab_cmdsize = 24usize;
        let le = symtab + symtab_cmdsize; // 208 (__LINKEDIT LC)
        let end_of_lc = le + SEGMENT_COMMAND_64_SIZE; // 280

        let mut stub = vec![0u8; LINKEDIT_FILEOFF + LINKEDIT_BODY];
        put_u32(&mut stub, 0, MH_MAGIC_64);
        put_u32(&mut stub, 4, CPU_TYPE_X86_64); // non-ARM64 → 0x1000 page branch
        put_u32(&mut stub, 16, 3); // ncmds

        // __TEXT with one mapped section far past end_of_lc (ample header slack).
        put_u32(&mut stub, text, LC_SEGMENT_64);
        put_u32(&mut stub, text + 4, text_cmdsize as u32);
        stub[text + 8..text + 14].copy_from_slice(b"__TEXT");
        put_u32(&mut stub, text + 64, 1); // nsects
        let sect = text + SEGMENT_COMMAND_64_SIZE;
        stub[sect..sect + 6].copy_from_slice(b"__text");
        put_u32(&mut stub, sect + 48, FIRST_SECT_OFFSET);

        // LC_SYMTAB BEFORE __LINKEDIT with nonzero symoff/stroff (into linkedit).
        put_u32(&mut stub, symtab, LC_SYMTAB);
        put_u32(&mut stub, symtab + 4, symtab_cmdsize as u32);
        put_u32(&mut stub, symtab + 8, LINKEDIT_FILEOFF as u32); // symoff
        put_u32(&mut stub, symtab + 16, (LINKEDIT_FILEOFF + 16) as u32); // stroff

        // __LINKEDIT (no LC_CODE_SIGNATURE anywhere).
        put_u32(&mut stub, le, LC_SEGMENT_64);
        put_u32(&mut stub, le + 4, SEGMENT_COMMAND_64_SIZE as u32);
        stub[le + 8..le + 18].copy_from_slice(b"__LINKEDIT");
        put_u64(&mut stub, le + 24, 0x1_0000); // vmaddr
        put_u64(&mut stub, le + 40, LINKEDIT_FILEOFF as u64); // fileoff
        put_u64(&mut stub, le + 48, LINKEDIT_BODY as u64); // filesize
        assert_eq!(end_of_lc, le + SEGMENT_COMMAND_64_SIZE);

        let raw = b"\x7fELF the synthetic-splice addon payload, compressible! ".repeat(20);
        let section = crate::build_section_payload(&raw, Platform::Darwin, Arch::X64, Libc::Na, 12);
        let spliced = splice_macho_segment(&stub, &section).expect("synthetic splice succeeds");
        assert_eq!(
            crate::unwrap_if_hybrid(&spliced).as_deref(),
            Some(raw.as_slice()),
            "the spliced Mach-O's SMOL/__PRESSED_DATA section round-trips to the raw addon"
        );
    }

    #[test]
    fn inject_elf_rejects_malformed_headers() {
        // 32-bit ELF (EI_CLASS != 2).
        let e32 = [0x7f, b'E', b'L', b'F', 1, 1, 1, 0];
        assert!(inject_elf(&e32, b"x")
            .unwrap_err()
            .to_string()
            .contains("64-bit"));
        // Big-endian ELF (EI_DATA != 1).
        let ebe = [0x7f, b'E', b'L', b'F', 2, 2, 1, 0];
        assert!(inject_elf(&ebe, b"x")
            .unwrap_err()
            .to_string()
            .contains("little-endian"));
        // Unexpected e_shentsize.
        let mut ebad = vec![0u8; 64];
        ebad[0..4].copy_from_slice(b"\x7fELF");
        ebad[4] = 2;
        ebad[5] = 1;
        put_u16(&mut ebad, 58, 40); // e_shentsize != 64
        assert!(inject_elf(&ebad, b"x")
            .unwrap_err()
            .to_string()
            .contains("e_shentsize"));
        // No usable section header table (e_shnum == 0).
        let mut enosht = vec![0u8; 64];
        enosht[0..4].copy_from_slice(b"\x7fELF");
        enosht[4] = 2;
        enosht[5] = 1;
        put_u16(&mut enosht, 58, 64); // e_shentsize == 64
        put_u16(&mut enosht, 60, 0); // e_shnum == 0
        assert!(inject_elf(&enosht, b"x")
            .unwrap_err()
            .to_string()
            .contains("no usable section header table"));
    }

    #[test]
    fn inject_pe_rejects_malformed_headers() {
        // Bad NT signature.
        let mut bad_sig = minimal_pe();
        bad_sig[0x40..0x44].copy_from_slice(b"XX\0\0");
        assert!(inject_pe(&bad_sig, b"x")
            .unwrap_err()
            .to_string()
            .contains("bad NT signature"));

        // Zero SectionAlignment.
        let mut zero_align = minimal_pe();
        let opt_off = 0x40 + 4 + 20;
        put_u32(&mut zero_align, opt_off + 32, 0); // SectionAlignment = 0
        assert!(inject_pe(&zero_align, b"x")
            .unwrap_err()
            .to_string()
            .contains("zero PE Section/FileAlignment"));

        // No header slack for a new section header (SizeOfHeaders too small).
        let mut no_slack = minimal_pe();
        put_u32(&mut no_slack, opt_off + 60, 0x100); // SizeOfHeaders < new_hdr + 40
        assert!(inject_pe(&no_slack, b"x")
            .unwrap_err()
            .to_string()
            .contains("no PE header slack"));
    }
}
