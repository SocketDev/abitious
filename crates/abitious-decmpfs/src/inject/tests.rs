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
    let section = crate::build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Glibc, 16);
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
    let elf_section = crate::build_section_payload(&raw, Platform::Linux, Arch::X64, Libc::Musl, 9);
    let elf = inject_pressed_data(&minimal_elf64(), &elf_section).expect("dispatch elf");
    assert_eq!(unwrap_if_hybrid(&elf).as_deref(), Some(raw.as_slice()));

    let pe_section = crate::build_section_payload(&raw, Platform::Win32, Arch::X64, Libc::Na, 9);
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
