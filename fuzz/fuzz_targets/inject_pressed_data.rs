#![no_main]
//! FUZZ target `inject_pressed_data` — the PRODUCER-side object-file injector, the
//! mirror of the reader. Where [`unwrap_if_hybrid`] WALKS a section table to READ a
//! pressed-data blob back out, [`inject_pressed_data`] walks the same Mach-O / ELF /
//! PE structures to SPLICE one in: it parses the mach_header_64 + load commands
//! (Mach-O), the section-header table (ELF), or the COFF section table (PE), and does
//! heavy file-offset arithmetic to relocate `__LINKEDIT` and re-base every
//! linkedit-pointing field. The fuzz crate's INVERTED profile turns `overflow-checks`
//! back ON, so any silent wrap in that arithmetic on a malformed header is a crash
//! finding — not a wrong-but-quiet output.
//!
//! Feeds arbitrary bytes AS the `binary` to inject into, with a fixed, real
//! producer-built `section` (what [`build_section_payload`] emits). Every arm must
//! resolve to `Ok(bytes)` or a graceful `Err(InjectError)` — never a panic, overflow,
//! OOM, or hang.
//!
//! Four lanes over one raw byte buffer:
//!
//! (a) [`inject_pressed_data`] — the magic-dispatching entry (the whole producer
//!     splice path an `abi` build hits).
//! (b–d) the three per-format injectors ([`inject_macho`], [`inject_elf`],
//!     [`inject_pe`]) called DIRECTLY, so each container parser is exercised on
//!     arbitrary bytes regardless of the leading magic byte the mutator happened to
//!     produce.
//!
//! Finding = panic / abort / overflow / OOM / hang. A graceful `Err` (unknown format,
//! malformed header, insufficient slack) is a NON-finding.

use std::sync::LazyLock;

use abitious_decmpfs::{
  build_section_payload, inject_elf, inject_macho, inject_pe, inject_pressed_data, Arch, Libc,
  Platform,
};
use libfuzzer_sys::fuzz_target;

/// A real producer-built pressed-data section, framed once. `inject_*` treats this
/// as the opaque blob to splice in; the fuzzed surface is the `binary` PARSE, so a
/// single fixed section keeps every exec on the object-walk arithmetic.
static SECTION: LazyLock<Vec<u8>> = LazyLock::new(|| {
  build_section_payload(b"fuzz addon payload bytes", Platform::Darwin, Arch::Arm64, Libc::Na, 3)
});

fuzz_target!(|data: &[u8]| {
  let section = SECTION.as_slice();

  // Lane (a): the magic-dispatching entry point.
  let _ = inject_pressed_data(data, section);

  // Lanes (b–d): each container parser directly, bypassing the leading-magic
  // dispatch so arbitrary bytes always reach every object-walk path.
  let _ = inject_macho(data, section);
  let _ = inject_elf(data, section);
  let _ = inject_pe(data, section);
});
