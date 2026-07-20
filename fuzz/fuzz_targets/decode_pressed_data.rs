#![no_main]
//! FUZZ target `decode_pressed_data` — the bare pressed-data SECTION decoder, the
//! frozen-ABI parse + zstd-decompress core beneath the object-file reader.
//!
//! Three lanes over one raw byte buffer:
//!
//! (a) fuzz bytes AS a pressed-data blob (magic + fixed header + zstd payload) ->
//!     [`decode_pressed_data`]. A malformed / tampered / too-short / zstd-bomb
//!     blob MUST return `None` (graceful); a decode that succeeds MUST respect the
//!     `MAX_DECOMPRESSED` cap. Never panic / overflow / OOM / hang.
//! (b) the non-decoding header readers over the same bytes
//!     ([`read_section_info`], [`pressed_data_cache_key`]) — must not panic.
//! (c) round-trip identity: frame arbitrary bytes as a real section with
//!     [`build_section_payload`] and decode them back — the decoder must recover
//!     the exact input. Empty input is skipped (the format legitimately rejects a
//!     zero `uncompressed_size`, a NON-finding).
//!
//! Finding = panic / abort / overflow / OOM / hang. A graceful `None` is a
//! NON-finding.

use abitious_decmpfs::{
  build_section_payload, decode_pressed_data, pressed_data_cache_key, read_section_info, Arch,
  Libc, Platform, MAX_DECOMPRESSED,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // Lane (a): arbitrary bytes as a pressed-data blob.
  if let Some(raw) = decode_pressed_data(data) {
    assert!(
      raw.len() as u64 <= MAX_DECOMPRESSED,
      "decode_pressed_data returned {} bytes, past the {MAX_DECOMPRESSED}-byte cap",
      raw.len(),
    );
  }

  // Lane (b): the non-decoding header readers.
  let _ = read_section_info(data);
  let _ = pressed_data_cache_key(data);

  // Lane (c): round-trip identity for a freshly framed section.
  if !data.is_empty() {
    let section = build_section_payload(data, Platform::Linux, Arch::X64, Libc::Glibc, 3);
    let recovered =
      decode_pressed_data(&section).expect("a freshly built pressed-data section must decode back");
    assert_eq!(
      recovered.as_slice(),
      data,
      "pressed-data round-trip must be the identity",
    );
  }
});
