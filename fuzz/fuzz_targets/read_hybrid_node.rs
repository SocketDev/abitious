#![no_main]
//! FUZZ target `read_hybrid_node` — the whole-file hybrid `.node` READER, the
//! highest-priority untrusted-input entry.
//!
//! Feeds RAW bytes straight off disk to [`unwrap_if_hybrid`], which dispatches on
//! the leading object magic (Mach-O / ELF / PE), walks the section /
//! load-command table to locate the `__PRESSED_DATA` section, then decodes the
//! zstd payload. This is the loader path an addon consumer hits: arbitrary
//! attacker-controlled bytes -> structured output or a clean `None`.
//!
//! Finding = panic / abort / overflow / OOM / hang. A graceful `None` (non-hybrid
//! or malformed object) is a NON-finding, and a successful decode that respects
//! the `MAX_DECOMPRESSED` DoS cap is correct behavior.

use abitious_decmpfs::{inspect_hybrid, unwrap_if_hybrid, MAX_DECOMPRESSED};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // Lane (a): the full loader path (object walk -> locate section -> decode).
  // Any decode that succeeds MUST stay within the DoS cap — a zstd bomb framed
  // inside a valid object must be rejected, never materialized past the cap.
  if let Some(raw) = unwrap_if_hybrid(data) {
    assert!(
      raw.len() as u64 <= MAX_DECOMPRESSED,
      "unwrap_if_hybrid returned {} bytes, past the {MAX_DECOMPRESSED}-byte cap",
      raw.len(),
    );
  }

  // Lane (b): the non-decoding inspection path over the same object bytes
  // (`abi inspect`) — locate the section and read its header without paying to
  // decompress. Must never panic on arbitrary input.
  let _ = inspect_hybrid(data);
});
