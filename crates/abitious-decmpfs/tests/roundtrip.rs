//! Full-oracle round trip for the M2 injector + resign (macOS producer path).
//!
//! Drives the LIBRARY directly (there is no producer CLI until M3): compresses a real
//! Mach-O `.node` with the M1 producer, injects it back as a signable
//! `SMOL/__PRESSED_DATA` section, and runs the oracle on the result:
//!   1. the section round-trips — `unwrap_if_hybrid` recovers the original addon
//!      byte-for-byte (always, signed or not);
//!   2. `codesign -v` passes — the injected section is signature-covered (requires the
//!      `resign` feature, which pulls apple-codesign; without it the injected Mach-O is
//!      left unsigned and this oracle is compiled out);
//!   3. `node` `process.dlopen` maps the file (no mmap/EACCES/strict-validation),
//!      proving the W^X read-only injected segment loads.
//!
//! macOS-only (the fixture is a Mach-O bundle) and skip-with-message when a
//! prerequisite (`cc`, `codesign`, or `node`) is missing — never touches the network.

#![cfg(target_os = "macos")]
// Skip-with-message diagnostics print to stderr when a prerequisite is absent —
// the established integration-test pattern.
#![allow(clippy::print_stderr)]

use abitious_decmpfs::{build_section_payload, inject_pressed_data, unwrap_if_hybrid};
use abitious_decmpfs::{Arch, Libc, Platform};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A minimal real Mach-O bundle: one exported napi symbol so it is a loadable addon.
/// `-headerpad,0x1000` guarantees the header slack the Mach-O injector needs.
fn build_fixture_addon(dir: &Path) -> Option<PathBuf> {
  let src = dir.join("fixture.c");
  std::fs::write(&src, "int napi_register_module_v1(void){return 0;}\n").ok()?;
  let out = dir.join("fixture.node");
  let status = Command::new("cc")
    .args([
      "-bundle",
      "-undefined",
      "dynamic_lookup",
      "-Wl,-headerpad,0x1000",
      "-o",
    ])
    .arg(&out)
    .arg(&src)
    .status()
    .ok()?;
  status.success().then_some(out)
}

#[test]
fn injected_addon_round_trips_and_passes_the_oracle() {
  let dir = std::env::temp_dir().join(format!("abitious-decmpfs-rt-{}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");
  let Some(addon) = build_fixture_addon(&dir) else {
    eprintln!("skip: no C compiler (cc) to build the fixture .node");
    std::fs::remove_dir_all(&dir).ok();
    return;
  };
  let raw = std::fs::read(&addon).expect("read fixture");

  // M1 producer → M2 injector → M1 reader.
  let section = build_section_payload(&raw, Platform::Darwin, Arch::Arm64, Libc::Na, 19);
  let injected = inject_pressed_data(&raw, &section).expect("inject pressed data");
  assert_eq!(
    unwrap_if_hybrid(&injected).as_deref(),
    Some(raw.as_slice()),
    "the injected SMOL/__PRESSED_DATA section must decode back to the original addon",
  );

  let out = dir.join("hybrid.node");
  std::fs::write(&out, &injected).expect("write injected");

  // Oracles 1 + 2 require the ad-hoc re-sign (the `resign` feature / apple-codesign).
  // Without it, `inject_pressed_data` strips the old signature and leaves the Mach-O
  // unsigned, so these loader-facing checks are compiled out.
  #[cfg(feature = "resign")]
  {
    // Oracle 1: codesign -v passes (the injected section is signature-covered).
    match Command::new("codesign").arg("-v").arg(&out).status() {
      Ok(cs) => assert!(cs.success(), "codesign -v must pass on the injected .node"),
      Err(_) => {
        eprintln!("note: `codesign` not found — skipped the signature-coverage oracle")
      }
    }

    // Oracle 2: node maps the file (W^X read-only injected segment loads — no
    // mmap/EACCES/strict-validation). A missing `node` skips only THIS check.
    let probe = format!(
            "try{{process.dlopen({{exports:{{}}}},{:?})}}catch(e){{const m=e.message;if(/mmap|errno=13|code signature|strict validation/.test(m)){{console.error(m);process.exit(1)}}}}",
            out.to_string_lossy()
        );
    match Command::new("node").args(["-e", &probe]).status() {
      Ok(node) => assert!(node.success(), "node dlopen must map the injected .node"),
      Err(_) => eprintln!("note: `node` not found — skipped the dlopen map check"),
    }
  }

  std::fs::remove_dir_all(&dir).ok();
}
