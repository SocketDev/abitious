//! Give the Mach-O injector header slack.
//!
//! `abitious-decmpfs`'s `inject_macho` splices a 152-byte `LC_SEGMENT_64` for
//! `SMOL/__PRESSED_DATA` into the stub's Mach-O header padding. Without extra headerpad
//! the linker leaves too little slack and injection fails with `InsufficientSlack`. This
//! links the cdylib with `-headerpad,0x1000` (matching the injector's documented
//! requirement) whenever the TARGET is macOS. A no-op on every other target.

fn main() {
  if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
    println!("cargo:rustc-link-arg=-Wl,-headerpad,0x1000");
  }
}
