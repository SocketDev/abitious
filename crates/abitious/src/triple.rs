//! The host target triple in npm's `@abitious/<triple>` naming — the Rust end of the
//! single source of truth (`scripts/targets.mts`).
//!
//! The auto-resolver only ever needs the ONE host triple, so rather than duplicate the
//! 8-entry list it DERIVES the host's triple from [`Platform`]/[`Arch`]/[`Libc`]`::detect()`
//! using the exact same `<os>-<arch>[-<abi>]` naming rule targets.mts and the JS loader use:
//! glibc Linux `-gnu`, musl Linux `-musl`, Windows `-msvc`, macOS none. [`triple_of`] is a
//! pure mapping so a table-driven test pins every combination to the npm string, catching any
//! drift from targets.mts.

use abitious_decmpfs::{Arch, Libc, Platform};

/// The npm triple for this host, e.g. `darwin-arm64` / `linux-x64-gnu` / `win32-x64-msvc`.
pub fn host_triple() -> String {
  triple_of(Platform::detect(), Arch::detect(), Libc::detect())
}

/// Pure mapping from the detected platform/arch/libc to the npm triple string. Split out so
/// every arm is unit-tested regardless of the host running the tests.
pub fn triple_of(platform: Platform, arch: Arch, libc: Libc) -> String {
  format!(
    "{}-{}{}",
    os_str(platform),
    arch_str(arch),
    abi_suffix(platform, libc)
  )
}

/// npm `os` / `process.platform` name.
fn os_str(platform: Platform) -> &'static str {
  match platform {
    Platform::Darwin => "darwin",
    Platform::Linux => "linux",
    Platform::Win32 => "win32",
  }
}

/// npm `cpu` / `process.arch` name.
fn arch_str(arch: Arch) -> &'static str {
  match arch {
    Arch::X64 => "x64",
    Arch::Arm64 => "arm64",
    Arch::Ia32 => "ia32",
    Arch::Arm => "arm",
  }
}

/// The napi-rs abi suffix: `-msvc` on Windows, `-gnu`/`-musl` on Linux, none on macOS.
/// Windows/macOS carry `Libc::Na`, so the suffix keys off the platform there.
fn abi_suffix(platform: Platform, libc: Libc) -> &'static str {
  match platform {
    Platform::Win32 => "-msvc",
    Platform::Darwin => "",
    Platform::Linux => match libc {
      Libc::Musl => "-musl",
      // Glibc (and the Na fallback that cannot occur on Linux) → the gnu abi.
      Libc::Glibc | Libc::Na => "-gnu",
    },
  }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
  use super::*;

  /// The 8 shipped targets, mirrored from scripts/targets.mts. If targets.mts changes,
  /// this table must change with it — the cross-language coupling made explicit.
  #[test]
  fn triple_of_matches_targets_mts() {
    let cases = [
      (Platform::Darwin, Arch::Arm64, Libc::Na, "darwin-arm64"),
      (Platform::Darwin, Arch::X64, Libc::Na, "darwin-x64"),
      (Platform::Linux, Arch::X64, Libc::Glibc, "linux-x64-gnu"),
      (Platform::Linux, Arch::Arm64, Libc::Glibc, "linux-arm64-gnu"),
      (Platform::Linux, Arch::X64, Libc::Musl, "linux-x64-musl"),
      (Platform::Linux, Arch::Arm64, Libc::Musl, "linux-arm64-musl"),
      (Platform::Win32, Arch::X64, Libc::Na, "win32-x64-msvc"),
      (Platform::Win32, Arch::Arm64, Libc::Na, "win32-arm64-msvc"),
    ];
    for (platform, arch, libc, expected) in cases {
      assert_eq!(triple_of(platform, arch, libc), expected);
    }
  }

  #[test]
  fn triple_of_covers_the_ia32_and_arm_arches() {
    // `ia32`/`arm` are not shipped @abitious targets, but `arch_str` handles the full
    // `Arch` enum; pin the two remaining arms so the mapping stays complete.
    assert_eq!(
      triple_of(Platform::Win32, Arch::Ia32, Libc::Na),
      "win32-ia32-msvc"
    );
    assert_eq!(
      triple_of(Platform::Linux, Arch::Arm, Libc::Glibc),
      "linux-arm-gnu"
    );
  }

  #[test]
  fn host_triple_is_one_of_the_shipped_targets() {
    const SHIPPED: [&str; 8] = [
      "darwin-arm64",
      "darwin-x64",
      "linux-x64-gnu",
      "linux-arm64-gnu",
      "linux-x64-musl",
      "linux-arm64-musl",
      "win32-x64-msvc",
      "win32-arm64-msvc",
    ];
    let host = host_triple();
    assert!(
      SHIPPED.contains(&host.as_str()),
      "host triple {host} not in the shipped set"
    );
  }
}
