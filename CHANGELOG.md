# Changelog

All notable changes to abitious are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 (`0.x`), the Rust API may change between minor versions; the pressed-data
section format is the frozen compatibility contract.

## [Unreleased]

### Added

- **`abitious-decmpfs`** — the frozen pressed-data section ABI: build a
  compressed-hybrid section from a raw addon, parse one back (SHA-512-verified),
  and locate it inside a Mach-O / ELF / PE binary.
- **`abitious-decmpfs` injectors** — the producer-side section INJECTOR:
  `inject_pressed_data` (magic-dispatched) plus `inject_macho` / `inject_elf` /
  `inject_pe`, which splice a pressed-data blob into a signable `SMOL/__PRESSED_DATA`
  (Mach-O), `.PRESSED_DATA` (ELF), or `.PRESSED` (PE) section so `unwrap_if_hybrid`
  round-trips it back. Hand-rolled `InjectError` (no `thiserror`).
- **`abitious-decmpfs` resign** — `resign` ad-hoc re-signs the injected Mach-O via
  `apple-codesign` so the injected section stays code-signature-covered
  (`codesign -v` clean). Behind the off-by-default `resign` feature (macOS only) so
  the default reader/ABI dependency tree stays free of reqwest/tokio/hyper.
- **`docs`** — the pressed-data section format specification.
