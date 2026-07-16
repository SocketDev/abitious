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
- **`abitious-decmpfs` `selfextract`** — the runtime self-extraction seam the stub
  uses: `self_path` (the loaded module's on-disk path via `dladdr` /
  `GetModuleFileNameW`), `cache_path` (a per-uid, content-addressed
  `<tmpdir>/abitious-cache/<uid>/<stem>-<hex cache_key>.node`), and `resolve_self`
  (read self → `unwrap_if_hybrid` the `SMOL/__PRESSED_DATA` SECTION → atomic-write
  the raw addon to the cache, reusing a warm hit → return the path; `None` for a
  non-hybrid, fail-soft on any I/O error). Plus `pressed_data_cache_key` to read a
  section's 16-byte content-address without decoding.
- **`abitious-stub`** — the generic self-extracting trampoline cdylib. Its
  `napi_register_module_v1` finds itself, `resolve_self`s the compressed addon out
  of its own section into the content-addressed cache, `dlopen`s that, and forwards
  registration into the real addon (`RTLD_LOCAL` + handle-scoped `dlsym`).
  Fail-soft: any failure returns the given `exports` unchanged. Links only the
  dep-lean reader + libc (no napi, no resign). Built with `-headerpad,0x1000` so the
  injector has Mach-O header slack.
- **`abitious-producer`** — the host producer binary:
  `abitious-producer <raw-addon.node> <stub.node> -o <out.node> [--level N]`.
  Compresses the addon, injects it into the stub's signable section, ad-hoc re-signs
  (macOS), atomically writes the hybrid, and prints a one-line JSON receipt (input,
  stub, output, raw/compressed sizes, cache key, platform/arch/libc). LOUD-fails
  (What/Where/Saw/Fix). Enables the `resign` feature (the accepted producer-only
  apple-codesign exception); no clap.
- **`docs`** — the pressed-data section format specification.
