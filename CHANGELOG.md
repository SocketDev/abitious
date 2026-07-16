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
- **`abitious-producer` library** — the producer core is now a `lib` + `bin`:
  `compress_node(raw_node, stub, out, level) -> Result<Receipt, ProducerError>` (with a
  public `Receipt` — input/stub/output, raw/compressed sizes, cache key, platform/arch/
  libc — and `Receipt::to_json`). The `abitious-producer` bin is a thin wrapper over it,
  so the bin and the `abi` CLI share one compress/inject/re-sign/atomic-write path.
- **`abitious`** — the `abi` build CLI (`[[bin]] name = "abi"`):
  `abi build [--compress] [--compress-level N] [--release] [--stub <path>] [-p <package>]
  [--out <path>]`. Runs `cargo build` for the HOST triple, resolves the package's `cdylib`
  artifact from `cargo metadata` (porting napi-rs `build.ts`'s cdylib resolution), copies
  it to `<name>.node` (or `--out`), and with `--compress` compresses it into a self-loading
  hybrid via `abitious_producer::compress_node`, printing the JSON receipt; otherwise
  leaves the raw `.node` and prints a small build receipt. Host triple only (the cross
  matrix and auto `@abitious/<triple>` stub resolution are later milestones). Hand-rolled
  arg parsing + `cargo metadata` JSON reader (no clap, no serde_json); no JS fallback;
  LOUD What/Where/Saw/Fix errors.
- **`abitious-decmpfs` fscompress engine** — a byte-faithful port of the `decmpfs`
  crate's transparent filesystem-compression engine into `abitious-decmpfs`, so a
  decmpfs-aware package manager depends on ONE crate for both the distribution SECTION
  format and install-time kernel compression. New `fscompress` module with the OS
  backends (macOS APFS decmpfs via the system `libcompression` LZVN codec + resource
  fork; Linux btrfs `FS_COMPR_FL` + the `btrfs.compression` property; Windows NTFS
  `FSCTL_SET_COMPRESSION`; an `Unsupported` fallback elsewhere), the success/skip
  taxonomy (`Outcome`, `UnsupportedReason`, `SkipReason`, `Support`, `Error`, `Stat`),
  the install-time entry points (`compress_bytes` one-pass writer, `compress_file`,
  `probe`, `stat`), the `Gate` selection surface (`Gate`, `GateParseError`,
  `SizePredicate`, `DEFAULT_GLOB`), and the apply→verify→rollback safety contract
  (kernel-roundtrip read-back oracle; every `Outcome` is a success, `Err` only on a
  genuine I/O fault that leaves integrity unknown). The PM-facing surface is
  re-exported at the crate root to mirror `decmpfs::` 1:1, so those PMs
  (pnpm-pacquet `PACQUET_COMPRESS_STORE`, bun, aube, zpm) can swap the dependency
  drop-in. No new dependencies: the macOS codec is `#[link(name = "compression")]` (a
  system framework, not a crate) and the syscalls use the already-present
  `libc`/`windows-sys`.
- **`abitious-decmpfs` `install_hybrid`** — the abitious install bridge:
  `install_hybrid(input, dest, gate) -> Result<Outcome, Error>` recovers a downloaded
  hybrid's raw addon from its pressed-data SECTION (`unwrap_if_hybrid`), else takes a
  plain addon as-is, and lands it at `dest` via `compress_bytes` — a kernel-compressed,
  read-back-verified, fail-soft store entry written in ONE pass. This is exactly a
  decmpfs-aware PM's content-addressed store write: the installed `.node` is
  transparently compressed on disk yet `dlopen`s at near-native speed (the kernel
  decompresses on read). Validated end-to-end on APFS
  (`crates/abitious-producer/tests/install_e2e.rs`): a real produced hybrid installs to
  a store entry whose on-disk allocation strictly shrinks and which `node
  process.dlopen` loads with the addon's `napi_register_module_v1` running.
- **out of scope (M5)** — the reflink `copy_file` / `try_clone_file` / `CopyOutcome`
  and `rm` / `RmOptions` surfaces of `decmpfs` are intentionally NOT ported; they are
  PM-link-step / CLI features outside the abitious install-compress path.
- **`docs`** — the pressed-data section format specification.
