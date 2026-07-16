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
  leaves the raw `.node` and prints a small build receipt. Builds the HOST triple; the
  cross-platform build matrix and the auto `@abitious/<triple>` stub resolution (when
  `--compress` is given without `--stub`) shipped in M6 — see below. Hand-rolled
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
- **npm distribution (`@abitious/<triple>` + `@abitious/cli`)** — the platform
  distribution layer, all DERIVED from one source of truth (`scripts/targets.mts`):
  8 prebuilt targets (darwin arm64/x64; linux x64/arm64 × gnu/musl; win32 x64/arm64 msvc),
  each shipping that host's generic stub `.node` + host `abi` producer as an
  `@abitious/<triple>` npm package, plus an `@abitious/cli` meta-package whose
  `optionalDependencies` fetch only the matching one. `scripts/gen-packages.mts` codegens
  the per-triple `package.json`s, the `cli` optional deps, and `targets.generated.json`
  (with a gen-then-`--check` in-sync guard and `--print-matrix` for the CI build matrix).
  The runtime loader (`npm/cli/loader.cjs`) maps this host to its triple (the napi-rs
  `<platform>-<arch>[-<abi>]` rule; musl-vs-glibc via
  `process.report.getReport().header.glibcVersionRuntime`) and resolves the installed
  platform package, raising an actionable error that names the package to install when it
  is absent.
- **`abitious` stub auto-resolution** — `abi build --compress` no longer requires
  `--stub`: when omitted, the stub is auto-resolved by walking up from the cwd for
  `node_modules/@abitious/<host-triple>/stub.node` (`crate::resolve`, std-only, the Rust
  mirror of the JS loader's triple rule, locked by a table-driven test in `triple.rs`);
  `--stub` still overrides, and a miss LOUD-fails naming the exact package to install
  (`npm install @abitious/cli`).
- **release pipeline (crates.io + npm via OIDC Trusted Publishing)** — two
  workflow-dispatch pipelines that publish with NO long-lived registry-token secret:
  `cargo-publish.yml` publishes all four crates to crates.io via Trusted Publishing
  (OIDC, `id-token: write`) with a build-provenance attestation, letting `cargo publish
  --workspace` compute the topological order (`abitious-decmpfs` → `abitious-producer` /
  `abitious-stub` → `abitious`); `npm-publish.yml` builds each triple from the
  `targets.mts` matrix and publishes the 8 `@abitious/<triple>` packages then
  `@abitious/cli` with npm provenance via OIDC. Both default to a dry run and gate the real
  publish behind a required-reviewer CI environment. `Cargo.toml` records a `version` on the
  intra-workspace path deps so crates.io captures the requirement when `path` is stripped
  at publish time.
- **`abitious` `abi inspect`** — a second `abi` subcommand:
  `abi inspect <file.node> [--decompress] [--json] [-o <path>]`. It parses a hybrid's
  pressed-data section WITHOUT decompressing and reports the magic, compressed/uncompressed
  sizes + download savings, the 16-byte cache key, the platform/arch/libc target,
  `has_config`, and whether the section's SHA-512 integrity verifies (`--json` for a
  machine-readable report); a plain (non-hybrid) `.node` is reported plainly, not as an
  error. `--decompress` recovers the raw addon (byte-identical to the original) to
  `-o <path>` or stdout. Backed by `abitious_decmpfs::inspect_hybrid` / `read_section_info`
  (returning a `SectionInfo`), which share the frozen `parse_header` with the decoder so the
  reporting and decoding readers can never drift from the byte layout.
- **self-extract cache hardening** — a warm cache hit is now reused only after its
  **SHA-512 is re-verified** against the freshly decoded (already integrity-checked) addon;
  a size or hash mismatch, or any read error, re-extracts atomically, so a poisoned or
  corrupt entry in a shared `/tmp` is never `dlopen`ed. The per-uid cache dir
  (`<tmpdir>/abitious-cache/<uid>/…`) is created `0700` and refused if it is a symlink, is
  not owned by us, or is group/other-writable; the atomic temp is opened
  `O_EXCL | O_NOFOLLOW` (`crate::selfextract`).
- **`fscompress` fallback messaging** — `Outcome::describe()` + `Display` for the
  `Unsupported` / `Skipped` / `NoGain` arms report honestly that the win is "download-only
  savings, installed size unchanged on this filesystem" when the store's filesystem cannot
  take transparent compression.
- **CI `ci.yml` dependency-budget allowlist** — a dedicated CI job enforces a POSITIVE
  allowlist over the SHIPPED stub + reader tree (`abitious-stub` + `abitious-decmpfs` with
  default features, i.e. NO `resign`): any crate outside the audited pure-Rust set fails the
  build. The producer-only `resign` → `apple-codesign` (reqwest/tokio/hyper) chain is
  macOS-target-gated + off by default, so it never reaches the shipped tree. It runs
  alongside a zizmor workflow audit and the fmt / clippy / `cargo test --workspace
  --locked` matrix, with every action SHA-pinned.
