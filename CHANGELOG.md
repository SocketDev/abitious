# Changelog

All notable changes to abitious are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 (`0.x`), the Rust API may change between minor versions; the pressed-data
section format is the frozen compatibility contract.

## [Unreleased]

### Added

- M8 - hardening, abi inspect, ci.yml dep-gate, coverage pass
- M7 - publish pipeline (crates.io + npm, OIDC Trusted Publishing)
- M6 - cross-matrix distribution + @abitious/&lt;triple&gt; + stub auto-resolve
- M5 - FS-compression engine + install_hybrid bridge
- M4 - abi build --compress CLI (host triple)
- M3 - producer + generic stub, self-extract proven e2e
- M2 — section injector + apple-codesign resign + oracle
- **`abitious-decmpfs`** — the frozen pressed-data section ABI: build a
- **`abitious-decmpfs` injectors** — the producer-side section INJECTOR:
- **`abitious-decmpfs` resign** — `resign` ad-hoc re-signs the injected Mach-O via
- **`abitious-decmpfs` `selfextract`** — the runtime self-extraction seam the stub
- **`abitious-stub`** — the generic self-extracting trampoline cdylib. Its
- **`abitious-producer`** — the host producer binary:
- **`abitious-producer` library** — the producer core is now a `lib` + `bin`:
- **`abitious`** — the `abi` build CLI (`[[bin]] name = "abi"`):
- **`abitious-decmpfs` fscompress engine** — a byte-faithful port of the `decmpfs`
- **`abitious-decmpfs` `install_hybrid`** — the abitious install bridge:
- **out of scope (M5)** — the reflink `copy_file` / `try_clone_file` / `CopyOutcome`
- **`docs`** — the pressed-data section format specification.
- **npm distribution (`@abitious/<triple>` + `@abitious/cli`)** — the platform
- **`abitious` stub auto-resolution** — `abi build --compress` no longer requires
- **release pipeline (crates.io + npm via OIDC Trusted Publishing)** — two
- **`abitious` `abi inspect`** — a second `abi` subcommand:
- **self-extract cache hardening** — a warm cache hit is now reused only after its
- **`fscompress` fallback messaging** — `Outcome::describe()` + `Display` for the
- **CI `ci.yml` dependency-budget allowlist** — a dedicated CI job enforces a POSITIVE

### Fixed

- **`tooling`** — lock fleet hook workspaces
- **`ci`** — enforce Rust fleet formatting
- **`tooling`** — satisfy fleet quality gates
- **`deps`** — refresh canonical Node types
- **`musl`** — build the stub cdylib dynamically on musl (-crt-static=false)
- address the quality-scan findings (security, 8-platform release, docs)
- **`ci`** — publish environments are cargo-publish / npm-publish (not release)
- **`ci`** — linkWorkspacePackages so cli's optionalDeps land in the lock
- **`ci`** — regenerate pnpm-lock.yaml for pnpm 11.10.0 + drop packageManager field
- **`windows`** — enable the windows-sys features fscompress needs
- **`marker`** — repo.type solo (0 JS packages/*, matching decmpfs + the detector)
