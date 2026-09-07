# abitious 💪

[![Follow @SocketSecurity](https://raw.githubusercontent.com/SocketDev/abitious/HEAD/assets/fleet/badge-follow-x.svg)](https://twitter.com/SocketSecurity)
[![Follow @socket.dev on Bluesky](https://raw.githubusercontent.com/SocketDev/abitious/HEAD/assets/fleet/badge-follow-bluesky.svg)](https://bsky.app/profile/socket.dev)

![coverage score](assets/repo/coverage-score.svg) [![Socket Badge](https://badge.socket.dev/cargo/package/abitious/0.1.0)](https://badge.socket.dev/cargo/package/abitious/0.1.0)

Ship Node.js native addons (`.node`) as **compressed hybrid files** - smaller to
download, smaller on disk, and loadable everywhere.

A `.node` addon is a native library. They are big, and every install ships the raw
bytes. abitious wraps each addon into a single **hybrid `.node`** that carries the
real addon zstd-compressed inside a signed object-file section:

- **On plain npm / yarn / pnpm**, a tiny generic stub decompresses the addon once
  at load time (`dlopen`), then hands off to the real code. The download is
  smaller; the `require()` path is unchanged.
- **On decmpfs-aware package managers** (bun, pnpm-pacquet, aube, zpm), the
  install step unwraps the hybrid back to the raw addon and stores it with
  filesystem compression, so the kernel decompresses it on read - native load,
  smallest on-disk footprint.

Both paths read **one frozen section format** - see
[`docs/pressed-data-format.md`](docs/pressed-data-format.md). It mirrors the
format `decmpfs` reads (`unwrap_if_hybrid`) and `socket-btm` produces, so the
whole ecosystem interoperates.

## Install

```sh
pnpm add @abitious/cli
```

## Usage

```console
# Build a napi cdylib for the host and wrap it as a self-loading hybrid .node.
# The stub is auto-resolved from an installed @abitious/<triple> package (npm install
# @abitious/cli), or pass --stub <path>.
abi build --release --compress [--compress-level 19] [-p <package>] [--out <path>]

# Inspect a hybrid's pressed-data section (sizes, cache key, target, integrity):
abi inspect <file.node> [--json]

# Extract the raw addon back out of a hybrid (byte-identical to the original):
abi inspect --decompress <file.node> [-o <out.node>]
```

## Development

```sh
pnpm install
pnpm run build
pnpm test
```

### Layout

| crate               | what it does                                                                                                                                                                                                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `abitious-decmpfs`  | the frozen section ABI (build / parse / locate a pressed-data section), the runtime **self-extract** seam (`selfextract`), and a byte-faithful port of the `decmpfs` **FS-compression engine** (`fscompress`: APFS decmpfs / btrfs / NTFS) + the `install_hybrid` install bridge |
| `abitious-stub`     | the generic self-extracting **trampoline** cdylib: one prebuilt image per platform whose `napi_register_module_v1` recovers the real addon from its own section and forwards registration                                                                                        |
| `abitious-producer` | the host build-time **producer** (`compress_node` + bin): compress a built `.node` into a pressed-data section, inject + ad-hoc re-sign it into the stub, write a hybrid                                                                                                         |
| `abitious`          | the **`abi` CLI**: `abi build [--compress]` (cargo-build a napi cdylib, wrap it) and `abi inspect` (report / extract a hybrid's section)                                                                                                                                         |

### Distribution

One prebuilt stub + host `abi` per platform ship as `@abitious/<triple>` npm packages
(darwin/linux/win32 × x64/arm64, glibc/musl) plus an `@abitious/cli` meta-package; the
package layout + CI matrix are DERIVED from a single source of truth
(`scripts/repo/targets.mts`) so a target is added in exactly one place. The four Rust crates
also publish to crates.io via Trusted Publishing (OIDC, no long-lived token).

### Status

**M1–M8 shipped.** The pressed-data section ABI is frozen (a spec + a checked-in interop
corpus that must keep decoding forever); the stub, producer, `abi build`/`abi inspect`
CLI, the FS-compression engine + `install_hybrid`, and the npm/crates.io distribution are
in place. The self-extract cache re-verifies each warm hit's SHA-512 before `dlopen`, so
a poisoned entry in a shared `/tmp` is never loaded.

## License

MIT - see [LICENSE](LICENSE).

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/SocketDev/abitious/HEAD/assets/fleet/socket-combomark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/SocketDev/abitious/HEAD/assets/fleet/socket-combomark-light.svg">
    <img width="320" height="91" alt="Socket" src="https://raw.githubusercontent.com/SocketDev/abitious/HEAD/assets/fleet/socket-combomark-light.svg">
  </picture>
</div>
