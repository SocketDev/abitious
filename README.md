# abitious

Ship Node.js native addons (`.node`) as **compressed hybrid files** — smaller to
download, smaller on disk, and loadable everywhere.

A `.node` addon is a native library. They are big, and every install ships the raw
bytes. abitious wraps each addon into a single **hybrid `.node`** that carries the
real addon zstd-compressed inside a signed object-file section:

- **On plain npm / yarn / pnpm**, a tiny generic stub decompresses the addon once
  at load time (`dlopen`), then hands off to the real code. The download is
  smaller; the `require()` path is unchanged.
- **On decmpfs-aware package managers** (bun, pnpm-pacquet, aube, zpm), the
  install step unwraps the hybrid back to the raw addon and stores it with
  filesystem compression, so the kernel decompresses it on read — native load,
  smallest on-disk footprint.

Both paths read **one frozen section format** — see
[`docs/PRESSED-DATA-FORMAT.md`](docs/PRESSED-DATA-FORMAT.md). It mirrors the
format `decmpfs` reads (`unwrap_if_hybrid`) and `socket-btm` produces, so the
whole ecosystem interoperates.

## Layout

| crate | what it does |
| --- | --- |
| `abitious-decmpfs` | the frozen section ABI: build a pressed-data section, parse one back, and locate it inside a Mach-O / ELF / PE binary |

Coming in later milestones: `abitious-stub` (the self-extracting trampoline),
`abitious-producer` (wrap a built `.node`), and the `abi` CLI (`abi build
--compress`), published to crates.io and as `@abitious/*` npm packages.

## Status

**M1** — the pressed-data section ABI is frozen, with a spec and a checked-in
interop corpus that must keep decoding forever.

## License

MIT — see [LICENSE](LICENSE).
