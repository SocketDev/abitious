# The pressed-data section format

**FROZEN — never change.** This is the on-disk compatibility contract between an
abitious hybrid `.node` and every reader in the ecosystem. Existing hybrids must
keep decoding forever, so the layout below is fixed; new capability goes in new
fields behind the `has_config` flag or a new format, never by re-interpreting
these bytes. The checked-in interop corpus
(`crates/abitious-decmpfs/tests/interop_corpus.rs`) enforces this.

This format is the mirror image of:

- **the reader** — `decmpfs`'s `unwrap_if_hybrid`
  (`decmpfs/crates/decmpfs/src/addon.rs`), and
- **the producer spec** — socket-btm's
  `packages/build-infra/lib/compressed-binary-format-constants.mts`
  (`smol_segment_reader.c`).

`abitious-decmpfs` implements both halves: `build_section_payload` (producer) and
`decode_pressed_data` / `unwrap_if_hybrid` (reader).

## Where the section lives

The pressed-data blob is stored as a **signable object-file section**, located via
the binary's section / load-command table — **never** an EOF footer (an appended
footer breaks Mach-O code-signature validation).

| Object format | Location                                                      |
| ------------- | ------------------------------------------------------------- |
| Mach-O 64-bit | section `__PRESSED_DATA` in segment `SMOL`                    |
| ELF 64-bit    | section `.PRESSED_DATA`                                       |
| PE / COFF     | section `.PRESSED` — the 8-char truncation of `.PRESSED_DATA` |

The magic dispatch: `cf fa ed fe` / `fe ed fa cf` → Mach-O, `7f 45 4c 46` → ELF,
`4d 5a` (`MZ`) → PE.

## Section byte layout

All integers are little-endian. Sizes in bytes.

| Field             | Size              | Notes                                                             |
| ----------------- | ----------------- | ----------------------------------------------------------------- |
| magic marker      | 32                | ASCII `__SMOL_PRESSED_DATA_MAGIC_MARKER`                          |
| compressed size   | 8                 | u64 — length of the zstd payload                                  |
| uncompressed size | 8                 | u64 — length of the raw `.node` addon                             |
| cache key         | 16                | first 16 bytes of `SHA-256(raw addon)`                            |
| platform metadata | 3                 | `platform`, `arch`, `libc` enum bytes (below)                     |
| integrity         | 64                | `SHA-512(zstd payload)`                                           |
| has_config        | 1                 | `0` = no config (abitious always emits `0`)                       |
| config            | 1192              | present **only** if `has_config == 1`; parsed-past, never emitted |
| payload           | _compressed size_ | the zstd frame                                                    |

Fixed header length up to and including `has_config` is **132 bytes**
(`32 + 8 + 8 + 16 + 3 + 64 + 1`).

### Platform / arch / libc enum bytes

| `platform`                         | `arch`                                   | `libc`                           |
| ---------------------------------- | ---------------------------------------- | -------------------------------- |
| `0` linux · `1` darwin · `2` win32 | `0` x64 · `1` arm64 · `2` ia32 · `3` arm | `0` glibc · `1` musl · `255` n/a |

## Decode contract

`decode_pressed_data` (and `unwrap_if_hybrid`, which finds the section first)
returns `Some(raw addon)` only when **all** of the following hold, else `None` —
never partial bytes:

1. the buffer is at least 132 bytes and starts with the magic marker;
2. `compressed size` and `uncompressed size` are non-zero and each `<= 512 MiB`
   (the DoS cap);
3. `SHA-512(payload)` equals the stored integrity hash (checked **before**
   decompressing, so a tampered frame is rejected up front);
4. the zstd frame decodes, and the decoded length equals `uncompressed size`.

The cache key and platform bytes are informational at decode time (used by
caches / installers, not required to recover the addon).

## Two load paths

- **Self-extract at `dlopen`** (plain npm): the generic stub reads its own
  `PRESSED_DATA` section, verifies + decodes, and extracts the recovered addon to
  a per-uid, content-addressed cache under `$TMPDIR`, then `dlopen`s it
  (`abitious_decmpfs::selfextract`). A warm cache hit is reused only after its
  **SHA-512 is re-verified** against the just-decoded addon, so a poisoned or
  corrupted cache entry in a shared `/tmp` is never `dlopen`ed (the per-uid dir is
  created `0700` and refused if pre-planted as a symlink / wrong-owner).
- **Unwrap + kernel-recompress at install** (decmpfs-aware package managers):
  the installer calls `unwrap_if_hybrid` (or `install_hybrid`), stores the
  recovered raw addon with filesystem compression, and the kernel decompresses it
  on read.

## Inspecting a hybrid

`abi inspect <file.node>` prints this header — magic, compressed/uncompressed
sizes, the cache key, the platform/arch/libc target, `has_config`, and whether
`SHA-512(payload)` verifies — without decompressing (`--json` for a machine
report). `abi inspect --decompress <file.node> [-o out]` recovers the raw addon.
The same header fields are exposed programmatically by
`abitious_decmpfs::inspect_hybrid` / `read_section_info` (returning a `SectionInfo`).

## Codec

zstd only, one codec end to end (statically linked on both producer and reader).
The producer's default level is chosen for a small download without hurting the
consumer's first-load decode cost; any level `1..=22` decodes identically.
