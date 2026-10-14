# abitious commands

Install `@abitious/cli` to add the `abi` executable. It builds a napi-rs workspace cdylib and can wrap it as a self-loading hybrid addon. Run `abi --help` to print the usage banner.

## `abi build`

```sh
abi build [--compress] [--compress-level N] [--release] [--stub PATH] [-p PACKAGE] [--out PATH]
```

`build` runs Cargo in the current working directory. It requires a Rust workspace package that produces a cdylib. It writes the built `.node` file to the selected output path, or to the default name for the cdylib.

| Option                    | Effect                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `--compress`              | Put the addon into a self-loading hybrid `.node`.                                                                                     |
| `--compress-level N`      | Set the zstd level. The default is `16`; compression clamps values to the supported range `1`–`22`.                                   |
| `--release`               | Build with Cargo's release profile.                                                                                                   |
| `--stub PATH`             | Use this prebuilt generic stub. If omitted with `--compress`, the CLI resolves the matching stub from the installed platform package. |
| `-p`, `--package PACKAGE` | Select a Cargo package in a workspace.                                                                                                |
| `--out PATH`, `-o PATH`   | Write the resulting `.node` file to this path.                                                                                        |
| `-h`, `--help`            | Print usage and exit successfully.                                                                                                    |

Example:

```sh
abi build --release --compress -p addon --out dist/addon.node
```

The command runs Cargo and writes the output file. With `--compress`, it also writes a temporary file before replacing the requested output. On macOS the producer ad-hoc re-signs the stub after injecting the pressed-data section.

## `abi pack-ffi`

```sh
abi pack-ffi <shared-library> --target <triple> --out <file.node> [--template PATH] [--compress-level N]
```

`pack-ffi` packages an existing native shared library in a self-extracting `.node` carrier. It does not run Cargo or require a Rust toolchain. Select the target of the library, such as `linux-x64-gnu` or `darwin-arm64`. The producer checks the library format and target before it writes the output.

| Option               | Effect                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `--target TRIPLE`    | Select the library target. The value must match a supported target.                                                                   |
| `--template PATH`    | Use this target's self-extracting N-API template. If omitted, the producer verifies the bundled template manifest and SHA-512 hashes. |
| `--compress-level N` | Set the zstd level. The default is `16`; compression clamps values to `1`–`22`.                                                       |
| `--out PATH`         | Write the carrier to this path.                                                                                                       |
| `-h`, `--help`       | Print usage and exit successfully.                                                                                                    |

Example:

```sh
abi pack-ffi target/release/libabitious_decmpfs.so --target linux-x64-gnu --out dist/abitious.node
```

When Node loads the carrier, it extracts the library to the OS temporary directory under `abitious-ffi-<uid>` on Unix or `abitious-ffi-<user>` on Windows. The filename contains the full SHA-512 and the platform library extension. The template rejects an invalid envelope, a target mismatch, a hash mismatch, or an unsafe cache path. It removes partial output when extraction fails. Darwin injection requires a macOS host because the producer must sign the modified binary.

The producer bundles include all eight target templates. The `build:tier-1-native-packages` workflow builds four native targets for push and pull request checks. Set `all-targets` in a manual workflow run, or push a `v*` tag, to build and aggregate all eight targets. The workflow artifact contains `abitious-ffi-producer-bundles.tar.gz` and its `.sha512` sidecar. It is available for up to 400 days, subject to repository retention policy, and needs authenticated access. A public, durable download requires the tag release asset pipeline and its publish-before-release gate.

## `abi inspect`

```sh
abi inspect FILE.node [--decompress] [--json] [-o PATH]
```

Without `--decompress`, the command reads the file and reports whether it has a pressed-data section, its sizes, cache key, stamped target, configuration flag, and integrity result. A plain `.node` file receives a plain-file report. `--json` emits the report as JSON.

| Option                  | Effect                                                                                                   |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| `--decompress`, `-d`    | Extract the original addon from a hybrid file. A plain addon is reported without extraction.             |
| `--json`                | Emit the inspection report as JSON.                                                                      |
| `--out PATH`, `-o PATH` | Write extracted bytes to this path. Without this option, decompression writes raw addon bytes to stdout. |
| `-h`, `--help`          | Print usage and exit successfully.                                                                       |

`inspect` only reads its input unless `--decompress` is selected. Decompression verifies the stored integrity hash before writing the original bytes. If the file is plain or the hybrid payload fails integrity verification, the command reports that no payload can be extracted and exits successfully. Read errors and invalid arguments print a diagnostic to stderr and exit with failure.

## Exit behavior

Successful commands exit with status `0`. Argument errors, missing files, Cargo failures, and producer failures exit with a non-zero status. Diagnostics name the failed operation and the corrective action.
