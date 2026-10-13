# abitious API reference

This page describes the public runtime module and the C ABI in each platform package. The Rust codec and producer crates are workspace implementation crates; they are not published as Rust libraries. The frozen pressed-data format has a separate [format specification](pressed-data-format.md).

## Node.js runtime module

Install `@abitious/cli` and require it from CommonJS:

```js
const addon = require('@abitious/cli')

console.log(addon.triple)
console.log(addon.stub)
console.log(addon.bin)
```

The module resolves the platform package while loading. It exports these paths and values:

| Property    | Meaning                                                                                |
| ----------- | -------------------------------------------------------------------------------------- |
| `triple`    | Resolved platform target, such as `linux-x64-gnu`.                                     |
| `pkg`       | Name of the matching `@abitious/<triple>` package.                                     |
| `dir`       | Installed directory for that platform package.                                         |
| `stub`      | Path to its generic self-extracting addon stub.                                        |
| `ffi`       | Path to its filesystem-compression shared library.                                     |
| `bin`       | Path to the host `abi` producer executable.                                            |
| `nativeFfi` | A filesystem API adapter, or `undefined` when no supported FFI or binder is available. |

On Node versions with `node:ffi`, or runtimes that provide `node:smol-ffi`, `nativeFfi.name` identifies the selected module. Otherwise the package can load its platform `bind.node` addon and identify it as `napi-bind`. A missing platform package makes `require('@abitious/cli')` throw an error that names the package to install.

The `nativeFfi` adapter provides `probe(path)`, `inspect(path)`, `compressFile(path)`, and `close()`. `probe` returns `0` for a supported filesystem, `1` when the file is already compressed, `2` when compression is unsupported, and `-1` on invalid input or an I/O error. `inspect` returns `{ compressed, logical, physical }`; `compressFile` returns `{ status, before, after }`. Compression status values are `0` compressed, `1` no size gain, `2` already compressed, `3` unsupported, and `4` skipped by the size gate. The byte counts use `bigint`.

The runtime FFI selects an available native module at load time. Node's built-in FFI is experimental and requires `--experimental-ffi` on Node 26. `nativeFfi` can be `undefined` when the runtime has no supported FFI module and the platform binder cannot load.

## Platform C ABI

Each platform package contains a shared library with four exported functions. Callers must pass UTF-8, NUL-terminated paths. The `abitious_ffi_version()` function returns ABI version `1`.

| Function                                             | Return values and output                                                                                                                                            |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `abitious_probe(path)`                               | `0` supported, `1` already compressed, `2` unsupported, `-1` invalid input or I/O error.                                                                            |
| `abitious_stat(path, compressed, logical, physical)` | `0` on success and writes the compression flag plus logical and physical byte counts; `-1` on error.                                                                |
| `abitious_compress_file(path, before, after)`        | `0` compressed, `1` no size gain, `2` already compressed, `3` unsupported, `4` skipped, `-1` on error. Optional output pointers receive byte counts when available. |
| `abitious_ffi_version()`                             | Returns `1`.                                                                                                                                                        |

The C functions that write through pointers require each non-null pointer to point to writable memory of the declared size. Treat these calls as unsafe at the FFI boundary. A successful compression changes the file at `path`; unsupported compression can leave the file unchanged.
