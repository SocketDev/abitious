'use strict'

// The abitious platform loader — PURE and fully injectable so the resolution logic
// is unit-tested with fake platform/arch/libc + a fake resolver (no real install
// needed). npm/cli/index.cjs wires it to the real process + require.resolve.
//
// Each supported target ships as an optional dependency `@abitious/<triple>` carrying
// that platform's prebuilt stub `.node` + host `abi` producer binary, so a package
// manager installs only the one matching this host. The supported set + the stub
// filename come from targets.generated.json — generated from scripts/repo/targets.mts by
// scripts/repo/gen-packages.mts. That targets.mts file is the single source of truth.
// Keep the abi-suffix rule in lockstep with napi-rs's loader and
// crates/abitious/src/triple.rs.

const { dirname, join } = require('node:path')

const DATA = require('./targets.generated.json')

const SUPPORTED = DATA.targets
const STUB_NODE = DATA.stubNode
const BIND_NODE = DATA.bindNode

/**
 * The napi-rs addon abi suffix for a host: glibc Linux `-gnu`, musl Linux
 * `-musl`, Windows `-msvc`, macOS none. musl-vs-glibc is detected exactly as
 * napi-rs does — `process.report.getReport().header.glibcVersionRuntime` is
 * present on glibc and absent on musl. `report` is injected so the branch is
 * testable off-host.
 */
function abiSuffix(platform, report) {
  if (platform === 'win32') {
    return '-msvc'
  }
  if (platform === 'linux') {
    const glibc =
      typeof report === 'object' && report !== null
        ? report.header?.glibcVersionRuntime
        : undefined
    return glibc ? '-gnu' : '-musl'
  }
  return ''
}

/**
 * Map a host (`{ platform, arch, report }`, `process`-shaped) to its target
 * triple `@abitious/<triple>`: `<platform>-<arch>[-<abi>]`.
 */
function hostTriple({ platform, arch, report }) {
  return `${platform}-${arch}${abiSuffix(platform, report)}`
}

// The in-process binder fallback: require the platform package's `bind.node`.
// Same surface the C-FFI wrapper builds, so consumers see one contract either way.
function loadBindFfi({ bindPath } = {}) {
  if (!bindPath) {
    return undefined
  }
  try {
    const bind = require(bindPath)
    if (
      typeof bind.probe !== 'function' ||
      typeof bind.stat !== 'function' ||
      typeof bind.compressFile !== 'function'
    ) {
      return undefined
    }
    return {
      __proto__: null,
      name: 'napi-bind',
      module: bind,
      probe(path) {
        return bind.probe(path)
      },
      inspect(path) {
        const { stat: bindStat } = bind
        const result = bindStat(path)
        if (result.status !== 0) {
          throw new Error(`abitious: filesystem stat failed for ${path}`)
        }
        return {
          __proto__: null,
          compressed: result.compressed,
          logical: result.logical,
          physical: result.physical,
        }
      },
      compressFile(path) {
        const result = bind.compressFile(path)
        if (result.status < 0) {
          throw new Error(`abitious: filesystem compression failed for ${path}`)
        }
        return {
          __proto__: null,
          status: result.status,
          before: result.before,
          after: result.after,
        }
      },
      // The binder is stateless per call; nothing to release.
      close() {},
    }
  } catch {
    // A missing or malformed platform artifact is a normal fallback miss.
  }
  return undefined
}

/**
 * Resolve using the real process + require.resolve (npm/cli/index.cjs entry).
 */
function loadNativeFfi({
  getBuiltinModule = process.getBuiltinModule,
  libraryPath,
} = {}) {
  if (typeof getBuiltinModule !== 'function') {
    return undefined
  }
  for (const name of ['node:ffi', 'node:smol-ffi']) {
    try {
      const module = getBuiltinModule(name)
      if (!module || typeof module.dlopen !== 'function' || !libraryPath) {
        continue
      }
      const library = module.dlopen(libraryPath, {
        abitious_probe: { arguments: ['string'], return: 'int32' },
        abitious_stat: {
          arguments: ['string', 'buffer', 'buffer', 'buffer'],
          return: 'int32',
        },
        abitious_compress_file: {
          arguments: ['string', 'buffer', 'buffer'],
          return: 'int32',
        },
      })
      const { functions } = library
      return {
        __proto__: null,
        name,
        module,
        probe(path) {
          return functions.abitious_probe(path)
        },
        inspect(path) {
          const compressed = Buffer.alloc(1)
          const logical = Buffer.alloc(8)
          const physical = Buffer.alloc(8)
          if (
            functions.abitious_stat(path, compressed, logical, physical) !== 0
          ) {
            throw new Error(`abitious: filesystem stat failed for ${path}`)
          }
          return {
            __proto__: null,
            compressed: compressed[0] !== 0,
            logical: logical.readBigUInt64LE(),
            physical: physical.readBigUInt64LE(),
          }
        },
        compressFile(path) {
          const before = Buffer.alloc(8)
          const after = Buffer.alloc(8)
          const status = functions.abitious_compress_file(path, before, after)
          if (status < 0) {
            throw new Error(
              `abitious: filesystem compression failed for ${path}`,
            )
          }
          return {
            __proto__: null,
            status,
            before: before.readBigUInt64LE(),
            after: after.readBigUInt64LE(),
          }
        },
        close() {
          library.lib.close()
        },
      }
    } catch {
      // A missing builtin, library, or symbol is a normal feature-detection miss.
    }
  }
  return undefined
}

const { createRequire } = require('node:module')

function loadPlatform({
  report = typeof process.report?.getReport === 'function'
    ? process.report.getReport()
    : undefined,
  resolve = request => createRequire(__filename).resolve(request),
  getBuiltinModule = process.getBuiltinModule,
  loadBind = loadBindFfi,
} = {}) {
  const platform = resolvePlatform({
    platform: process.platform,
    arch: process.arch,
    report,
    resolve,
  })
  return {
    __proto__: null,
    ...platform,
    nativeFfi:
      loadNativeFfi({ libraryPath: platform.ffi, getBuiltinModule }) ??
      loadBind({ bindPath: join(platform.dir, BIND_NODE) }),
  }
}
/**
 * Resolve the installed platform package for a host and return its paths.
 */
function resolvePlatform({ platform, arch, report, resolve }) {
  const triple = hostTriple({ platform, arch, report })
  const entry = SUPPORTED.find(t => t.triple === triple)
  const pkg = `@abitious/${triple}`

  if (!entry) {
    throw new Error(
      `abitious: unsupported platform ${triple}.\n` +
        `  Where: ${platform}-${arch}\n` +
        `  Saw:   no @abitious platform package exists for this host\n` +
        `  Fix:   supported targets are ${SUPPORTED.map(t => t.triple).join(', ')}.`,
    )
  }

  let manifest
  try {
    manifest = resolve(`${pkg}/package.json`)
  } catch {
    throw new Error(
      `abitious: no prebuilt binary for ${triple}.\n` +
        `  Where: require.resolve("${pkg}/package.json")\n` +
        `  Saw:   the optional dependency ${pkg} is not installed\n` +
        `  Fix:   install it — \`npm install ${pkg}\` (or reinstall @abitious/cli so\n` +
        `         the matching optionalDependency is fetched for this platform).`,
    )
  }

  const dir = dirname(manifest)
  return {
    __proto__: null,
    triple,
    pkg,
    dir,
    stub: join(dir, STUB_NODE),
    ffi: join(dir, entry.ffiArtifact),
    bind: join(dir, BIND_NODE),
    bin: join(dir, entry.bin),
  }
}

module.exports = {
  __proto__: null,
  abiSuffix,
  hostTriple,
  resolvePlatform,
  loadPlatform,
  loadBindFfi,
  loadNativeFfi,
  SUPPORTED,
  STUB_NODE,
  BIND_NODE,
}
