// Unit tests for the platform loader — the host→triple mapping + package resolution,
// driven entirely by injected fake platform/arch/libc + a fake resolver, so every
// branch (glibc/musl, each supported triple, missing dep, unsupported host) is proven
// off-host with zero installs. Run: `pnpm test npm/cli/test/loader.test.mjs`.

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import { createRequire } from 'node:module'
import path from 'node:path'

import { test } from 'vitest'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'

const require = createRequire(import.meta.url)
const loader = require('../loader.cjs')
const {
  abiSuffix,
  hostTriple,
  loadBindFfi,
  loadNativeFfi,
  loadPlatform,
  resolvePlatform,
  SUPPORTED,
} = loader

// A glibc host reports a runtime version; a musl host does not.
const GLIBC = { header: { glibcVersionRuntime: '2.39' } }
const MUSL = { header: {} }

test('abiSuffix covers every host abi', () => {
  assert.equal(abiSuffix('darwin', undefined), '')
  assert.equal(abiSuffix('win32', undefined), '-msvc')
  assert.equal(abiSuffix('linux', GLIBC), '-gnu')
  assert.equal(abiSuffix('linux', MUSL), '-musl')
  assert.equal(abiSuffix('linux', undefined), '-musl')
})

test('loadNativeFfi opens the library through supported builtins in order', () => {
  let closed = false
  const functions = {
    abitious_probe: filePath => (filePath === '/supported' ? 0 : 2),
    abitious_stat(filePath, compressed, logical, physical) {
      assert.equal(filePath, '/file')
      compressed[0] = 1
      logical.writeBigUInt64LE(123n)
      physical.writeBigUInt64LE(45n)
      return 0
    },
    abitious_compress_file(filePath, before, after) {
      assert.equal(filePath, '/file')
      before.writeBigUInt64LE(123n)
      after.writeBigUInt64LE(45n)
      return 0
    },
  }
  const builtin = {
    dlopen(libraryPath, definitions) {
      assert.equal(libraryPath, '/library')
      assert.deepEqual(Object.keys(definitions), [
        'abitious_probe',
        'abitious_stat',
        'abitious_compress_file',
      ])
      return { functions, lib: { close: () => (closed = true) } }
    },
  }
  const seen = []
  const result = loadNativeFfi({
    libraryPath: '/library',
    getBuiltinModule(name) {
      seen.push(name)
      return name === 'node:smol-ffi' ? builtin : undefined
    },
  })
  assert.equal(Object.getPrototypeOf(result), null)
  assert.equal(result.name, 'node:smol-ffi')
  assert.equal(result.module, builtin)
  assert.deepEqual(seen, ['node:ffi', 'node:smol-ffi'])
  assert.equal(result.probe('/supported'), 0)
  assert.deepEqual(result.inspect('/file'), {
    __proto__: null,
    compressed: true,
    logical: 123n,
    physical: 45n,
  })
  assert.deepEqual(result.compressFile('/file'), {
    __proto__: null,
    status: 0,
    before: 123n,
    after: 45n,
  })
  result.close()
  assert.equal(closed, true)
})

test('loadNativeFfi treats absent APIs and rejected builtins as unsupported', () => {
  assert.equal(loadNativeFfi({ getBuiltinModule: undefined }), undefined)
  assert.equal(
    loadNativeFfi({
      getBuiltinModule() {
        throw new Error('not available')
      },
      libraryPath: '/library',
    }),
    undefined,
  )
})

test('hostTriple maps each host to its @abitious/<triple>', () => {
  assert.equal(
    hostTriple({ platform: 'darwin', arch: 'arm64' }),
    'darwin-arm64',
  )
  assert.equal(hostTriple({ platform: 'darwin', arch: 'x64' }), 'darwin-x64')
  assert.equal(hostTriple({ platform: 'win32', arch: 'x64' }), 'win32-x64-msvc')
  assert.equal(
    hostTriple({ platform: 'win32', arch: 'arm64' }),
    'win32-arm64-msvc',
  )
  assert.equal(
    hostTriple({ platform: 'linux', arch: 'x64', report: GLIBC }),
    'linux-x64-gnu',
  )
  assert.equal(
    hostTriple({ platform: 'linux', arch: 'arm64', report: GLIBC }),
    'linux-arm64-gnu',
  )
  assert.equal(
    hostTriple({ platform: 'linux', arch: 'x64', report: MUSL }),
    'linux-x64-musl',
  )
  assert.equal(
    hostTriple({ platform: 'linux', arch: 'arm64', report: MUSL }),
    'linux-arm64-musl',
  )
})

test('every hostTriple output is a supported target (source-of-truth coverage)', () => {
  assert.equal(SUPPORTED.length, 8)
  const hosts = [
    { platform: 'darwin', arch: 'arm64' },
    { platform: 'darwin', arch: 'x64' },
    { platform: 'win32', arch: 'x64' },
    { platform: 'win32', arch: 'arm64' },
    { platform: 'linux', arch: 'x64', report: GLIBC },
    { platform: 'linux', arch: 'arm64', report: GLIBC },
    { platform: 'linux', arch: 'x64', report: MUSL },
    { platform: 'linux', arch: 'arm64', report: MUSL },
  ]
  const triples = new Set(SUPPORTED.map(t => t.triple))
  for (let i = 0, { length } = hosts; i < length; i += 1) {
    const host = hosts[i]
    assert.ok(triples.has(hostTriple(host)), `unsupported: ${hostTriple(host)}`)
  }
})

test('resolvePlatform returns the stub + bin paths from the resolved package dir', () => {
  const fakeManifest = path.join(
    '/fake',
    'node_modules',
    '@abitious',
    'darwin-arm64',
    'package.json',
  )
  const seen = []
  const resolved = resolvePlatform({
    platform: 'darwin',
    arch: 'arm64',
    resolve: request => {
      seen.push(request)
      return fakeManifest
    },
  })
  assert.equal(resolved.triple, 'darwin-arm64')
  assert.equal(resolved.pkg, '@abitious/darwin-arm64')
  assert.equal(resolved.dir, path.dirname(fakeManifest))
  assert.equal(resolved.stub, path.join(resolved.dir, 'stub.node'))
  assert.equal(
    resolved.ffi,
    path.join(resolved.dir, 'libabitious_decmpfs.dylib'),
  )
  assert.equal(resolved.bin, path.join(resolved.dir, 'abi'))
  assert.deepEqual(seen, ['@abitious/darwin-arm64/package.json'])
})

test('resolvePlatform names the .exe bin on Windows', () => {
  const fakeManifest = path.join(
    '/fake',
    '@abitious',
    'win32-x64-msvc',
    'package.json',
  )
  const resolved = resolvePlatform({
    platform: 'win32',
    arch: 'x64',
    resolve: () => fakeManifest,
  })
  assert.equal(resolved.bin, path.join(path.dirname(fakeManifest), 'abi.exe'))
})

test('resolvePlatform throws an actionable error when the optional dep is missing', () => {
  assert.throws(
    () =>
      resolvePlatform({
        platform: 'linux',
        arch: 'x64',
        report: GLIBC,
        resolve: () => {
          throw new Error('Cannot find module')
        },
      }),
    err => {
      assert.match(err.message, /no prebuilt binary for linux-x64-gnu/)
      assert.match(err.message, /@abitious\/linux-x64-gnu/)
      assert.match(err.message, /install/)
      return true
    },
  )
})

test('resolvePlatform rejects an unsupported host, listing what is supported', () => {
  assert.throws(
    () =>
      resolvePlatform({
        platform: 'freebsd',
        arch: 'x64',
        resolve: () => '/nope',
      }),
    err => {
      assert.match(err.message, /unsupported platform freebsd-x64/)
      assert.match(err.message, /darwin-arm64/)
      return true
    },
  )
})

test('loadBindFfi loads a bind.node surface and mirrors the C-FFI shapes', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'bind-fake-'))
  const pkgDir = path.join(dir, '@abitious', 'darwin-arm64')
  mkdirSync(pkgDir, { recursive: true })
  const modPath = path.join(pkgDir, 'bind.node.js')
  writeFileSync(
    modPath,
    [
      'module.exports = {',
      "  probe: (p) => (p === '/supported' ? 0 : 2),",
      '  stat(p) {',
      '    void p',
      "    const ok = p === '/file'",
      '    return { __proto__: null, status: ok ? 0 : -1, compressed: true, logical: 123n, physical: 45n }',
      '  },',
      '  compressFile() {',
      '    return { __proto__: null, status: 0, before: 123n, after: 45n }',
      '  },',
      '}',
    ].join('\n'),
  )
  const bound = loadBindFfi({ bindPath: modPath })
  assert.equal(bound.name, 'napi-bind')
  assert.equal(bound.probe('/supported'), 0)
  assert.equal(bound.probe('/unsupported'), 2)
  assert.deepEqual(bound.inspect('/file'), {
    __proto__: null,
    compressed: true,
    logical: 123n,
    physical: 45n,
  })
  assert.throws(() => bound.inspect('/failing'), /filesystem stat failed/)
  assert.deepEqual(bound.compressFile('/file'), {
    __proto__: null,
    status: 0,
    before: 123n,
    after: 45n,
  })
  bound.close()
  safeDeleteSync(dir)
})

test('loadBindFfi rejects a surface missing any of the three functions', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'bind-partial-'))
  const pkgDir = path.join(dir, '@abitious', 'darwin-arm64')
  mkdirSync(pkgDir, { recursive: true })
  const modPath = path.join(pkgDir, 'bind.node.js')
  writeFileSync(modPath, 'module.exports = { probe: () => 0 }')
  assert.equal(loadBindFfi({ bindPath: modPath }), undefined)
  assert.equal(
    loadBindFfi({ bindPath: path.join(dir, 'absent.node.js') }),
    undefined,
  )
  safeDeleteSync(dir)
})
test('loadPlatform prefers builtins, then the binder', () => {
  const seen = []
  const bindSurface = {
    __proto__: null,
    name: 'napi-bind',
    probe: () => 0,
  }
  // Builtins present: node:ffi wins, the binder is never consulted.
  const withBuiltin = loadPlatform({
    report: GLIBC,
    resolve: request => `/sandbox/${request}`,
    getBuiltinModule: name => {
      seen.push(name)
      return name === 'node:ffi'
        ? { dlopen: () => ({ functions: {}, lib: { close: () => {} } }) }
        : undefined
    },
  })
  assert.equal(withBuiltin.nativeFfi.name, 'node:ffi')
  assert.deepEqual(seen, ['node:ffi'])

  // Builtins absent: the binder answers through the platform package's bind path.
  let requested
  const withBind = loadPlatform({
    report: GLIBC,
    resolve: request => `/sandbox/${request}`,
    getBuiltinModule: () => undefined,
    loadBind: ({ bindPath } = {}) => {
      requested = bindPath
      return bindSurface
    },
  })
  assert.equal(withBind.nativeFfi.name, 'napi-bind')
  assert.equal(
    requested,
    `/sandbox//package.json`
      .replace('//package.json', '/@abitious/darwin-arm64/bind.node')
      .replace('/sandbox/', '/sandbox/'),
  )
})
test('loadPlatform wires the real process (process.report) + require.resolve', () => {
  // The production entry: it reads process.report.getReport() (the glibc-detection wiring on
  // Linux) and require.resolve()s THIS host's @abitious package. The optional dep is not
  // installed in this workspace, so it throws the actionable error — but only after the
  // report wiring + host-triple computation have run. If a host dep ever is present, it
  // returns coherent paths instead; assert whichever outcome occurs.
  const hostReport =
    typeof process.report?.getReport === 'function'
      ? process.report.getReport()
      : undefined
  const expected = hostTriple({
    platform: process.platform,
    arch: process.arch,
    report: hostReport,
  })
  try {
    const res = loadPlatform()
    assert.equal(res.triple, expected)
    assert.equal(res.pkg, `@abitious/${expected}`)
    assert.ok(res.bin.length > 0 && res.stub.length > 0)
  } catch (err) {
    assert.match(err.message, /no prebuilt binary|unsupported platform/)
  }
})
