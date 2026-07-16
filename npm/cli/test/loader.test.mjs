// Unit tests for the platform loader — the host→triple mapping + package resolution,
// driven entirely by injected fake platform/arch/libc + a fake resolver, so every
// branch (glibc/musl, each supported triple, missing dep, unsupported host) is proven
// off-host with zero installs. Run: node --test.

import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { test } from 'node:test'

const require = createRequire(import.meta.url)
const loader = require('../loader.cjs')
const { abiSuffix, hostTriple, loadPlatform, resolvePlatform, SUPPORTED } = loader

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

test('hostTriple maps each host to its @abitious/<triple>', () => {
  assert.equal(hostTriple({ platform: 'darwin', arch: 'arm64' }), 'darwin-arm64')
  assert.equal(hostTriple({ platform: 'darwin', arch: 'x64' }), 'darwin-x64')
  assert.equal(hostTriple({ platform: 'win32', arch: 'x64' }), 'win32-x64-msvc')
  assert.equal(hostTriple({ platform: 'win32', arch: 'arm64' }), 'win32-arm64-msvc')
  assert.equal(hostTriple({ platform: 'linux', arch: 'x64', report: GLIBC }), 'linux-x64-gnu')
  assert.equal(hostTriple({ platform: 'linux', arch: 'arm64', report: GLIBC }), 'linux-arm64-gnu')
  assert.equal(hostTriple({ platform: 'linux', arch: 'x64', report: MUSL }), 'linux-x64-musl')
  assert.equal(hostTriple({ platform: 'linux', arch: 'arm64', report: MUSL }), 'linux-arm64-musl')
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
  for (const host of hosts) {
    assert.ok(triples.has(hostTriple(host)), `unsupported: ${hostTriple(host)}`)
  }
})

test('resolvePlatform returns the stub + bin paths from the resolved package dir', () => {
  const fakeManifest = path.join('/fake', 'node_modules', '@abitious', 'darwin-arm64', 'package.json')
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
  assert.equal(resolved.bin, path.join(resolved.dir, 'abi'))
  assert.deepEqual(seen, ['@abitious/darwin-arm64/package.json'])
})

test('resolvePlatform names the .exe bin on Windows', () => {
  const fakeManifest = path.join('/fake', '@abitious', 'win32-x64-msvc', 'package.json')
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
    () => resolvePlatform({ platform: 'freebsd', arch: 'x64', resolve: () => '/nope' }),
    err => {
      assert.match(err.message, /unsupported platform freebsd-x64/)
      assert.match(err.message, /darwin-arm64/)
      return true
    },
  )
})

test('loadPlatform wires the real process (process.report) + require.resolve', () => {
  // The production entry: it reads process.report.getReport() (the glibc-detection wiring on
  // Linux) and require.resolve()s THIS host's @abitious package. The optional dep is not
  // installed in this workspace, so it throws the actionable error — but only after the
  // report wiring + host-triple computation have run. If a host dep ever is present, it
  // returns coherent paths instead; assert whichever outcome occurs.
  const hostReport =
    typeof process.report?.getReport === 'function' ? process.report.getReport() : undefined
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
