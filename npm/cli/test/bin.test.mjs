// Subprocess tests for the `abi` bin shim (npm/cli/bin.cjs): it resolves this host's
// platform package (loader.cjs), execs the prebuilt `abi`, and forwards argv + the exit
// code. Every branch is driven off a hermetic sandbox — copies of the cli entry files plus a
// fake @abitious/<triple> package carrying a fake `abi` we control — so no real install or
// native binary is needed. Run: node --test.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const cliDir = path.join(here, '..')
const loader = require('../loader.cjs')

// This host's triple + bin name, computed exactly as loader.loadPlatform() would.
const report =
  typeof process.report?.getReport === 'function' ? process.report.getReport() : undefined
const TRIPLE = loader.hostTriple({ platform: process.platform, arch: process.arch, report })
const BIN_NAME = loader.SUPPORTED.find(t => t.triple === TRIPLE).bin

// bin.cjs execs a real subprocess; on win32 the fake `abi.exe` cannot be a shell script, so
// the exec-routing subprocess cases run on unix only. The resolution logic itself is proven
// cross-platform by loader.test.mjs.
const unixOnly = {
  skip: process.platform === 'win32' ? 'exec routing is unix-only here' : false,
}

const sandboxes = []

/**
 * A throwaway copy of the cli entry files (+ optionally a fake @abitious/<triple> package
 * carrying a fake `abi`) under a fresh mkdtemp dir. `bin: null` omits the `abi` file (to
 * drive the spawn-error arm); a string is written as the executable `abi` script.
 */
function makeSandbox({ withPackage = true, bin } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'abitious-bin-test-'))
  sandboxes.push(root)
  for (const f of ['bin.cjs', 'loader.cjs', 'targets.generated.json']) {
    fs.copyFileSync(path.join(cliDir, f), path.join(root, f))
  }
  if (withPackage) {
    const pkgDir = path.join(root, 'node_modules', '@abitious', TRIPLE)
    fs.mkdirSync(pkgDir, { recursive: true })
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({ name: `@abitious/${TRIPLE}`, version: '0.0.0' }),
    )
    fs.writeFileSync(path.join(pkgDir, 'stub.node'), '')
    if (bin !== null) {
      const binPath = path.join(pkgDir, BIN_NAME)
      fs.writeFileSync(binPath, bin ?? '#!/bin/sh\nexit 0\n')
      fs.chmodSync(binPath, 0o755)
    }
  }
  return root
}

test.after(() => {
  for (const root of sandboxes) {
    // Exact, test-created mkdtemp path only — never a glob or an outside path.
    if (root.startsWith(os.tmpdir())) {
      fs.rmSync(root, { recursive: true, force: true })
    }
  }
})

function runBin(root, args = []) {
  return spawnSync(process.execPath, [path.join(root, 'bin.cjs'), ...args], {
    encoding: 'utf8',
  })
}

test('execs the resolved abi and forwards argv + a numeric exit code', unixOnly, () => {
  // A fake `abi` that echoes its argv and exits 7; bin.cjs must forward both.
  const root = makeSandbox({ bin: '#!/bin/sh\necho "args:$*"\nexit 7\n' })
  const r = runBin(root, ['inspect', 'x.node'])
  assert.equal(r.status, 7, `exit code forwarded; stderr=${r.stderr}`)
  assert.match(r.stdout, /args:inspect x\.node/)
})

test(
  'exits 1 with an actionable error when the abi binary is missing (spawn error)',
  unixOnly,
  () => {
    // Package resolves, but its `abi` file is absent → spawnSync sets result.error (ENOENT).
    const root = makeSandbox({ bin: null })
    const r = runBin(root, ['build'])
    assert.equal(r.status, 1)
    assert.match(r.stderr, /failed to exec/)
    assert.match(r.stderr, /reinstall @abitious\//)
  },
)

test('maps a signal death (result.status === null) to exit 1', unixOnly, () => {
  // The fake `abi` kills itself with SIGKILL → spawnSync returns status:null (+ a signal);
  // bin.cjs's `result.status === null ? 1 : result.status` path yields exit 1.
  const root = makeSandbox({ bin: '#!/bin/sh\nkill -9 $$\n' })
  const r = runBin(root)
  assert.equal(r.status, 1, `signal death maps to 1; signal=${r.signal} stderr=${r.stderr}`)
})

test('exits 1 with the loader error when no platform package is installed', () => {
  // No @abitious/<triple> in the sandbox → loadPlatform() throws; bin.cjs catches it,
  // prints the message, and exits 1 (the try/catch around loadPlatform at the top of bin.cjs).
  const root = makeSandbox({ withPackage: false })
  const r = runBin(root)
  assert.equal(r.status, 1)
  assert.match(r.stderr, /no prebuilt binary|unsupported platform/)
})
