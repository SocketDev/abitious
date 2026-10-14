// Unit tests for the codegen (scripts/repo/gen-packages.mts) — the single-source-of-truth
// discipline: --check must report in-sync (proving the committed generated files match
// targets.mts), and --print-matrix must derive the CI matrix from the same list with
// darwin targets on macOS runners. Run: `pnpm test` npm/cli/test/codegen.test.mjs.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import { test } from 'vitest'

import { FFI_STUB_NODE, TARGETS } from '../../../scripts/repo/targets.mts'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.join(here, '..', '..', '..')
const gen = path.join(repoRoot, 'scripts', 'repo', 'gen-packages.mts')

function run(...args) {
  const result = spawnSync(process.execPath, [gen, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  })
  assert.ifError(result.error)
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

test('gen-packages --check reports the committed files in sync with targets.mts', () => {
  const out = run('--check')
  assert.match(out, /in sync/)
})

test('gen-packages --print-matrix derives the tier-1 CI targets from the source of truth', () => {
  // The fast CI matrix is native on each runner: darwin arm64/x64 and linux
  // x64/arm64-gnu. Musl and Windows are included in the manual full-build matrix.
  const matrix = JSON.parse(run('--print-matrix'))
  // map() returns a fresh array and Node 18 lacks toSorted().
  // oxlint-disable-next-line unicorn/no-array-sort -- fresh array sort
  const triples = matrix.map(m => m.triple).sort()
  assert.deepEqual(triples, [
    'darwin-arm64',
    'darwin-x64',
    'linux-arm64-gnu',
    'linux-x64-gnu',
  ])
})

test('gen-packages --print-matrix-all derives the full target set (all 8)', () => {
  // The manual full-build dispatch uses this unfiltered set. Every target ships a
  // prebuilt, so this matrix contains all eight entries from targets.mts.
  const matrix = JSON.parse(run('--print-matrix-all'))
  // map() returns a fresh array and Node 18 lacks toSorted().
  // oxlint-disable-next-line unicorn/no-array-sort -- fresh array sort
  const triples = matrix.map(m => m.triple).sort()
  assert.deepEqual(triples, [
    'darwin-arm64',
    'darwin-x64',
    'linux-arm64-gnu',
    'linux-arm64-musl',
    'linux-x64-gnu',
    'linux-x64-musl',
    'win32-arm64-msvc',
    'win32-x64-msvc',
  ])
  // Every entry carries the fields the build workflow consumes. The `libc` value
  // selects musl toolchain setup for the two musl targets.
  const musl = matrix.filter(m => m.libc === 'musl').map(m => m.triple)
  // map() returns a fresh array and Node 18 lacks toSorted().
  // oxlint-disable-next-line unicorn/no-array-sort -- fresh array sort
  musl.sort()
  assert.deepEqual(musl, ['linux-arm64-musl', 'linux-x64-musl'])
  for (const entry of matrix) {
    assert.ok(entry.rust, `${entry.triple} needs a rust target`)
    assert.ok(entry.runner, `${entry.triple} needs a runner`)
    assert.ok(entry.stubArtifact, `${entry.triple} needs a stub artifact name`)
    assert.ok(
      entry.ffiStubArtifact,
      `${entry.triple} needs an FFI template artifact`,
    )
    assert.ok(entry.bin, `${entry.triple} needs a bin name`)
  }
})

test('darwin targets build on macOS runners (so the producer resign step runs)', () => {
  const matrix = JSON.parse(run('--print-matrix'))
  for (const entry of matrix) {
    if (entry.os === 'darwin') {
      assert.match(
        entry.runner,
        /^macos/,
        `${entry.triple} must build on a macOS runner`,
      )
    }
    // Every entry carries the fields the workflow consumes.
    assert.ok(entry.rust, `${entry.triple} needs a rust target`)
    assert.ok(entry.stubArtifact, `${entry.triple} needs a stub artifact name`)
    assert.ok(entry.bin, `${entry.triple} needs a bin name`)
  }
})

test('platform package manifests carry every foreign FFI template and its index', () => {
  for (const target of TARGETS) {
    const manifest = JSON.parse(
      readFileSync(
        path.join(repoRoot, 'npm', target.triple, 'package.json'),
        'utf8',
      ),
    )
    assert.ok(manifest.files.includes('LICENSE'))
    assert.ok(manifest.files.includes('THIRD-PARTY-NOTICES.md'))
    assert.ok(manifest.files.includes('templates/manifest.json'))
    for (const template of TARGETS) {
      assert.ok(
        manifest.files.includes(
          `templates/${template.triple}/${FFI_STUB_NODE}`,
        ),
      )
    }
  }
})
