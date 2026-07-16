// Unit tests for the codegen (scripts/gen-packages.mts) — the single-source-of-truth
// discipline: --check must report in-sync (proving the committed generated files match
// targets.mts), and --print-matrix must derive the CI matrix from the same list with
// darwin targets on macOS runners. Run: node --test.

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { test } from 'node:test'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.join(here, '..', '..', '..')
const gen = path.join(repoRoot, 'scripts', 'gen-packages.mts')

function run(...args) {
  return execFileSync(process.execPath, [gen, ...args], { cwd: repoRoot, encoding: 'utf8' })
}

test('gen-packages --check reports the committed files in sync with targets.mts', () => {
  const out = run('--check')
  assert.match(out, /in sync/)
})

test('gen-packages --print-matrix derives the tier-1 CI targets from the source of truth', () => {
  // The CI BUILD matrix is the tier-1 subset — native on their runner, no cross C
  // toolchain: darwin arm64/x64 + linux x64/arm64-gnu. musl (needs a musl C
  // cross-toolchain for zstd-sys) and Windows are tier-2: still generated as
  // @abitious/<triple> manifests + optionalDependencies (asserted in sync by the
  // --check test above), but excluded from the CI build until their toolchains /
  // validation land. Promote by flipping `tier1` in targets.mts.
  const matrix = JSON.parse(run('--print-matrix'))
  const triples = matrix.map(m => m.triple).sort()
  assert.deepEqual(triples, [
    'darwin-arm64',
    'darwin-x64',
    'linux-arm64-gnu',
    'linux-x64-gnu',
  ])
})

test('darwin targets build on macOS runners (so the producer resign step runs)', () => {
  const matrix = JSON.parse(run('--print-matrix'))
  for (const entry of matrix) {
    if (entry.os === 'darwin') {
      assert.match(entry.runner, /^macos/, `${entry.triple} must build on a macOS runner`)
    }
    // Every entry carries the fields the workflow consumes.
    assert.ok(entry.rust, `${entry.triple} needs a rust target`)
    assert.ok(entry.stubArtifact, `${entry.triple} needs a stub artifact name`)
    assert.ok(entry.bin, `${entry.triple} needs a bin name`)
  }
})
