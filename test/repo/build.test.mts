import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { test } from 'vitest'

const repoRoot = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
)

void test('build describes itself without starting a build', () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/repo/build.mts', '--describe'],
    { cwd: repoRoot, encoding: 'utf8', timeout: 10_000 },
  )

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /build/i)
})
