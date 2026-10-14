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

void test('release dry-run returns a machine-readable plan without writing', () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/repo/release.mts', '--dry-run', '--json'],
    { cwd: repoRoot, encoding: 'utf8', timeout: 10_000 },
  )

  assert.equal(result.status, 0, result.stderr)
  const plan = JSON.parse(result.stdout)
  assert.equal(plan.dryRun, true)
  assert.match(plan.tag, /^v\d+\.\d+\.\d+/)
})
