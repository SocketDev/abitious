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

void test('gen-packages prints the platform matrix without writing files', () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/repo/gen-packages.mts', '--print-matrix'],
    { cwd: repoRoot, encoding: 'utf8', timeout: 10_000 },
  )

  assert.equal(result.status, 0, result.stderr)
  const matrix: unknown = JSON.parse(result.stdout)
  assert.ok(Array.isArray(matrix) && matrix.length > 0)
  assert.ok(
    matrix.every(
      target =>
        typeof target === 'object' &&
        target !== null &&
        'triple' in target &&
        typeof target.triple === 'string',
    ),
  )
})
