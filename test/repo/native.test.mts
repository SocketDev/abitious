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

void test('native test runner describes its locked workspace command', () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/repo/test/native.mts', '--describe'],
    { cwd: repoRoot, encoding: 'utf8', timeout: 10_000 },
  )

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /locked Rust workspace tests/u)
})
