import assert from 'node:assert/strict'

import { afterEach, test } from 'vitest'
import { main } from '../../../../../../scripts/repo/npm/prepare-native.mts'

const envKeys = [
  'GITHUB_REPOSITORY',
  'GITHUB_SHA',
  'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT',
]
const savedEnv = new Map(envKeys.map(key => [key, process.env[key]]))

afterEach(() => {
  for (const key of envKeys) {
    const value = savedEnv.get(key)
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
})

test('native preparation rejects missing publish identity before resolving producer artifacts', async () => {
  for (const key of envKeys) delete process.env[key]

  await assert.rejects(main(), /Native producer source is missing/u)
})
