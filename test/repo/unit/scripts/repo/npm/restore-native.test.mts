import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { afterEach, test, vi } from 'vitest'
import { verifyNativePackagesForPublish } from '../../../../../../scripts/repo/npm/restore-native.mts'

const envKeys = [
  'GITHUB_REPOSITORY',
  'GITHUB_SHA',
  'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'SCAN_SOURCE_SHA',
  'SCAN_PUBLISH_RUN_ID',
  'SCAN_VERSION',
  'NATIVE_PUBLISH_RUN_ATTEMPT',
]
const savedEnv = new Map(envKeys.map(key => [key, process.env[key]]))

afterEach(() => {
  vi.restoreAllMocks()
  for (const key of envKeys) {
    const value = savedEnv.get(key)
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
})

test('offline publish verification uses publish run identity without GitHub credentials', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'native-offline-test-'))
  try {
    const receiptPath = path.join(root, 'receipt.json')
    await writeFile(receiptPath, '{')
    process.env['GITHUB_REPOSITORY'] = 'SocketDev/abitious'
    process.env['GITHUB_SHA'] = 'a'.repeat(40)
    process.env['GITHUB_RUN_ID'] = '42'
    process.env['GITHUB_RUN_ATTEMPT'] = '2'
    process.env['GITHUB_TOKEN'] = ''
    process.env['GH_TOKEN'] = ''
    delete process.env['SCAN_PUBLISH_RUN_ID']
    delete process.env['NATIVE_PUBLISH_RUN_ATTEMPT']
    delete process.env['SCAN_VERSION']

    await assert.rejects(
      verifyNativePackagesForPublish({
        receiptPath,
        checkoutHead: 'a'.repeat(40),
      }),
      SyntaxError,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('offline publish verification rejects a checked-out source mismatch before reading the receipt', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'native-offline-test-'))
  try {
    process.env['GITHUB_REPOSITORY'] = 'SocketDev/abitious'
    process.env['GITHUB_SHA'] = 'a'.repeat(40)
    process.env['GITHUB_RUN_ID'] = '42'
    process.env['GITHUB_RUN_ATTEMPT'] = '2'
    delete process.env['SCAN_PUBLISH_RUN_ID']
    await assert.rejects(
      verifyNativePackagesForPublish({
        receiptPath: path.join(root, 'missing.json'),
        checkoutHead: 'b'.repeat(40),
      }),
      /offline checked-out source/u,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
