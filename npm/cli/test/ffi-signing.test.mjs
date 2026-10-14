import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { test } from 'vitest'

import {
  signFfiReleasePart,
  validateFfiMacosSigningReceipt,
} from '../../../scripts/repo/sign-ffi-release.mts'

const producerSha = 'b'.repeat(40)
const submissionId = '12345678-1234-4234-8234-123456789abc'

function createPart(root) {
  const packageDir = path.join(root, 'package')
  const templateDir = path.join(root, 'template')
  mkdirSync(packageDir)
  mkdirSync(templateDir)
  for (const name of [
    'abi',
    'bind.node',
    'libabitious_decmpfs.dylib',
    'stub.node',
  ]) {
    writeFileSync(path.join(packageDir, name), Buffer.from(name))
  }
  const templateFile = path.join(templateDir, 'ffi-stub.node')
  writeFileSync(templateFile, Buffer.from('template'))
  return { packageDir, templateFile }
}

function adapters(overrides = {}) {
  const calls = []
  return {
    calls,
    withKeychain: async (_config, callback) => callback('identity-hash'),
    sign: async (filePath, options) => {
      calls.push(['sign', filePath, options.identity])
      return true
    },
    verify: async filePath => {
      calls.push(['verify', filePath])
    },
    notarize: async filePath => {
      calls.push(['notarize', filePath])
      return { submissionId, status: 'Accepted' }
    },
    ...overrides,
  }
}

test('Darwin release signing emits verified Developer ID and notary rows', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-ffi-signing-'))
  try {
    const part = createPart(root)
    const outputFile = path.join(root, 'macos-signing.json')
    const mock = adapters()
    const receipt = await signFfiReleasePart(
      {
        target: 'darwin-arm64',
        ...part,
        producerSha,
        outputFile,
        certificateBase64: 'certificate',
        certificatePassword: 'password',
        identityLabel: 'Developer ID Application: Example (ABCDE12345)',
      },
      mock,
    )
    assert.equal(receipt.files.length, 5)
    assert.equal(mock.calls.filter(call => call[0] === 'sign').length, 5)
    assert.equal(mock.calls.filter(call => call[0] === 'verify').length, 5)
    assert.equal(mock.calls.filter(call => call[0] === 'notarize').length, 5)
    const parsed = JSON.parse(readFileSync(outputFile, 'utf8'))
    assert.deepEqual(
      validateFfiMacosSigningReceipt(parsed, {
        producerSha,
        target: 'darwin-arm64',
        ...part,
      }),
      receipt,
    )
  } finally {
    safeDeleteSync(root, { recursive: true })
  }
})

test('Darwin release signing fails closed when notarization is skipped', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-ffi-signing-'))
  try {
    const part = createPart(root)
    await assert.rejects(
      signFfiReleasePart(
        {
          target: 'darwin-x64',
          ...part,
          producerSha,
          outputFile: path.join(root, 'macos-signing.json'),
          certificateBase64: 'certificate',
          certificatePassword: 'password',
          identityLabel: 'Developer ID Application: Example (ABCDE12345)',
        },
        adapters({ notarize: async () => false }),
      ),
      /Apple notarization did not finish/u,
    )
  } finally {
    safeDeleteSync(root, { recursive: true })
  }
})

test('bundle receipt validation rejects changed macOS bytes', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-ffi-signing-'))
  try {
    const part = createPart(root)
    const receipt = await signFfiReleasePart(
      {
        target: 'darwin-x64',
        ...part,
        producerSha,
        outputFile: path.join(root, 'macos-signing.json'),
        certificateBase64: 'certificate',
        certificatePassword: 'password',
        identityLabel: 'Developer ID Application: Example (ABCDE12345)',
      },
      adapters(),
    )
    writeFileSync(path.join(part.packageDir, 'abi'), 'changed')
    assert.throws(
      () =>
        validateFfiMacosSigningReceipt(receipt, {
          producerSha,
          target: 'darwin-x64',
          ...part,
        }),
      /lacks verified signing evidence/u,
    )
  } finally {
    safeDeleteSync(root, { recursive: true })
  }
})
