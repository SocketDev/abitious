import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { test } from 'vitest'
import { TARGETS } from '../../../../../../scripts/repo/targets.mts'
import { validateNativePackageReceipt } from '../../../../../../scripts/repo/npm/native-receipt.mts'

const repoRoot = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../../../',
)

test('native receipt binds exact package and file identities and hashes', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'native-receipt-test-'))
  try {
    const packages = TARGETS.map(target => {
      const checkout = path.join(root, target.triple)
      mkdirSync(checkout, { recursive: true })
      const manifest = JSON.parse(
        readFileSync(
          path.join(repoRoot, 'npm', target.triple, 'package.json'),
          'utf8',
        ),
      ) as { files: string[]; name: string; version: string }
      writeFileSync(
        path.join(checkout, 'package.json'),
        JSON.stringify(manifest),
      )
      const files = [...manifest.files, 'package.json'].map(name => {
        const content =
          name === 'package.json'
            ? readFileSync(path.join(checkout, name))
            : Buffer.from(`${target.triple}:${name}`)
        if (name !== 'package.json') {
          mkdirSync(path.dirname(path.join(checkout, name)), {
            recursive: true,
          })
          writeFileSync(path.join(checkout, name), content)
        }
        return {
          name,
          sha512: crypto.createHash('sha512').update(content).digest('hex'),
        }
      })
      return { name: manifest.name, version: manifest.version, files }
    })
    const receipt = {
      version: 1,
      repository: 'SocketDev/abitious',
      sourceSha: 'a'.repeat(40),
      publishRunId: 42,
      publishRunAttempt: 2,
      workflowPath: '.github/workflows/build-tier-1-native-packages.yml',
      runId: 51,
      runAttempt: 1,
      artifacts: TARGETS.map((target, index) => ({
        id: index + 1,
        name: `abitious-ffi-source-${target.triple}`,
        digest: `sha256:${String(index + 1).padStart(64, '0')}`,
      })),
      packages,
    }
    const expected = {
      repository: receipt.repository,
      sourceSha: receipt.sourceSha,
      publishRunId: receipt.publishRunId,
      publishRunAttempt: receipt.publishRunAttempt,
      expectedVersion: packages[0]!.version,
      packageRoot: root,
    }
    assert.equal(validateNativePackageReceipt(receipt, expected).runId, 51)
    assert.throws(() =>
      validateNativePackageReceipt(
        { ...receipt, sourceSha: 'b'.repeat(40) },
        expected,
      ),
    )
    assert.throws(() =>
      validateNativePackageReceipt(
        { ...receipt, publishRunAttempt: 1 },
        expected,
      ),
    )
    const changed = structuredClone(receipt)
    changed.packages[0]!.files[0]!.sha512 = '0'.repeat(128)
    assert.throws(() => validateNativePackageReceipt(changed, expected))
    const offlineExpectation = { ...expected, verifyPayloadFiles: false }
    rmSync(path.join(root, TARGETS[0]!.triple, packages[0]!.files[0]!.name))
    assert.equal(
      validateNativePackageReceipt(receipt, offlineExpectation).runId,
      51,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
