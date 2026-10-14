import crypto from 'node:crypto'
import { lstatSync, readFileSync } from 'node:fs'
import path from 'node:path'

import { assertSafeArtifactPath } from './native-validation.mts'
import { TARGETS } from '../targets.mts'

export interface NativePackageReceipt {
  version: 1
  repository: string
  sourceSha: string
  publishRunId: number
  publishRunAttempt: number
  workflowPath: string
  runId: number
  runAttempt: number
  artifacts: Array<{ id: number; name: string; digest: string }>
  packages: Array<{
    name: string
    version: string
    files: Array<{ name: string; sha512: string }>
  }>
}

export interface NativePackageReceiptExpectation {
  repository: string
  sourceSha: string
  publishRunId: number
  publishRunAttempt: number
  expectedVersion: string
  packageRoot: string
  verifyPayloadFiles?: boolean
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0
}

function sha512File(filePath: string): string {
  return crypto
    .createHash('sha512')
    .update(readFileSync(filePath))
    .digest('hex')
}

function receiptError(where: string): Error {
  return new Error(
    `Native package receipt is invalid. Where: ${where}. Saw an identity, file set, or hash mismatch; wanted the exact signed publish payload. Fix: rerun the reserved publish source.`,
  )
}

export function validateNativePackageReceipt(
  value: unknown,
  expected: NativePackageReceiptExpectation,
): NativePackageReceipt {
  const receipt = value as NativePackageReceipt
  if (
    !receipt ||
    receipt.version !== 1 ||
    receipt.repository !== expected.repository ||
    receipt.sourceSha !== expected.sourceSha ||
    !isPositiveInteger(receipt.publishRunId) ||
    receipt.publishRunId !== expected.publishRunId ||
    !isPositiveInteger(receipt.publishRunAttempt) ||
    receipt.publishRunAttempt !== expected.publishRunAttempt ||
    receipt.workflowPath !==
      '.github/workflows/build-tier-1-native-packages.yml' ||
    !isPositiveInteger(receipt.runId) ||
    !isPositiveInteger(receipt.runAttempt) ||
    !Array.isArray(receipt.artifacts) ||
    !Array.isArray(receipt.packages)
  ) {
    throw receiptError('receipt identity')
  }

  const expectedArtifacts = new Set(
    TARGETS.map(target => `abitious-ffi-source-${target.triple}`),
  )
  const artifactIds = new Set<number>()
  if (receipt.artifacts.length !== expectedArtifacts.size) {
    throw receiptError('producer artifact set')
  }
  for (const artifact of receipt.artifacts) {
    if (
      !artifact ||
      !expectedArtifacts.delete(artifact.name) ||
      !isPositiveInteger(artifact.id) ||
      artifactIds.has(artifact.id) ||
      !/^sha256:[a-f0-9]{64}$/u.test(artifact.digest)
    ) {
      throw receiptError('producer artifact identity')
    }
    artifactIds.add(artifact.id)
  }

  const expectedPackages = new Set(TARGETS.map(target => target.triple))
  const packageNames = new Set<string>()
  if (receipt.packages.length !== expectedPackages.size) {
    throw receiptError('platform package set')
  }
  for (const pkg of receipt.packages) {
    const triple = pkg?.name?.replace(/^@abitious\//u, '') ?? ''
    if (
      !expectedPackages.delete(triple) ||
      packageNames.has(pkg.name) ||
      pkg.version !== expected.expectedVersion ||
      !Array.isArray(pkg.files)
    ) {
      throw receiptError('platform package identity')
    }
    packageNames.add(pkg.name)
    const checkoutDirectory = path.join(expected.packageRoot, triple)
    const manifest = JSON.parse(
      readFileSync(path.join(checkoutDirectory, 'package.json'), 'utf8'),
    ) as { files?: unknown; name?: unknown; version?: unknown }
    if (
      manifest.name !== pkg.name ||
      manifest.version !== expected.expectedVersion ||
      !Array.isArray(manifest.files) ||
      manifest.files.some(name => typeof name !== 'string')
    ) {
      throw receiptError(`${triple}/package.json`)
    }
    const expectedFiles = [...(manifest.files as string[]), 'package.json']
    const receivedFiles = new Set<string>()
    if (pkg.files.length !== expectedFiles.length) {
      throw receiptError(`${triple} file set`)
    }
    for (const file of pkg.files) {
      if (
        !file ||
        typeof file.name !== 'string' ||
        !/^[a-f0-9]{128}$/u.test(file.sha512) ||
        receivedFiles.has(file.name)
      ) {
        throw receiptError(`${triple} file identity`)
      }
      assertSafeArtifactPath(file.name)
      receivedFiles.add(file.name)
    }
    if (
      expectedFiles.toSorted().join('\n') !==
      [...receivedFiles].toSorted().join('\n')
    ) {
      throw receiptError(`${triple} file set`)
    }
    for (const file of pkg.files) {
      const filePath = path.join(checkoutDirectory, file.name)
      if (
        expected.verifyPayloadFiles === false &&
        file.name !== 'package.json'
      ) {
        continue
      }
      const stat = lstatSync(filePath, { throwIfNoEntry: false })
      if (!stat) throw receiptError(`${triple}/${file.name}`)
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw receiptError(`${triple}/${file.name}`)
      }
      if (sha512File(filePath) !== file.sha512) {
        throw receiptError(`${triple}/${file.name}`)
      }
    }
  }
  return receipt
}

export function readNativePackageReceipt(
  receiptPath: string,
  expected: NativePackageReceiptExpectation,
): NativePackageReceipt {
  return validateNativePackageReceipt(
    JSON.parse(readFileSync(receiptPath, 'utf8')) as unknown,
    expected,
  )
}
