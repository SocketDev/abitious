import crypto from 'node:crypto'
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { fileURLToPath } from 'node:url'

import { getEnvValue } from '@socketsecurity/lib-stable/env/rewire'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { extractZipArchive } from '../../fleet/artifact/zip.mts'
import { isMainModule } from '../../fleet/process/is-main-module.mts'
import { runMain } from '../../fleet/process/main/run.mts'
import type { ScriptMeta } from '../../fleet/process/main/run.mts'
import { getScriptArgs } from '../../fleet/process/script-output.mts'
import {
  downloadGithubDispatchApi,
  requestGithubDispatchApi,
} from '../../fleet/registry/github-dispatch.mts'
import { runCapture } from '../../fleet/registry/shared.mts'
import { downloadPinnedNativeProducerArtifacts } from './native-producer.mts'
import {
  readNativePackageReceipt,
  validateNativePackageReceipt,
} from './native-receipt.mts'
import { stageNativeProducerPayloads } from './native-validation.mts'

const REPO_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
)
const CACHE_ROOT = path.join(REPO_ROOT, '.cache/fleet/npm-native')
const RECEIPT_PATH = path.join(CACHE_ROOT, 'receipt.json')
const PUBLISH_WORKFLOW = '.github/workflows/publish-npm.yml'
const MAX_RECEIPT_BYTES = 1_048_576

interface GithubArtifact {
  id: number
  name: string
  digest: string
  expired: boolean
  size_in_bytes: number
}

interface GithubRun {
  id: number
  run_attempt: number
  status: string
  conclusion: string | null
  event: string
  path: string
  head_sha: string
  head_branch: string
  repository: { full_name: string }
  head_repository: { full_name: string }
}

async function githubJson<T>(endpoint: string): Promise<T> {
  return JSON.parse(
    (
      await requestGithubDispatchApi(endpoint, {
        deadlineMs: Date.now() + 60_000,
      })
    ).toString('utf8'),
  ) as T
}

function receiptFailure(where: string): Error {
  return new Error(
    `Native package receipt cannot be restored. Where: ${where}. Saw an unrelated, incomplete, or changed identity; wanted the exact successful publish run. Fix: rerun the reserved publish source.`,
  )
}

function sha256(bytes: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`
}

function validatePublishRun(
  run: GithubRun,
  expected: {
    repository: string
    sourceSha: string
    publishRunId: number
    defaultBranch: string
  },
): void {
  if (
    run.id !== expected.publishRunId ||
    !Number.isSafeInteger(run.run_attempt) ||
    run.run_attempt < 1 ||
    run.status !== 'completed' ||
    run.conclusion !== 'success' ||
    run.event !== 'workflow_dispatch' ||
    run.path !== PUBLISH_WORKFLOW ||
    run.head_sha !== expected.sourceSha ||
    run.head_branch !== expected.defaultBranch ||
    run.repository?.full_name !== expected.repository ||
    run.head_repository?.full_name !== expected.repository
  ) {
    throw receiptFailure('parent publish run')
  }
}

async function readParentReceipt(config: {
  repository: string
  sourceSha: string
  publishRunId: number
  defaultBranch: string
}): Promise<{ bytes: Buffer; run: GithubRun }> {
  const run = await githubJson<GithubRun>(
    `repos/${config.repository}/actions/runs/${config.publishRunId}`,
  )
  validatePublishRun(run, config)
  const listing = await githubJson<{
    artifacts: GithubArtifact[]
    total_count: number
  }>(
    `repos/${config.repository}/actions/runs/${config.publishRunId}/artifacts?per_page=100`,
  )
  if (
    !Array.isArray(listing.artifacts) ||
    listing.total_count !== listing.artifacts.length
  ) {
    throw receiptFailure('parent artifact listing')
  }
  const matches = listing.artifacts.filter(
    artifact => artifact.name === 'npm-signed-native-packages',
  )
  const artifact = matches[0]
  if (
    matches.length !== 1 ||
    !artifact ||
    !Number.isSafeInteger(artifact.id) ||
    artifact.id < 1 ||
    artifact.expired !== false ||
    artifact.size_in_bytes < 1 ||
    artifact.size_in_bytes > MAX_RECEIPT_BYTES ||
    !/^sha256:[a-f0-9]{64}$/u.test(artifact.digest)
  ) {
    throw receiptFailure('parent receipt artifact identity')
  }
  const metadata = await githubJson<GithubArtifact>(
    `repos/${config.repository}/actions/artifacts/${artifact.id}`,
  )
  if (
    metadata.id !== artifact.id ||
    metadata.name !== artifact.name ||
    metadata.digest !== artifact.digest ||
    metadata.expired !== false ||
    metadata.size_in_bytes !== artifact.size_in_bytes
  ) {
    throw receiptFailure('parent receipt artifact metadata')
  }

  const scratch = mkdtempSync(
    path.join(os.tmpdir(), 'abitious-native-receipt-'),
  )
  try {
    const zipPath = path.join(scratch, 'receipt.zip')
    await downloadGithubDispatchApi(
      `repos/${config.repository}/actions/artifacts/${artifact.id}/zip`,
      zipPath,
      MAX_RECEIPT_BYTES,
    )
    const bytes = readFileSync(zipPath)
    if (sha256(bytes) !== artifact.digest) {
      throw receiptFailure('parent receipt ZIP digest')
    }
    const entries = extractZipArchive(bytes, {
      maxArchiveBytes: MAX_RECEIPT_BYTES,
      maxEntries: 2,
      maxEntryBytes: MAX_RECEIPT_BYTES,
      maxTotalBytes: MAX_RECEIPT_BYTES,
    })
    if (
      entries.length !== 1 ||
      entries[0]!.name !== 'receipt.json' ||
      entries[0]!.data.length === 0
    ) {
      throw receiptFailure('parent receipt ZIP contents')
    }
    const currentRun = await githubJson<GithubRun>(
      `repos/${config.repository}/actions/runs/${config.publishRunId}`,
    )
    validatePublishRun(currentRun, config)
    if (currentRun.run_attempt !== run.run_attempt) {
      throw receiptFailure(
        'parent publish attempt changed during receipt download',
      )
    }
    return { bytes: entries[0]!.data, run }
  } finally {
    safeDeleteSync(scratch)
  }
}

export async function restoreNativePackages(): Promise<void> {
  const repository = getEnvValue('GITHUB_REPOSITORY') ?? ''
  const sourceSha = getEnvValue('SCAN_SOURCE_SHA') ?? ''
  const publishRunText = getEnvValue('SCAN_PUBLISH_RUN_ID') ?? ''
  const defaultBranch = getEnvValue('DEFAULT_BRANCH') ?? ''
  const expectedVersion = getEnvValue('SCAN_VERSION') ?? ''
  const publishRunId = Number(publishRunText)
  if (
    !/^[\w.-]+\/[\w.-]+$/u.test(repository) ||
    !/^[a-f0-9]{40}$/u.test(sourceSha) ||
    !/^[1-9]\d*$/u.test(publishRunText) ||
    !defaultBranch ||
    !expectedVersion
  ) {
    throw receiptFailure('scan inputs')
  }
  const head = (
    await runCapture('git', ['rev-parse', 'HEAD'], REPO_ROOT)
  ).stdout.trim()
  if (head !== sourceSha) {
    throw receiptFailure('checked-out scan source')
  }
  const cliManifest = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'npm', 'cli', 'package.json'), 'utf8'),
  ) as { version?: unknown }
  if (cliManifest.version !== expectedVersion) {
    throw receiptFailure('CLI package version')
  }

  const parent = await readParentReceipt({
    repository,
    sourceSha,
    publishRunId,
    defaultBranch,
  })
  const receipt = validateNativePackageReceipt(
    JSON.parse(parent.bytes.toString('utf8')) as unknown,
    {
      repository,
      sourceSha,
      publishRunId,
      publishRunAttempt: parent.run.run_attempt,
      expectedVersion,
      packageRoot: path.join(REPO_ROOT, 'npm'),
      verifyPayloadFiles: false,
    },
  )
  const producer = await downloadPinnedNativeProducerArtifacts({
    repository,
    sourceSha,
    runId: receipt.runId,
    runAttempt: receipt.runAttempt,
    workflowPath: receipt.workflowPath,
    artifacts: receipt.artifacts,
  })
  const confirmedParent = await readParentReceipt({
    repository,
    sourceSha,
    publishRunId,
    defaultBranch,
  })
  if (
    confirmedParent.run.run_attempt !== parent.run.run_attempt ||
    !confirmedParent.bytes.equals(parent.bytes)
  ) {
    throw receiptFailure('parent receipt changed during producer download')
  }
  const parentAfterProducer = await githubJson<GithubRun>(
    `repos/${repository}/actions/runs/${publishRunId}`,
  )
  validatePublishRun(parentAfterProducer, {
    repository,
    sourceSha,
    publishRunId,
    defaultBranch,
  })
  if (parentAfterProducer.run_attempt !== parent.run.run_attempt) {
    throw receiptFailure(
      'parent publish attempt changed during producer download',
    )
  }
  const hashes = new Map<string, string>()
  for (const pkg of receipt.packages) {
    const triple = pkg.name.slice('@abitious/'.length)
    for (const file of pkg.files) {
      if (file.name !== 'package.json') {
        hashes.set(path.join(triple, file.name), file.sha512)
      }
    }
  }
  if (
    hashes.size !==
    receipt.packages.reduce((count, pkg) => count + pkg.files.length - 1, 0)
  ) {
    throw receiptFailure('duplicate package file identity')
  }

  const partsDirectory = path.join(CACHE_ROOT, 'restored-parts')
  const bundleDirectory = path.join(CACHE_ROOT, 'restored-bundles')
  safeDeleteSync(partsDirectory)
  safeDeleteSync(bundleDirectory)
  stageNativeProducerPayloads({
    artifacts: producer.artifacts,
    partsDirectory,
    bundleDirectory,
    packageRoot: path.join(REPO_ROOT, 'npm'),
    sourceSha,
    expectedVersion,
    expectedFileHashes: hashes,
  })
  validateNativePackageReceipt(receipt, {
    repository,
    sourceSha,
    publishRunId,
    publishRunAttempt: parent.run.run_attempt,
    expectedVersion,
    packageRoot: path.join(REPO_ROOT, 'npm'),
  })

  mkdirSync(CACHE_ROOT, { recursive: true })
  const pending = path.join(CACHE_ROOT, 'receipt.json.pending')
  safeDeleteSync(pending)
  writeFileSync(pending, `${JSON.stringify(receipt, null, 2)}\n`, {
    mode: 0o600,
  })
  safeDeleteSync(RECEIPT_PATH)
  renameSync(pending, RECEIPT_PATH)
  const envPath = getEnvValue('GITHUB_ENV')
  if (envPath) {
    appendFileSync(
      envPath,
      `NATIVE_PUBLISH_RUN_ATTEMPT=${parent.run.run_attempt}\n`,
    )
  }
  const outputPath = getEnvValue('GITHUB_OUTPUT')
  if (outputPath) {
    appendFileSync(
      outputPath,
      `publish-run-attempt=${parent.run.run_attempt}\n`,
    )
  }
}

export async function verifyNativePackagesForPublish(
  options: { receiptPath?: string; checkoutHead?: string } = {},
): Promise<void> {
  const repository = getEnvValue('GITHUB_REPOSITORY') ?? ''
  const sourceSha =
    getEnvValue('SCAN_SOURCE_SHA') ?? getEnvValue('GITHUB_SHA') ?? ''
  const scanRunText = getEnvValue('SCAN_PUBLISH_RUN_ID') ?? ''
  const publishRunText = scanRunText || getEnvValue('GITHUB_RUN_ID') || ''
  const publishAttemptText = scanRunText
    ? (getEnvValue('NATIVE_PUBLISH_RUN_ATTEMPT') ?? '')
    : (getEnvValue('GITHUB_RUN_ATTEMPT') ?? '')
  const cliManifest = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'npm', 'cli', 'package.json'), 'utf8'),
  ) as { version?: unknown }
  const expectedVersion =
    (scanRunText
      ? getEnvValue('SCAN_VERSION')
      : typeof cliManifest.version === 'string'
        ? cliManifest.version
        : '') ?? ''
  const publishRunId = Number(publishRunText)
  const publishRunAttempt = Number(publishAttemptText)
  if (
    !/^[\w.-]+\/[\w.-]+$/u.test(repository) ||
    !/^[a-f0-9]{40}$/u.test(sourceSha) ||
    !/^[1-9]\d*$/u.test(publishRunText) ||
    !/^[1-9]\d*$/u.test(publishAttemptText) ||
    !expectedVersion
  ) {
    throw receiptFailure('offline publish inputs')
  }
  const head =
    options.checkoutHead ??
    (await runCapture('git', ['rev-parse', 'HEAD'], REPO_ROOT)).stdout.trim()
  if (head !== sourceSha) {
    throw receiptFailure('offline checked-out source')
  }
  readNativePackageReceipt(options.receiptPath ?? RECEIPT_PATH, {
    repository,
    sourceSha,
    publishRunId,
    publishRunAttempt,
    expectedVersion,
    packageRoot: path.join(REPO_ROOT, 'npm'),
  })
}

const SCRIPT_META: ScriptMeta = {
  describe: 'restores pinned native package payloads or verifies them offline',
  help: 'Usage: restore-native.mts [--verify-local]',
  json: 'result',
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    args: getScriptArgs(),
    options: { 'verify-local': { type: 'boolean' } },
  })
  if (values['verify-local']) {
    await verifyNativePackagesForPublish()
    return
  }
  await restoreNativePackages()
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
