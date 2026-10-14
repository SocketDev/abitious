import crypto from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { isMainModule } from '../../fleet/process/is-main-module.mts'
import { runMain } from '../../fleet/process/main/run.mts'
import type { ScriptMeta } from '../../fleet/process/main/run.mts'
import { getEnvValue } from '@socketsecurity/lib-stable/env/rewire'
import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { TARGETS } from '../targets.mts'
import { validateNativePackageReceipt } from './native-receipt.mts'
import { resolveNativeProducerArtifacts } from './native-producer.mts'
import {
  stageNativeProducerPayloads,
  validateNativeProducerRun,
} from './native-validation.mts'

const REPO_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
)
const CACHE_ROOT = path.join(REPO_ROOT, '.cache/fleet/npm-native')
const WORKFLOW_PATH = '.github/workflows/build-tier-1-native-packages.yml'

function fileDigest(filePath: string): string {
  return crypto
    .createHash('sha512')
    .update(readFileSync(filePath))
    .digest('hex')
}

export async function main(): Promise<void> {
  const repository = getEnvValue('GITHUB_REPOSITORY') ?? ''
  const sourceSha = getEnvValue('GITHUB_SHA') ?? ''
  const publishRunId = Number(getEnvValue('GITHUB_RUN_ID'))
  const publishRunAttempt = Number(getEnvValue('GITHUB_RUN_ATTEMPT'))
  if (
    !/^[\w.-]+\/[\w.-]+$/u.test(repository) ||
    !/^[a-f0-9]{40}$/u.test(sourceSha) ||
    !Number.isSafeInteger(publishRunId) ||
    publishRunId < 1 ||
    !Number.isSafeInteger(publishRunAttempt) ||
    publishRunAttempt < 1
  ) {
    throw new Error(
      'Native producer source is missing. Where: publish job. Saw no repository, full source SHA, or run identity; wanted exact workflow identities. Fix: run this step in the trusted GitHub publish workflow.',
    )
  }
  if (getEnvValue('GITHUB_EVENT_NAME') !== 'workflow_dispatch') {
    throw new Error(
      'Native producer preparation is not trusted. Where: publish job. Saw a non-dispatch event; wanted the resumed signed publish workflow. Fix: resume the reserved publish source through the trusted workflow.',
    )
  }

  const version = JSON.parse(
    readFileSync(
      path.join(REPO_ROOT, 'npm', TARGETS[0]!.triple, 'package.json'),
      'utf8',
    ),
  )['version'] as string
  for (const target of TARGETS) {
    const manifest = JSON.parse(
      readFileSync(
        path.join(REPO_ROOT, 'npm', target.triple, 'package.json'),
        'utf8',
      ),
    ) as Record<string, unknown>
    if (manifest['version'] !== version) {
      throw new Error(
        'Native platform package versions differ. Where: npm platform manifests. Saw multiple versions; wanted one release version. Fix: regenerate the workspace packages before publishing.',
      )
    }
  }

  mkdirSync(CACHE_ROOT, { recursive: true })
  const resolved = await resolveNativeProducerArtifacts({
    repository,
    sourceSha,
    workflowPath: WORKFLOW_PATH,
    receiptPath: path.join(CACHE_ROOT, 'producer-dispatch.json'),
  })
  validateNativeProducerRun(resolved.run, {
    repository,
    sourceSha,
    requireMacosSigning: true,
  })
  const partsDirectory = path.join(CACHE_ROOT, 'parts')
  const bundleDirectory = path.join(CACHE_ROOT, 'bundles')
  safeDeleteSync(partsDirectory)
  safeDeleteSync(bundleDirectory)
  stageNativeProducerPayloads({
    artifacts: resolved.artifacts,
    partsDirectory,
    bundleDirectory,
    packageRoot: path.join(REPO_ROOT, 'npm'),
    sourceSha,
    expectedVersion: version,
  })

  const packages = TARGETS.map(target => {
    const directory = path.join(REPO_ROOT, 'npm', target.triple)
    const manifest = JSON.parse(
      readFileSync(path.join(directory, 'package.json'), 'utf8'),
    ) as { files: string[]; name: string; version: string }
    const files = [
      ...manifest.files.map(name => ({
        name,
        sha512: fileDigest(path.join(directory, name)),
      })),
      {
        name: 'package.json',
        sha512: fileDigest(path.join(directory, 'package.json')),
      },
    ]
    return {
      name: manifest.name,
      version: manifest.version,
      files,
    }
  })
  const receipt = {
    version: 1,
    repository,
    sourceSha,
    publishRunId,
    publishRunAttempt,
    workflowPath: WORKFLOW_PATH,
    runId: resolved.run.id,
    runAttempt: resolved.run.run_attempt,
    artifacts: resolved.artifacts.map(({ artifact }) => ({
      id: artifact.id,
      name: artifact.name,
      digest: artifact.digest,
    })),
    packages,
  }
  const validatedReceipt = validateNativePackageReceipt(receipt, {
    repository,
    sourceSha,
    publishRunId,
    publishRunAttempt,
    expectedVersion: version,
    packageRoot: path.join(REPO_ROOT, 'npm'),
  })
  writeFileSync(
    path.join(CACHE_ROOT, 'receipt.json'),
    `${JSON.stringify(validatedReceipt, null, 2)}\n`,
    { mode: 0o600 },
  )
}

const SCRIPT_META: ScriptMeta = {
  describe: 'validates and stages exact-source signed native npm packages',
  help: 'Usage: prepare-native.mts [--json]',
  json: 'result',
}

if (isMainModule(import.meta.url)) {
  runMain(() => main(), SCRIPT_META)
}
