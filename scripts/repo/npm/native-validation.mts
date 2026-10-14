import crypto from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { extractZipArchive } from '../../fleet/artifact/zip.mts'
import { aggregateFfiTemplateParts } from '../ffi-templates.mts'
import { assertRegularZipEntries } from './native/validation/zip.mts'
import { assertSafeArtifactPath } from './native/validation/zip.mts'

export { assertSafeArtifactPath }
import {
  abiBin,
  BIND_NODE,
  FFI_STUB_NODE,
  ffiArtifact,
  STUB_NODE,
  TARGETS,
} from '../targets.mts'

import type { Target } from '../targets.mts'

const PRODUCER_WORKFLOW = '.github/workflows/build-tier-1-native-packages.yml'
const MAX_ARCHIVE_BYTES = 268_435_456
const MAX_ENTRY_BYTES = 134_217_728
const REPO_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
)
const EXPECTED_EXTRA_ARTIFACTS = new Set([
  'abitious-ffi-producer-bundles',
  'github-release-assets',
])

export interface NativeWorkflowRun {
  id: number
  run_attempt: number
  status: string
  conclusion: string | null
  event: string
  path: string
  head_sha: string
  repository: { full_name: string }
  head_repository: { full_name: string }
  jobs?:
    | {
        jobs?:
          | Array<{
              name?: string | undefined
              conclusion?: string | undefined
              steps?:
                | Array<{
                    name?: string | undefined
                    conclusion?: string | undefined
                  }>
                | undefined
            }>
          | undefined
      }
    | undefined
}

export interface NativeArtifact {
  id: number
  name: string
  digest: string
  expired: boolean
}

interface NativeProducerRunExpectation {
  repository: string
  sourceSha: string
  requireMacosSigning?: boolean | undefined
}

function isNativeRepositoryName(value: string): boolean {
  return /^[\w.-]+\/[\w.-]+$/u.test(value)
}

function isNativeSourceSha(value: string): boolean {
  return /^[a-f0-9]{40}$/u.test(value)
}

function hasTrustedNativeRunIdentity(
  run: NativeWorkflowRun,
  expected: NativeProducerRunExpectation,
): boolean {
  return (
    isNativeRepositoryName(expected.repository) &&
    isNativeSourceSha(expected.sourceSha) &&
    run.status === 'completed' &&
    run.conclusion === 'success' &&
    run.event === 'workflow_dispatch' &&
    run.path === PRODUCER_WORKFLOW &&
    run.head_sha === expected.sourceSha &&
    run.repository?.full_name === expected.repository &&
    run.head_repository?.full_name === expected.repository &&
    Number.isSafeInteger(run.id) &&
    run.id >= 1 &&
    Number.isSafeInteger(run.run_attempt) &&
    run.run_attempt >= 1
  )
}

function hasSignedMacosProducerJobs(run: NativeWorkflowRun): boolean {
  const aggregate = run.jobs?.jobs?.find(
    job => job.name === 'Aggregate complete producer bundles',
  )
  if (aggregate?.conclusion !== 'success') {
    return false
  }
  const darwinJobs = ['Build (darwin-arm64)', 'Build (darwin-x64)']
  return darwinJobs.every(name => {
    const job = run.jobs?.jobs?.find(candidate => candidate.name === name)
    return (
      job?.conclusion === 'success' &&
      job.steps?.some(
        step =>
          step.name === 'Developer id sign and notarize darwin release files' &&
          step.conclusion === 'success',
      )
    )
  })
}

export function validateNativeProducerRun(
  value: unknown,
  expected: NativeProducerRunExpectation,
): NativeWorkflowRun {
  const run = value as NativeWorkflowRun
  if (!run || !hasTrustedNativeRunIdentity(run, expected)) {
    throw new Error(
      'Native producer run is not trusted. Where: GitHub Actions. Saw a failed or unrelated run; wanted a successful exact-source workflow dispatch. Fix: build the selected source SHA on the default branch.',
    )
  }
  if (expected.requireMacosSigning && !hasSignedMacosProducerJobs(run)) {
    throw new Error(
      'Native producer run lacks signed macOS templates. Where: Aggregate complete producer bundles. Saw no successful aggregate job; wanted the signed eight-target producer set. Fix: dispatch the qualified default-branch build.',
    )
  }
  return run
}

export function selectNativeProducerArtifacts(
  artifacts: readonly NativeArtifact[],
): NativeArtifact[] {
  const expectedNames = new Set(
    TARGETS.map(target => `abitious-ffi-source-${target.triple}`),
  )
  const selected = new Map<string, NativeArtifact>()
  const ids = new Set<number>()
  for (const artifact of artifacts) {
    if (EXPECTED_EXTRA_ARTIFACTS.has(artifact.name)) {
      continue
    }
    if (!expectedNames.has(artifact.name) || selected.has(artifact.name)) {
      throw new Error(
        'Native producer artifacts contain an unexpected or duplicate target. Where: artifact listing. Saw a conflicting name; wanted one artifact for every platform. Fix: rerun the complete native workflow.',
      )
    }
    if (
      !Number.isSafeInteger(artifact.id) ||
      artifact.id < 1 ||
      ids.has(artifact.id) ||
      artifact.expired !== false ||
      !/^sha256:[a-f0-9]{64}$/u.test(artifact.digest)
    ) {
      throw new Error(
        'Native producer artifact identity is invalid. Where: artifact listing. Saw an expired, duplicate, or undigested artifact; wanted immutable live bytes. Fix: rerun the complete native workflow.',
      )
    }
    ids.add(artifact.id)
    selected.set(artifact.name, artifact)
  }
  if (selected.size !== expectedNames.size) {
    throw new Error(
      'Native producer artifacts are incomplete. Where: artifact listing. Saw a missing platform; wanted all eight targets. Fix: run the complete native workflow.',
    )
  }
  return TARGETS.map(target =>
    selected.get(`abitious-ffi-source-${target.triple}`)!,
  )
}

function hasMatchingNativePackageIdentity(
  manifest: Record<string, unknown>,
  target: string,
  expectedVersion: string,
  checkoutManifest: Record<string, unknown>,
): boolean {
  return (
    manifest['name'] === `@abitious/${target}` &&
    manifest['version'] === expectedVersion &&
    checkoutManifest['version'] === expectedVersion
  )
}

function hasMatchingNativePackageFiles(
  files: unknown,
  checkoutManifest: Record<string, unknown>,
  targetConfig: Target,
): boolean {
  if (!Array.isArray(files)) {
    return false
  }
  const checkoutFiles = checkoutManifest['files'] as string[]
  if (
    JSON.stringify(files.toSorted()) !==
    JSON.stringify(checkoutFiles.toSorted())
  ) {
    return false
  }
  return [
    'LICENSE',
    'README.md',
    'THIRD-PARTY-NOTICES.md',
    abiBin(targetConfig.os),
    BIND_NODE,
    ffiArtifact(targetConfig.os),
    STUB_NODE,
    'templates/manifest.json',
    ...TARGETS.map(item => `templates/${item.triple}/${FFI_STUB_NODE}`),
  ].every(name => files.includes(name))
}

function hasMatchingNativePackagePlatform(
  manifest: Record<string, unknown>,
  checkoutManifest: Record<string, unknown>,
): boolean {
  return (
    JSON.stringify(manifest['os']) === JSON.stringify(checkoutManifest['os']) &&
    JSON.stringify(manifest['cpu']) ===
      JSON.stringify(checkoutManifest['cpu']) &&
    manifest['repository'] === checkoutManifest['repository'] &&
    JSON.stringify(manifest['libc']) ===
      JSON.stringify(checkoutManifest['libc'])
  )
}

export function validateNativePackageManifest(
  value: unknown,
  target: string,
  expectedVersion: string,
): Record<string, unknown> {
  const manifest = value as Record<string, unknown>
  const targetConfig = TARGETS.find(item => item.triple === target)
  const checkoutManifest = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'npm', target, 'package.json'), 'utf8'),
  ) as Record<string, unknown>
  if (
    !targetConfig ||
    !manifest ||
    !hasMatchingNativePackageIdentity(
      manifest,
      target,
      expectedVersion,
      checkoutManifest,
    ) ||
    !hasMatchingNativePackageFiles(
      manifest['files'],
      checkoutManifest,
      targetConfig,
    ) ||
    !hasMatchingNativePackagePlatform(manifest, checkoutManifest)
  ) {
    throw new Error(
      `Native platform manifest does not match the checkout. Where: ${target}/package.json. Saw an unexpected name, version, or file list; wanted @abitious/${target}@${expectedVersion}. Fix: regenerate package manifests before publishing.`,
    )
  }
  return manifest
}

function digestSha256(bytes: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`
}

interface StageNativeProducerPayloadsConfig {
  artifacts: ReadonlyArray<{ artifact: NativeArtifact; bytes: Buffer }>
  partsDirectory: string
  bundleDirectory: string
  packageRoot: string
  sourceSha: string
  expectedVersion: string
  expectedFileHashes?: ReadonlyMap<string, string> | undefined
}

interface NativeStagedPackageFile {
  source: string
  destination: string
  executable: boolean
}

function extractNativeProducerParts(
  config: StageNativeProducerPayloadsConfig,
  selected: readonly NativeArtifact[],
): void {
  const byId = new Map(
    config.artifacts.map(row => [row.artifact.id, row.bytes]),
  )
  for (let index = 0, { length } = selected; index < length; index += 1) {
    const artifact = selected[index]!
    const bytes = byId.get(artifact.id)
    if (!bytes || digestSha256(bytes) !== artifact.digest) {
      throw new Error(
        'Native producer archive digest differs. Where: downloaded artifact. Saw unverified bytes; wanted the immutable SHA256. Fix: download the producer artifact again.',
      )
    }
    const entries = extractZipArchive(bytes, {
      maxArchiveBytes: MAX_ARCHIVE_BYTES,
      maxEntries: 512,
      maxEntryBytes: MAX_ENTRY_BYTES,
      maxTotalBytes: MAX_ARCHIVE_BYTES,
    })
    assertRegularZipEntries(bytes, entries)
    const partDir = path.join(config.partsDirectory, artifact.name)
    for (
      let entryIndex = 0, { length: entryLength } = entries;
      entryIndex < entryLength;
      entryIndex += 1
    ) {
      const entry = entries[entryIndex]!
      if (entry.name.endsWith('/')) {
        continue
      }
      const output = path.join(partDir, entry.name)
      mkdirSync(path.dirname(output), { recursive: true })
      writeFileSync(output, entry.data, { flag: 'wx' })
    }
  }
}

function collectNativePackageFiles(
  config: StageNativeProducerPayloadsConfig,
): NativeStagedPackageFile[] {
  const staged: NativeStagedPackageFile[] = []
  for (
    let targetIndex = 0, { length } = TARGETS;
    targetIndex < length;
    targetIndex += 1
  ) {
    const target = TARGETS[targetIndex]!
    const packageDir = path.join(config.bundleDirectory, target.triple)
    const manifest = validateNativePackageManifest(
      JSON.parse(
        readFileSync(path.join(packageDir, 'package.json'), 'utf8'),
      ) as unknown,
      target.triple,
      config.expectedVersion,
    )
    const files = manifest['files'] as string[]
    for (
      let fileIndex = 0, { length: fileLength } = files;
      fileIndex < fileLength;
      fileIndex += 1
    ) {
      const name = files[fileIndex]!
      if (name === 'package.json') {
        continue
      }
      assertSafeArtifactPath(name)
      const source = path.join(packageDir, name)
      const stat = lstatSync(source, { throwIfNoEntry: false })
      if (!stat?.isFile() || stat.isSymbolicLink() || stat.size === 0) {
        throw new Error(
          `Native package payload is incomplete. Where: ${target.triple}/${name}. Saw a missing, linked, or empty file; wanted the validated package payload. Fix: rebuild the producer artifact.`,
        )
      }
      staged.push({
        source,
        destination: path.join(config.packageRoot, target.triple, name),
        executable: name === abiBin(target.os),
      })
    }
  }
  return staged
}

function assertNativePackageReceipt(
  config: StageNativeProducerPayloadsConfig,
  staged: readonly NativeStagedPackageFile[],
): void {
  if (!config.expectedFileHashes) {
    return
  }
  if (config.expectedFileHashes.size !== staged.length) {
    throw new Error(
      'Native package receipt file set differs. Where: staged package contents. Saw a missing or extra file; wanted the retained release file set. Fix: restore the exact producer receipt.',
    )
  }
  for (let index = 0, { length } = staged; index < length; index += 1) {
    const file = staged[index]!
    const relative = path.relative(config.packageRoot, file.destination)
    const expected = config.expectedFileHashes.get(relative)
    const actual = crypto
      .createHash('sha512')
      .update(readFileSync(file.source))
      .digest('hex')
    if (expected !== actual) {
      throw new Error(
        `Native package file differs from the retained receipt. Where: ${relative}. Saw a different SHA512; wanted the staged source identity. Fix: restore the exact producer artifact.`,
      )
    }
  }
}

function writeNativePackageFiles(
  staged: readonly NativeStagedPackageFile[],
): void {
  for (let index = 0, { length } = staged; index < length; index += 1) {
    const file = staged[index]!
    mkdirSync(path.dirname(file.destination), { recursive: true })
    copyFileSync(file.source, file.destination)
    if (file.executable && process.platform !== 'win32') {
      chmodSync(file.destination, 0o755)
    }
  }
}

export function stageNativeProducerPayloads(
  config: StageNativeProducerPayloadsConfig,
): void {
  const selected = selectNativeProducerArtifacts(
    config.artifacts.map(row => row.artifact),
  )
  extractNativeProducerParts(config, selected)
  aggregateFfiTemplateParts({
    partsDir: config.partsDirectory,
    producerSha: config.sourceSha,
    outDir: config.bundleDirectory,
    requireMacosSigning: true,
  })
  const staged = collectNativePackageFiles(config)
  assertNativePackageReceipt(config, staged)
  writeNativePackageFiles(staged)
}
