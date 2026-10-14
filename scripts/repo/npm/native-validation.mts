import crypto from 'node:crypto'
import {
  copyFileSync,
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { extractZipArchive } from '../../fleet/artifact/zip.mts'
import { aggregateFfiTemplateParts } from '../ffi-templates.mts'
import {
  abiBin,
  BIND_NODE,
  ffiArtifact,
  FFI_STUB_NODE,
  STUB_NODE,
  TARGETS,
} from '../targets.mts'

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
  status: string
  conclusion: string | null
  event: string
  path: string
  head_sha: string
  repository: { full_name: string }
  head_repository: { full_name: string }
  jobs?: {
    jobs?: Array<{
      name?: string
      conclusion?: string
      steps?: Array<{ name?: string; conclusion?: string }>
    }>
  }
}

export interface NativeArtifact {
  id: number
  name: string
  digest: string
  expired: boolean
}

export function validateNativeProducerRun(
  value: unknown,
  expected: {
    repository: string
    sourceSha: string
    requireMacosSigning?: boolean
  },
): NativeWorkflowRun {
  const run = value as NativeWorkflowRun
  if (
    !run ||
    !/^[\w.-]+\/[\w.-]+$/u.test(expected.repository) ||
    !/^[a-f0-9]{40}$/u.test(expected.sourceSha) ||
    run.status !== 'completed' ||
    run.conclusion !== 'success' ||
    run.event !== 'workflow_dispatch' ||
    run.path !== PRODUCER_WORKFLOW ||
    run.head_sha !== expected.sourceSha ||
    run.repository?.full_name !== expected.repository ||
    run.head_repository?.full_name !== expected.repository ||
    !Number.isSafeInteger(run.id) ||
    run.id < 1
  ) {
    throw new Error(
      'Native producer run is not trusted. Where: GitHub Actions. Saw a failed or unrelated run; wanted a successful exact-source workflow dispatch. Fix: build the selected source SHA on the default branch.',
    )
  }
  if (expected.requireMacosSigning) {
    const aggregate = run.jobs?.jobs?.find(
      job => job.name === 'Aggregate complete producer bundles',
    )
    const darwinJobs = ['Build (darwin-arm64)', 'Build (darwin-x64)']
    const signed = darwinJobs.every(name => {
      const job = run.jobs?.jobs?.find(candidate => candidate.name === name)
      return (
        job?.conclusion === 'success' &&
        job.steps?.some(
          step =>
            step.name ===
              'Developer id sign and notarize darwin release files' &&
            step.conclusion === 'success',
        )
      )
    })
    if (aggregate?.conclusion !== 'success' || !signed) {
      throw new Error(
        'Native producer run lacks signed macOS templates. Where: Aggregate complete producer bundles. Saw no successful aggregate job; wanted the signed eight-target producer set. Fix: dispatch the qualified default-branch build.',
      )
    }
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
    if (EXPECTED_EXTRA_ARTIFACTS.has(artifact.name)) continue
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
  const files = manifest?.['files']
  if (
    !targetConfig ||
    !manifest ||
    manifest['name'] !== `@abitious/${target}` ||
    manifest['version'] !== expectedVersion ||
    checkoutManifest['version'] !== expectedVersion ||
    !Array.isArray(files) ||
    JSON.stringify(files.toSorted()) !==
      JSON.stringify((checkoutManifest['files'] as string[]).toSorted()) ||
    ![
      'LICENSE',
      'README.md',
      'THIRD-PARTY-NOTICES.md',
      abiBin(targetConfig?.os ?? ''),
      BIND_NODE,
      ffiArtifact(targetConfig?.os ?? ''),
      STUB_NODE,
      'templates/manifest.json',
      ...TARGETS.map(item => `templates/${item.triple}/${FFI_STUB_NODE}`),
    ].every(name => files.includes(name)) ||
    JSON.stringify(manifest['os']) !== JSON.stringify(checkoutManifest['os']) ||
    JSON.stringify(manifest['cpu']) !==
      JSON.stringify(checkoutManifest['cpu']) ||
    manifest['repository'] !== checkoutManifest['repository'] ||
    JSON.stringify(manifest['libc']) !==
      JSON.stringify(checkoutManifest['libc'])
  ) {
    throw new Error(
      `Native platform manifest does not match the checkout. Where: ${target}/package.json. Saw an unexpected name, version, or file list; wanted @abitious/${target}@${expectedVersion}. Fix: regenerate package manifests before publishing.`,
    )
  }
  return manifest
}

function assertSafeArtifactPath(name: string): void {
  const segments = name.replace(/\/$/u, '').split('/')
  if (
    !name ||
    name.startsWith('/') ||
    name.includes('\\') ||
    name.endsWith('//') ||
    segments.some(
      segment => segment === '' || segment === '.' || segment === '..',
    )
  ) {
    throw new Error(
      'Native artifact contains an unsafe path. Where: ZIP entry. Saw an absolute or traversing name; wanted a relative package file. Fix: rebuild and upload the artifact.',
    )
  }
}

function assertRegularZipEntries(
  archive: Buffer,
  entries: ReturnType<typeof extractZipArchive>,
): void {
  const names = new Set<string>()
  for (const entry of entries) {
    assertSafeArtifactPath(entry.name)
    if (names.has(entry.name)) {
      throw new Error(
        'Native artifact contains a duplicate path. Where: ZIP entry. Saw the same name twice; wanted unique files. Fix: rebuild and upload the artifact.',
      )
    }
    names.add(entry.name)
  }
  let eocdOffset = -1
  for (
    let cursor = archive.length - 22;
    cursor >= Math.max(0, archive.length - 65_558);
    cursor -= 1
  ) {
    if (archive.readUInt32LE(cursor) === 0x06054b50) {
      eocdOffset = cursor
      break
    }
  }
  if (eocdOffset < 0)
    throw new Error('Native artifact ZIP directory is incomplete.')
  let cursor = archive.readUInt32LE(eocdOffset + 16)
  for (const entry of entries) {
    if (
      cursor + 46 > archive.length ||
      archive.readUInt32LE(cursor) !== 0x02014b50
    ) {
      throw new Error('Native artifact ZIP directory is incomplete.')
    }
    const madeBy = archive.readUInt16LE(cursor + 4) >>> 8
    const mode = archive.readUInt32LE(cursor + 38) >>> 16
    const kind = mode & 0o170000
    const isDirectory = entry.name.endsWith('/')
    if (
      (isDirectory && kind !== 0 && kind !== 0o040000) ||
      (!isDirectory && madeBy === 3 && kind !== 0 && kind !== 0o100000)
    ) {
      throw new Error(
        'Native artifact contains a non-regular ZIP entry. Where: ZIP metadata. Saw a link or special file; wanted regular package files. Fix: rebuild and upload the artifact.',
      )
    }
    cursor +=
      46 +
      archive.readUInt16LE(cursor + 28) +
      archive.readUInt16LE(cursor + 30) +
      archive.readUInt16LE(cursor + 32)
  }
}

function digestSha256(bytes: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`
}

export function stageNativeProducerPayloads(config: {
  artifacts: readonly { artifact: NativeArtifact; bytes: Buffer }[]
  partsDirectory: string
  bundleDirectory: string
  packageRoot: string
  sourceSha: string
  expectedVersion: string
}): void {
  const selected = selectNativeProducerArtifacts(
    config.artifacts.map(row => row.artifact),
  )
  const byId = new Map(
    config.artifacts.map(row => [row.artifact.id, row.bytes]),
  )
  for (const artifact of selected) {
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
    for (const entry of entries) {
      if (entry.name.endsWith('/')) continue
      const output = path.join(partDir, entry.name)
      mkdirSync(path.dirname(output), { recursive: true })
      writeFileSync(output, entry.data, { flag: 'wx' })
    }
  }
  aggregateFfiTemplateParts({
    partsDir: config.partsDirectory,
    producerSha: config.sourceSha,
    outDir: config.bundleDirectory,
    requireMacosSigning: true,
  })

  const staged: Array<{
    source: string
    destination: string
    executable: boolean
  }> = []
  for (const target of TARGETS) {
    const packageDir = path.join(config.bundleDirectory, target.triple)
    const manifest = validateNativePackageManifest(
      JSON.parse(
        readFileSync(path.join(packageDir, 'package.json'), 'utf8'),
      ) as unknown,
      target.triple,
      config.expectedVersion,
    )
    const files = manifest['files'] as string[]
    for (const name of files) {
      if (name === 'package.json') continue
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
  for (const file of staged) {
    mkdirSync(path.dirname(file.destination), { recursive: true })
    copyFileSync(file.source, file.destination)
    if (file.executable && process.platform !== 'win32') {
      chmodSync(file.destination, 0o755)
    }
  }
}
