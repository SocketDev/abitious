import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { test } from 'vitest'
import { createZipArchive } from '../../../../../../scripts/fleet/artifact/zip.mts'

import {
  selectNativeProducerArtifacts,
  stageNativeProducerPayloads,
  validateNativePackageManifest,
  validateNativeProducerRun,
} from '../../../../../../scripts/repo/npm/native-validation.mts'
import { stageFfiTemplatePart } from '../../../../../../scripts/repo/ffi-templates.mts'
import { abiBin, TARGETS } from '../../../../../../scripts/repo/targets.mts'

const repoRoot = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../../..',
)
const sourceSha = 'a'.repeat(40)

function artifactFixture(
  root: string,
  mutate?: { target: string; path: string; value: string },
) {
  const partsDirectory = path.join(root, 'parts')
  mkdirSync(partsDirectory, { recursive: true })
  const artifacts = TARGETS.map((target, index) => {
    const sourcePackage = path.join(root, 'source', target.triple)
    mkdirSync(sourcePackage, { recursive: true })
    const manifest = JSON.parse(
      readFileSync(
        path.join(repoRoot, 'npm', target.triple, 'package.json'),
        'utf8',
      ),
    ) as { files: string[] }
    writeFileSync(
      path.join(sourcePackage, 'package.json'),
      JSON.stringify(manifest),
    )
    for (const name of manifest.files) {
      if (name.startsWith('templates/')) continue
      const file = path.join(sourcePackage, name)
      mkdirSync(path.dirname(file), { recursive: true })
      writeFileSync(file, `payload:${target.triple}:${name}`)
    }
    const templateFile = path.join(root, `${target.triple}.node`)
    writeFileSync(templateFile, `template:${target.triple}`)
    const partDirectory = path.join(
      partsDirectory,
      `abitious-ffi-source-${target.triple}`,
    )
    stageFfiTemplatePart(target.triple, {
      packageDir: sourcePackage,
      templateFile,
      producerSha: sourceSha,
      outDir: partDirectory,
    })
    if (target.os === 'darwin') {
      const files = [
        `package/${abiBin(target.os)}`,
        'package/bind.node',
        `package/${target.os === 'darwin' ? 'libabitious_decmpfs.dylib' : ''}`,
        'package/stub.node',
        'template/ffi-stub.node',
      ].toSorted()
      writeFileSync(
        path.join(partDirectory, 'macos-signing.json'),
        JSON.stringify({
          schemaVersion: 1,
          producerSha: sourceSha,
          target: target.triple,
          files: files.map(name => {
            const file = path.join(partDirectory, name)
            return {
              path: name,
              sha512: crypto
                .createHash('sha512')
                .update(readFileSync(file))
                .digest('hex'),
              submissionId: '11111111-1111-4111-8111-111111111111',
            }
          }),
        }),
      )
    }
    if (mutate?.target === target.triple) {
      writeFileSync(path.join(partDirectory, mutate.path), mutate.value)
    }
    const zipEntries: Array<{ name: string; data: Buffer }> = []
    function collect(directory: string): void {
      for (const name of readdirSync(directory)) {
        const file = path.join(directory, name)
        if (lstatSync(file).isDirectory()) collect(file)
        else {
          zipEntries.push({
            name: path.relative(partDirectory, file).split(path.sep).join('/'),
            data: readFileSync(file),
          })
        }
      }
    }
    collect(partDirectory)
    const bytes = createZipArchive(zipEntries)
    return {
      artifact: {
        id: index + 1,
        name: `abitious-ffi-source-${target.triple}`,
        digest: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
        expired: false,
      },
      bytes,
    }
  })
  return { artifacts, partsDirectory }
}

function producerRun() {
  return {
    id: 123,
    run_attempt: 2,
    status: 'completed',
    conclusion: 'success',
    event: 'workflow_dispatch',
    path: '.github/workflows/build-tier-1-native-packages.yml',
    head_sha: sourceSha,
    repository: { full_name: 'SocketDev/abitious' },
    head_repository: { full_name: 'SocketDev/abitious' },
    jobs: {
      jobs: [
        {
          name: 'Build (darwin-arm64)',
          conclusion: 'success',
          steps: [
            {
              name: 'Developer id sign and notarize darwin release files',
              conclusion: 'success',
            },
          ],
        },
        {
          name: 'Build (darwin-x64)',
          conclusion: 'success',
          steps: [
            {
              name: 'Developer id sign and notarize darwin release files',
              conclusion: 'success',
            },
          ],
        },
        { name: 'Aggregate complete producer bundles', conclusion: 'success' },
      ],
    },
  }
}

function artifacts() {
  return TARGETS.map((target, index) => ({
    id: index + 1,
    name: `abitious-ffi-source-${target.triple}`,
    digest: `sha256:${String(index).padStart(64, '0')}`,
    expired: false,
  }))
}

test('producer run binds repository, workflow, event, source, and signed aggregate', () => {
  const run = producerRun()
  assert.equal(
    validateNativeProducerRun(run, {
      repository: 'SocketDev/abitious',
      sourceSha,
      requireMacosSigning: true,
    }).id,
    123,
  )
  assert.throws(() =>
    validateNativeProducerRun(
      { ...run, head_sha: 'b'.repeat(40) },
      { repository: 'SocketDev/abitious', sourceSha },
    ),
  )
  assert.throws(() =>
    validateNativeProducerRun(
      { ...run, run_attempt: 0 },
      { repository: 'SocketDev/abitious', sourceSha },
    ),
  )
  assert.throws(() =>
    validateNativeProducerRun(
      { ...run, repository: { full_name: 'fork/abitious' } },
      { repository: 'SocketDev/abitious', sourceSha },
    ),
  )
  assert.throws(() =>
    validateNativeProducerRun(
      { ...run, path: '.github/workflows/other.yml' },
      { repository: 'SocketDev/abitious', sourceSha },
    ),
  )
  assert.throws(() =>
    validateNativeProducerRun(
      {
        ...run,
        jobs: {
          jobs: run.jobs.jobs.map(job =>
            job.name === 'Build (darwin-x64)' ? { ...job, steps: [] } : job,
          ),
        },
      },
      {
        repository: 'SocketDev/abitious',
        sourceSha,
        requireMacosSigning: true,
      },
    ),
  )
})

test('artifact selection requires one immutable live artifact per target', () => {
  const selected = selectNativeProducerArtifacts([
    ...artifacts(),
    {
      id: 99,
      name: 'abitious-ffi-producer-bundles',
      digest: `sha256:${'a'.repeat(64)}`,
      expired: false,
    },
  ])
  assert.deepEqual(
    selected.map(artifact => artifact.name),
    TARGETS.map(target => `abitious-ffi-source-${target.triple}`),
  )
  assert.throws(() => selectNativeProducerArtifacts(artifacts().slice(1)))
  assert.throws(() =>
    selectNativeProducerArtifacts([...artifacts(), artifacts()[0]!]),
  )
  assert.throws(() =>
    selectNativeProducerArtifacts(
      artifacts().map((artifact, index) =>
        index === 0 ? { ...artifact, expired: true } : artifact,
      ),
    ),
  )
  assert.throws(() =>
    selectNativeProducerArtifacts(
      artifacts().map((artifact, index) =>
        index === 0 ? { ...artifact, digest: 'sha256:bad' } : artifact,
      ),
    ),
  )
})

test('platform manifests match checked-in target name and version', () => {
  const manifest = JSON.parse(
    readFileSync(path.join(repoRoot, 'npm/linux-x64-gnu/package.json'), 'utf8'),
  ) as unknown
  const expectedVersion = (manifest as Record<string, unknown>)[
    'version'
  ] as string
  assert.equal(
    validateNativePackageManifest(manifest, 'linux-x64-gnu', expectedVersion)[
      'name'
    ],
    '@abitious/linux-x64-gnu',
  )
  assert.throws(() =>
    validateNativePackageManifest(manifest, 'linux-arm64-gnu', expectedVersion),
  )
  assert.throws(() =>
    validateNativePackageManifest(
      manifest,
      'linux-x64-gnu',
      `${expectedVersion}-mismatch`,
    ),
  )
})

test('unsafe archive paths do not change any native package target', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'native-stage-'))
  const packageRoot = path.join(root, 'npm')
  const sentinel = path.join(packageRoot, 'linux-x64-gnu', 'sentinel')
  await mkdir(path.dirname(sentinel), { recursive: true })
  await writeFile(sentinel, 'preserve')
  const unsafe = createZipArchive([
    { name: '../escape', data: Buffer.from('payload') },
  ])
  const safe = createZipArchive([
    { name: 'part.json', data: Buffer.from('{}') },
  ])
  const artifacts = TARGETS.map((target, index) => {
    const bytes = index === 0 ? unsafe : safe
    return {
      artifact: {
        id: index + 1,
        name: `abitious-ffi-source-${target.triple}`,
        digest: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
        expired: false,
      },
      bytes,
    }
  })
  try {
    assert.throws(() =>
      stageNativeProducerPayloads({
        artifacts,
        partsDirectory: path.join(root, 'parts'),
        bundleDirectory: path.join(root, 'bundles'),
        packageRoot,
        sourceSha,
        expectedVersion: JSON.parse(
          readFileSync(path.join(repoRoot, 'npm/cli/package.json'), 'utf8'),
        ).version as string,
      }),
    )
    assert.equal(await readFile(sentinel, 'utf8'), 'preserve')
    assert.equal(
      await readFile(path.join(root, 'escape'), 'utf8').catch(() => ''),
      '',
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('all signed producer parts stage only after complete package validation', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'native-stage-valid-'))
  const packageRoot = path.join(root, 'npm')
  const { artifacts } = artifactFixture(root)
  const expectedVersion = (
    JSON.parse(
      readFileSync(path.join(repoRoot, 'npm/cli/package.json'), 'utf8'),
    ) as { version: string }
  ).version
  try {
    stageNativeProducerPayloads({
      artifacts,
      partsDirectory: path.join(root, 'downloaded-parts'),
      bundleDirectory: path.join(root, 'bundles'),
      packageRoot,
      sourceSha,
      expectedVersion,
    })
    for (const target of TARGETS) {
      assert.ok(
        readFileSync(path.join(packageRoot, target.triple, abiBin(target.os)))
          .length > 0,
      )
      assert.equal(
        await readFile(
          path.join(packageRoot, target.triple, 'package.json'),
          'utf8',
        ).catch(() => ''),
        '',
      )
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('a late package version mismatch leaves every target unchanged', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'native-stage-invalid-'))
  const packageRoot = path.join(root, 'npm')
  const sentinel = path.join(packageRoot, 'darwin-arm64', 'sentinel')
  await mkdir(path.dirname(sentinel), { recursive: true })
  await writeFile(sentinel, 'preserve')
  const invalidManifest = JSON.parse(
    readFileSync(
      path.join(repoRoot, 'npm/win32-arm64-msvc/package.json'),
      'utf8',
    ),
  ) as { version: string }
  invalidManifest.version = '9.9.9'
  const { artifacts } = artifactFixture(root, {
    target: 'win32-arm64-msvc',
    path: 'package/package.json',
    value: JSON.stringify(invalidManifest),
  })
  const expectedVersion = (
    JSON.parse(
      readFileSync(path.join(repoRoot, 'npm/cli/package.json'), 'utf8'),
    ) as { version: string }
  ).version
  try {
    assert.throws(() =>
      stageNativeProducerPayloads({
        artifacts,
        partsDirectory: path.join(root, 'downloaded-parts'),
        bundleDirectory: path.join(root, 'bundles'),
        packageRoot,
        sourceSha,
        expectedVersion,
      }),
    )
    assert.equal(await readFile(sentinel, 'utf8'), 'preserve')
    assert.equal(
      await readFile(
        path.join(packageRoot, 'darwin-arm64', 'abi'),
        'utf8',
      ).catch(() => ''),
      '',
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
