import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { test } from 'vitest'

import {
  downloadPinnedNativeProducerArtifacts,
  resolveNativeProducerArtifacts,
} from '../../../scripts/repo/npm/native-producer.mts'
import { TARGETS } from '../../../scripts/repo/targets.mts'

const repository = 'SocketDev/abitious'
const sourceSha = 'a'.repeat(40)
const workflowPath = '.github/workflows/build-tier-1-native-packages.yml'

function json(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value))
}

function producerRun(id = 77) {
  return {
    id,
    status: 'completed',
    conclusion: 'success',
    event: 'workflow_dispatch',
    path: workflowPath,
    head_sha: sourceSha,
    head_branch: 'main',
    run_attempt: 1,
    repository: { full_name: repository },
    head_repository: { full_name: repository },
  }
}

function producerJobs(signed = true) {
  return {
    total_count: 3,
    jobs: [
      ...['Build (darwin-arm64)', 'Build (darwin-x64)'].map(name => ({
        name,
        conclusion: 'success',
        steps: [
          ...(signed
            ? [
                {
                  name: 'Developer id sign and notarize darwin release files',
                  conclusion: 'success',
                },
              ]
            : []),
        ],
      })),
      { name: 'Aggregate complete producer bundles', conclusion: 'success' },
    ],
  }
}

function artifactRows(bytes = Buffer.from([1, 2, 3])) {
  const digest = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`
  return TARGETS.map((target, index) => ({
    id: index + 1,
    name: `abitious-ffi-source-${target.triple}`,
    digest,
    expired: false,
  }))
}

test('dispatch intent reconciles an ambiguous POST and resolves exact-source artifacts', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'native-producer-test-'))
  try {
    const receiptPath = path.join(root, 'dispatch.json')
    let runListings = 0
    let dispatches = 0
    const artifacts = artifactRows()
    const requests: string[] = []
    const request = async (
      endpoint: string,
      options?: { method?: 'GET' | 'POST'; input?: unknown },
    ): Promise<Buffer> => {
      requests.push(endpoint)
      if (options?.method === 'POST') {
        dispatches += 1
        assert.equal(
          endpoint,
          `repos/${repository}/actions/workflows/build-tier-1-native-packages.yml/dispatches`,
        )
        assert.deepEqual(options.input, {
          ref: 'main',
          inputs: { 'all-targets': true, 'source-sha': sourceSha },
          return_run_details: true,
        })
        throw new Error('connection closed after dispatch acceptance')
      }
      if (endpoint === `repos/${repository}`)
        return json({ default_branch: 'main' })
      if (endpoint.includes('/actions/workflows/')) {
        runListings += 1
        return json({
          total_count: runListings > 1 ? 1 : 0,
          workflow_runs: runListings > 1 ? [producerRun()] : [],
        })
      }
      if (endpoint === `repos/${repository}/actions/runs/77`)
        return json(producerRun())
      if (
        endpoint ===
        `repos/${repository}/actions/runs/77/jobs?per_page=100&page=1`
      )
        return json(producerJobs())
      if (
        endpoint ===
        `repos/${repository}/actions/runs/77/artifacts?per_page=100&page=1`
      ) {
        return json({ total_count: artifacts.length, artifacts })
      }
      const artifactId = Number(
        endpoint.match(/actions\/artifacts\/(\d+)$/u)?.[1],
      )
      if (artifactId) return json(artifacts[artifactId - 1])
      throw new Error(`Unexpected endpoint ${endpoint}`)
    }
    const result = await resolveNativeProducerArtifacts({
      repository,
      sourceSha,
      workflowPath,
      receiptPath,
      dependencies: {
        request,
        download: async (_endpoint, destination) => {
          mkdirSync(path.dirname(destination), { recursive: true })
          writeFileSync(destination, Buffer.from([1, 2, 3]))
        },
        sleep: async () => {},
        now: () => 1_000,
      },
    })
    assert.equal(result.run.id, 77)
    assert.equal(result.artifacts.length, 8)
    assert.deepEqual(
      result.artifacts.map(item => item.artifact.id),
      [1, 2, 3, 4, 5, 6, 7, 8],
    )
    assert.ok(
      result.artifacts.every(item => item.bytes.equals(Buffer.from([1, 2, 3]))),
    )
    assert.equal(dispatches, 1)
    const intent = JSON.parse(await readFile(receiptPath, 'utf8')) as {
      runId: number
      sourceSha: string
      dispatchAttempted: boolean
    }
    assert.equal(intent.runId, 77)
    assert.equal(intent.sourceSha, sourceSha)
    assert.equal(intent.dispatchAttempted, true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('does not reuse a successful run without signed macOS outputs', async () => {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'native-producer-unsigned-'),
  )
  try {
    let runListings = 0
    let dispatches = 0
    const archiveBytes = Buffer.from([4, 5, 6])
    const artifacts = artifactRows(archiveBytes)
    const unsignedRun = producerRun(44)
    const signedRun = producerRun(77)
    const request = async (
      endpoint: string,
      options?: { method?: 'GET' | 'POST'; input?: unknown },
    ): Promise<Buffer> => {
      if (options?.method === 'POST') {
        dispatches += 1
        return Buffer.alloc(0)
      }
      if (endpoint === `repos/${repository}`)
        return json({ default_branch: 'main' })
      if (endpoint.includes('/actions/workflows/')) {
        runListings += 1
        const workflowRuns =
          runListings === 1 ? [unsignedRun] : [signedRun, unsignedRun]
        return json({
          total_count: workflowRuns.length,
          workflow_runs: workflowRuns,
        })
      }
      if (endpoint === `repos/${repository}/actions/runs/44`)
        return json(unsignedRun)
      if (
        endpoint ===
        `repos/${repository}/actions/runs/44/jobs?per_page=100&page=1`
      )
        return json({ total_count: 3, jobs: producerJobs(false).jobs })
      if (endpoint === `repos/${repository}/actions/runs/77`)
        return json(signedRun)
      if (
        endpoint ===
        `repos/${repository}/actions/runs/77/jobs?per_page=100&page=1`
      )
        return json(producerJobs())
      if (
        endpoint ===
        `repos/${repository}/actions/runs/77/artifacts?per_page=100&page=1`
      )
        return json({ total_count: artifacts.length, artifacts })
      const artifactId = Number(
        endpoint.match(/actions\/artifacts\/(\d+)$/u)?.[1],
      )
      if (artifactId) return json(artifacts[artifactId - 1])
      throw new Error(`Unexpected endpoint ${endpoint}`)
    }
    const result = await resolveNativeProducerArtifacts({
      repository,
      sourceSha,
      workflowPath,
      receiptPath: path.join(root, 'dispatch.json'),
      dependencies: {
        request,
        download: async (_endpoint, destination) => {
          mkdirSync(path.dirname(destination), { recursive: true })
          writeFileSync(destination, archiveBytes)
        },
        sleep: async () => {},
        now: () => 1_000,
      },
    })
    assert.equal(result.run.id, 77)
    assert.equal(dispatches, 1)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('rejects ambiguous new runs after an accepted dispatch', async () => {
  const root = await mkdtemp(
    path.join(os.tmpdir(), 'native-producer-ambiguous-'),
  )
  try {
    let runListings = 0
    let dispatches = 0
    const request = async (
      endpoint: string,
      options?: { method?: 'GET' | 'POST'; input?: unknown },
    ): Promise<Buffer> => {
      if (options?.method === 'POST') {
        dispatches += 1
        throw new Error('connection closed after dispatch acceptance')
      }
      if (endpoint === `repos/${repository}`)
        return json({ default_branch: 'main' })
      if (endpoint.includes('/actions/workflows/')) {
        runListings += 1
        const workflowRuns =
          runListings === 1 ? [] : [producerRun(77), producerRun(78)]
        return json({
          total_count: workflowRuns.length,
          workflow_runs: workflowRuns,
        })
      }
      throw new Error(`Unexpected endpoint ${endpoint}`)
    }
    await assert.rejects(
      resolveNativeProducerArtifacts({
        repository,
        sourceSha,
        workflowPath,
        receiptPath: path.join(root, 'dispatch.json'),
        dependencies: {
          request,
          download: async () => {},
          sleep: async () => {},
          now: () => 1_000,
        },
      }),
      /multiple new exact-source run IDs/u,
    )
    assert.equal(dispatches, 1)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('receipt replay reads the exact attempt and rejects attempt drift after download', async () => {
  let runDetails = 0
  let downloads = 0
  const archiveBytes = Buffer.from([9])
  const artifacts = artifactRows(archiveBytes)
  const request = async (endpoint: string): Promise<Buffer> => {
    if (endpoint === `repos/${repository}`)
      return json({ default_branch: 'main' })
    if (endpoint === `repos/${repository}/actions/runs/77`) {
      runDetails += 1
      return json({
        ...producerRun(),
        run_attempt: runDetails === 1 ? 1 : 2,
      })
    }
    if (
      endpoint ===
      `repos/${repository}/actions/runs/77/jobs?per_page=100&page=1`
    )
      return json(producerJobs())
    if (
      endpoint ===
      `repos/${repository}/actions/runs/77/artifacts?per_page=100&page=1`
    )
      return json({ total_count: artifacts.length, artifacts })
    const artifactId = Number(
      endpoint.match(/actions\/artifacts\/(\d+)$/u)?.[1],
    )
    if (artifactId) return json(artifacts[artifactId - 1])
    throw new Error(`Unexpected endpoint ${endpoint}`)
  }
  await assert.rejects(
    downloadPinnedNativeProducerArtifacts({
      repository,
      sourceSha,
      runId: 77,
      runAttempt: 1,
      workflowPath,
      artifacts: artifacts.map(({ id, name, digest }) => ({
        id,
        name,
        digest,
      })),
      dependencies: {
        request,
        download: async (_endpoint, destination) => {
          downloads += 1
          mkdirSync(path.dirname(destination), { recursive: true })
          writeFileSync(destination, archiveBytes)
        },
        sleep: async () => {},
        now: () => 1_000,
      },
    }),
    /attempt changed while reading its receipt/u,
  )
  assert.equal(runDetails, 2)
  assert.equal(downloads, 8)
})

test('rejects a noncanonical workflow before making API requests', async () => {
  let requests = 0
  await assert.rejects(
    resolveNativeProducerArtifacts({
      repository,
      sourceSha,
      workflowPath: '.github/workflows/other.yml',
      receiptPath: '/tmp/unused-dispatch.json',
      dependencies: {
        request: async () => {
          requests += 1
          return json({})
        },
      },
    }),
  )
  assert.equal(requests, 0)
})
