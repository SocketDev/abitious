import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'

import {
  downloadGithubDispatchApi,
  requestGithubDispatchApi,
} from '../../../../fleet/registry/github-dispatch.mts'
import {
  selectNativeProducerArtifacts,
  validateNativeProducerRun,
} from '../../native-validation.mts'
import type {
  NativeArtifact,
  NativeWorkflowRun,
} from '../../native-validation.mts'

export const PRODUCER_WORKFLOW =
  '.github/workflows/build-tier-1-native-packages.yml'
export const POLL_INTERVAL_MS = 5_000
export const DEADLINE_MS = 60 * 60 * 1000
const MAX_RUN_PAGES = 10
const MAX_ARTIFACT_PAGES = 5
const MAX_JOBS_PAGES = 10
const MAX_ARTIFACT_BYTES = 268_435_456
const MAX_TOTAL_ARTIFACT_BYTES = 536_870_912

export interface ResolvedNativeProducerArtifact {
  artifact: NativeArtifact
  bytes: Buffer
}

export interface NativeProducerDependencies {
  request: (
    endpoint: string,
    options?: { method?: 'GET' | 'POST'; input?: unknown; deadlineMs?: number },
  ) => Promise<Buffer>
  download: (
    endpoint: string,
    destination: string,
    maxBytes: number,
  ) => Promise<void>
  sleep: (milliseconds: number) => Promise<void>
  now: () => number
}

export interface ResolveNativeProducerConfig {
  repository: string
  sourceSha: string
  workflowPath: string
  receiptPath: string
  dependencies?: Partial<NativeProducerDependencies>
}

export interface DownloadPinnedNativeProducerArtifactsConfig {
  repository: string
  sourceSha: string
  runId: number
  runAttempt: number
  workflowPath: string
  artifacts: readonly Pick<NativeArtifact, 'id' | 'name' | 'digest'>[]
  dependencies?: Partial<NativeProducerDependencies>
}

interface WorkflowListing {
  workflow_runs: ProducerRun[]
  total_count: number
}

export interface NativeProducerRun extends NativeWorkflowRun {
  head_branch?: string
  run_attempt: number
}

type ProducerRun = NativeProducerRun

interface ArtifactListing {
  artifacts: NativeArtifact[]
  total_count: number
}

interface JobsListing {
  jobs: NonNullable<NonNullable<NativeWorkflowRun['jobs']>['jobs']>
  total_count: number
}

export interface DispatchIntent {
  version: 1
  repository: string
  sourceSha: string
  workflowPath: string
  defaultBranch: string
  baselineRunIds: number[]
  dispatchAttempted: boolean
  runId?: number
  runAttempt?: number
}

export const defaultDependencies: NativeProducerDependencies = {
  request: requestGithubDispatchApi,
  download: downloadGithubDispatchApi,
  sleep: async milliseconds =>
    await new Promise(resolve => setTimeout(resolve, milliseconds)),
  now: Date.now,
}

export function githubJson<T>(bytes: Buffer): T {
  return JSON.parse(bytes.toString('utf8')) as T
}

function checkedPageCount(
  totalCount: number,
  pageSize: number,
  maxPages: number,
): number {
  if (!Number.isSafeInteger(totalCount) || totalCount < 0) {
    throw new Error(
      'GitHub listing count is invalid. Where: Actions API. Saw an invalid count; wanted bounded pagination. Fix: inspect the workflow listing.',
    )
  }
  const pages = Math.max(1, Math.ceil(totalCount / pageSize))
  if (pages > maxPages) {
    throw new Error(
      'GitHub listing exceeds its page limit. Where: Actions API. Saw too many results; wanted a bounded producer lookup. Fix: narrow the source SHA or clean up workflow history.',
    )
  }
  return pages
}

export async function listWorkflowRuns(
  request: NativeProducerDependencies['request'],
  repository: string,
  workflowPath: string,
  sourceSha: string,
  deadlineMs?: number,
): Promise<ProducerRun[]> {
  const rows: ProducerRun[] = []
  let pages = 1
  let totalCount = 0
  for (let page = 1; page <= pages; page += 1) {
    const endpoint = `repos/${repository}/actions/workflows/${encodeURIComponent(path.posix.basename(workflowPath))}/runs?head_sha=${sourceSha}&event=workflow_dispatch&per_page=100&page=${page}`
    const listing = githubJson<WorkflowListing>(
      await request(
        endpoint,
        deadlineMs === undefined ? undefined : { deadlineMs },
      ),
    )
    if (!Array.isArray(listing.workflow_runs)) {
      throw new Error(
        'GitHub workflow listing is invalid. Where: Actions API. Saw no run array; wanted exact-source workflow runs. Fix: inspect the workflow response.',
      )
    }
    if (page === 1) {
      totalCount = listing.total_count
      pages = checkedPageCount(totalCount, 100, MAX_RUN_PAGES)
    }
    rows.push(...listing.workflow_runs)
    if (rows.length > 1_000) {
      throw new Error(
        'GitHub workflow listing is too large. Where: Actions API. Saw more than 1,000 runs; wanted bounded producer lookup. Fix: filter the workflow history.',
      )
    }
  }
  if (rows.length !== totalCount) {
    throw new Error(
      'GitHub workflow listing is incomplete. Where: Actions API. Saw fewer runs than reported; wanted a complete baseline. Fix: retry the producer lookup.',
    )
  }
  return rows
}

export function exactSourceRuns(
  runs: readonly ProducerRun[],
  sourceSha: string,
  defaultBranch: string,
): ProducerRun[] {
  return runs
    .filter(
      run =>
        run.head_sha === sourceSha &&
        run.head_branch === defaultBranch &&
        run.event === 'workflow_dispatch',
    )
    .toSorted((left, right) => right.id - left.id)
}

export function readIntent(receiptPath: string): DispatchIntent | undefined {
  if (!existsSync(receiptPath)) return undefined
  try {
    const value = JSON.parse(
      readFileSync(receiptPath, 'utf8'),
    ) as DispatchIntent
    if (
      value.version === 1 &&
      /^[\w.-]+\/[\w.-]+$/u.test(value.repository) &&
      /^[a-f0-9]{40}$/u.test(value.sourceSha) &&
      value.workflowPath === PRODUCER_WORKFLOW &&
      typeof value.defaultBranch === 'string' &&
      Array.isArray(value.baselineRunIds) &&
      value.baselineRunIds.every(id => Number.isSafeInteger(id) && id > 0) &&
      typeof value.dispatchAttempted === 'boolean' &&
      (value.runId === undefined ||
        (Number.isSafeInteger(value.runId) && value.runId > 0)) &&
      (value.runAttempt === undefined ||
        (Number.isSafeInteger(value.runAttempt) && value.runAttempt > 0))
    ) {
      return value
    }
  } catch (cause) {
    throw new Error(
      'Native producer intent is unreadable. Where: dispatch receipt. Saw invalid JSON; wanted a durable retry record. Fix: inspect the intent before dispatching again.',
      { cause },
    )
  }
  throw new Error(
    'Native producer intent is invalid. Where: dispatch receipt. Saw a malformed or incomplete retry record; wanted a durable source-bound intent. Fix: inspect the intent before dispatching again.',
  )
}

export function writeIntent(receiptPath: string, intent: DispatchIntent): void {
  const directory = path.dirname(receiptPath)
  const temporary = `${receiptPath}.${process.pid}.tmp`
  mkdirSync(directory, { recursive: true })
  writeFileSync(temporary, `${JSON.stringify(intent, null, 2)}\n`, {
    mode: 0o600,
  })
  const file = openSync(temporary, 'r')
  try {
    fsyncSync(file)
  } finally {
    closeSync(file)
  }
  renameSync(temporary, receiptPath)
  const directoryHandle = openSync(directory, 'r')
  try {
    fsyncSync(directoryHandle)
  } finally {
    closeSync(directoryHandle)
  }
}

export async function listJobs(
  request: NativeProducerDependencies['request'],
  repository: string,
  runId: number,
  deadlineMs: number,
): Promise<NonNullable<NativeWorkflowRun['jobs']>['jobs']> {
  const jobs: NonNullable<NonNullable<NativeWorkflowRun['jobs']>['jobs']> = []
  let pages = 1
  let totalCount = 0
  for (let page = 1; page <= pages; page += 1) {
    const listing = githubJson<JobsListing>(
      await request(
        `repos/${repository}/actions/runs/${runId}/jobs?per_page=100&page=${page}`,
        { deadlineMs },
      ),
    )
    if (!Array.isArray(listing.jobs)) {
      throw new Error(
        'GitHub job listing is invalid. Where: Actions API. Saw no job array; wanted every producer job. Fix: inspect the selected run.',
      )
    }
    if (page === 1) {
      totalCount = listing.total_count
      pages = checkedPageCount(totalCount, 100, MAX_JOBS_PAGES)
    }
    jobs.push(...listing.jobs)
  }
  if (jobs.length !== totalCount) {
    throw new Error(
      'GitHub job listing is incomplete. Where: Actions API. Saw fewer jobs than reported; wanted the complete producer run. Fix: retry the run lookup.',
    )
  }
  return jobs
}

export async function completedRun(
  request: NativeProducerDependencies['request'],
  repository: string,
  sourceSha: string,
  runId: number,
  defaultBranch: string,
  deadlineMs: number,
  now: NativeProducerDependencies['now'],
  sleep: NativeProducerDependencies['sleep'],
): Promise<NativeProducerRun> {
  while (now() < deadlineMs) {
    const run = githubJson<ProducerRun>(
      await request(`repos/${repository}/actions/runs/${runId}`, {
        deadlineMs,
      }),
    )
    if (
      run.id !== runId ||
      run.head_sha !== sourceSha ||
      typeof run.head_branch !== 'string' ||
      run.head_branch !== defaultBranch ||
      !Number.isSafeInteger(run.run_attempt) ||
      typeof run.run_attempt !== 'number' ||
      run.run_attempt < 1
    ) {
      throw new Error(
        'Native producer run source changed. Where: GitHub Actions. Saw a different branch or SHA; wanted the exact source on the default branch. Fix: dispatch the validated source SHA.',
      )
    }
    if (run.status === 'completed') {
      run.jobs = {
        jobs: (await listJobs(request, repository, runId, deadlineMs)) ?? [],
      }
      const validated = validateNativeProducerRun(run, {
        repository,
        sourceSha,
        requireMacosSigning: true,
      })
      return {
        ...validated,
        head_branch: run.head_branch,
        run_attempt: run.run_attempt,
      }
    }
    await sleep(Math.min(POLL_INTERVAL_MS, deadlineMs - now()))
  }
  throw new Error(
    'Native producer deadline expired. Where: GitHub Actions. Saw no completed run within one hour; wanted the validated producer artifacts. Fix: inspect the run and resume with the same dispatch receipt.',
  )
}

export async function isQualifiedCompletedRun(
  request: NativeProducerDependencies['request'],
  repository: string,
  sourceSha: string,
  candidate: ProducerRun,
  defaultBranch: string,
  deadlineMs: number,
): Promise<boolean> {
  const run = githubJson<ProducerRun>(
    await request(`repos/${repository}/actions/runs/${candidate.id}`, {
      deadlineMs,
    }),
  )
  if (
    run.status !== 'completed' ||
    run.conclusion !== 'success' ||
    run.head_sha !== sourceSha ||
    run.head_branch !== defaultBranch ||
    !Number.isSafeInteger(run.run_attempt) ||
    run.run_attempt < 1
  ) {
    return false
  }
  run.jobs = {
    jobs: (await listJobs(request, repository, candidate.id, deadlineMs)) ?? [],
  }
  try {
    validateNativeProducerRun(run, {
      repository,
      sourceSha,
      requireMacosSigning: true,
    })
    return true
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith(
        'Native producer run lacks signed macOS templates.',
      )
    ) {
      return false
    }
    throw error
  }
}

export async function listArtifacts(
  request: NativeProducerDependencies['request'],
  repository: string,
  runId: number,
  deadlineMs: number,
): Promise<NativeArtifact[]> {
  const artifacts: NativeArtifact[] = []
  let pages = 1
  let totalCount = 0
  for (let page = 1; page <= pages; page += 1) {
    const listing = githubJson<ArtifactListing>(
      await request(
        `repos/${repository}/actions/runs/${runId}/artifacts?per_page=100&page=${page}`,
        { deadlineMs },
      ),
    )
    if (!Array.isArray(listing.artifacts)) {
      throw new Error(
        'GitHub artifact listing is invalid. Where: Actions API. Saw no artifact array; wanted the complete producer set. Fix: inspect the selected run.',
      )
    }
    if (page === 1) {
      totalCount = listing.total_count
      pages = checkedPageCount(totalCount, 100, MAX_ARTIFACT_PAGES)
    }
    artifacts.push(...listing.artifacts)
  }
  if (artifacts.length !== totalCount) {
    throw new Error(
      'GitHub artifact listing is incomplete. Where: Actions API. Saw fewer artifacts than reported; wanted the complete producer set. Fix: retry the artifact lookup.',
    )
  }
  return selectNativeProducerArtifacts(artifacts)
}

export async function downloadArtifacts(
  request: NativeProducerDependencies['request'],
  download: NativeProducerDependencies['download'],
  repository: string,
  artifacts: readonly NativeArtifact[],
): Promise<ResolvedNativeProducerArtifact[]> {
  const scratch = mkdtempSync(
    path.join(os.tmpdir(), 'abitious-native-producer-'),
  )
  try {
    const result: ResolvedNativeProducerArtifact[] = []
    let totalBytes = 0
    for (const artifact of artifacts) {
      const metadata = githubJson<NativeArtifact>(
        await request(`repos/${repository}/actions/artifacts/${artifact.id}`),
      )
      if (
        metadata.id !== artifact.id ||
        metadata.name !== artifact.name ||
        metadata.digest !== artifact.digest ||
        metadata.expired !== false
      ) {
        throw new Error(
          'Native producer artifact identity changed. Where: GitHub artifact. Saw expired or different metadata; wanted the selected immutable identity. Fix: rerun the producer workflow.',
        )
      }
      const archivePath = path.join(scratch, `${artifact.id}.zip`)
      await download(
        `repos/${repository}/actions/artifacts/${artifact.id}/zip`,
        archivePath,
        MAX_ARTIFACT_BYTES,
      )
      const bytes = readFileSync(archivePath)
      totalBytes += bytes.length
      if (
        bytes.length > MAX_ARTIFACT_BYTES ||
        totalBytes > MAX_TOTAL_ARTIFACT_BYTES
      ) {
        throw new Error(
          'Native producer payload exceeds its total byte limit. Where: downloaded artifacts. Saw more than 512 MiB; wanted a bounded artifact set. Fix: reduce the producer payload.',
        )
      }
      const actualDigest = `sha256:${crypto
        .createHash('sha256')
        .update(bytes)
        .digest('hex')}`
      if (actualDigest !== artifact.digest) {
        throw new Error(
          'Native producer archive digest differs. Where: downloaded artifact. Saw unverified bytes; wanted the receipt SHA256. Fix: download the producer artifact again.',
        )
      }
      result.push({ artifact, bytes })
    }
    return result
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}
