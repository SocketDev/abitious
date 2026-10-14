import path from 'node:path'
import { selectNativeProducerArtifacts } from './native-validation.mts'
import {
  DEADLINE_MS,
  POLL_INTERVAL_MS,
  defaultDependencies,
  downloadArtifacts,
  exactSourceRuns,
  completedRun,
  githubJson,
  isQualifiedCompletedRun,
  listArtifacts,
  listWorkflowRuns,
  readIntent,
  writeIntent,
  PRODUCER_WORKFLOW,
} from './native/producer/github.mts'
import type {
  DownloadPinnedNativeProducerArtifactsConfig,
  DispatchIntent,
  NativeProducerRun,
  ResolveNativeProducerConfig,
  ResolvedNativeProducerArtifact,
} from './native/producer/github.mts'
export type {
  DownloadPinnedNativeProducerArtifactsConfig,
  NativeProducerDependencies,
  NativeProducerRun,
  ResolveNativeProducerConfig,
  ResolvedNativeProducerArtifact,
} from './native/producer/github.mts'

export async function resolveNativeProducerArtifacts(
  config: ResolveNativeProducerConfig,
): Promise<{
  run: NativeProducerRun
  artifacts: ResolvedNativeProducerArtifact[]
}> {
  const { repository, sourceSha, workflowPath, receiptPath } = config
  if (
    !/^[\w.-]+\/[\w.-]+$/u.test(repository) ||
    !/^[a-f0-9]{40}$/u.test(sourceSha) ||
    workflowPath !== PRODUCER_WORKFLOW ||
    !receiptPath
  ) {
    throw new Error(
      'Native producer request is invalid. Where: resolver input. Saw an invalid repository, SHA, workflow, or intent path; wanted the canonical producer request. Fix: supply the exact repository, source SHA, workflow path, and dispatch receipt path.',
    )
  }
  const dependencies = { ...defaultDependencies, ...config.dependencies }
  const deadlineMs = dependencies.now() + DEADLINE_MS
  const repositoryMetadata = githubJson<{ default_branch: string }>(
    await dependencies.request(`repos/${repository}`),
  )
  const defaultBranch = repositoryMetadata.default_branch
  if (
    !defaultBranch ||
    defaultBranch.includes('..') ||
    defaultBranch.startsWith('-')
  ) {
    throw new Error(
      'Repository default branch is invalid. Where: GitHub repository. Saw an unsafe branch name; wanted the canonical default branch. Fix: inspect repository metadata.',
    )
  }
  const priorIntent = readIntent(receiptPath)
  const matchingIntent =
    priorIntent?.repository === repository &&
    priorIntent.sourceSha === sourceSha &&
    priorIntent.workflowPath === workflowPath &&
    priorIntent.defaultBranch === defaultBranch
      ? priorIntent
      : undefined
  const initialRuns = await listWorkflowRuns(
    dependencies.request,
    repository,
    workflowPath,
    sourceSha,
    deadlineMs,
  )
  const exactRuns = exactSourceRuns(initialRuns, sourceSha, defaultBranch)
  const activeRuns = exactRuns.filter(run => run.status !== 'completed')
  const successfulCompletedRuns = exactRuns.filter(
    run => run.status === 'completed' && run.conclusion === 'success',
  )
  const qualifiedCompletedRuns: NativeProducerRun[] = []
  for (const candidate of successfulCompletedRuns) {
    if (
      await isQualifiedCompletedRun(
        dependencies.request,
        repository,
        sourceSha,
        candidate,
        defaultBranch,
        deadlineMs,
      )
    ) {
      qualifiedCompletedRuns.push(candidate)
    }
  }
  const eligibleRuns = [...activeRuns, ...qualifiedCompletedRuns].toSorted(
    (left, right) => right.id - left.id,
  )
  if (
    eligibleRuns.length > 1 &&
    !eligibleRuns.some(run => run.id === matchingIntent?.runId)
  ) {
    throw new Error(
      'Native producer has multiple eligible runs for this source. Where: GitHub Actions. Saw duplicate exact-source attempts; wanted one unambiguous producer run. Fix: inspect the attempts and resume with a run-bound intent.',
    )
  }
  const pinnedRun = exactRuns.find(run => run.id === matchingIntent?.runId)
  const pinnedRunIsUnqualifiedComplete = Boolean(
    matchingIntent?.runId &&
    pinnedRun?.status === 'completed' &&
    !qualifiedCompletedRuns.some(run => run.id === pinnedRun.id),
  )
  let runId = pinnedRunIsUnqualifiedComplete ? undefined : matchingIntent?.runId
  let expectedRunAttempt = pinnedRunIsUnqualifiedComplete
    ? undefined
    : matchingIntent?.runAttempt
  let dispatchAttempted = pinnedRunIsUnqualifiedComplete
    ? false
    : (matchingIntent?.dispatchAttempted ?? false)
  let baselineRunIds = pinnedRunIsUnqualifiedComplete
    ? [
        ...new Set([
          ...(matchingIntent?.baselineRunIds ?? []),
          ...exactRuns.map(run => run.id),
        ]),
      ]
    : (matchingIntent?.baselineRunIds ?? exactRuns.map(run => run.id))
  const reusableRun = eligibleRuns[0]
  if (!runId && reusableRun && !dispatchAttempted) {
    runId = reusableRun.id
    expectedRunAttempt = reusableRun.run_attempt
    writeIntent(receiptPath, {
      version: 1,
      repository,
      sourceSha,
      workflowPath,
      defaultBranch,
      baselineRunIds,
      dispatchAttempted: false,
      runId,
      ...(Number.isSafeInteger(reusableRun.run_attempt) &&
      reusableRun.run_attempt > 0
        ? { runAttempt: reusableRun.run_attempt }
        : {}),
    })
  }
  if (!runId && !dispatchAttempted && !reusableRun) {
    const intent: DispatchIntent = {
      version: 1,
      repository,
      sourceSha,
      workflowPath,
      defaultBranch,
      baselineRunIds,
      dispatchAttempted: true,
    }
    dispatchAttempted = true
    writeIntent(receiptPath, intent)
    try {
      const response = await dependencies.request(
        `repos/${repository}/actions/workflows/${encodeURIComponent(path.posix.basename(workflowPath))}/dispatches`,
        {
          method: 'POST',
          input: {
            ref: defaultBranch,
            inputs: { 'all-targets': true, 'source-sha': sourceSha },
            return_run_details: true,
          },
        },
      )
      if (response.length) {
        const dispatched = githubJson<{
          workflow_run_id?: number
          run_id?: number
          id?: number
        }>(response)
        runId = dispatched.workflow_run_id ?? dispatched.run_id ?? dispatched.id
        if (
          runId !== undefined &&
          (!Number.isSafeInteger(runId) || runId < 1)
        ) {
          throw new Error('GitHub dispatch returned an invalid run ID.')
        }
      }
    } catch {
      // Reconcile against the baseline below; an accepted POST may have lost its response.
    }
  }
  if (!runId) {
    while (dependencies.now() < deadlineMs) {
      const runs = await listWorkflowRuns(
        dependencies.request,
        repository,
        workflowPath,
        sourceSha,
        deadlineMs,
      )
      const newRuns = exactSourceRuns(runs, sourceSha, defaultBranch).filter(
        run => !baselineRunIds.includes(run.id),
      )
      if (newRuns.length > 1) {
        throw new Error(
          'Native producer dispatch is ambiguous. Where: GitHub Actions. Saw multiple new exact-source run IDs; wanted one run for this intent. Fix: inspect the duplicate runs before retrying.',
        )
      }
      const candidate = newRuns[0]
      if (candidate) {
        runId = candidate.id
        expectedRunAttempt = candidate.run_attempt
        const intent: DispatchIntent = {
          version: 1,
          repository,
          sourceSha,
          workflowPath,
          defaultBranch,
          baselineRunIds,
          dispatchAttempted: true,
          runId,
          ...(Number.isSafeInteger(candidate.run_attempt) &&
          candidate.run_attempt > 0
            ? { runAttempt: candidate.run_attempt }
            : {}),
        }
        writeIntent(receiptPath, intent)
        break
      }
      await dependencies.sleep(
        Math.min(POLL_INTERVAL_MS, deadlineMs - dependencies.now()),
      )
    }
  }
  if (!runId) {
    throw new Error(
      'Native producer dispatch could not be reconciled. Where: GitHub Actions. Saw no new exact-source run after the dispatch attempt; wanted one run tied to the durable intent. Fix: inspect GitHub Actions and resume with the same intent receipt.',
    )
  }
  const run = await completedRun(
    dependencies.request,
    repository,
    sourceSha,
    runId,
    defaultBranch,
    deadlineMs,
    dependencies.now,
    dependencies.sleep,
  )
  if (
    expectedRunAttempt !== undefined &&
    expectedRunAttempt !== run.run_attempt
  ) {
    throw new Error(
      'Native producer intent attempt changed. Where: dispatch receipt. Saw a different GitHub attempt; wanted the durably selected attempt. Fix: inspect the run before resolving artifacts again.',
    )
  }
  writeIntent(receiptPath, {
    version: 1,
    repository,
    sourceSha,
    workflowPath,
    defaultBranch,
    baselineRunIds,
    dispatchAttempted,
    runId: run.id,
    runAttempt: run.run_attempt,
  })
  const artifacts = await listArtifacts(
    dependencies.request,
    repository,
    run.id,
    deadlineMs,
  )
  const resolved = await downloadArtifacts(
    dependencies.request,
    dependencies.download,
    repository,
    artifacts,
  )
  const refreshed = githubJson<NativeProducerRun>(
    await dependencies.request(`repos/${repository}/actions/runs/${run.id}`, {
      deadlineMs,
    }),
  )
  if (
    refreshed.id !== run.id ||
    refreshed.run_attempt !== run.run_attempt ||
    refreshed.status !== 'completed' ||
    refreshed.conclusion !== 'success' ||
    refreshed.head_sha !== sourceSha ||
    refreshed.head_branch !== defaultBranch
  ) {
    throw new Error(
      'Native producer attempt changed while downloading artifacts. Where: GitHub Actions. Saw a different or incomplete attempt; wanted stable run-bound artifacts. Fix: resolve the completed producer again.',
    )
  }
  writeIntent(receiptPath, {
    version: 1,
    repository,
    sourceSha,
    workflowPath,
    defaultBranch,
    baselineRunIds,
    dispatchAttempted,
    runId: run.id,
    runAttempt: run.run_attempt,
  })
  return { run, artifacts: resolved }
}

export async function downloadPinnedNativeProducerArtifacts(
  config: DownloadPinnedNativeProducerArtifactsConfig,
): Promise<{
  run: NativeProducerRun
  artifacts: ResolvedNativeProducerArtifact[]
}> {
  const {
    repository,
    sourceSha,
    runId,
    runAttempt,
    workflowPath,
    artifacts: receiptArtifacts,
  } = config
  if (
    !/^[\w.-]+\/[\w.-]+$/u.test(repository) ||
    !/^[a-f0-9]{40}$/u.test(sourceSha) ||
    workflowPath !== PRODUCER_WORKFLOW ||
    !Number.isSafeInteger(runId) ||
    runId < 1 ||
    !Number.isSafeInteger(runAttempt) ||
    runAttempt < 1 ||
    receiptArtifacts.length !== 8
  ) {
    throw new Error(
      'Native producer receipt is invalid. Where: scan receipt. Saw an invalid source, run, attempt, or artifact list; wanted one exact signed producer run. Fix: inspect the retained receipt.',
    )
  }
  const dependencies = { ...defaultDependencies, ...config.dependencies }
  const deadlineMs = dependencies.now() + DEADLINE_MS
  const expectedArtifacts = selectNativeProducerArtifacts(
    receiptArtifacts.map(artifact => ({ ...artifact, expired: false })),
  )
  const repositoryMetadata = githubJson<{ default_branch: string }>(
    await dependencies.request(`repos/${repository}`),
  )
  const defaultBranch = repositoryMetadata.default_branch
  if (!defaultBranch) {
    throw new Error(
      'Repository default branch is invalid. Where: GitHub repository. Saw no default branch; wanted the branch used by the signed producer. Fix: inspect repository metadata.',
    )
  }
  const run = await completedRun(
    dependencies.request,
    repository,
    sourceSha,
    runId,
    defaultBranch,
    deadlineMs,
    dependencies.now,
    dependencies.sleep,
  )
  if (run.run_attempt !== runAttempt) {
    throw new Error(
      'Native producer receipt attempt differs. Where: scan receipt. Saw a different GitHub attempt; wanted the recorded producer attempt. Fix: retrieve the source-bound receipt again.',
    )
  }
  const listedArtifacts = await listArtifacts(
    dependencies.request,
    repository,
    runId,
    deadlineMs,
  )
  if (
    expectedArtifacts.some((expected, index) => {
      const actual = listedArtifacts[index]
      return (
        actual?.id !== expected.id ||
        actual.name !== expected.name ||
        actual.digest !== expected.digest
      )
    })
  ) {
    throw new Error(
      'Native producer receipt artifact set differs. Where: GitHub Actions. Saw an artifact ID, name, or digest change; wanted the exact recorded producer set. Fix: retrieve the source-bound receipt again.',
    )
  }
  const resolved = await downloadArtifacts(
    dependencies.request,
    dependencies.download,
    repository,
    listedArtifacts,
  )
  const refreshed = githubJson<NativeProducerRun>(
    await dependencies.request(`repos/${repository}/actions/runs/${runId}`, {
      deadlineMs,
    }),
  )
  if (
    refreshed.id !== runId ||
    refreshed.run_attempt !== runAttempt ||
    refreshed.status !== 'completed' ||
    refreshed.conclusion !== 'success' ||
    refreshed.path !== workflowPath ||
    refreshed.event !== 'workflow_dispatch' ||
    refreshed.head_sha !== sourceSha ||
    refreshed.head_branch !== defaultBranch ||
    refreshed.repository?.full_name !== repository ||
    refreshed.head_repository?.full_name !== repository
  ) {
    throw new Error(
      'Native producer attempt changed while reading its receipt. Where: GitHub Actions. Saw a different or incomplete attempt; wanted stable run-bound artifacts. Fix: retrieve the source-bound receipt again.',
    )
  }
  return { run, artifacts: resolved }
}
