import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'

import { isPlainObject } from '@socketsecurity/lib-stable/objects/predicates'

export const PRODUCER_WORKFLOW =
  '.github/workflows/build-tier-1-native-packages.yml'

export interface DispatchIntent {
  version: 1
  repository: string
  sourceSha: string
  workflowPath: string
  defaultBranch: string
  baselineRunIds: number[]
  dispatchAttempted: boolean
  runId?: number | undefined
  runAttempt?: number | undefined
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

function hasIntentSource(value: Record<string, unknown>): boolean {
  return (
    value['version'] === 1 &&
    typeof value['repository'] === 'string' &&
    /^[\w.-]+\/[\w.-]+$/u.test(value['repository']) &&
    typeof value['sourceSha'] === 'string' &&
    /^[a-f0-9]{40}$/u.test(value['sourceSha']) &&
    value['workflowPath'] === PRODUCER_WORKFLOW &&
    typeof value['defaultBranch'] === 'string'
  )
}

function isDispatchIntent(value: unknown): value is DispatchIntent {
  if (!isPlainObject(value) || !hasIntentSource(value)) {
    return false
  }
  const baselineRunIds = value['baselineRunIds']
  return (
    Array.isArray(baselineRunIds) &&
    baselineRunIds.every(isPositiveInteger) &&
    typeof value['dispatchAttempted'] === 'boolean' &&
    (value['runId'] === undefined || isPositiveInteger(value['runId'])) &&
    (value['runAttempt'] === undefined ||
      isPositiveInteger(value['runAttempt']))
  )
}

export function readIntent(receiptPath: string): DispatchIntent | undefined {
  if (!existsSync(receiptPath)) {
    return undefined
  }
  try {
    const value: unknown = JSON.parse(readFileSync(receiptPath, 'utf8'))
    if (isDispatchIntent(value)) {
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
  const file = openSync(temporary, 'r+')
  try {
    fsyncSync(file)
  } finally {
    closeSync(file)
  }
  renameSync(temporary, receiptPath)
  if (process.platform !== 'win32') {
    const directoryHandle = openSync(directory, 'r')
    try {
      fsyncSync(directoryHandle)
    } finally {
      closeSync(directoryHandle)
    }
  }
}
