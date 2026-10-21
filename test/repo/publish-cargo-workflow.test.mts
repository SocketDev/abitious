import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { test } from 'vitest'
import { parse } from 'yaml'

const repoRoot = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
)

async function readWorkflow(file: string) {
  const source = await readFile(path.join(repoRoot, file), 'utf8')
  return parse(source) as {
    jobs: Record<
      string,
      { steps: Array<{ uses?: string; with?: Record<string, string> }> }
    >
  }
}

test('Cargo workflows pass the credentials required by fleet setup', async () => {
  for (const file of [
    '.github/workflows/publish-cargo.yml',
    '.github/workflows/nightly-cargo.yml',
  ]) {
    const workflow = await readWorkflow(file)
    const setupSteps = Object.values(workflow.jobs)
      .flatMap(job => job.steps)
      .filter(step => step.uses?.endsWith('/setup-and-install'))

    assert.notEqual(setupSteps.length, 0, `${file} has fleet setup`)
    for (const step of setupSteps) {
      assert.equal(
        step.with?.['socket-api-token'],
        '${{ secrets.SOCKET_API_TOKEN_FOR_CLI_AND_SFW }}',
        `${file} passes the Socket API token`,
      )
      assert.equal(
        step.with?.['payload-token-client-id'],
        '${{ secrets.SOCKET_RELEASE_CLIENT_ID || vars.SOCKET_RELEASE_CLIENT_ID }}',
        `${file} passes the fleet payload token client ID`,
      )
      assert.equal(
        step.with?.['payload-token-private-key'],
        '${{ secrets.SOCKET_RELEASE_APP_PRIVATE_KEY }}',
        `${file} passes the fleet payload token private key`,
      )
    }
  }
})

test('Cargo provenance action is covered by the generated workflow lock', async () => {
  const lock = parse(
    await readFile(
      path.join(repoRoot, '.github/workflows/actions.lock'),
      'utf8',
    ),
  ) as {
    workflows: Record<string, string[]>
    dependencies: Record<
      string,
      { commit?: string; owner_id?: number; repo_id?: number }
    >
  }
  const workflowPath = '.github/workflows/publish-cargo.yml'
  const actionRef = 'actions/attest-build-provenance@v2.4.0'
  const lockedCommit = lock.dependencies[
    'actions/attest-build-provenance@v2.4.0'
  ]

  assert.ok(lock.workflows[workflowPath]?.includes(actionRef))
  assert.match(lockedCommit?.commit ?? '', /^sha1-[a-f\d]{40}$/u)
  assert.equal(lockedCommit?.owner_id, 44036562)
  assert.equal(lockedCommit?.repo_id, 760702757)
})
