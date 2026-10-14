import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'

import { test } from 'vitest'

const repoRoot = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../../../',
)

test('npm publish prepares signed native packages with a scoped producer token', async () => {
  const workflow = parse(
    await readFile(
      path.join(repoRoot, '.github/workflows/publish-npm.yml'),
      'utf8',
    ),
  ) as {
    jobs: {
      'npm-publish': {
        steps: Array<{
          name?: string
          id?: string
          if?: string
          env?: Record<string, string>
          run?: string
          with?: Record<string, string>
        }>
      }
      'scan-staged-package': {
        steps: Array<{
          name?: string
          id?: string
          env?: Record<string, string>
          run?: string
        }>
      }
    }
  }
  const steps = workflow.jobs['npm-publish'].steps
  const mint = steps.find(step => step.name === 'Mint native producer token')
  const prepare = steps.find(
    step => step.name === 'Prepare exact-source signed native packages',
  )
  const receipt = steps.find(
    step => step.name === 'Retain signed native package receipt',
  )

  assert.ok(mint)
  assert.equal(mint.id, 'native-producer-app')
  assert.equal(
    mint.if,
    "${{ inputs.resume-publish == true && steps.content-trust.outputs.trusted == 'true' }}",
  )
  assert.equal(
    mint.env?.['PERMISSIONS'],
    '{"actions":"write","contents":"read"}',
  )
  assert.match(mint.run ?? '', /mint-app-installation-token\.mjs/u)
  assert.ok(prepare)
  assert.equal(prepare.if, '${{ inputs.resume-publish == true }}')
  assert.equal(
    prepare.env?.['GH_TOKEN'],
    '${{ steps.native-producer-app.outputs.token }}',
  )
  assert.equal(prepare.env?.['GITHUB_SHA'], '${{ github.sha }}')
  assert.equal(prepare.run, 'pnpm run npm:prepare-native')
  assert.ok(receipt)
  assert.equal(receipt.if, '${{ inputs.resume-publish == true }}')
  assert.equal(receipt.with?.['path'], '.cache/fleet/npm-native/receipt.json')
  assert.ok(steps.indexOf(prepare) < steps.indexOf(receipt))
  assert.ok(
    steps.indexOf(receipt) <
      steps.findIndex(
        step => step.name === 'Validate repository publish contract',
      ),
  )

  const packageJson = JSON.parse(
    await readFile(path.join(repoRoot, 'package.json'), 'utf8'),
  ) as { scripts: Record<string, string> }
  assert.equal(
    packageJson.scripts['npm:prepare-native'],
    'node scripts/repo/npm/prepare-native.mts',
  )
  assert.equal(
    packageJson.scripts['build:publish'],
    'node scripts/repo/npm/restore-native.mts --verify-local',
  )

  const wheelhouse = JSON.parse(
    await readFile(
      path.join(repoRoot, '.config/repo/socket-wheelhouse.json'),
      'utf8',
    ),
  ) as { release?: Record<string, unknown> }
  assert.equal(wheelhouse.release?.['artifactWorkflow'], undefined)
  assert.equal(
    wheelhouse.release?.['githubAssetWorkflow'],
    'build-tier-1-native-packages.yml',
  )

  const nativeWorkflow = parse(
    await readFile(
      path.join(repoRoot, '.github/workflows/build-tier-1-native-packages.yml'),
      'utf8',
    ),
  ) as {
    jobs: {
      build: {
        steps: Array<{ name?: string; if?: string }>
      }
      prepare: {
        steps: Array<{
          name?: string
          env?: Record<string, string>
          run?: string
        }>
      }
      aggregate: {
        steps: Array<{
          name?: string
          env?: Record<string, string>
          run?: string
        }>
      }
    }
    on: {
      workflow_dispatch: {
        inputs: Record<string, unknown>
      }
    }
  }
  assert.ok(nativeWorkflow.on.workflow_dispatch.inputs['source-sha'])
  const sign = nativeWorkflow.jobs.build.steps.find(
    step => step.name === 'Developer id sign and notarize darwin release files',
  )
  assert.ok(sign)
  assert.match(sign.if ?? '', /inputs\.all-targets/u)
  assert.match(sign.if ?? '', /inputs\.source-sha == github\.sha/u)
  assert.match(sign.if ?? '', /github\.event\.repository\.default_branch/u)
  const matrix = nativeWorkflow.jobs.prepare.steps.find(
    step => step.name === 'Derive the tier-1 matrix from targets.mts',
  )
  assert.ok(matrix)
  assert.equal(
    matrix.env?.['APPLE_DEVELOPER_ID_APPLICATION_CERTS_P12'],
    '${{ secrets.APPLE_DEVELOPER_ID_APPLICATION_CERTS_P12 }}',
  )
  assert.match(matrix.run ?? '', /MacOS signing cannot start/u)
  const credentialGuard = spawnSync(
    'bash',
    ['-euo', 'pipefail', '-c', matrix.run ?? ''],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        APPLE_APP_SPECIFIC_PASSWORD: '',
        APPLE_DEVELOPER_ID_APPLICATION_CERTS_P12: '',
        APPLE_DEVELOPER_ID_APPLICATION_CERTS_P12_PASS: '',
        APPLE_ID: '',
        APPLE_TEAM_ID: '',
        ALL_TARGETS: 'true',
        DEFAULT_BRANCH: 'main',
        EVENT_NAME: 'workflow_dispatch',
        GITHUB_OUTPUT: '/dev/null',
        REF: 'refs/heads/main',
        SOURCE_SHA_INPUT: 'a'.repeat(40),
        WORKFLOW_SHA: 'a'.repeat(40),
      },
    },
  )
  assert.equal(credentialGuard.status, 1, credentialGuard.stderr)
  assert.match(credentialGuard.stderr, /MacOS signing cannot start/u)
  const aggregate = nativeWorkflow.jobs.aggregate.steps.find(
    step => step.name === 'Verify and assemble platform producer bundles',
  )
  assert.ok(aggregate)
  assert.equal(aggregate.env?.['SOURCE_SHA_INPUT'], '${{ inputs.source-sha }}')
  assert.match(aggregate.run ?? '', /--require-macos-signing/u)

  const scanSteps = workflow.jobs['scan-staged-package'].steps
  const restore = scanSteps.find(
    step => step.name === 'Restore exact signed native package receipt',
  )
  const scan = scanSteps.find(step => step.name === 'Scan exact staged bytes')
  assert.ok(restore)
  assert.equal(restore.id, 'restore-native')
  assert.equal(restore.env?.['GH_TOKEN'], '${{ github.token }}')
  assert.equal(
    restore.env?.['SCAN_SOURCE_SHA'],
    '${{ inputs.scan-source-sha }}',
  )
  assert.equal(restore.run, 'node scripts/repo/npm/restore-native.mts')
  assert.ok(scan)
  assert.equal(
    scan.env?.['NATIVE_PUBLISH_RUN_ATTEMPT'],
    '${{ steps.restore-native.outputs.publish-run-attempt }}',
  )
})
