import assert from 'node:assert/strict'
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'

import { test } from 'vitest'

const repoRoot = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
)
const workflowPath = path.join(
  repoRoot,
  '.github/workflows/build-tier-1-native-packages.yml',
)
const alpineImage =
  'node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1'

async function runStage(libc: 'gnu' | 'musl') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abitious-stage-'))
  try {
    const bin = path.join(root, 'bin')
    const dest = path.join(root, `npm/linux-x64-${libc}`)
    const log = path.join(root, 'calls.log')
    await mkdir(bin, { recursive: true })
    await mkdir(dest, { recursive: true })
    await writeFile(
      path.join(bin, 'docker'),
      '#!/bin/sh\nprintf "%s\\0" "$@" >> "$DOCKER_LOG"\n',
    )
    await writeFile(
      path.join(bin, 'node'),
      '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NODE_LOG"\n',
    )
    const producer = path.join(dest, 'abi')
    await writeFile(
      producer,
      '#!/bin/sh\nprintf "%s\\n" "$*" >> "$PRODUCER_LOG"\n',
    )
    await Promise.all([
      chmod(path.join(bin, 'docker'), 0o755),
      chmod(path.join(bin, 'node'), 0o755),
      chmod(producer, 0o755),
    ])

    const workflow = parse(await readFile(workflowPath, 'utf8'))
    const step = workflow.jobs.build.steps.find(
      (candidate: { name?: string }) =>
        candidate.name === 'Stage and load the matching ffi template',
    )
    assert.ok(step)
    const env = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      PWD: root,
      DOCKER_LOG: log,
      NODE_LOG: path.join(root, 'node.log'),
      PRODUCER_LOG: path.join(root, 'producer.log'),
      TRIPLE: `linux-x64-${libc}`,
      RUST_TARGET: `x86_64-unknown-linux-${libc}`,
      FFI_STUB_ARTIFACT: 'libffi_stub.a',
      FFI_ARTIFACT: 'libabitious_decmpfs.so',
      LIBC: libc,
      BIN: 'abi',
      SOURCE_SHA: 'fixture-sha',
    }
    const result = spawnSync('bash', ['-euo', 'pipefail', '-c', step.run], {
      cwd: root,
      encoding: 'utf8',
      env,
      timeout: 10_000,
    })
    assert.equal(result.status, 0, result.stderr)

    return {
      dockerCalls: await readFile(log, 'utf8').catch(() => ''),
      nodeCalls: await readFile(env.NODE_LOG, 'utf8'),
      producerCalls: await readFile(env.PRODUCER_LOG, 'utf8').catch(() => ''),
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

test('musl producer and smoke run in the pinned Alpine container', async () => {
  const result = await runStage('musl')
  const args = result.dockerCalls.split('\0').filter(Boolean)

  assert.equal(args.filter(arg => arg === alpineImage).length, 2)
  assert.ok(args.includes('/workspace/npm/linux-x64-musl/abi'))
  assert.ok(args.includes('pack-ffi'))
  assert.ok(args.some(arg => arg.endsWith(':/workspace')))
  assert.ok(args.includes('node'))
  assert.ok(args.includes('--input-type=commonjs'))
  assert.equal(result.producerCalls, '')
})

test('GNU producer stays on the host', async () => {
  const result = await runStage('gnu')

  assert.equal(result.dockerCalls, '')
  assert.match(
    result.producerCalls,
    /^pack-ffi npm\/linux-x64-gnu\/libabitious_decmpfs\.so/m,
  )
  assert.match(result.nodeCalls, /--input-type=commonjs -e/)
})
