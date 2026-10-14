import process from 'node:process'

import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'

import { REPO_ROOT } from '../../fleet/paths.mts'
import { isMainModule } from '../../fleet/process/is-main-module.mts'
import { runMain } from '../../fleet/process/main/run.mts'
import { scriptStdio } from '../../fleet/process/script-output.mts'

import type { ScriptMeta } from '../../fleet/process/main/run.mts'

export async function testNativeWorkspace(): Promise<void> {
  const result = await spawn('cargo', ['test', '--workspace', '--locked'], {
    cwd: REPO_ROOT,
    shell: process.platform === 'win32',
    stdio: scriptStdio('inherit'),
  })
  if (result.code !== 0) {
    throw new Error(
      `Rust workspace tests failed. Where: cargo test --workspace --locked. Saw exit code ${result.code}; wanted 0. Fix: resolve the failing Rust tests and run this command again.`,
    )
  }
}

const SCRIPT_META: ScriptMeta = {
  describe: 'runs the locked Rust workspace tests',
  heavyJob: 'test',
  help: 'Usage: pnpm run test:rust\nRuns cargo test --workspace --locked.',
  json: 'result',
}

if (isMainModule(import.meta.url)) {
  runMain(testNativeWorkspace, SCRIPT_META)
}
