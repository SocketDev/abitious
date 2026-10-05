import process from 'node:process'

import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'

import { resolveBuildMode } from '../fleet/build/mode.mts'
import { REPO_ROOT } from '../fleet/paths.mts'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/main/run.mts'
import { scriptStdio } from '../fleet/process/script-output.mts'

export async function buildNativeWorkspace(): Promise<void> {
  const mode = resolveBuildMode(process.argv.slice(2))
  const args = ['build', '--workspace']
  if (mode === 'prod') {
    args.push('--release')
  }
  const result = await spawn('cargo', args, {
    cwd: REPO_ROOT,
    stdio: scriptStdio('inherit'),
  })
  if (result.code !== 0) {
    throw new Error(
      `Native build failed. Where: Cargo workspace. Saw exit code ${result.code}, wanted 0. Fix: resolve the compiler errors and run build again.`,
    )
  }
}

if (isMainModule(import.meta.url)) {
  runMain(buildNativeWorkspace, {
    describe: 'Build the native workspace in development or production mode.',
    heavyJob: 'build',
    help: 'Usage: pnpm run build [--prod]\nDevelopment uses incremental debug compilation; production uses the optimized release profile.',
    json: 'result',
  })
}
