#!/usr/bin/env node
'use strict'

// The `abi` bin — a thin wrapper (napi-rs `@napi-rs/cli` style): resolve this host's
// platform package, then exec its prebuilt native `abi` producer, forwarding argv,
// stdio, and the exit code. All real work is in the native binary; this only routes.

const { spawnSync } = require('node:child_process')
const { loadPlatform } = require('./loader.cjs')

let resolution
try {
  resolution = loadPlatform()
} catch (error) {
  process.stderr.write(`${error.message}\n`)
  process.exit(1)
}

const result = spawnSync(resolution.bin, process.argv.slice(2), { stdio: 'inherit' })

if (result.error) {
  process.stderr.write(
    `abitious: failed to exec the prebuilt \`abi\` producer.\n` +
      `  Where: ${resolution.bin}\n` +
      `  Saw:   ${result.error.message}\n` +
      `  Fix:   reinstall ${resolution.pkg} so its \`abi\` binary is present + executable.\n`,
  )
  process.exit(1)
}

process.exit(result.status === null ? 1 : result.status)
