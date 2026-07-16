'use strict'

// @abitious/cli runtime entry: resolve THIS host's platform package and export the
// paths it carries — the prebuilt generic stub (`.node`) and the host `abi` producer
// binary. Throws an actionable error (naming the package to install) when the matching
// optional dependency is absent. The `abi` bin (bin.cjs) execs `bin`; a JS toolchain
// injecting hybrids programmatically reads `stub`.

const { loadPlatform } = require('./loader.cjs')

module.exports = loadPlatform()
