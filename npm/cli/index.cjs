'use strict'

// @abitious/cli runtime entry: resolve THIS host's platform package and export the
// paths it carries — the prebuilt generic stub (`.node`) and the host `abi` producer
// binary. When the matching optional dependency is absent it throws an actionable
// error that names the package to install. The `abi` bin (bin.cjs) execs `bin`; a JS toolchain
// injecting hybrids programmatically reads `stub`.

const { loadPlatform } = require('./loader.cjs')

module.exports = loadPlatform()
