'use strict'

// @abitious/cli runtime entry: resolve THIS host's platform package and export the
// paths it carries — the prebuilt stub (`.node`), decmpfs C ABI library, and host
// `abi` producer binary. When the matching optional dependency is absent it throws an actionable
// error that names the package to install. The `abi` bin (bin.cjs) execs `bin`; a JS toolchain
// injecting hybrids programmatically reads `stub`.

const { loadPlatform, loadNativeFfi } = require('./loader.cjs')

const platform = loadPlatform()

module.exports = {
  ...platform,
  nativeFfi: platform.nativeFfi ?? loadNativeFfi({ libraryPath: platform.ffi }),
}
