'use strict'

// The abitious platform loader — PURE and fully injectable so the resolution logic
// is unit-tested with fake platform/arch/libc + a fake resolver (no real install
// needed). npm/cli/index.cjs wires it to the real process + require.resolve.
//
// Each supported target ships as an optional dependency `@abitious/<triple>` carrying
// that platform's prebuilt stub `.node` + host `abi` producer binary, so a package
// manager installs only the one matching this host. The supported set + the stub
// filename come from targets.generated.json — generated from scripts/targets.mts by
// scripts/gen-packages.mts (the single source of truth). Keep the abi-suffix rule in
// lockstep with napi-rs's loader and crates/abitious/src/triple.rs.

const { dirname, join } = require('node:path')

const DATA = require('./targets.generated.json')

const SUPPORTED = DATA.targets
const STUB_NODE = DATA.stubNode

/**
 * The napi-rs addon abi suffix for a host: glibc Linux `-gnu`, musl Linux `-musl`,
 * Windows `-msvc`, macOS none. musl-vs-glibc is detected exactly as napi-rs does —
 * `process.report.getReport().header.glibcVersionRuntime` is present on glibc and
 * absent on musl. `report` is injected so the branch is testable off-host.
 */
function abiSuffix(platform, report) {
  if (platform === 'win32') {
    return '-msvc'
  }
  if (platform === 'linux') {
    const glibc =
      report && typeof report === 'object' ? report.header?.glibcVersionRuntime : undefined
    return glibc ? '-gnu' : '-musl'
  }
  return ''
}

/**
 * Map a host (`{ platform, arch, report }`, `process`-shaped) to its target triple
 * `@abitious/<triple>`: `<platform>-<arch>[-<abi>]`.
 */
function hostTriple({ platform, arch, report }) {
  return `${platform}-${arch}${abiSuffix(platform, report)}`
}

/**
 * Resolve the installed platform package for a host and return the paths it carries.
 *
 * @param {object} opts
 * @param {string} opts.platform  process.platform
 * @param {string} opts.arch      process.arch
 * @param {object} [opts.report]  process.report.getReport() (for glibc detection)
 * @param {(request: string) => string} opts.resolve  resolves `<pkg>/package.json`
 *   to an absolute path (throws when the optional dep is not installed).
 * @returns {{ triple: string, pkg: string, dir: string, stub: string, bin: string }}
 * @throws {Error} an actionable error naming the host triple, the package to install,
 *   and what was tried, when no matching optional dependency is present.
 */
function resolvePlatform({ platform, arch, report, resolve }) {
  const triple = hostTriple({ platform, arch, report })
  const entry = SUPPORTED.find(t => t.triple === triple)
  const pkg = `@abitious/${triple}`

  if (!entry) {
    throw new Error(
      `abitious: unsupported platform ${triple}.\n` +
        `  Where: ${platform}-${arch}\n` +
        `  Saw:   no @abitious platform package exists for this host\n` +
        `  Fix:   supported targets are ${SUPPORTED.map(t => t.triple).join(', ')}.`,
    )
  }

  let manifest
  try {
    manifest = resolve(`${pkg}/package.json`)
  } catch {
    throw new Error(
      `abitious: no prebuilt binary for ${triple}.\n` +
        `  Where: require.resolve("${pkg}/package.json")\n` +
        `  Saw:   the optional dependency ${pkg} is not installed\n` +
        `  Fix:   install it — \`npm install ${pkg}\` (or reinstall @abitious/cli so\n` +
        `         the matching optionalDependency is fetched for this platform).`,
    )
  }

  const dir = dirname(manifest)
  return {
    triple,
    pkg,
    dir,
    stub: join(dir, STUB_NODE),
    bin: join(dir, entry.bin),
  }
}

/** Resolve using the real process + require.resolve (npm/cli/index.cjs entry). */
function loadPlatform() {
  const { createRequire } = require('node:module')
  const req = createRequire(__filename)
  const report =
    typeof process.report?.getReport === 'function' ? process.report.getReport() : undefined
  return resolvePlatform({
    platform: process.platform,
    arch: process.arch,
    report,
    resolve: request => req.resolve(request),
  })
}

module.exports = { abiSuffix, hostTriple, resolvePlatform, loadPlatform, SUPPORTED, STUB_NODE }
