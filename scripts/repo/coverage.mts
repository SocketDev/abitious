// Production-coverage runner. The crates mark their test modules
// `#[cfg_attr(coverage_nightly, coverage(off))]` so the report reflects PRODUCTION
// code, not test fixtures/harness. That attribute needs the unstable
// `coverage_attribute` feature — only NIGHTLY rustc accepts it, and only under a
// nightly toolchain does cargo-llvm-cov set the `coverage_nightly` cfg. On stable
// the markers are inert (tests would inflate the number) and the feature gate
// errors, so this script REQUIRES nightly + the llvm-tools component and fails
// loud (What / Where / Saw-vs-wanted / Fix) rather than reporting a wrong number.
//
//   node scripts/repo/coverage.mts                 # full annotated report (--workspace)
//   node scripts/repo/coverage.mts --summary-only  # table only
//   node scripts/repo/coverage.mts --json --summary-only
//   node scripts/repo/coverage.mts --badge         # regenerate assets/coverage-score.svg
//
// The whole Cargo workspace is measured (`--workspace`): the frozen section ABI
// (abitious-decmpfs), the stub trampoline, the producer library/bin, and the `abi`
// CLI. Mirrors decmpfs's runner; the only shape change is workspace-wide scope.

import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import type { SpawnSyncOptions } from '@socketsecurity/lib-stable/process/spawn/types'

const logger = getDefaultLogger()

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

function runSync(
  command: string,
  args: readonly string[],
  config: SpawnSyncOptions,
): string {
  const result = spawnSync(command, args, config)
  if (result.error) {
    throw result.error
  }
  if (result.status !== 0) {
    const stderr =
      typeof result.stderr === 'string'
        ? result.stderr
        : result.stderr.toString()
    throw new Error(stderr || `${command} exited ${result.status}`)
  }
  return typeof result.stdout === 'string'
    ? result.stdout
    : result.stdout.toString()
}

function fail(what: string, fix: string): never {
  logger.fail(`coverage: ${what}`)
  logger.fail(`  fix: ${fix}`)
  process.exit(1)
}

// Resolve a nightly toolchain via rustup: prefer the rolling `nightly` channel,
// else the newest dated nightly.
function resolveNightly(): string {
  let list = ''
  try {
    list = runSync('rustup', ['toolchain', 'list'], { encoding: 'utf8' })
  } catch {
    fail(
      'rustup not found — coverage needs a rustup-managed nightly toolchain',
      'install rustup (https://rustup.rs), then `rustup toolchain install nightly`',
    )
  }
  const names = list
    .split('\n')
    .map(line => line.trim().replace(/ \(.*\)$/, ''))
    .filter(Boolean)
  const rolling = names.find(
    name => name.startsWith('nightly-') && !/^nightly-\d/.test(name),
  )
  const dated = names
    .filter(name => /^nightly-\d{4}-\d\d-\d\d/.test(name))
    .toSorted()
    .at(-1)
  const toolchain = rolling ?? dated
  if (!toolchain) {
    fail(
      'no nightly toolchain installed — the coverage(off) markers need nightly rustc',
      'rustup toolchain install nightly && rustup component add llvm-tools-preview --toolchain nightly',
    )
  }
  return toolchain
}

const toolchain = resolveNightly()
const tcRoot = path.join(os.homedir(), '.rustup', 'toolchains', toolchain)
const rustc = path.join(tcRoot, 'bin', 'rustc')
const cargo = path.join(tcRoot, 'bin', 'cargo')
if (!existsSync(rustc) || !existsSync(cargo)) {
  fail(
    `nightly toolchain ${toolchain} is missing rustc/cargo under ${tcRoot}`,
    `rustup toolchain install ${toolchain}`,
  )
}

// The feature gate rejects a stable channel — confirm we really have nightly.
const version = runSync(rustc, ['--version'], { encoding: 'utf8' }).trim()
if (!version.includes('nightly')) {
  fail(
    `resolved rustc is not nightly (${version}) — coverage_attribute is nightly-only`,
    'rustup toolchain install nightly',
  )
}

// Locate the toolchain's own llvm-cov / llvm-profdata (the llvm-tools component);
// the socket shim on PATH would otherwise resolve a stable rustc/llvm.
function llvmBin(name: string): string {
  const base = path.join(tcRoot, 'lib', 'rustlib')
  const triples = existsSync(base) ? readdirSync(base) : []
  for (const triple of triples) {
    const candidate = path.join(base, triple, 'bin', name)
    if (existsSync(candidate)) {
      return candidate
    }
  }
  return ''
}
const llvmCov = llvmBin('llvm-cov')
const llvmProfdata = llvmBin('llvm-profdata')
if (!llvmCov || !llvmProfdata) {
  fail(
    `llvm-tools missing from ${toolchain} (no llvm-cov / llvm-profdata)`,
    `rustup component add llvm-tools-preview --toolchain ${toolchain}`,
  )
}

const covEnv = {
  ...process.env,
  LLVM_COV: llvmCov,
  LLVM_PROFDATA: llvmProfdata,
  RUSTC: rustc,
  RUSTUP_TOOLCHAIN: toolchain,
}

// Run cargo-llvm-cov over the whole workspace. `-- --include-ignored` runs the
// ignored perf/bomb probes too, so their bodies count and the number is production
// coverage, not probe-body-deflated.
function runCargoLlvmCov(
  extraArgs: string[],
  { capture }: { capture: boolean },
): string {
  const options: SpawnSyncOptions = {
    cwd: root,
    encoding: 'utf8',
    // Capture stdout (the JSON summary) for --badge; otherwise stream everything through.
    stdio: capture ? ['inherit', 'pipe', 'inherit'] : 'inherit',
    env: covEnv,
    maxBuffer: 64 * 1024 * 1024,
  }
  return runSync(
    cargo,
    ['llvm-cov', '--workspace', ...extraArgs, '--', '--include-ignored'],
    options,
  )
}

// shields.io-style flat badge, byte-compatible with the fleet template
// (decmpfs/assets/coverage-score.svg). Label box is the fixed "coverage" (60px);
// the value box grows with the digit count. Color ramps by percent.
function badgeColor(pct: number): string {
  if (pct >= 90) {
    return '#4c1'
  }
  if (pct >= 80) {
    return '#97ca00'
  }
  if (pct >= 70) {
    return '#a4a61d'
  }
  if (pct >= 60) {
    return '#dfb317'
  }
  return '#e05d44'
}

function renderBadge(pct: number): string {
  const value = `${pct}%`
  const labelBox = 60
  const valueBox = value.length * 8 + 12
  const width = labelBox + valueBox
  const valueTextLen = value.length * 80
  const valueX = (labelBox + valueBox / 2) * 10
  const color = badgeColor(pct)
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="coverage: ${pct}%">
  <title>coverage: ${pct}%</title>
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${width}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelBox}" height="20" fill="#555"/>
    <rect x="${labelBox}" width="${valueBox}" height="20" fill="${color}"/>
    <rect width="${width}" height="20" fill="url(#g)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="300" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="500">coverage</text>
    <text x="300" y="140" transform="scale(.1)" textLength="500">coverage</text>
    <text x="${valueX}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${valueTextLen}">${pct}%</text>
    <text x="${valueX}" y="140" transform="scale(.1)" textLength="${valueTextLen}">${pct}%</text>
  </g>
</svg>
`
}

logger.log(`coverage: nightly=${toolchain}`)

if (process.argv.includes('--badge')) {
  // Capture a JSON summary, extract the TOTAL line coverage, and regenerate the
  // README badge from the measured production number.
  const passthrough = process.argv.slice(2).filter(arg => arg !== '--badge')
  let json = ''
  try {
    json = runCargoLlvmCov(['--json', '--summary-only', ...passthrough], {
      capture: true,
    })
  } catch {
    process.exit(1)
  }
  let totals: { lines: { percent: number }; regions: { percent: number } }
  try {
    totals = JSON.parse(json).data[0].totals
  } catch {
    fail(
      'could not parse cargo-llvm-cov --json output for the badge',
      'run `node scripts/repo/coverage.mts --json --summary-only` and inspect the output',
    )
  }
  const regionPct = Math.round(totals.regions.percent)
  const out = path.join(root, 'assets', 'coverage-score.svg')
  mkdirSync(path.dirname(out), { recursive: true })
  // The badge reports REGION coverage — the conservative, fleet-canonical number
  // (mirrors decmpfs/assets/coverage-score.svg). Line coverage is logged alongside.
  writeFileSync(out, renderBadge(regionPct))
  logger.log(
    `coverage: region=${totals.regions.percent.toFixed(2)}% line=${totals.lines.percent.toFixed(2)}% -> ${out} (badge ${regionPct}%)`,
  )
} else {
  try {
    runCargoLlvmCov(process.argv.slice(2), { capture: false })
  } catch {
    process.exit(1)
  }
}
