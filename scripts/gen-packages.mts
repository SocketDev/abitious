// Codegen driven ENTIRELY by scripts/targets.mts (the single source of truth):
//
//   node scripts/gen-packages.mts                  write all generated files
//   node scripts/gen-packages.mts --check          fail (exit 1) if any is out of sync
//   node scripts/gen-packages.mts --print-matrix       print the tier-1 push/PR CI matrix
//   node scripts/gen-packages.mts --print-matrix-all   print the full release matrix (all targets)
//
// Generated outputs (each also verified by --check):
//   • npm/<triple>/package.json         one per TARGETS entry (os/cpu/libc-gated)
//   • npm/cli/package.json              its `optionalDependencies` block only
//   • npm/cli/targets.generated.json    the loader's data view of TARGETS
//
// Idempotent: re-running writes byte-identical files. `--check` is the fleet
// gen-then-check discipline — CI runs it so a hand-edit that drifts from targets.mts
// fails the build. Never mutates anything outside npm/ (the repo is otherwise read-only
// to this script); every write targets an exact, named path.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { STUB_NODE, TARGETS, abiBin, stubArtifact } from './targets.mts'

const scriptsDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(scriptsDir, '..')
const npmRoot = join(repoRoot, 'npm')
const cliDir = join(npmRoot, 'cli')

const cliManifest = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf8'))
const VERSION: string = cliManifest.version
const REPOSITORY = cliManifest.repository
const LICENSE: string = cliManifest.license
const ENGINES = cliManifest.engines
const PUBLISH_CONFIG = cliManifest.publishConfig

/** A single generated file: its absolute path and canonical contents. */
interface GenFile {
  path: string
  contents: string
}

/** Stable JSON with a trailing newline — the on-disk canonical form. */
function json(value: unknown): string {
  return `${JSON.stringify(value, undefined, 2)}\n`
}

/** The per-triple `@abitious/<triple>` platform package.json. */
function platformPackage(triple: string): unknown {
  const target = TARGETS.find(t => t.triple === triple)!
  const bin = abiBin(target.os)
  return {
    name: `@abitious/${triple}`,
    version: VERSION,
    description: `abitious prebuilt stub + host \`abi\` producer for ${triple}.`,
    license: LICENSE,
    repository: REPOSITORY,
    engines: ENGINES,
    os: [target.os],
    cpu: [target.cpu],
    ...(target.libc ? { libc: [target.libc] } : {}),
    // Build-time artifacts, not a runtime addon: no `main`. The loader
    // (npm/cli/index.cjs) resolves these files by name.
    files: [STUB_NODE, bin, 'README.md'].sort(),
    publishConfig: PUBLISH_CONFIG,
  }
}

/** The main `@abitious/cli` optionalDependencies map (every triple, pinned exact). */
function optionalDependencies(): Record<string, string> {
  const deps: Record<string, string> = {}
  for (const target of TARGETS) {
    deps[`@abitious/${target.triple}`] = VERSION
  }
  return deps
}

/** The loader's data view of TARGETS (npm/cli/targets.generated.json). */
function loaderData(): unknown {
  return {
    // A banner so a reader of the JSON knows it is generated.
    _generated: 'scripts/gen-packages.mts from scripts/targets.mts — do not edit',
    stubNode: STUB_NODE,
    targets: TARGETS.map(t => ({
      triple: t.triple,
      os: t.os,
      cpu: t.cpu,
      ...(t.libc ? { libc: t.libc } : {}),
      bin: abiBin(t.os),
    })),
  }
}

/**
 * The CI build matrix `include:` array, derived from TARGETS. Default (`all=false`)
 * is the tier-1 subset — native on their runner, no cross C toolchain — for the fast
 * push/PR CI (build.yml). `all=true` is the full, unfiltered set (every target ships a
 * prebuilt) for the release build (github-release.yml + npm-publish.yml), where the
 * musl C toolchain is installed per-target. Either way the triple list is never
 * duplicated in YAML — both are single-sourced from TARGETS.
 */
function matrix(all = false): unknown[] {
  return TARGETS.filter(t => all || t.tier1).map(t => ({
    triple: t.triple,
    os: t.os,
    cpu: t.cpu,
    libc: t.libc ?? '',
    rust: t.rust,
    runner: t.runner,
    stubArtifact: stubArtifact(t.os),
    bin: abiBin(t.os),
  }))
}

/** Compute every generated file's canonical (path, contents). */
function planned(): GenFile[] {
  const files: GenFile[] = []

  // The main CLI package.json: rewrite ONLY optionalDependencies, preserve the rest.
  const cli = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf8'))
  cli.optionalDependencies = optionalDependencies()
  files.push({ path: join(cliDir, 'package.json'), contents: json(cli) })

  // The loader data view.
  files.push({ path: join(cliDir, 'targets.generated.json'), contents: json(loaderData()) })

  // Each per-triple platform package.json.
  for (const target of TARGETS) {
    files.push({
      path: join(npmRoot, target.triple, 'package.json'),
      contents: json(platformPackage(target.triple)),
    })
  }

  return files
}

function writeAll(files: GenFile[]): void {
  for (const file of files) {
    mkdirSync(dirname(file.path), { recursive: true })
    writeFileSync(file.path, file.contents)
  }
  // A minimal placeholder README per platform package (never overwritten if present
  // with custom content — but the default is regenerated so a fresh checkout is whole).
  for (const target of TARGETS) {
    const readme = join(npmRoot, target.triple, 'README.md')
    if (!existsSync(readme)) {
      writeFileSync(
        readme,
        `# @abitious/${target.triple}\n\n` +
          `Prebuilt abitious stub + host \`abi\` producer for \`${target.triple}\`.\n\n` +
          `This package is an optional dependency of \`@abitious/cli\`; the matching one for\n` +
          `your platform is installed automatically. The binaries are populated by CI.\n`,
      )
    }
  }
}

function check(files: GenFile[]): number {
  const drift: string[] = []
  for (const file of files) {
    const actual = existsSync(file.path) ? readFileSync(file.path, 'utf8') : ''
    if (actual !== file.contents) {
      drift.push(file.path)
    }
  }
  if (drift.length) {
    console.error('gen-packages --check: OUT OF SYNC with scripts/targets.mts:')
    for (const path of drift) {
      console.error(`  • ${path}`)
    }
    console.error('Fix: run `pnpm run gen` (node scripts/gen-packages.mts) and commit.')
    return 1
  }
  console.log(`gen-packages --check: in sync (${files.length} files).`)
  return 0
}

const mode = process.argv[2]
if (mode === '--print-matrix') {
  // Compact single-line JSON for GitHub Actions `fromJSON` (tier-1 push/PR subset).
  process.stdout.write(JSON.stringify(matrix()))
} else if (mode === '--print-matrix-all') {
  // Compact single-line JSON for GitHub Actions `fromJSON` (full release set: all targets).
  process.stdout.write(JSON.stringify(matrix(true)))
} else if (mode === '--check') {
  process.exit(check(planned()))
} else {
  writeAll(planned())
  console.log(`gen-packages: wrote ${planned().length} generated files + placeholder READMEs.`)
}
