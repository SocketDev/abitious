// Cut an abitious release — the ONE command that tags and triggers publishing.
// You never tag by hand: this owns the tag, points it at the release commit, and
// (with --push) pushes it, firing github-release.yml → cargo-publish.yml +
// npm-publish.yml.
//
//   node scripts/repo/release.mts               # release the committed version
//   node scripts/repo/release.mts --dry-run     # preview: version + CHANGELOG, no writes
//   node scripts/repo/release.mts 0.2.0         # bump the workspace + npm packages first
//   node scripts/repo/release.mts [ver] --push  # also push branch + tag (triggers CI)
//
// A committed `-prerelease` version (0.1.1-prerelease) auto-finalizes to the plain
// semver (0.1.1). The CHANGELOG `## [Unreleased]` is promoted to `## <version>`.
// Pure logic lives in release-lib.mts (unit-tested, no I/O).

import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/main/run.mts'

import type { ScriptMeta } from '../fleet/process/main/run.mts'
import {
  bumpNpmManifest,
  bumpWorkspaceCargo,
  changelogSection,
  promoteChangelog,
  resolveRelease,
  workspaceVersion,
} from './release-lib.mts'

const logger = getDefaultLogger()
const SCOPE = '@abitious/'

type ReleaseConfig = {
  arg: string
  push: boolean
  dryRun: boolean
  jsonRequested: boolean
}

type ReleaseContext = ReleaseConfig & {
  root: string
  current: string
  version: string
  mode: ReturnType<typeof resolveRelease>['mode']
  bump: boolean
  npmManifests: string[]
  changed: string[]
}

function fail(msg: string): never {
  throw new Error(`release: ${msg}`)
}

function parseOptions(): ReleaseConfig {
  const argv = process.argv.slice(2).filter(a => !a.startsWith('--'))
  const arg = (argv[0] ?? '').replace(/^v/, '')
  if (arg && !/^\d+\.\d+\.\d+$/.test(arg)) {
    fail(
      `usage: node scripts/repo/release.mts [x.y.z] [--dry-run] [--push]\n` +
        `  saw: ${JSON.stringify(argv[0])}. fix: omit the arg to release the committed ` +
        `version, or pass a semver like 0.2.0 to bump first.`,
    )
  }
  return {
    arg,
    push: process.argv.includes('--push'),
    dryRun: process.argv.includes('--dry-run'),
    jsonRequested: process.argv.includes('--json'),
  }
}

function releaseRoot(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
}

function readReleaseFile(root: string, rel: string): string {
  return readFileSync(path.join(root, rel), 'utf8')
}

function writeReleaseFile(root: string, rel: string, src: string): void {
  writeFileSync(path.join(root, rel), src)
}

function git(
  root: string,
  args: string[],
  options: { stdio?: 'inherit' | 'pipe' | undefined } = {},
): string {
  const result = spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    ...options,
  })
  if (result.status !== 0) {
    fail(`git ${args[0]} exited ${result.status ?? 'on a signal'}.`)
  }
  return result.stdout ?? ''
}

function createReleaseContext(
  root: string,
  config: ReleaseConfig,
): ReleaseContext {
  const { arg, push, dryRun, jsonRequested } = config
  const current = workspaceVersion(readReleaseFile(root, 'Cargo.toml'))
  if (current === undefined) {
    fail('no [workspace.package] version in Cargo.toml.')
  }
  const { version, mode } = resolveRelease(current, arg)
  const npmManifests = readdirSync(path.join(root, 'npm'))
    .map(name => path.join('npm', name, 'package.json'))
    .filter(rel => existsSync(path.join(root, rel)))
  return {
    arg,
    push,
    dryRun,
    jsonRequested,
    root,
    current,
    version,
    mode,
    bump: version !== current,
    npmManifests,
    changed: [],
  }
}

function previewRelease(context: ReleaseContext): void {
  const {
    root,
    current,
    version,
    mode,
    bump,
    npmManifests,
    push,
    jsonRequested,
  } = context
  const cl = promoteChangelog(readReleaseFile(root, 'CHANGELOG.md'), version)
  const changelog = cl.hasSection
    ? cl.changed
      ? `## [Unreleased] → ## ${version}`
      : `## ${version} present — kept verbatim`
    : `no section — a ## ${version} must be written first`
  if (jsonRequested) {
    process.stdout.write(
      `${JSON.stringify({
        dryRun: true,
        currentVersion: current,
        version,
        mode,
        changelog,
        manifestsChanged: bump,
        tag: `v${version}`,
        push,
      })}\n`,
    )
    return
  }
  logger.log(
    `release (dry-run):\n` +
      `  committed version: ${current}\n` +
      `  release version:   ${version}  (${mode})\n` +
      `  changelog:         ${changelog}\n` +
      `  manifests:         ${bump ? `Cargo.toml + ${npmManifests.length} npm package.json + Cargo.lock → ${version}` : `unchanged (already ${version})`}\n` +
      `  tag:               v${version} at HEAD\n` +
      `  push:              ${push ? 'yes → github-release.yml publishes' : 'no (re-run with --push)'}`,
  )
}

function assertCleanTree(context: ReleaseContext): void {
  if (git(context.root, ['status', '--porcelain']).trim()) {
    fail('working tree is dirty. Fix: commit or stash before releasing.')
  }
}

function bumpRelease(context: ReleaseContext): void {
  const { root, version, npmManifests, changed } = context
  writeReleaseFile(
    root,
    'Cargo.toml',
    bumpWorkspaceCargo(readReleaseFile(root, 'Cargo.toml'), version),
  )
  changed.push('Cargo.toml')
  for (const rel of npmManifests) {
    writeReleaseFile(
      root,
      rel,
      bumpNpmManifest(readReleaseFile(root, rel), version, SCOPE),
    )
    changed.push(rel)
  }
  const updated = spawnSync('cargo', ['update', '--offline', '--workspace'], {
    cwd: root,
    stdio: 'inherit',
  })
  if (updated.status !== 0) {
    fail(`cargo update exited ${updated.status ?? 'on a signal'}.`)
  }
  changed.push('Cargo.lock')
  const relocked = spawnSync(
    'pnpm',
    ['install', '--lockfile-only', '--ignore-scripts'],
    { cwd: root, stdio: 'inherit' },
  )
  if (relocked.status !== 0) {
    fail(
      `pnpm install --lockfile-only exited ${relocked.status ?? 'on a signal'}.`,
    )
  }
  if (git(root, ['status', '--porcelain', 'pnpm-lock.yaml']).trim()) {
    changed.push('pnpm-lock.yaml')
  }
}

function promoteReleaseChangelog(context: ReleaseContext): void {
  const { root, version, changed } = context
  const promoted = promoteChangelog(
    readReleaseFile(root, 'CHANGELOG.md'),
    version,
  )
  if (promoted.changed) {
    writeReleaseFile(root, 'CHANGELOG.md', promoted.text)
    changed.push('CHANGELOG.md')
  }
}

function validateRelease(context: ReleaseContext): void {
  const { root, version, npmManifests } = context
  const section = changelogSection(
    readReleaseFile(root, 'CHANGELOG.md'),
    version,
  )
  if (!section || /TODO: describe the user-visible changes/.test(section)) {
    fail(
      `CHANGELOG.md "## ${version}" section is missing or a TODO stub. ` +
        `Fix: fill it in, commit, then re-run.`,
    )
  }
  if (workspaceVersion(readReleaseFile(root, 'Cargo.toml')) !== version) {
    fail(`Cargo.toml [workspace.package] version is not ${version} after edit.`)
  }
  for (const rel of npmManifests) {
    const manifest: { version?: string | undefined } = JSON.parse(
      readReleaseFile(root, rel),
    )
    const pkgVersion = manifest.version
    if (pkgVersion !== version) {
      fail(`${rel} version is ${pkgVersion}, expected ${version}.`)
    }
  }
}

function commitReleaseChanges(context: ReleaseContext): void {
  const { root, version, changed } = context
  if (changed.length > 0) {
    git(
      root,
      ['commit', '-o', ...changed, '-m', `chore: bump version to ${version}`],
      { stdio: 'inherit' },
    )
  }
}

function assertReleaseMissing(context: ReleaseContext, tag: string): void {
  if (!context.push) {
    return
  }
  const released = spawnSync(
    'gh',
    ['release', 'view', tag, '--json', 'tagName'],
    {
      cwd: context.root,
      encoding: 'utf8',
    },
  )
  if (released.status === 0) {
    fail(
      `GitHub Release ${tag} already exists and is immutable — bump the version ` +
        `instead of moving ${tag}.`,
    )
  }
}

function tagAndPushRelease(context: ReleaseContext, tag: string): void {
  const { root, push } = context
  git(root, ['tag', '-f', tag], { stdio: 'inherit' })
  if (!push) {
    return
  }
  const branch = git(root, ['symbolic-ref', '--short', 'HEAD']).trim()
  git(root, ['push', 'origin', branch], { stdio: 'inherit' })
  git(root, ['push', 'origin', tag], { stdio: 'inherit' })
}

function reportRelease(context: ReleaseContext, tag: string): void {
  const { arg, changed, jsonRequested, push, version } = context
  logger.log(
    jsonRequested
      ? JSON.stringify({ version, tag, changed, pushed: push })
      : `release: ${changed.length ? 'prepared + ' : ''}tagged ${tag} at HEAD.` +
          (push
            ? ' Pushed — github-release.yml cuts the Release, which publishes.'
            : ` Review, then: node scripts/repo/release.mts ${arg ? version + ' ' : ''}--push`),
  )
}

function main(): number {
  const context = createReleaseContext(releaseRoot(), parseOptions())
  if (context.dryRun) {
    previewRelease(context)
    return 0
  }
  assertCleanTree(context)
  if (context.bump) {
    bumpRelease(context)
  }
  promoteReleaseChangelog(context)
  validateRelease(context)
  commitReleaseChanges(context)
  const tag = `v${context.version}`
  assertReleaseMissing(context, tag)
  tagAndPushRelease(context, tag)
  reportRelease(context, tag)
  return 0
}

const SCRIPT_META: ScriptMeta = {
  describe:
    'prepares a signed release tag and can push it to the publish workflows',
  help: 'Usage: pnpm run release [x.y.z] [--dry-run] [--push] [--json]',
  json: 'native',
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
