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

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { getDefaultLogger } from '@socketsecurity/lib-stable/logger/default'
import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'
import {
  bumpNpmManifest,
  bumpWorkspaceCargo,
  changelogSection,
  promoteChangelog,
  resolveRelease,
  workspaceVersion,
} from './release-lib.mts'

const logger = getDefaultLogger()
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const argv = process.argv.slice(2).filter(a => !a.startsWith('--'))
const arg = (argv[0] ?? '').replace(/^v/, '')
const push = process.argv.includes('--push')
const dryRun = process.argv.includes('--dry-run')
const SCOPE = '@abitious/'

function die(msg: string): never {
  process.stderr.write(`release: ${msg}\n`)
  process.exit(1)
}

function git(args: string[], options: { stdio?: 'inherit' | 'pipe' } = {}): string {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', ...options })
  if (result.status !== 0) {
    die(`git ${args[0]} exited ${result.status ?? 'on a signal'}.`)
  }
  return String(result.stdout ?? '')
}

const read = (rel: string): string => readFileSync(path.join(root, rel), 'utf8')
const write = (rel: string, src: string): void => writeFileSync(path.join(root, rel), src)

if (arg && !/^\d+\.\d+\.\d+$/.test(arg)) {
  die(
    `usage: node scripts/repo/release.mts [x.y.z] [--dry-run] [--push]\n` +
      `  saw: ${JSON.stringify(argv[0])}. fix: omit the arg to release the committed ` +
      `version, or pass a semver like 0.2.0 to bump first.`,
  )
}

const current = workspaceVersion(read('Cargo.toml'))
if (current === undefined) {
  die('no [workspace.package] version in Cargo.toml.')
}
const { version, mode } = resolveRelease(current, arg)
const bump = version !== current

// Every npm/<name>/package.json is version-locked to the workspace.
const npmManifests = readdirSync(path.join(root, 'npm'))
  .map(name => path.join('npm', name, 'package.json'))
  .filter(rel => existsSync(path.join(root, rel)))

// Preview the plan and exit before touching anything.
if (dryRun) {
  const cl = promoteChangelog(read('CHANGELOG.md'), version)
  const changelog = cl.hasSection
    ? cl.changed
      ? `## [Unreleased] → ## ${version}`
      : `## ${version} present — kept verbatim`
    : `no section — a ## ${version} must be written first`
  logger.log(
    `release (dry-run):\n` +
      `  committed version: ${current}\n` +
      `  release version:   ${version}  (${mode})\n` +
      `  changelog:         ${changelog}\n` +
      `  manifests:         ${bump ? `Cargo.toml + ${npmManifests.length} npm package.json + Cargo.lock → ${version}` : `unchanged (already ${version})`}\n` +
      `  tag:               v${version} at HEAD\n` +
      `  push:              ${push ? 'yes → github-release.yml publishes' : 'no (re-run with --push)'}`,
  )
  process.exit(0)
}

// A release must reflect committed state — the tag points at a commit.
if (git(['status', '--porcelain']).trim()) {
  die('working tree is dirty. Fix: commit or stash before releasing.')
}

const changed: string[] = []

if (bump) {
  write('Cargo.toml', bumpWorkspaceCargo(read('Cargo.toml'), version))
  changed.push('Cargo.toml')
  for (const rel of npmManifests) {
    write(rel, bumpNpmManifest(read(rel), version, SCOPE))
    changed.push(rel)
  }
  const updated = spawnSync('cargo', ['update', '--offline', '--workspace'], {
    cwd: root,
    stdio: 'inherit',
  })
  if (updated.status !== 0) {
    die(`cargo update exited ${updated.status ?? 'on a signal'}.`)
  }
  changed.push('Cargo.lock')
  // The npm manifest versions changed, so resync the workspace lockfile — a
  // release must never leave pnpm-lock.yaml drifted (a dirty lock blocks the
  // next release and ships stale `link:` specifiers).
  const relocked = spawnSync('pnpm', ['install', '--lockfile-only', '--ignore-scripts'], {
    cwd: root,
    stdio: 'inherit',
  })
  if (relocked.status !== 0) {
    die(`pnpm install --lockfile-only exited ${relocked.status ?? 'on a signal'}.`)
  }
  if (git(['status', '--porcelain', 'pnpm-lock.yaml']).trim()) {
    changed.push('pnpm-lock.yaml')
  }
}

// Promote the CHANGELOG to the release version (both bump + as-committed paths).
const promoted = promoteChangelog(read('CHANGELOG.md'), version)
if (promoted.changed) {
  write('CHANGELOG.md', promoted.text)
  changed.push('CHANGELOG.md')
}

// Gate: a real, filled CHANGELOG section, and version parity across manifests.
const section = changelogSection(read('CHANGELOG.md'), version)
if (!section || /TODO: describe the user-visible changes/.test(section)) {
  die(
    `CHANGELOG.md "## ${version}" section is missing or a TODO stub. ` +
      `Fix: fill it in, commit, then re-run.`,
  )
}
if (workspaceVersion(read('Cargo.toml')) !== version) {
  die(`Cargo.toml [workspace.package] version is not ${version} after edit.`)
}
for (const rel of npmManifests) {
  const pkgVersion = (JSON.parse(read(rel)) as { version?: string }).version
  if (pkgVersion !== version) {
    die(`${rel} version is ${pkgVersion}, expected ${version}.`)
  }
}

if (changed.length) {
  git(['commit', '-o', ...changed, '-m', `chore: bump version to ${version}`], {
    stdio: 'inherit',
  })
}

const tag = `v${version}`
// verify-before-acting: a tag whose GitHub Release was already cut is immutable
// — refuse to move it. A tag with no Release (e.g. a failed release run) is safe
// to re-fire.
if (push) {
  const released = spawnSync('gh', ['release', 'view', tag, '--json', 'tagName'], {
    cwd: root,
    encoding: 'utf8',
  })
  if (released.status === 0) {
    die(
      `GitHub Release ${tag} already exists and is immutable — bump the version ` +
        `instead of moving ${tag}.`,
    )
  }
}
git(['tag', '-f', tag], { stdio: 'inherit' })

if (push) {
  const branch = git(['symbolic-ref', '--short', 'HEAD']).trim()
  git(['push', 'origin', branch], { stdio: 'inherit' })
  git(['push', 'origin', tag], { stdio: 'inherit' })
}

logger.log(
  `release: ${changed.length ? 'prepared + ' : ''}tagged ${tag} at HEAD.` +
    (push
      ? ' Pushed — github-release.yml cuts the Release, which publishes.'
      : ` Review, then: node scripts/repo/release.mts ${arg ? version + ' ' : ''}--push`),
)
