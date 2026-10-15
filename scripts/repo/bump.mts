import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { spawnSync } from '@socketsecurity/lib-stable/process/spawn/child'

import { isMainModule } from '../../scripts/fleet/process/is-main-module.mts'
import { runMain } from '../../scripts/fleet/process/main/run.mts'
import type { ScriptMeta } from '../../scripts/fleet/process/main/run.mts'
import { bumpWorkspaceCargo, workspaceVersion } from './release-lib.mts'

const CANONICAL_BUMP = 'scripts/fleet/release/bump/run.mts'

interface CargoLockEntry {
  readonly name: string
  readonly version: string
  readonly source: string | undefined
  readonly start: number
  readonly end: number
}

export function canonicalBumpArgs(args: readonly string[]): string[] {
  const result = args.filter(arg => arg !== '--write-only')
  const first = args.indexOf('--write-only')
  if (first !== -1) {
    result.splice(Math.min(first, result.length), 0, '--write-only')
  } else {
    result.push('--write-only')
  }
  return result
}

function stableVersionParts(version: string): readonly number[] {
  // Capture each numeric component and reject leading zeroes except for zero.
  const match = version.match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/)
  if (!match) {
    throw new Error(`Invalid stable version ${version}. Fix: use X.Y.Z.`)
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])]
}

function compareVersions(left: string, right: string): number {
  const a = stableVersionParts(left)
  const b = stableVersionParts(right)
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] !== b[index]) {
      return a[index]! < b[index]! ? -1 : 1
    }
  }
  return 0
}

function workspaceCrateNames(root: string, cargo: string): string[] {
  const crateRoot = path.join(root, 'crates')
  const members = cargo.match(/^\s*members\s*=\s*\[([\s\S]*?)\]/mu)?.[1]
  if (!members) {
    throw new Error(
      'Cargo.toml has no explicit workspace members. Fix: list each crate under [workspace].members.',
    )
  }
  const dirs = [...members.matchAll(/"([^"]+)"/gu)].map(match => {
    const member = match[1]!
    if (!member.startsWith('crates/') || member.split('/').length !== 2) {
      throw new Error(
        'Unsupported Cargo workspace member ' +
          member +
          '. Fix: add crate directories under crates/.',
      )
    }
    return member.slice('crates/'.length)
  })
  const names: string[] = []
  for (let i = 0, { length } = dirs; i < length; i += 1) {
    const dir = dirs[i]!
    const manifestPath = path.join(root, 'crates', dir, 'Cargo.toml')
    const manifest = readFileSync(manifestPath, 'utf8')
    const name = manifest.match(/^name\s*=\s*"([^"]+)"/m)?.[1]
    const packageSection =
      manifest
        .split(/(?=^\[)/mu)
        .find(section => section.startsWith('[package]')) ?? ''
    if (
      !name ||
      !/^version\.workspace\s*=\s*true$/m.test(packageSection ?? '')
    ) {
      throw new Error(
        `Invalid workspace crate manifest ${manifestPath}. Fix: define package name and version.workspace = true.`,
      )
    }
    names.push(name)
  }
  if (!names.length) {
    throw new Error(`No workspace crates found under ${crateRoot}.`)
  }
  return names
}

function localLockEntries(text: string): CargoLockEntry[] {
  const starts: number[] = []
  // Match package headers as whole lines, allowing CRLF and trailing spaces.
  const matcher = /^\[\[package\]\]\s*$/gmu
  for (let match = matcher.exec(text); match; match = matcher.exec(text)) {
    starts.push(match.index)
  }
  return starts.map((start, index) => {
    const end = starts[index + 1] ?? text.length
    const block = text.slice(start, end)
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1]
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1]
    if (!name || !version) {
      throw new Error(
        'Malformed Cargo.lock package entry. Fix: regenerate the lockfile.',
      )
    }
    return {
      __proto__: null,
      name,
      version,
      source: block.match(/^source\s*=\s*"([^"]+)"/m)?.[1],
      start,
      end,
    }
  })
}

function bumpLocalLockEntries(
  text: string,
  names: readonly string[],
  current: string,
  target: string,
): string {
  const nameSet = new Set(names)
  const entries = localLockEntries(text)
  const matched = entries.filter(
    entry => nameSet.has(entry.name) && entry.source === undefined,
  )
  const found = new Set(matched.map(entry => entry.name))
  const missing = names.filter(name => !found.has(name))
  const duplicates = names.filter(
    name => matched.filter(entry => entry.name === name).length !== 1,
  )
  if (missing.length || duplicates.length) {
    throw new Error(
      `Cargo.lock workspace entries are missing or duplicated: ${[...new Set([...missing, ...duplicates])].join(', ')}. Fix: regenerate Cargo.lock before bumping.`,
    )
  }
  for (let i = 0, { length } = matched; i < length; i += 1) {
    const entry = matched[i]!
    if (entry.version !== current) {
      throw new Error(
        `Cargo.lock ${entry.name} is ${entry.version}, wanted workspace version ${current}. Fix: synchronize the lockfile before bumping.`,
      )
    }
  }
  let result = ''
  let cursor = 0
  for (let i = 0, { length } = matched; i < length; i += 1) {
    const entry = matched[i]!
    const block = text.slice(entry.start, entry.end)
    // Keep the version assignment and surrounding whitespace unchanged.
    const updated = block.replace(
      /^(version\s*=\s*")[^"]+("\s*)$/m,
      (_line, before: string, after: string) => `${before}${target}${after}`,
    )
    result += text.slice(cursor, entry.start) + updated
    cursor = entry.end
  }
  result += text.slice(cursor)
  const localNames = new Set(names)
  // Capture package, version and optional source to update local lock references.
  return result.replace(
    /"([^"]+) ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?: \(([^"]+)\))?"/gu,
    (entry, name: string, version: string, source: string | undefined) =>
      localNames.has(name) &&
      version === current &&
      (!source || source.startsWith('path+'))
        ? entry.replace(version, () => target)
        : entry,
  )
}

function validateInternalPins(cargo: string, current: string): void {
  const pins = [
    ...cargo.matchAll(
      /path\s*=\s*"crates\/[^"]+"\s*,\s*version\s*=\s*"([^"]+)"/gu,
    ),
  ]
  if (!pins.length || pins.some(pin => pin[1] !== current)) {
    throw new Error(
      `Cargo.toml internal path versions do not all match ${current}. Fix: synchronize workspace dependency pins before bumping.`,
    )
  }
}

function fuzzLocalCrateNames(
  root: string,
  workspaceNames: readonly string[],
): string[] {
  const fuzzManifestPath = path.join(root, 'fuzz', 'Cargo.toml')
  if (!existsSync(fuzzManifestPath)) {
    return []
  }
  const fuzzManifest = readFileSync(fuzzManifestPath, 'utf8')
  const crateNames = new Set<string>()
  for (const match of fuzzManifest.matchAll(
    /path\s*=\s*"\.\.\/crates\/([^"]+)"/gu,
  )) {
    const crateManifest = readFileSync(
      path.join(root, 'crates', match[1]!, 'Cargo.toml'),
      'utf8',
    )
    const name = crateManifest.match(/^name\s*=\s*"([^"]+)"/m)?.[1]
    if (!name || !workspaceNames.includes(name)) {
      throw new Error(
        `Invalid fuzz path dependency for ${match[1]}. Fix: point it at a workspace crate.`,
      )
    }
    crateNames.add(name)
  }
  return [...crateNames].toSorted()
}

export function syncCargoVersion(root: string, target: string): string[] {
  const cargoPath = path.join(root, 'Cargo.toml')
  const lockPath = path.join(root, 'Cargo.lock')
  const fuzzLockPath = path.join(root, 'fuzz', 'Cargo.lock')
  const cargo = readFileSync(cargoPath, 'utf8')
  const current = workspaceVersion(cargo)
  if (!current) {
    throw new Error(
      'Cargo.toml has no workspace version. Fix: define [workspace.package].version.',
    )
  }
  if (compareVersions(target, current) < 0) {
    throw new Error(
      `Cargo workspace version cannot move down from ${current} to ${target}. Fix: choose a newer target version.`,
    )
  }
  validateInternalPins(cargo, current)
  const names = workspaceCrateNames(root, cargo)
  const lock = readFileSync(lockPath, 'utf8')
  const updatedLock = bumpLocalLockEntries(lock, names, current, target)
  const fuzzNames = fuzzLocalCrateNames(root, names)
  const originalFuzzLock = existsSync(fuzzLockPath)
    ? readFileSync(fuzzLockPath, 'utf8')
    : undefined
  const fuzzLock =
    originalFuzzLock === undefined
      ? undefined
      : bumpLocalLockEntries(originalFuzzLock, fuzzNames, current, target)
  const updatedCargo = bumpWorkspaceCargo(cargo, target)
  if (workspaceVersion(updatedCargo) !== target) {
    throw new Error(
      `Cargo.toml workspace version was not updated to ${target}. Fix: check the workspace version declaration.`,
    )
  }
  const changed: string[] = []
  if (updatedCargo !== cargo) {
    writeFileSync(cargoPath, updatedCargo)
    changed.push('Cargo.toml')
  }
  if (updatedLock !== lock) {
    writeFileSync(lockPath, updatedLock)
    changed.push('Cargo.lock')
  }
  if (fuzzLock !== undefined) {
    if (fuzzLock !== originalFuzzLock) {
      writeFileSync(fuzzLockPath, fuzzLock)
      changed.push('fuzz/Cargo.lock')
    }
  }
  return changed
}

export interface CanonicalBumpRunner {
  (
    root: string,
    script: string,
    args: readonly string[],
    env: NodeJS.ProcessEnv,
  ): number | null
}

function runCanonicalBump(
  root: string,
  script: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): number | null {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: root,
    env,
    stdio: 'inherit',
  }).status
}

export function runBumpOverlay(
  root: string,
  args: readonly string[],
  options: { runner?: CanonicalBumpRunner | undefined } = {},
): string[] {
  const canonicalArgs = canonicalBumpArgs(args)
  const status = (options.runner ?? runCanonicalBump)(
    root,
    path.join(root, CANONICAL_BUMP),
    canonicalArgs,
    { ...process.env, SOCKET_SHIM_ACTIVE_PNPM: '1' },
  )
  if (status !== 0) {
    throw new Error(
      `Canonical npm bump exited ${status ?? 'on a signal'}. Fix: resolve the npm bump before Cargo synchronization.`,
    )
  }
  if (args.some(arg => arg === '--dry-run' || arg.startsWith('--dry-run='))) {
    return []
  }
  let manifest: { version?: unknown | undefined }
  try {
    manifest = JSON.parse(
      readFileSync(path.join(root, 'npm', 'cli', 'package.json'), 'utf8'),
    ) as { version?: unknown | undefined }
  } catch {
    throw new Error(
      'npm/cli/package.json is unreadable. Fix: run the canonical npm bump first.',
    )
  }
  if (typeof manifest.version !== 'string') {
    throw new Error(
      'npm/cli/package.json has no version. Fix: run the canonical npm bump first.',
    )
  }
  return syncCargoVersion(root, manifest.version)
}

export function main(): number {
  const root = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../..',
  )
  runBumpOverlay(root, process.argv.slice(2))
  return 0
}

const SCRIPT_META: ScriptMeta = {
  describe:
    'run the canonical npm bump and align Cargo workspace versions and locks',
  help: 'Usage: node scripts/repo/bump.mts [canonical bump options]',
  json: 'native',
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
