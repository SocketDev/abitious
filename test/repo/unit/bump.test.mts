import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, test, vi } from 'vitest'

import {
  canonicalBumpArgs,
  runBumpOverlay,
  syncCargoVersion,
} from '../../../scripts/repo/bump.mts'

const crateNames = [
  'abitious',
  'abitious-bind',
  'abitious-decmpfs',
  'abitious-ffi-stub',
  'abitious-producer',
  'abitious-stub',
]
const fixtureDirs: string[] = []

function makeFixture(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-bump-overlay-'))
  fixtureDirs.push(root)
  mkdirSync(path.join(root, 'crates'), { recursive: true })
  mkdirSync(path.join(root, 'npm', 'cli'), { recursive: true })
  mkdirSync(path.join(root, 'fuzz'), { recursive: true })
  const pins = [
    'abitious-decmpfs = { path = "crates/abitious-decmpfs", version = "0.1.0" }',
    'abitious-producer = { path = "crates/abitious-producer", version = "0.1.0" }',
    'decmpfs = "=0.1.5"',
  ]
  writeFileSync(
    path.join(root, 'Cargo.toml'),
    `[workspace]\nmembers = [${crateNames.map(name => `"crates/${name}"`).join(', ')}]\n\n[workspace.package]\nversion = "0.1.0"\n\n[workspace.dependencies]\n${pins.join('\n')}\n`,
  )
  for (const name of crateNames) {
    mkdirSync(path.join(root, 'crates', name), { recursive: true })
    writeFileSync(
      path.join(root, 'crates', name, 'Cargo.toml'),
      `[package]\nname = "${name}"\nversion.workspace = true\n`,
    )
  }
  const lockEntries = crateNames
    .map(
      (name, index) =>
        `[[package]]\nname = "${name}"\nversion = "0.1.0"\n` +
        (index === 0
          ? 'dependencies = [\n "abitious-decmpfs 0.1.0",\n "decmpfs 0.1.5 (registry+https://github.com/rust-lang/crates.io-index)",\n]\n'
          : ''),
    )
    .join('\n')
  writeFileSync(
    path.join(root, 'Cargo.lock'),
    `version = 4\n\n${lockEntries}\n[[package]]\nname = "abitious-decmpfs"\nversion = "9.9.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "decmpfs"\nversion = "0.1.5"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`,
  )
  writeFileSync(
    path.join(root, 'fuzz', 'Cargo.lock'),
    `version = 4\n\n[[package]]\nname = "abitious-decmpfs"\nversion = "0.1.0"\n\n[[package]]\nname = "abitious-fuzz"\nversion = "0.0.0"\ndependencies = [\n "abitious-decmpfs",\n]\n`,
  )
  writeFileSync(
    path.join(root, 'fuzz', 'Cargo.toml'),
    '[dependencies]\nabitious-decmpfs = { path = "../crates/abitious-decmpfs" }\n',
  )
  writeFileSync(
    path.join(root, 'npm', 'cli', 'package.json'),
    `${JSON.stringify({ name: '@abitious/cli', version: '0.1.0' }, null, 2)}\n`,
  )
  return root
}

function read(root: string, rel: string): string {
  return readFileSync(path.join(root, rel), 'utf8')
}

function writeNpmTarget(root: string, version = '0.2.0'): void {
  writeFileSync(
    path.join(root, 'npm', 'cli', 'package.json'),
    `${JSON.stringify({ name: '@abitious/cli', version }, null, 2)}\n`,
  )
}

afterEach(() => {
  for (const dir of fixtureDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
  vi.restoreAllMocks()
})

describe('repo bump overlay', () => {
  test('adds canonical write-only once and preserves the caller arguments', () => {
    expect(canonicalBumpArgs(['--json', '--release-as', '0.2.0'])).toEqual([
      '--json',
      '--release-as',
      '0.2.0',
      '--write-only',
    ])
    expect(canonicalBumpArgs(['--write-only', '--json'])).toEqual([
      '--write-only',
      '--json',
    ])
  })

  test('runs canonical npm bump then aligns workspace and only local lock entries', () => {
    const root = makeFixture()
    const runner = vi.fn((_root, _script, args, env) => {
      expect(args).toEqual(['--json', '--release-as', '0.2.0', '--write-only'])
      expect(env.SOCKET_SHIM_ACTIVE_PNPM).toBe('1')
      writeNpmTarget(root)
      return 0
    })
    expect(
      runBumpOverlay(root, ['--json', '--release-as', '0.2.0'], runner),
    ).toEqual(['Cargo.toml', 'Cargo.lock', 'fuzz/Cargo.lock'])
    expect(read(root, 'Cargo.toml')).toContain('version = "0.2.0"')
    expect(read(root, 'Cargo.toml')).toContain('decmpfs = "=0.1.5"')
    for (const name of crateNames) {
      expect(read(root, 'Cargo.lock')).toContain(
        `name = "${name}"\nversion = "0.2.0"`,
      )
    }
    expect(read(root, 'Cargo.lock')).toContain(
      'name = "decmpfs"\nversion = "0.1.5"\nsource = "registry+',
    )
    expect(read(root, 'Cargo.lock')).toContain(
      'name = "abitious-decmpfs"\nversion = "9.9.9"\nsource = "registry+',
    )
    expect(read(root, 'Cargo.lock')).toContain('"abitious-decmpfs 0.2.0"')
    expect(read(root, 'Cargo.lock')).toContain(
      '"decmpfs 0.1.5 (registry+https://github.com/rust-lang/crates.io-index)"',
    )
    expect(read(root, 'fuzz/Cargo.lock')).toContain(
      'name = "abitious-decmpfs"\nversion = "0.2.0"',
    )
    expect(read(root, 'fuzz/Cargo.lock')).toContain(
      'name = "abitious-fuzz"\nversion = "0.0.0"',
    )
    const aligned = read(root, 'Cargo.lock')
    expect(syncCargoVersion(root, '0.2.0')).toEqual([])
    expect(read(root, 'Cargo.lock')).toBe(aligned)
  })

  test('dry-run invokes canonical preview and leaves Cargo files untouched', () => {
    const root = makeFixture()
    const cargo = read(root, 'Cargo.toml')
    const lock = read(root, 'Cargo.lock')
    const runner = vi.fn((_root, _script, args) => {
      expect(args).toEqual(['--dry-run', '--write-only'])
      return 0
    })
    expect(runBumpOverlay(root, ['--dry-run'], runner)).toEqual([])
    expect(read(root, 'Cargo.toml')).toBe(cargo)
    expect(read(root, 'Cargo.lock')).toBe(lock)
  })

  test('canonical failure does not write Cargo files', () => {
    const root = makeFixture()
    const cargo = read(root, 'Cargo.toml')
    const lock = read(root, 'Cargo.lock')
    expect(() => runBumpOverlay(root, [], () => 1)).toThrow(
      /Canonical npm bump exited 1/u,
    )
    expect(read(root, 'Cargo.toml')).toBe(cargo)
    expect(read(root, 'Cargo.lock')).toBe(lock)
  })

  test('missing required lock entries fail before writing Cargo files', () => {
    const root = makeFixture()
    const cargo = read(root, 'Cargo.toml')
    const lockPath = path.join(root, 'Cargo.lock')
    const lock = read(root, 'Cargo.lock').replace(
      '[[package]]\nname = "abitious-bind"\nversion = "0.1.0"\n\n',
      '',
    )
    writeFileSync(lockPath, lock)
    expect(() => syncCargoVersion(root, '0.2.0')).toThrow(/abitious-bind/u)
    expect(read(root, 'Cargo.toml')).toBe(cargo)
    expect(read(root, 'Cargo.lock')).toBe(lock)
  })

  test('rejects a lower target and mismatched internal pins without Cargo writes', () => {
    const root = makeFixture()
    const original = read(root, 'Cargo.toml')
    expect(() => syncCargoVersion(root, '0.0.9')).toThrow(/cannot move down/u)
    writeFileSync(
      path.join(root, 'Cargo.toml'),
      original.replace('version = "0.1.0" }', 'version = "0.1.1" }'),
    )
    const mismatch = read(root, 'Cargo.toml')
    expect(() => syncCargoVersion(root, '0.2.0')).toThrow(
      /internal path versions/u,
    )
    expect(read(root, 'Cargo.toml')).toBe(mismatch)
  })

  test('accepts a missing optional fuzz lockfile', () => {
    const root = makeFixture()
    rmSync(path.join(root, 'fuzz', 'Cargo.lock'))
    expect(syncCargoVersion(root, '0.2.0')).toEqual([
      'Cargo.toml',
      'Cargo.lock',
    ])
  })
})
