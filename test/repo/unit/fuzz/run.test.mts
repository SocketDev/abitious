import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect, test } from 'vitest'
import { getEnvValue } from '@socketsecurity/lib-stable/env/rewire'

const runner = fileURLToPath(
  new URL('../../../../fuzz/run.sh', import.meta.url),
)

function makeFixture(options: { host?: string; fails?: boolean } = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'fuzz-host-target-'))
  const bin = path.join(root, 'bin')
  mkdirSync(bin)
  writeFileSync(
    path.join(bin, 'rustc'),
    options.fails
      ? '#!/bin/sh\nexit 1\n'
      : `#!/bin/sh\nprintf '%s\\n' 'rustc fixture' 'host: ${options.host ?? ''}'\n`,
    { mode: 0o755 },
  )
  writeFileSync(
    path.join(bin, 'cargo'),
    '#!/bin/sh\nif [ "$2" = --version ]; then exit 0; fi\nprintf "%s\\0" "$@" >> "$FUZZ_CAPTURE"\n',
    { mode: 0o755 },
  )
  return { root, bin, capture: path.join(root, 'cargo-args') }
}

function runFixture(
  fixture: ReturnType<typeof makeFixture>,
  options: { target?: string } = {},
) {
  return spawnSync('bash', [runner, 'read_hybrid_node', '1'], {
    env: {
      PATH: `${fixture.bin}${path.delimiter}${getEnvValue('PATH') ?? ''}`,
      FUZZ_TOOLCHAIN: 'nightly',
      FUZZ_TARGET_TRIPLE: options.target ?? '',
      FUZZ_CAPTURE: fixture.capture,
      CARGO_BUILD_TARGET: 'x86_64-unknown-linux-musl',
    },
    encoding: 'utf8',
    timeout: 5000,
  })
}

function capturedArgs(file: string): string[] {
  return readFileSync(file, 'utf8').split('\0').filter(Boolean)
}

test.each(['x86_64-unknown-linux-gnu', 'aarch64-apple-darwin'])(
  'uses host %s instead of the Cargo build target',
  host => {
    const fixture = makeFixture({ host })
    try {
      const result = runFixture(fixture)
      expect(result.status, result.stderr).toBe(0)
      const args = capturedArgs(fixture.capture)
      expect(args.slice(0, 6)).toEqual([
        '+nightly',
        'fuzz',
        'run',
        '--target',
        host,
        'read_hybrid_node',
      ])
      expect(args.slice(6, 8)).toEqual(['--', '-max_total_time=1'])
      expect(args).toContain('-print_final_stats=1')
      expect(args).toContain('-timeout=10')
      expect(args).toContain('-rss_limit_mb=2048')
      expect(args).toContain('-max_len=65536')
      expect(args.some(value => value.startsWith('-dict='))).toBe(true)
    } finally {
      rmSync(fixture.root, { recursive: true, force: true })
    }
  },
)

test('explicit target skips host detection', () => {
  const fixture = makeFixture({ fails: true })
  try {
    const result = runFixture(fixture, { target: 'aarch64-unknown-linux-gnu' })
    expect(result.status, result.stderr).toBe(0)
    expect(capturedArgs(fixture.capture).slice(3, 5)).toEqual([
      '--target',
      'aarch64-unknown-linux-gnu',
    ])
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test.each([{ host: '' }, { fails: true }])(
  'rejects unavailable host metadata %j',
  options => {
    const fixture = makeFixture(options)
    try {
      const result = runFixture(fixture)
      expect(result.status, result.stderr).toBe(1)
      expect(result.signal).toBeNull()
      expect(existsSync(fixture.capture)).toBe(false)
    } finally {
      rmSync(fixture.root, { recursive: true, force: true })
    }
  },
)
