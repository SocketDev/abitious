// No-network, no-fs unit tests for the pure release helpers. Run: node --test.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  bumpNpmManifest,
  bumpWorkspaceCargo,
  changelogSection,
  promoteChangelog,
  resolveRelease,
  workspaceVersion,
} from './release-lib.mts'

test('resolveRelease: prerelease hint finalizes, arg bumps, else as-committed', () => {
  assert.deepEqual(resolveRelease('0.1.1-prerelease', ''), {
    version: '0.1.1',
    mode: 'finalize',
  })
  assert.deepEqual(resolveRelease('0.1.0', '0.2.0'), { version: '0.2.0', mode: 'bump' })
  assert.deepEqual(resolveRelease('0.1.0', ''), { version: '0.1.0', mode: 'as-committed' })
  // An arg equal to the current version is not a bump.
  assert.deepEqual(resolveRelease('0.1.0', '0.1.0'), {
    version: '0.1.0',
    mode: 'as-committed',
  })
})

const CARGO = `[workspace]
members = ["crates/a"]

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
abitious-decmpfs = { path = "crates/abitious-decmpfs", version = "0.1.0" }
windows-sys = { version = "0.59", features = ["x"] }
`

test('workspaceVersion reads [workspace.package] version', () => {
  assert.equal(workspaceVersion(CARGO), '0.1.0')
  assert.equal(workspaceVersion('[workspace]\nmembers = []\n'), undefined)
})

test('bumpWorkspaceCargo bumps workspace + internal pins, not external deps', () => {
  const out = bumpWorkspaceCargo(CARGO, '0.2.0')
  assert.match(out, /\[workspace\.package\]\nversion = "0\.2\.0"/)
  assert.match(out, /abitious-decmpfs = \{ path = "crates\/abitious-decmpfs", version = "0\.2\.0" \}/)
  assert.match(out, /windows-sys = \{ version = "0\.59"/, 'external dep version untouched')
})

test('bumpNpmManifest sets version + scoped optionalDependencies only', () => {
  const src = JSON.stringify(
    {
      name: '@abitious/cli',
      version: '0.1.0',
      optionalDependencies: { '@abitious/darwin-arm64': '0.1.0', 'other-dep': '^1.0.0' },
    },
    null,
    2,
  )
  const out = JSON.parse(bumpNpmManifest(src, '0.2.0', '@abitious/'))
  assert.equal(out.version, '0.2.0')
  assert.equal(out.optionalDependencies['@abitious/darwin-arm64'], '0.2.0')
  assert.equal(out.optionalDependencies['other-dep'], '^1.0.0', 'non-scoped dep untouched')
})

test('promoteChangelog: renames [Unreleased], keeps an existing section, else stubs', () => {
  const unreleased = '# Changelog\n\n## [Unreleased]\n\n- a change\n'
  const p1 = promoteChangelog(unreleased, '0.1.0')
  assert.ok(p1.changed && p1.hasSection)
  assert.match(p1.text, /\n## 0\.1\.0\n\n- a change/)
  assert.doesNotMatch(p1.text, /\[Unreleased\]/)

  const existing = '# Changelog\n\n## 0.1.0\n\n- a change\n'
  const p2 = promoteChangelog(existing, '0.1.0')
  assert.ok(!p2.changed && p2.hasSection)
  assert.equal(p2.text, existing)

  const none = '# Changelog\n\n## 0.0.9\n\n- old\n'
  const p3 = promoteChangelog(none, '0.1.0')
  assert.ok(p3.changed && !p3.hasSection)
  assert.match(p3.text, /## 0\.1\.0\n\n- TODO/)
})

test('changelogSection extracts the version body until the next heading', () => {
  const src = '# Changelog\n\n## 0.1.0\n\n- one\n- two\n\n## 0.0.9\n\n- old\n'
  assert.equal(changelogSection(src, '0.1.0'), '- one\n- two')
  assert.equal(changelogSection(src, '9.9.9'), '')
})
