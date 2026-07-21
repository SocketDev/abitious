// Pure, side-effect-free helpers for the abitious release entry (release.mts).
// Kept importable + no-I/O so they can be unit-tested with no network and no
// filesystem — the release script wires these to real files, git, and cargo.

export interface Resolution {
  version: string
  mode: 'finalize' | 'bump' | 'as-committed'
}

// Resolve the version to release from the committed workspace version and an
// optional explicit arg:
//   - a `-prerelease` (or any `-suffix`) committed version + no arg → FINALIZE
//     to the plain semver (0.1.1-prerelease → 0.1.1);
//   - a new semver arg → BUMP;
//   - otherwise release WHAT IS COMMITTED (first release of an already-set
//     version, e.g. debuting 0.1.0).
export function resolveRelease(current: string, arg: string): Resolution {
  const pre = current.match(/^(?<base>\d+\.\d+\.\d+)-[0-9A-Za-z.-]+$/)
  if (pre && !arg) {
    return { version: pre.groups!['base']!, mode: 'finalize' }
  }
  if (arg && arg !== current) {
    return { version: arg, mode: 'bump' }
  }
  return { version: current, mode: 'as-committed' }
}

// Read `[workspace.package] version` from a workspace Cargo.toml.
export function workspaceVersion(cargoToml: string): string | undefined {
  return cargoToml.match(
    /\[workspace\.package\][^[]*?\nversion\s*=\s*"(?<version>[^"]+)"/,
  )?.groups?.['version']
}

// Rewrite the workspace version and every internal `path = "crates/…", version =
// "…"` pin to `version`. External dep versions (no `path = "crates/"`) are left
// untouched.
export function bumpWorkspaceCargo(cargoToml: string, version: string): string {
  return cargoToml
    .replace(
      /(\[workspace\.package\][^[]*?\nversion\s*=\s*")[^"]+(")/,
      `$1${version}$2`,
    )
    .replace(
      /(path = "crates\/[^"]+", version = ")[^"]+(")/g,
      `$1${version}$2`,
    )
}

// Set an npm manifest's version and any `scope`-prefixed optionalDependencies to
// `version`, preserving 2-space formatting.
export function bumpNpmManifest(
  json: string,
  version: string,
  scope: string,
): string {
  const pkg = JSON.parse(json) as {
    version?: string
    optionalDependencies?: Record<string, string> | undefined
  }
  pkg.version = version
  const opt = pkg.optionalDependencies
  if (opt) {
    for (const name of Object.keys(opt)) {
      if (name.startsWith(scope)) {
        opt[name] = version
      }
    }
  }
  return JSON.stringify(pkg, null, 2) + '\n'
}

export interface ChangelogPromotion {
  text: string
  changed: boolean
  // Whether the result has a real `## <version>` section (vs a stub needing prose).
  hasSection: boolean
}

// Promote the CHANGELOG for a release: keep an existing `## <version>` verbatim;
// else rename the `## [Unreleased]` heading to `## <version>`; else insert a
// TODO stub the release gate will reject until filled.
export function promoteChangelog(src: string, version: string): ChangelogPromotion {
  if (src.includes(`## ${version}`)) {
    return { text: src, changed: false, hasSection: true }
  }
  if (/\n## \[Unreleased\]/.test(src)) {
    return {
      text: src.replace(/\n## \[Unreleased\]/, `\n## ${version}`),
      changed: true,
      hasSection: true,
    }
  }
  return {
    text: src.replace(
      /\n## /,
      `\n## ${version}\n\n- TODO: describe the user-visible changes in this release.\n\n## `,
    ),
    changed: true,
    hasSection: false,
  }
}

// The body of the `## <version>` CHANGELOG section (until the next `## `), for the
// release gate to confirm it's real (non-empty, no TODO stub).
export function changelogSection(src: string, version: string): string {
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = src.match(new RegExp(`\\n## ${escaped}\\n(?<body>[\\s\\S]*?)(?:\\n## |$)`))
  return (match?.groups?.['body'] ?? '').trim()
}
