// The SINGLE SOURCE OF TRUTH for every platform abitious ships a prebuilt for.
//
// One list, four consumers — never duplicate it, always derive from it:
//   1. codegen (scripts/repo/gen-packages.mts)        → each @abitious/<triple> package.json
//                                                   + @abitious/cli optionalDependencies
//                                                   + npm/cli/targets.generated.json (loader data)
//   2. the runtime loader (npm/cli/index.cjs)     → via the generated targets.generated.json
//   3. the CI matrices (.github/workflows/*.yml) → via `gen-packages --print-matrix`
//      (build.yml, the tier-1 push/PR subset) and `--print-matrix-all` (github-release.yml
//      + npm-publish.yml, all targets for a release)
//   4. the Rust stub auto-resolver (crates/abitious/src/triple.rs) → the SAME
//      `<os>-<arch>[-<abi>]` naming rule, locked by a table-driven unit test.
//
// These are ADDONS + host build tools distributed on npm, so the triple follows
// napi-rs's `platformArchABI` (`<platform>-<arch>[-<abi>]`) where the abi is
// explicit: glibc Linux is `-gnu`, musl Linux is `-musl`, Windows is `-msvc`,
// macOS none. The abi must be in the name because a native artifact built against
// one C library cannot load on another, and glibc/musl hosts genuinely coexist.
// `libc` is also emitted as the npm install gate.

export interface Target {
  /**
   * The npm suffix / package name tail: `@abitious/<triple>`.
   */
  triple: string
  /**
   * Npm `os` gate + `process.platform` value: darwin | linux | win32.
   */
  os: string
  /**
   * Npm `cpu` gate + `process.arch` value: arm64 | x64 | ia32 | arm.
   */
  cpu: string
  /**
   * Npm `libc` gate — glibc | musl on Linux, omitted elsewhere.
   */
  libc?: string | undefined
  /**
   * The Rust target triple `cargo build --target` / `rustup target add` uses.
   */
  rust: string
  /**
   * The GitHub Actions runner label to build this target on.
   */
  runner: string
  /**
   * Tier-1 targets build in the FAST push/PR CI matrix (build.yml) — native on
   * their runner, no cross C toolchain. Tier-2 targets — musl (zstd-sys needs a
   * musl C toolchain) and Windows — are EXCLUDED from that fast subset
   * (`--print-matrix`) but ARE built + shipped in the full RELEASE matrix
   * (`--print-matrix-all`, used by github-release.yml + npm-publish.yml). Every
   * target is always generated as an.
   *
   * @abitious/<triple> manifest + optionalDependency regardless of tier; `tier1` only
   * selects the fast push/PR build subset.
   */
  tier1?: boolean | undefined
}

// The 8 napi-compress defaults.
export const TARGETS: Target[] = [
  {
    triple: 'darwin-arm64',
    os: 'darwin',
    cpu: 'arm64',
    rust: 'aarch64-apple-darwin',
    runner: 'macos-14',
    tier1: true,
  },
  {
    triple: 'darwin-x64',
    os: 'darwin',
    cpu: 'x64',
    rust: 'x86_64-apple-darwin',
    runner: 'macos-13',
    tier1: true,
  },
  {
    triple: 'linux-x64-gnu',
    os: 'linux',
    cpu: 'x64',
    libc: 'glibc',
    rust: 'x86_64-unknown-linux-gnu',
    runner: 'ubuntu-latest',
    tier1: true,
  },
  {
    triple: 'linux-arm64-gnu',
    os: 'linux',
    cpu: 'arm64',
    libc: 'glibc',
    rust: 'aarch64-unknown-linux-gnu',
    runner: 'ubuntu-24.04-arm',
    tier1: true,
  },
  {
    triple: 'linux-x64-musl',
    os: 'linux',
    cpu: 'x64',
    libc: 'musl',
    rust: 'x86_64-unknown-linux-musl',
    runner: 'ubuntu-latest',
  },
  {
    triple: 'linux-arm64-musl',
    os: 'linux',
    cpu: 'arm64',
    libc: 'musl',
    rust: 'aarch64-unknown-linux-musl',
    runner: 'ubuntu-24.04-arm',
  },
  {
    triple: 'win32-x64-msvc',
    os: 'win32',
    cpu: 'x64',
    rust: 'x86_64-pc-windows-msvc',
    runner: 'windows-latest',
  },
  {
    triple: 'win32-arm64-msvc',
    os: 'win32',
    cpu: 'arm64',
    rust: 'aarch64-pc-windows-msvc',
    runner: 'windows-11-arm',
  },
]

/**
 * The cargo cdylib basename for the generic stub on `os`. cargo prefixes `lib`
 * on Unix and appends the platform extension; Windows has no prefix. Kept in
 * lockstep with `abitious-stub`'s `[lib]` (crate name `abitious_stub`, dashes →
 * underscores).
 */
export function stubArtifact(os: string): string {
  switch (os) {
    case 'darwin':
      return 'libabitious_stub.dylib'
    case 'win32':
      return 'abitious_stub.dll'
    default:
      return 'libabitious_stub.so'
  }
}

/**
 * The prebuilt stub `.node` filename inside each @abitious/<triple> package.
 */
export const STUB_NODE = 'stub.node'

/**
 * The host `abi` CLI binary name inside each package (`.exe` on Windows).
 */
export function abiBin(os: string): string {
  return os === 'win32' ? 'abi.exe' : 'abi'
}
