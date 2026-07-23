// Type declarations for @abitious/cli. Hand-maintained in lockstep with loader.cjs
// (this repo hand-rolls the loader + build rather than using napi CLI codegen).

/**
 * A resolved platform package: the paths its prebuilt artifacts live at.
 */
export interface PlatformResolution {
  /**
   * The resolved host triple, e.g. `darwin-arm64` / `linux-x64-gnu`.
   */
  triple: string
  /**
   * The platform package name, `@abitious/<triple>`.
   */
  pkg: string
  /**
   * The installed platform package's directory.
   */
  dir: string
  /**
   * Absolute path to the prebuilt generic stub `.node` for this host.
   */
  stub: string
  /**
   * Absolute path to the host `abi` producer binary (`abi.exe` on Windows).
   */
  bin: string
}

/**
 * A host descriptor — the fields of `process` the loader reads.
 */
export interface Host {
  /**
   * `process.platform`: `darwin` | `linux` | `win32`.
   */
  platform: string
  /**
   * `process.arch`: `arm64` | `x64` | `ia32` | `arm`.
   */
  arch: string
  /**
   * `process.report.getReport()` — present on glibc, absent/undefined on musl.
   */
  report?:
    | { header?: { glibcVersionRuntime?: string | undefined } | undefined }
    | undefined
}

/**
 * A supported target's data view (from targets.generated.json).
 */
export interface SupportedTarget {
  triple: string
  os: string
  cpu: string
  libc?: string | undefined
  bin: string
}

/**
 * The napi-rs addon abi suffix for a host: `-gnu` (glibc Linux), `-musl` (musl
 * Linux), `-msvc` (Windows), or `''` (macOS).
 */
export function abiSuffix(
  platform: string,
  // oxlint-disable-next-line typescript/no-duplicate-type-constituents -- fleet optional-explicit-undefined convention: the explicit | undefined on an optional is intentional, not redundant.
  report?: Host['report'] | undefined,
): string

/**
 * Map a host to its `@abitious/<triple>` triple (`<platform>-<arch>[-<abi>]`).
 */
export function hostTriple(host: Host): string

/**
 * Resolve the installed platform package for a host. `resolve` resolves
 * `<pkg>/package.json` to an absolute path (throws when not installed). Throws
 * an actionable error when no matching optional dependency is present.
 */
export function resolvePlatform(
  opts: Host & { resolve: (request: string) => string },
): PlatformResolution

/**
 * Resolve using the real `process` + `require.resolve`.
 */
export function loadPlatform(): PlatformResolution

/**
 * The supported targets (from targets.generated.json).
 */
export const SUPPORTED: readonly SupportedTarget[]

/**
 * The prebuilt stub `.node` filename inside each platform package.
 */
export const STUB_NODE: string
