import path from 'node:path'

export * from '../../fleet/paths.mts'

export function resolveNpmCliPackageJsonPath(root: string): string {
  return path.join(root, 'npm', 'cli', 'package.json')
}
