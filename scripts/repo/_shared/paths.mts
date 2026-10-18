import path from 'node:path'

export function resolveNpmCliPackageJsonPath(root: string): string {
  return path.join(root, 'npm', 'cli', 'package.json')
}
