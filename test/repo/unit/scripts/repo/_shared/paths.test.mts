import { expect, test } from 'vitest'

import { resolveNpmCliPackageJsonPath } from '../../../../../../scripts/repo/_shared/paths.mts'

test('resolveNpmCliPackageJsonPath owns the CLI manifest location', () => {
  expect(resolveNpmCliPackageJsonPath('/repo')).toBe(
    '/repo/npm/cli/package.json',
  )
})
