import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import crypto from 'node:crypto'
import path from 'node:path'
import { parseArgs } from 'node:util'

import { getScriptArgs } from '../fleet/process/script-output.mts'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/main/run.mts'

import type { ScriptMeta } from '../fleet/process/main/run.mts'

import { isPlainObject } from '@socketsecurity/lib-stable/objects/predicates'

import { FFI_STUB_NODE, TARGETS } from './targets.mts'

export interface FfiTemplatePartMetadata {
  schemaVersion: 1
  producerSha: string
  target: string
  path: 'template/ffi-stub.node'
  sha512: string
}

export interface FfiTemplateManifest {
  schemaVersion: 1
  producerSha: string
  templates: Array<{
    target: string
    path: string
    sha512: string
  }>
}

export interface FfiProducerBundleManifest {
  schemaVersion: 1
  producerSha: string
  packages: Array<{
    target: string
    path: string
    abiPath: string
    abiSha512: string
    templateManifestPath: string
    templateManifestSha512: string
  }>
}

interface StageConfig {
  packageDir: string
  templateFile: string
  producerSha: string
  outDir: string
}

interface AggregateConfig {
  partsDir: string
  producerSha: string
  outDir: string
}

interface ValidatedPart {
  target: string
  packageDir: string
  templateFile: string
  sha512: string
}

const SHA512_RE = /^[a-f0-9]{128}$/u
const SOURCE_SHA_RE = /^[a-f0-9]{40}$/u

function digestFile(filePath: string): string {
  return crypto
    .createHash('sha512')
    .update(readFileSync(filePath))
    .digest('hex')
}

function assertRegularFile(filePath: string, label: string): void {
  const info = lstatSync(filePath, { throwIfNoEntry: false })
  if (!info?.isFile() || info.isSymbolicLink()) {
    throw new Error(
      `${label} is not a regular file. Where: ${filePath}. Saw a missing file or a link; wanted a regular file. Fix: rebuild the target artifact and retry.`,
    )
  }
}

function assertPlainTree(directory: string): void {
  const info = lstatSync(directory, { throwIfNoEntry: false })
  if (!info?.isDirectory() || info.isSymbolicLink()) {
    throw new Error(
      `The package input is not a regular directory. Where: ${directory}. Saw a missing directory or a link; wanted a local package tree. Fix: stage the platform package before aggregation.`,
    )
  }
  const names = readdirSync(directory)
  for (let index = 0, { length } = names; index < length; index += 1) {
    const child = path.join(directory, names[index]!)
    const entry = lstatSync(child)
    if (entry.isSymbolicLink()) {
      throw new Error(
        `The package input contains a link. Where: ${child}. Saw a symbolic link; wanted regular package files. Fix: rebuild the platform package without links.`,
      )
    }
    if (entry.isDirectory()) {
      assertPlainTree(child)
    } else if (!entry.isFile()) {
      throw new Error(
        `The package input contains a non-file entry. Where: ${child}. Saw a special file; wanted regular files and directories. Fix: rebuild the platform package.`,
      )
    }
  }
}

function expectedTargets(): string[] {
  return TARGETS.map(target => target.triple).toSorted()
}

function validProducerSha(producerSha: string): void {
  if (!SOURCE_SHA_RE.test(producerSha)) {
    throw new Error(
      'The producer revision is invalid. Where: --producer-sha. Saw a value other than a 40-character lowercase Git SHA; wanted an immutable source revision. Fix: pass the exact workflow source SHA.',
    )
  }
}

function emptyOutputDirectory(directory: string): void {
  const info = lstatSync(directory, { throwIfNoEntry: false })
  if (info) {
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      readdirSync(directory).length > 0
    ) {
      throw new Error(
        `The output directory is not empty. Where: ${directory}. Saw an existing entry; wanted a new output directory. Fix: choose a fresh path.`,
      )
    }
  } else {
    mkdirSync(directory, { recursive: true })
  }
}

export function stageFfiTemplatePart(
  targetName: string,
  config: StageConfig,
): FfiTemplatePartMetadata {
  const target = TARGETS.find(item => item.triple === targetName)
  if (!target) {
    throw new Error(
      `The target is unsupported. Where: --target. Saw ${targetName}; wanted one of ${expectedTargets().join(', ')}. Fix: select a target from scripts/repo/targets.mts.`,
    )
  }
  validProducerSha(config.producerSha)
  assertPlainTree(config.packageDir)
  const packageJsonPath = path.join(config.packageDir, 'package.json')
  assertRegularFile(packageJsonPath, 'The platform manifest')
  const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
  if (!isPlainObject(packageJson)) {
    throw new Error(
      `The platform manifest is not a JSON object: ${packageJsonPath}.`,
    )
  }
  if (packageJson['name'] !== `@abitious/${target.triple}`) {
    throw new Error(
      `The package target does not match its artifact. Where: ${packageJsonPath}. Saw ${String(packageJson['name'])}; wanted @abitious/${target.triple}. Fix: regenerate the platform package manifest.`,
    )
  }
  assertRegularFile(config.templateFile, 'The FFI template')
  if (existsSync(path.join(config.packageDir, 'templates'))) {
    throw new Error(
      `The source package already contains templates. Where: ${config.packageDir}. Saw pre-existing template files; wanted a platform package before aggregation. Fix: remove stale build output and retry.`,
    )
  }
  emptyOutputDirectory(config.outDir)

  const templateFile = path.join(config.outDir, 'template', FFI_STUB_NODE)
  const packageOutput = path.join(config.outDir, 'package')
  mkdirSync(path.dirname(templateFile), { recursive: true })
  copyFileSync(config.templateFile, templateFile)
  cpSync(config.packageDir, packageOutput, {
    recursive: true,
    errorOnExist: true,
  })
  const metadata: FfiTemplatePartMetadata = {
    schemaVersion: 1,
    producerSha: config.producerSha,
    target: target.triple,
    path: `template/${FFI_STUB_NODE}`,
    sha512: digestFile(templateFile),
  }
  writeFileSync(
    path.join(config.outDir, 'part.json'),
    `${JSON.stringify(metadata, null, 2)}\n`,
  )
  return metadata
}

function validatePart(
  artifactDir: string,
  target: string,
  producerSha: string,
): ValidatedPart {
  const metadataPath = path.join(artifactDir, 'part.json')
  const templateFile = path.join(artifactDir, 'template', FFI_STUB_NODE)
  const packageDir = path.join(artifactDir, 'package')
  assertRegularFile(metadataPath, 'The template part manifest')
  assertRegularFile(templateFile, 'The FFI template')
  assertPlainTree(packageDir)

  const metadata: unknown = JSON.parse(readFileSync(metadataPath, 'utf8'))
  if (!isPlainObject(metadata)) {
    throw new Error(
      `The template part manifest is not a JSON object: ${metadataPath}.`,
    )
  }
  const actualDigest = digestFile(templateFile)
  if (
    metadata['schemaVersion'] !== 1 ||
    metadata['producerSha'] !== producerSha ||
    metadata['target'] !== target ||
    metadata['path'] !== `template/${FFI_STUB_NODE}` ||
    typeof metadata['sha512'] !== 'string' ||
    !SHA512_RE.test(metadata['sha512']) ||
    metadata['sha512'] !== actualDigest
  ) {
    throw new Error(
      `The template part failed verification. Where: ${artifactDir}. Saw target, source SHA, path, or SHA-512 metadata that did not match; wanted the verified ${target} artifact from ${producerSha}. Fix: rebuild this target from the selected workflow run.`,
    )
  }

  const packageJsonPath = path.join(packageDir, 'package.json')
  assertRegularFile(packageJsonPath, 'The platform manifest')
  const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
  if (!isPlainObject(packageJson)) {
    throw new Error(
      `The platform manifest is not a JSON object: ${packageJsonPath}.`,
    )
  }
  if (packageJson['name'] !== `@abitious/${target}`) {
    throw new Error(
      `The package target does not match its template. Where: ${packageJsonPath}. Saw ${String(packageJson['name'])}; wanted @abitious/${target}. Fix: rebuild the target package in the same workflow run.`,
    )
  }
  const part: ValidatedPart = {
    target,
    packageDir,
    templateFile,
    sha512: actualDigest,
  }
  Object.setPrototypeOf(part, null)
  return part
}

export function aggregateFfiTemplateParts(
  config: AggregateConfig,
): FfiProducerBundleManifest {
  validProducerSha(config.producerSha)
  const targetTriples = expectedTargets()
  const partNames = readdirSync(config.partsDir).toSorted()
  const expectedNames = targetTriples
    .map(target => `abitious-ffi-source-${target}`)
    .toSorted()
  if (JSON.stringify(partNames) !== JSON.stringify(expectedNames)) {
    throw new Error(
      `The template artifact set is incomplete or has duplicate targets. Where: ${config.partsDir}. Saw ${partNames.join(', ') || 'no parts'}; wanted exactly ${expectedNames.join(', ')}. Fix: run all eight target builds from one workflow SHA.`,
    )
  }
  const parts = targetTriples.map(target =>
    validatePart(
      path.join(config.partsDir, `abitious-ffi-source-${target}`),
      target,
      config.producerSha,
    ),
  )
  emptyOutputDirectory(config.outDir)

  const templateRows = parts.map(part => ({
    __proto__: null,
    target: part.target,
    path: `templates/${part.target}/${FFI_STUB_NODE}`,
    sha512: part.sha512,
  }))
  const templateManifest: FfiTemplateManifest = {
    schemaVersion: 1,
    producerSha: config.producerSha,
    templates: templateRows,
  }
  Object.setPrototypeOf(templateManifest, null)
  const packageRows: FfiProducerBundleManifest['packages'] = []

  for (let index = 0, { length } = parts; index < length; index += 1) {
    const part = parts[index]!
    const packageOutput = path.join(config.outDir, part.target)
    cpSync(part.packageDir, packageOutput, {
      recursive: true,
      errorOnExist: true,
    })
    const templatesDirectory = path.join(packageOutput, 'templates')
    mkdirSync(templatesDirectory)
    for (
      let templateIndex = 0, { length: templateCount } = parts;
      templateIndex < templateCount;
      templateIndex += 1
    ) {
      const templatePart = parts[templateIndex]!
      const templateDirectory = path.join(
        templatesDirectory,
        templatePart.target,
      )
      mkdirSync(templateDirectory)
      copyFileSync(
        templatePart.templateFile,
        path.join(templateDirectory, FFI_STUB_NODE),
      )
    }
    const templateManifestPath = path.join(templatesDirectory, 'manifest.json')
    writeFileSync(
      templateManifestPath,
      `${JSON.stringify(templateManifest, null, 2)}\n`,
    )
    const packageJson: unknown = JSON.parse(
      readFileSync(path.join(packageOutput, 'package.json'), 'utf8'),
    )
    if (!isPlainObject(packageJson)) {
      throw new Error(
        `The platform manifest is not a JSON object: ${part.target}/package.json.`,
      )
    }
    const allowedFiles = new Set(
      Array.isArray(packageJson['files'])
        ? packageJson['files'].filter(
            (file): file is string => typeof file === 'string',
          )
        : [],
    )
    for (
      let rowIndex = 0, { length: rowCount } = templateRows;
      rowIndex < rowCount;
      rowIndex += 1
    ) {
      const row = templateRows[rowIndex]!
      if (!allowedFiles.has(row.path)) {
        throw new Error(
          `The package file list omits a verified template. Where: ${part.target}/package.json. Saw no ${row.path} entry; wanted every target template. Fix: regenerate manifests from scripts/repo/targets.mts.`,
        )
      }
    }
    if (!allowedFiles.has('LICENSE')) {
      throw new Error(
        `The package file list omits its license. Where: ${part.target}/package.json. Saw no LICENSE entry; wanted the package license with the native binaries. Fix: regenerate manifests from scripts/repo/targets.mts.`,
      )
    }
    if (!allowedFiles.has('THIRD-PARTY-NOTICES.md')) {
      throw new Error(
        `The package file list omits third-party notices. Where: ${part.target}/package.json. Saw no THIRD-PARTY-NOTICES.md entry; wanted license notices with the native binaries. Fix: regenerate manifests from scripts/repo/targets.mts.`,
      )
    }
    if (!allowedFiles.has('templates/manifest.json')) {
      throw new Error(
        `The package file list omits the template manifest. Where: ${part.target}/package.json. Saw no templates/manifest.json entry; wanted the verified template index. Fix: regenerate manifests from scripts/repo/targets.mts.`,
      )
    }
    const abiName =
      TARGETS.find(target => target.triple === part.target)!.os === 'win32'
        ? 'abi.exe'
        : 'abi'
    const abiPath = path.join(packageOutput, abiName)
    assertRegularFile(abiPath, 'The producer CLI')
    const target = TARGETS.find(item => item.triple === part.target)!
    if (target.os !== 'win32') {
      chmodSync(abiPath, 0o755)
    }
    const packageRow: FfiProducerBundleManifest['packages'][number] = {
      target: part.target,
      path: part.target,
      abiPath: `${part.target}/${abiName}`,
      abiSha512: digestFile(abiPath),
      templateManifestPath: `${part.target}/templates/manifest.json`,
      templateManifestSha512: digestFile(templateManifestPath),
    }
    Object.setPrototypeOf(packageRow, null)
    packageRows.push(packageRow)
  }

  const bundleManifest: FfiProducerBundleManifest = {
    schemaVersion: 1,
    producerSha: config.producerSha,
    packages: packageRows,
  }
  Object.setPrototypeOf(bundleManifest, null)
  writeFileSync(
    path.join(config.outDir, 'bundle-manifest.json'),
    `${JSON.stringify(bundleManifest, null, 2)}\n`,
  )
  return bundleManifest
}

function requiredOption(
  values: Record<string, string | boolean | undefined>,
  key: string,
): string {
  const value = values[key]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Missing required option --${key}.`)
  }
  return value
}

function main(): { exitCode: number; data?: unknown | undefined } {
  const { positionals, values } = parseArgs({
    args: getScriptArgs(),
    options: {
      target: { type: 'string' },
      package: { type: 'string' },
      template: { type: 'string' },
      'producer-sha': { type: 'string' },
      out: { type: 'string' },
      parts: { type: 'string' },
    },
    allowPositionals: true,
  })
  const action = positionals[0]
  if (action === 'stage') {
    const result = stageFfiTemplatePart(requiredOption(values, 'target'), {
      packageDir: requiredOption(values, 'package'),
      templateFile: requiredOption(values, 'template'),
      producerSha: requiredOption(values, 'producer-sha'),
      outDir: requiredOption(values, 'out'),
    })
    return { exitCode: 0, data: result }
  }
  if (action === 'aggregate') {
    const result = aggregateFfiTemplateParts({
      partsDir: requiredOption(values, 'parts'),
      producerSha: requiredOption(values, 'producer-sha'),
      outDir: requiredOption(values, 'out'),
    })
    return { exitCode: 0, data: result }
  }
  throw new Error('Select `stage` or `aggregate`.')
}

const SCRIPT_META: ScriptMeta = {
  describe: 'stages and verifies native FFI templates for producer bundles',
  help: `Usage: node scripts/repo/ffi-templates.mts <stage|aggregate> [options]

  stage --target <triple> --package <dir> --template <file> --producer-sha <sha> --out <dir>
  aggregate --parts <dir> --producer-sha <sha> --out <dir>
  --json  emit a structured result`,
  json: 'result',
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
