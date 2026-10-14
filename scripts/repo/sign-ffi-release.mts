import crypto from 'node:crypto'
import { lstatSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'

import { getEnvValue } from '@socketsecurity/lib-stable/env/rewire'
import { isPlainObject } from '@socketsecurity/lib-stable/objects/predicates'
import { spawn } from '@socketsecurity/lib-stable/process/spawn/child'

import { developerIdSign } from '../fleet/apple-sign.mts'
import type { DeveloperIdSignOptions } from '../fleet/apple-sign.mts'
import { notarizeMachO } from '../fleet/apple-notarize.mts'
import type { AppleNotarizationReceipt } from '../fleet/apple-notarize.mts'
import { ffiArtifact, TARGETS } from './targets.mts'
import { getDeveloperIdIdentityLabel } from '../fleet/registry/apple/identity.mts'
import { withTemporaryAppleKeychain } from '../fleet/registry/apple/ci/keychain.mts'
import { isMainModule } from '../fleet/process/is-main-module.mts'
import { runMain } from '../fleet/process/main/run.mts'
import { getScriptArgs } from '../fleet/process/script-output.mts'

import type { ScriptMeta } from '../fleet/process/main/run.mts'

export interface FfiMacosSigningReceipt {
  schemaVersion: 1
  producerSha: string
  target: string
  files: Array<{
    path: string
    sha512: string
    submissionId: string
  }>
}

export interface SignFfiReleaseConfig {
  target: string
  packageDir: string
  templateFile: string
  producerSha: string
  outputFile: string
  certificateBase64: string
  certificatePassword: string
  identityLabel: string
}

export interface SignFfiReleaseAdapters {
  withKeychain: typeof withTemporaryAppleKeychain
  sign: (
    binaryPath: string,
    options?: DeveloperIdSignOptions | undefined,
  ) => Promise<boolean>
  verify: (filePath: string) => Promise<void>
  notarize: (binaryPath: string) => Promise<AppleNotarizationReceipt | false>
}

const SHA512_RE = /^[a-f0-9]{128}$/u
const SOURCE_SHA_RE = /^[a-f0-9]{40}$/u
const SUBMISSION_ID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu

function digestFile(filePath: string): string {
  return crypto
    .createHash('sha512')
    .update(readFileSync(filePath))
    .digest('hex')
}

function releaseFilePaths(target: string): string[] {
  const platform = TARGETS.find(item => item.triple === target)
  if (!platform || platform.os !== 'darwin') {
    throw new Error(
      `What: macOS release signing needs a Darwin target. Where: --target. Saw ${target}; wanted darwin-arm64 or darwin-x64. Fix: select a Darwin target.`,
    )
  }
  return [
    'package/abi',
    'package/bind.node',
    `package/${ffiArtifact(platform.os)}`,
    'package/stub.node',
    'template/ffi-stub.node',
  ].toSorted((left, right) => left.localeCompare(right))
}

function assertMacosSigningReceiptHeader(
  value: Record<string, unknown>,
  rows: unknown[],
  config: { producerSha: string; target: string },
  expectedPaths: string[],
): void {
  const actualPaths = rows.filter(isPlainObject).map(file => file['path'])
  if (
    value['schemaVersion'] !== 1 ||
    value['producerSha'] !== config.producerSha ||
    value['target'] !== config.target ||
    rows.length !== expectedPaths.length ||
    actualPaths.length !== expectedPaths.length ||
    JSON.stringify(
      actualPaths.toSorted((left, right) =>
        String(left).localeCompare(String(right)),
      ),
    ) !== JSON.stringify(expectedPaths)
  ) {
    throw new Error(
      'What: the macOS signing receipt does not match the release binaries. Where: macos-signing.json. Saw an incomplete or different target record; wanted the exact target files from this workflow SHA. Fix: rerun signing and notarization.',
    )
  }
}

function validateMacosSigningRows(
  rows: unknown[],
  expectedPaths: string[],
  config: { packageDir: string; templateFile: string },
): FfiMacosSigningReceipt['files'] {
  const packageRoot = path.resolve(config.packageDir)
  const templateFile = path.resolve(config.templateFile)
  const files: FfiMacosSigningReceipt['files'] = []
  for (let index = 0, { length } = rows; index < length; index += 1) {
    const entry = rows[index]!
    if (!isPlainObject(entry) || typeof entry['path'] !== 'string') {
      throw new Error('The macOS signing receipt has an invalid file row.')
    }
    const relativePath = entry['path']
    if (!expectedPaths.includes(relativePath)) {
      throw new Error('The macOS signing receipt has an unexpected file row.')
    }
    const filePath =
      relativePath === 'template/ffi-stub.node'
        ? templateFile
        : path.join(packageRoot, relativePath.slice('package/'.length))
    if (
      typeof entry['sha512'] !== 'string' ||
      !SHA512_RE.test(entry['sha512']) ||
      entry['sha512'] !== digestFile(filePath) ||
      typeof entry['submissionId'] !== 'string' ||
      !SUBMISSION_ID_RE.test(entry['submissionId'])
    ) {
      throw new Error(
        `What: a macOS binary lacks verified signing evidence. Where: ${relativePath}. Saw a hash or notarization receipt mismatch; wanted matching signed bytes and an accepted Apple submission. Fix: rerun the macOS release gate.`,
      )
    }
    files.push({
      path: relativePath,
      sha512: entry['sha512'],
      submissionId: entry['submissionId'],
    })
  }
  return files
}

export function validateFfiMacosSigningReceipt(
  value: unknown,
  config: {
    producerSha: string
    target: string
    packageDir: string
    templateFile: string
  },
): FfiMacosSigningReceipt {
  const expectedPaths = releaseFilePaths(config.target)
  if (!isPlainObject(value) || !Array.isArray(value['files'])) {
    throw new Error(
      'What: the macOS signing receipt is invalid. Where: macos-signing.json. Saw no file list; wanted a Developer ID and notarization record for every binary. Fix: rebuild the signed target.',
    )
  }
  const rows = value['files']
  assertMacosSigningReceiptHeader(value, rows, config, expectedPaths)
  const receipt: FfiMacosSigningReceipt = {
    schemaVersion: 1,
    producerSha: config.producerSha,
    target: config.target,
    files: validateMacosSigningRows(rows, expectedPaths, config),
  }
  Object.setPrototypeOf(receipt, null)
  return receipt
}

function assertRegularFile(filePath: string): void {
  const info = lstatSync(filePath, { throwIfNoEntry: false })
  if (!info?.isFile() || info.isSymbolicLink()) {
    throw new Error(
      `What: a macOS release binary is missing. Where: ${filePath}. Saw no regular file; wanted a file from the native build. Fix: rebuild the target before signing.`,
    )
  }
}

async function verifyDeveloperSignature(filePath: string): Promise<void> {
  const result = await spawn(
    'codesign',
    ['--verify', '--strict', '--verbose=2', filePath],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  )
  if (result.code !== 0) {
    throw new Error(
      `What: Developer ID signature verification failed. Where: ${filePath}. Saw exit code ${result.code}; wanted a valid signature. Fix: inspect the codesign output and sign the release binary again.`,
    )
  }
}

export async function signFfiReleasePart(
  config: SignFfiReleaseConfig,
  adapters: SignFfiReleaseAdapters = {
    withKeychain: withTemporaryAppleKeychain,
    sign: developerIdSign,
    verify: verifyDeveloperSignature,
    notarize: notarizeMachO,
  },
): Promise<FfiMacosSigningReceipt> {
  if (!SOURCE_SHA_RE.test(config.producerSha)) {
    throw new Error(
      'What: the producer revision is invalid. Where: --producer-sha. Saw a value other than a 40-character lowercase Git SHA; wanted the workflow source SHA. Fix: pass the exact source revision.',
    )
  }
  const files = releaseFilePaths(config.target)
  const packageRoot = path.resolve(config.packageDir)
  const templateFile = path.resolve(config.templateFile)
  const resolvedFiles = files.map(file => ({
    __proto__: null,
    path: file,
    filePath:
      file === 'template/ffi-stub.node'
        ? templateFile
        : path.join(packageRoot, file.slice('package/'.length)),
  }))
  for (let index = 0, { length } = resolvedFiles; index < length; index += 1) {
    assertRegularFile(resolvedFiles[index]!.filePath)
  }

  const signedFiles: FfiMacosSigningReceipt['files'] = []
  await adapters.withKeychain(
    {
      certificateBase64: config.certificateBase64,
      p12Password: config.certificatePassword,
      identityLabel: config.identityLabel,
    },
    async identityHash => {
      for (
        let index = 0, { length } = resolvedFiles;
        index < length;
        index += 1
      ) {
        const file = resolvedFiles[index]!
        const signed = await adapters.sign(file.filePath, {
          identity: identityHash,
        })
        if (!signed) {
          throw new Error(
            `What: Developer ID signing did not run. Where: ${file.path}. Saw no macOS Mach-O signature; wanted a signed release binary. Fix: stop the public handoff and check the signing helper.`,
          )
        }
        await adapters.verify(file.filePath)
        const notarization = await adapters.notarize(file.filePath)
        if (
          !notarization ||
          notarization.status !== 'Accepted' ||
          !SUBMISSION_ID_RE.test(notarization.submissionId)
        ) {
          throw new Error(
            `What: Apple notarization did not finish. Where: ${file.path}. Saw no accepted submission; wanted a notarized release binary. Fix: check Apple credentials and the notary submission.`,
          )
        }
        signedFiles.push({
          path: file.path,
          sha512: digestFile(file.filePath),
          submissionId: notarization.submissionId,
        })
      }
    },
  )
  const receipt: FfiMacosSigningReceipt = {
    schemaVersion: 1,
    producerSha: config.producerSha,
    target: config.target,
    files: signedFiles,
  }
  Object.setPrototypeOf(receipt, null)
  writeFileSync(config.outputFile, `${JSON.stringify(receipt, null, 2)}\n`, {
    flag: 'wx',
  })
  return receipt
}

function requiredEnv(name: string): string {
  const value = getEnvValue(name)
  if (!value) {
    throw new Error(
      `What: Apple release signing configuration is missing. Where: ${name}. Saw an empty value; wanted signing or notarization credentials. Fix: configure the fleet Apple release credentials before tagging.`,
    )
  }
  return value
}

function main(): { exitCode: number; data?: unknown | undefined } {
  const { values } = parseArgs({
    args: getScriptArgs(),
    options: {
      target: { type: 'string' },
      package: { type: 'string' },
      template: { type: 'string' },
      'producer-sha': { type: 'string' },
      out: { type: 'string' },
    },
  })
  const optionValues: Record<string, string | boolean | undefined> = values
  const requiredOption = (key: string): string => {
    const value = optionValues[key]
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`Missing required option --${key}.`)
    }
    return value
  }
  const receipt = signFfiReleasePart({
    target: requiredOption('target'),
    packageDir: requiredOption('package'),
    templateFile: requiredOption('template'),
    producerSha: requiredOption('producer-sha'),
    outputFile: requiredOption('out'),
    certificateBase64: requiredEnv('APPLE_DEVELOPER_ID_APPLICATION_CERTS_P12'),
    certificatePassword: requiredEnv(
      'APPLE_DEVELOPER_ID_APPLICATION_CERTS_P12_PASS',
    ),
    identityLabel: getDeveloperIdIdentityLabel(),
  })
  return { exitCode: 0, data: receipt }
}

const SCRIPT_META: ScriptMeta = {
  describe: 'Developer ID signs and notarizes Darwin producer bundle binaries',
  help: `Usage: node scripts/repo/sign-ffi-release.mts --target <darwin-triple> --package <dir> --template <file> --producer-sha <sha> --out <receipt.json>

Requires the configured Developer ID certificate and Apple notarization credentials. It fails when either signing or notarization is unavailable.`,
  json: 'result',
}

if (isMainModule(import.meta.url)) {
  runMain(main, SCRIPT_META)
}
