import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { safeDeleteSync } from '@socketsecurity/lib-stable/fs/safe'
import { test } from 'vitest'

import { aggregateFfiTemplateParts } from '../../scripts/repo/ffi-templates.mts'
import type {
  FfiProducerBundleManifest,
  FfiTemplateManifest,
} from '../../scripts/repo/ffi-templates.mts'
import { abiBin, TARGETS } from '../../scripts/repo/targets.mts'

const producerSha = 'a'.repeat(40)

function hash(bytes: string | Uint8Array): string {
  return crypto.createHash('sha512').update(bytes).digest('hex')
}

function createParts(root: string): string {
  const parts = path.join(root, 'parts')
  mkdirSync(parts)
  for (const target of TARGETS) {
    const directory = path.join(parts, `abitious-ffi-source-${target.triple}`)
    const packageDirectory = path.join(directory, 'package')
    const templateDirectory = path.join(directory, 'template')
    mkdirSync(packageDirectory, { recursive: true })
    mkdirSync(templateDirectory)
    writeFileSync(
      path.join(packageDirectory, 'package.json'),
      JSON.stringify({
        name: `@abitious/${target.triple}`,
        files: [
          'LICENSE',
          'THIRD-PARTY-NOTICES.md',
          'templates/manifest.json',
          ...TARGETS.map(item => `templates/${item.triple}/ffi-stub.node`),
        ],
      }),
    )
    writeFileSync(
      path.join(packageDirectory, abiBin(target.os)),
      `producer ${target.triple}`,
    )
    writeFileSync(path.join(packageDirectory, 'LICENSE'), 'license')
    writeFileSync(
      path.join(packageDirectory, 'THIRD-PARTY-NOTICES.md'),
      'notices',
    )
    const templateFile = path.join(templateDirectory, 'ffi-stub.node')
    const templateBytes = Buffer.from(`template ${target.triple}`)
    writeFileSync(templateFile, templateBytes)
    writeFileSync(
      path.join(directory, 'part.json'),
      JSON.stringify({
        schemaVersion: 1,
        producerSha,
        target: target.triple,
        path: 'template/ffi-stub.node',
        sha512: hash(templateBytes),
      }),
    )
  }
  return parts
}

function addMacosSigningReceipts(parts: string): void {
  const darwinTargets = TARGETS.filter(item => item.os === 'darwin')
  for (let index = 0, { length } = darwinTargets; index < length; index += 1) {
    const target = darwinTargets[index]!
    const directory = path.join(parts, `abitious-ffi-source-${target.triple}`)
    const packageDirectory = path.join(directory, 'package')
    for (const name of [
      'bind.node',
      'libabitious_decmpfs.dylib',
      'stub.node',
    ]) {
      writeFileSync(path.join(packageDirectory, name), `signed ${name}`)
    }
    const files = [
      'package/abi',
      'package/bind.node',
      'package/libabitious_decmpfs.dylib',
      'package/stub.node',
      'template/ffi-stub.node',
    ].map(file => {
      const filePath = path.join(directory, file)
      return {
        path: file,
        sha512: hash(readFileSync(filePath)),
        submissionId: '12345678-1234-4234-8234-123456789abc',
      }
    })
    writeFileSync(
      path.join(directory, 'macos-signing.json'),
      JSON.stringify({
        schemaVersion: 1,
        producerSha,
        target: target.triple,
        files,
      }),
    )
  }
}

test('aggregation builds all producer bundles with verified eight-target templates', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-ffi-templates-'))
  try {
    const parts = createParts(root)
    const out = path.join(root, 'bundles')
    const result = aggregateFfiTemplateParts({
      partsDir: parts,
      producerSha,
      outDir: out,
    })
    assert.equal(result.packages.length, TARGETS.length)
    for (const target of TARGETS) {
      const bundle = path.join(out, target.triple)
      const manifestPath = path.join(bundle, 'templates', 'manifest.json')
      const manifest = JSON.parse(
        readFileSync(manifestPath, 'utf8'),
      ) as FfiTemplateManifest
      assert.equal(manifest.producerSha, producerSha)
      assert.equal(manifest.templates.length, TARGETS.length)
      for (const row of manifest.templates) {
        assert.equal(
          hash(readFileSync(path.join(bundle, row.path))),
          row.sha512,
        )
      }
      if (os.platform() !== 'win32' && target.os !== 'win32') {
        const producer = path.join(bundle, abiBin(target.os))
        assert.equal(statSync(producer).mode & 0o777, 0o755)
      }
      const selected = manifest.templates.find(
        item => item.target === target.triple,
      )
      assert.ok(selected)
    }
    const bundleManifest = JSON.parse(
      readFileSync(path.join(out, 'bundle-manifest.json'), 'utf8'),
    ) as FfiProducerBundleManifest
    assert.equal(bundleManifest.producerSha, producerSha)
  } finally {
    safeDeleteSync(root, { recursive: true })
  }
})

test('aggregation rejects a template set that omits a target', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-ffi-templates-'))
  try {
    const parts = createParts(root)
    const missing = path.join(
      parts,
      `abitious-ffi-source-${TARGETS[0]!.triple}`,
    )
    safeDeleteSync(missing, { recursive: true })
    assert.throws(
      () =>
        aggregateFfiTemplateParts({
          partsDir: parts,
          producerSha,
          outDir: path.join(root, 'bundles'),
        }),
      /incomplete or has duplicate targets/u,
    )
  } finally {
    safeDeleteSync(root, { recursive: true })
  }
})

test('tag aggregation requires matching macOS signing and notarization receipts', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'abitious-ffi-templates-'))
  try {
    const parts = createParts(root)
    const options = {
      partsDir: parts,
      producerSha,
      outDir: path.join(root, 'bundles'),
      requireMacosSigning: true,
    }
    assert.throws(
      () => aggregateFfiTemplateParts(options),
      /macOS signing receipt/u,
    )
    addMacosSigningReceipts(parts)
    const result = aggregateFfiTemplateParts(options)
    const darwinTargets = TARGETS.filter(item => item.os === 'darwin')
    for (
      let index = 0, { length } = darwinTargets;
      index < length;
      index += 1
    ) {
      const target = darwinTargets[index]!
      const receipt = JSON.parse(
        readFileSync(
          path.join(root, 'bundles', target.triple, 'macos-signing.json'),
          'utf8',
        ),
      )
      assert.equal(receipt.target, target.triple)
      assert.equal(receipt.producerSha, producerSha)
      assert.equal(receipt.files.length, 5)
    }
    assert.equal(result.packages.length, TARGETS.length)
  } finally {
    safeDeleteSync(root, { recursive: true })
  }
})
