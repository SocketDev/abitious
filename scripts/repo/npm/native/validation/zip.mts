import type { extractZipArchive } from '../../../../fleet/artifact/zip.mts'

export function assertSafeArtifactPath(name: string): void {
  const segments = name.replace(/\/$/u, '').split('/')
  if (
    !name ||
    name.startsWith('/') ||
    name.includes('\\') ||
    name.endsWith('//') ||
    segments.some(
      segment => segment === '' || segment === '.' || segment === '..',
    )
  ) {
    throw new Error(
      'Native artifact contains an unsafe path. Where: ZIP entry. Saw an absolute or traversing name; wanted a relative package file. Fix: rebuild and upload the artifact.',
    )
  }
}

function assertUniqueNativeZipEntries(
  entries: ReturnType<typeof extractZipArchive>,
): void {
  const names = new Set<string>()
  for (let index = 0, { length } = entries; index < length; index += 1) {
    const entry = entries[index]!
    assertSafeArtifactPath(entry.name)
    if (names.has(entry.name)) {
      throw new Error(
        'Native artifact contains a duplicate path. Where: ZIP entry. Saw the same name twice; wanted unique files. Fix: rebuild and upload the artifact.',
      )
    }
    names.add(entry.name)
  }
}

function findNativeZipDirectoryOffset(archive: Buffer): number {
  for (
    let cursor = archive.length - 22;
    cursor >= Math.max(0, archive.length - 65_558);
    cursor -= 1
  ) {
    if (archive.readUInt32LE(cursor) === 0x06_05_4b_50) {
      return cursor
    }
  }
  throw new Error('Native artifact ZIP directory is incomplete.')
}

function isRegularNativeZipEntry(
  name: string,
  madeBy: number,
  kind: number,
): boolean {
  const isDirectory = name.endsWith('/')
  return (
    (isDirectory && (kind === 0 || kind === 0o04_0000)) ||
    (!isDirectory && (madeBy !== 3 || kind === 0 || kind === 0o10_0000))
  )
}

function assertNativeZipDirectoryEntries(
  archive: Buffer,
  entries: ReturnType<typeof extractZipArchive>,
  directoryOffset: number,
): void {
  let cursor = archive.readUInt32LE(directoryOffset + 16)
  for (let index = 0, { length } = entries; index < length; index += 1) {
    const entry = entries[index]!
    if (
      cursor + 46 > archive.length ||
      archive.readUInt32LE(cursor) !== 0x02_01_4b_50
    ) {
      throw new Error('Native artifact ZIP directory is incomplete.')
    }
    const madeBy = archive.readUInt16LE(cursor + 4) >>> 8
    const mode = archive.readUInt32LE(cursor + 38) >>> 16
    const kind = mode & 0o17_0000
    if (!isRegularNativeZipEntry(entry.name, madeBy, kind)) {
      throw new Error(
        'Native artifact contains a non-regular ZIP entry. Where: ZIP metadata. Saw a link or special file; wanted regular package files. Fix: rebuild and upload the artifact.',
      )
    }
    cursor +=
      46 +
      archive.readUInt16LE(cursor + 28) +
      archive.readUInt16LE(cursor + 30) +
      archive.readUInt16LE(cursor + 32)
  }
}

export function assertRegularZipEntries(
  archive: Buffer,
  entries: ReturnType<typeof extractZipArchive>,
): void {
  assertUniqueNativeZipEntries(entries)
  const directoryOffset = findNativeZipDirectoryOffset(archive)
  assertNativeZipDirectoryEntries(archive, entries, directoryOffset)
}
