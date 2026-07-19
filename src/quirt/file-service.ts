import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  cp, lstat, link, mkdir, open, opendir, readlink, realpath, rename, rm, rmdir, stat, symlink, unlink, type FileHandle
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, normalize, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { QuirtError } from "./error.js";

export const QUIRT_FILE_PAGE_MAX = 1024 * 1024;
export const QUIRT_FILE_PATCH_MAX = 32 * 1024 * 1024;
export const QUIRT_SEARCH_SCAN_MAX = 512 * 1024 * 1024;
const QUIRT_SEARCH_ENTRY_MAX = 1_000_000;
const QUIRT_SEARCH_PATH_BYTES_MAX = 64 * 1024 * 1024;

export type QuirtFileType = "file" | "directory" | "symlink" | "socket" | "fifo" | "block-device" | "character-device" | "unknown";

export interface QuirtFileIdentity {
  device: number;
  inode: number;
  size: number;
  mtimeMs: number;
}

export interface QuirtFileMetadata extends QuirtFileIdentity {
  path: string;
  type: QuirtFileType;
  mode: number;
  uid: number;
  gid: number;
  nlink: number;
  atime: string;
  mtime: string;
  ctime: string;
  birthtime: string;
  symlinkTarget?: string;
  followedSymlink: boolean;
}

export interface QuirtFilePage {
  metadata: QuirtFileMetadata;
  offset: number;
  nextOffset: number;
  byteCount: number;
  eof: boolean;
  changedDuringRead: boolean;
  sha256: string;
  content: Buffer;
}

export interface QuirtFileServiceHooks {
  moveRename?: typeof rename;
  afterRead?: (path: string) => Promise<void>;
  beforeRemoveIsolation?: (path: string) => Promise<void>;
}

function errno(cause: unknown): string | undefined {
  return cause instanceof Error && "code" in cause && typeof cause.code === "string" ? cause.code : undefined;
}

function mapError(cause: unknown, action: string): never {
  if (cause instanceof QuirtError) throw cause;
  const code = errno(cause);
  if (code === "ENOENT") throw new QuirtError("not_found", `Quirt ${action} target was not found`);
  if (code === "EEXIST") throw new QuirtError("already_exists", `Quirt ${action} target already exists`);
  if (code === "ENOTEMPTY") throw new QuirtError("conflict", `Quirt ${action} directory is not empty`);
  if (code === "ELOOP") throw new QuirtError("symlink_conflict", `Quirt ${action} refused a symlink`);
  if (code === "EACCES" || code === "EPERM") throw new QuirtError("authorization_failed", `Quirt ${action} was denied by the host`);
  if (code === "EINVAL" || code === "ENOTDIR" || code === "EISDIR") throw new QuirtError("invalid_request", `Quirt ${action} target is invalid`);
  throw new QuirtError("internal_error", `Quirt ${action} failed safely`);
}

export function quirtPath(value: string, workingDirectory = "/root"): string {
  if (typeof value !== "string" || value.length < 1 || value.includes("\0") || Buffer.byteLength(value) > 4096) throw new QuirtError("invalid_request", "Quirt path is invalid");
  if (!isAbsolute(workingDirectory) || workingDirectory.includes("\0")) throw new QuirtError("invalid_request", "Quirt working directory is invalid");
  const path = normalize(isAbsolute(value) ? value : resolve(workingDirectory, value));
  if (!isAbsolute(path)) throw new QuirtError("invalid_request", "Quirt path is invalid");
  return path;
}

function fileType(value: Awaited<ReturnType<typeof lstat>>): QuirtFileType {
  if (value.isFile()) return "file";
  if (value.isDirectory()) return "directory";
  if (value.isSymbolicLink()) return "symlink";
  if (value.isSocket()) return "socket";
  if (value.isFIFO()) return "fifo";
  if (value.isBlockDevice()) return "block-device";
  if (value.isCharacterDevice()) return "character-device";
  return "unknown";
}

function identity(value: Awaited<ReturnType<typeof stat>>): QuirtFileIdentity {
  return { device: Number(value.dev), inode: Number(value.ino), size: Number(value.size), mtimeMs: Number(value.mtimeMs) };
}

function sameIdentity(left: QuirtFileIdentity, right: QuirtFileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

async function metadata(path: string, followSymlinks: boolean): Promise<QuirtFileMetadata> {
  const raw = followSymlinks ? await stat(path) : await lstat(path);
  const linkTarget = !followSymlinks && raw.isSymbolicLink() ? await readlink(path) : undefined;
  return Object.freeze({
    path,
    type: fileType(raw),
    ...identity(raw),
    mode: raw.mode & 0o7777,
    uid: raw.uid,
    gid: raw.gid,
    nlink: raw.nlink,
    atime: raw.atime.toISOString(),
    mtime: raw.mtime.toISOString(),
    ctime: raw.ctime.toISOString(),
    birthtime: raw.birthtime.toISOString(),
    ...(linkTarget === undefined ? {} : { symlinkTarget: linkTarget }),
    followedSymlink: followSymlinks
  });
}

async function sha256File(path: string, followSymlinks = false): Promise<string> {
  const hash = createHash("sha256");
  const flags = constants.O_RDONLY | (followSymlinks ? 0 : constants.O_NOFOLLOW);
  const handle = await open(path, flags);
  try {
    await pipeline(handle.createReadStream({ autoClose: false }), hash);
    return hash.digest("hex");
  } finally { await handle.close(); }
}

async function sha256Handle(handle: FileHandle): Promise<string> { const hash = createHash("sha256"); await pipeline(handle.createReadStream({ autoClose: false, start: 0 }), hash); return hash.digest("hex"); }

async function assertExpected(path: string, input: { expectedDigest?: string; expectedDevice?: number; expectedInode?: number; followSymlinks?: boolean }): Promise<void> {
  const current = await metadata(path, input.followSymlinks ?? false);
  if (input.expectedDevice !== undefined && current.device !== input.expectedDevice) throw new QuirtError("conflict", "Quirt file device changed");
  if (input.expectedInode !== undefined && current.inode !== input.expectedInode) throw new QuirtError("conflict", "Quirt file inode changed");
  if (input.expectedDigest !== undefined) {
    if (!/^[a-f0-9]{64}$/u.test(input.expectedDigest)) throw new QuirtError("invalid_request", "Quirt expected digest is invalid");
    const actual = await sha256File(path, input.followSymlinks ?? false);
    if (actual !== input.expectedDigest) throw new QuirtError("digest_mismatch", "Quirt file digest precondition failed", false, { expected: input.expectedDigest, actual });
  }
}

async function parentIdentity(path: string): Promise<{ path: string; real: string; device: number; inode: number }> {
  const parent = dirname(path);
  const [raw, actual] = await Promise.all([lstat(parent), realpath(parent)]);
  if (!raw.isDirectory() || raw.isSymbolicLink()) throw new QuirtError("symlink_conflict", "Quirt destination parent is unsafe");
  return { path: parent, real: actual, device: raw.dev, inode: raw.ino };
}

async function verifyParent(expected: Awaited<ReturnType<typeof parentIdentity>>): Promise<void> {
  const [raw, actual] = await Promise.all([lstat(expected.path), realpath(expected.path)]);
  if (!raw.isDirectory() || raw.isSymbolicLink() || actual !== expected.real || raw.dev !== expected.device || raw.ino !== expected.inode) throw new QuirtError("changed_during_operation", "Quirt destination parent changed during operation");
}

async function applyHandleMetadata(handle: FileHandle, input: { mode?: number; uid?: number; gid?: number; atime?: string; mtime?: string }): Promise<void> {
  if (input.mode !== undefined) await handle.chmod(input.mode);
  if (input.uid !== undefined || input.gid !== undefined) await handle.chown(input.uid ?? -1, input.gid ?? -1);
  if (input.atime !== undefined || input.mtime !== undefined) {
    const current = await handle.stat(); const atime = input.atime === undefined ? current.atime : new Date(input.atime); const mtime = input.mtime === undefined ? current.mtime : new Date(input.mtime);
    if (!Number.isFinite(atime.getTime()) || !Number.isFinite(mtime.getTime())) throw new QuirtError("invalid_request", "Quirt file timestamp is invalid"); await handle.utimes(atime, mtime);
  }
}

async function fsyncDirectory(path: string): Promise<void> { const handle = await open(path, constants.O_RDONLY); try { await handle.sync(); } finally { await handle.close(); } }

export class QuirtFileService {
  constructor(private readonly hooks: QuirtFileServiceHooks = {}) {}
  async stat(input: { path: string; workingDirectory?: string; followSymlinks?: boolean; digest?: boolean }): Promise<Record<string, unknown>> {
    const path = quirtPath(input.path, input.workingDirectory);
    try {
      const result = await metadata(path, input.followSymlinks ?? false);
      const digest = input.digest === true && result.type === "file" ? await sha256File(path, input.followSymlinks ?? false) : undefined;
      const after = await metadata(path, input.followSymlinks ?? false); if (!sameIdentity(result, after) || result.type !== after.type) throw new QuirtError("changed_during_operation", "Quirt stat target changed while hashing", true, { before: result, after });
      return { metadata: after, ...(digest === undefined ? {} : { sha256: digest }) };
    } catch (cause) { mapError(cause, "stat"); }
  }

  async read(input: { path: string; workingDirectory?: string; followSymlinks?: boolean; offset?: number; maximumBytes?: number }): Promise<QuirtFilePage> {
    const path = quirtPath(input.path, input.workingDirectory);
    const offset = input.offset ?? 0; const maximum = input.maximumBytes ?? QUIRT_FILE_PAGE_MAX;
    if (!Number.isSafeInteger(offset) || offset < 0) throw new QuirtError("invalid_offset", "Quirt file offset is invalid");
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > QUIRT_FILE_PAGE_MAX) throw new QuirtError("invalid_request", "Quirt file page size is invalid");
    const flags = constants.O_RDONLY | (input.followSymlinks === true ? 0 : constants.O_NOFOLLOW);
    try {
      const handle = await open(path, flags);
      try {
        const beforeStat = await handle.stat(); const before = identity(beforeStat);
        if (!beforeStat.isFile()) throw new QuirtError("invalid_request", "Quirt file read requires a regular file");
        if (offset > before.size) throw new QuirtError("invalid_offset", "Quirt file offset is beyond end of file");
        const length = Math.min(maximum, before.size - offset); const content = Buffer.alloc(length);
        const read = length === 0 ? 0 : (await handle.read(content, 0, length, offset)).bytesRead;
        const bytes = content.subarray(0, read); await this.hooks.afterRead?.(path); const after = identity(await handle.stat()); const pathAfter = await metadata(path, input.followSymlinks ?? false); const changed = !sameIdentity(before, after) || !sameIdentity(after, pathAfter);
        if (changed) throw new QuirtError("changed_during_operation", "Quirt file changed during read", true, { before, after, pathAfter });
        return Object.freeze({ metadata: pathAfter, offset, nextOffset: offset + read, byteCount: read, eof: offset + read >= before.size, changedDuringRead: false, sha256: createHash("sha256").update(bytes).digest("hex"), content: bytes });
      } finally { await handle.close(); }
    } catch (cause) { mapError(cause, "read"); }
  }

  async write(input: {
    path: string; workingDirectory?: string; content: Buffer; create?: boolean; replace?: boolean; append?: boolean;
    offset?: number; atomic?: boolean; noClobber?: boolean; createParents?: boolean; followSymlinks?: boolean;
    expectedDigest?: string; expectedDevice?: number; expectedInode?: number; mode?: number; uid?: number; gid?: number;
    atime?: string; mtime?: string; durable?: boolean;
  }): Promise<Record<string, unknown>> {
    const requestedPath = quirtPath(input.path, input.workingDirectory); let path = requestedPath; const content = Buffer.from(input.content);
    if (input.append === true && input.offset !== undefined) throw new QuirtError("invalid_request", "Quirt append and offset are mutually exclusive");
    if (input.offset !== undefined && (!Number.isSafeInteger(input.offset) || input.offset < 0)) throw new QuirtError("invalid_offset", "Quirt write offset is invalid");
    if (input.mode !== undefined && (!Number.isSafeInteger(input.mode) || input.mode < 0 || input.mode > 0o7777)) throw new QuirtError("invalid_request", "Quirt file mode is invalid");
    try {
      if (input.followSymlinks === true) { try { if ((await lstat(path)).isSymbolicLink()) path = await realpath(path); } catch (cause) { if (errno(cause) !== "ENOENT") throw cause; } }
      if (input.createParents === true) await mkdir(dirname(path), { recursive: true, mode: 0o755 });
      let exists = true; let prior: QuirtFileMetadata | null = null; try { prior = await metadata(path, input.followSymlinks ?? false); } catch (cause) { if (errno(cause) === "ENOENT") exists = false; else throw cause; }
      if (exists && (input.noClobber === true || (input.replace !== true && input.append !== true && input.offset === undefined))) throw new QuirtError("already_exists", "Quirt file already exists");
      if (!exists && input.create !== true && input.replace !== true) throw new QuirtError("not_found", "Quirt file does not exist and creation was not authorized");
      if (exists && (input.expectedDigest !== undefined || input.expectedDevice !== undefined || input.expectedInode !== undefined)) await assertExpected(path, input);
      if (exists && input.followSymlinks !== true && (await lstat(path)).isSymbolicLink()) throw new QuirtError("symlink_conflict", "Quirt write refused a symlink");
      const atomic = input.atomic ?? (input.append !== true && input.offset === undefined);
      const atomic = input.atomic ?? (input.append !== true && input.offset === undefined);
      if (atomic) {
        if (input.append === true || input.offset !== undefined) throw new QuirtError("invalid_request", "Quirt atomic write does not support append or offset mode");
        const parent = await parentIdentity(path); const temporary = join(dirname(path), `.${basename(path)}.quirt-${randomUUID()}.tmp`);
        const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, input.mode ?? prior?.mode ?? 0o600);
        let placed = false;
        try {
          let cursor = 0; while (cursor < content.length) cursor += (await handle.write(content, cursor, content.length - cursor, cursor)).bytesWritten;
          await applyHandleMetadata(handle, input); if (input.durable !== false) await handle.sync();
          await handle.close();
          await verifyParent(parent);
          if (exists && (input.expectedDigest !== undefined || input.expectedDevice !== undefined || input.expectedInode !== undefined)) await assertExpected(path, input);
          if (input.noClobber === true || (!exists && input.replace !== true)) { await link(temporary, path); await unlink(temporary); }
          else await rename(temporary, path);
          placed = true;
          if (input.durable !== false) await fsyncDirectory(dirname(path));
        } finally {
          try { await handle.close(); } catch { /* already closed */ }
          if (!placed) try { await unlink(temporary); } catch { /* best-effort private temporary cleanup */ }
        }
      } else {
        let flags = (input.expectedDigest === undefined ? constants.O_WRONLY : constants.O_RDWR) | constants.O_NOFOLLOW;
        if (!exists) flags |= constants.O_CREAT | constants.O_EXCL;
        if (input.append === true) flags |= constants.O_APPEND;
        const handle = await open(path, flags, input.mode ?? 0o600);
        try {
          const opened = identity(await handle.stat()); if (prior !== null && (opened.device !== prior.device || opened.inode !== prior.inode)) throw new QuirtError("changed_during_operation", "Quirt write target changed before opening", true); if (input.expectedDigest !== undefined) { const actual = await sha256Handle(handle); if (actual !== input.expectedDigest) throw new QuirtError("digest_mismatch", "Quirt file digest precondition failed", false, { expected: input.expectedDigest, actual }); } if (input.append !== true && input.offset === undefined && input.replace === true) await handle.truncate(0);
          let cursor = 0; const position = input.append === true ? null : input.offset ?? 0;
          while (cursor < content.length) cursor += (await handle.write(content, cursor, content.length - cursor, position === null ? null : position + cursor)).bytesWritten;
          await applyHandleMetadata(handle, input); if (input.durable !== false) await handle.sync();
        } finally { await handle.close(); }
      }
      const verified = await this.stat({ path, followSymlinks: input.followSymlinks, digest: true }); const result = verified.metadata as QuirtFileMetadata;
      return { requestedPath, resolvedPath: path, metadata: result, sha256: verified.sha256 ?? null, writtenBytes: content.length, durable: input.durable !== false, atomic };
    } catch (cause) { mapError(cause, "write"); }
  }

  async patch(input: { path: string; workingDirectory?: string; expectedDigest: string; edits: readonly { start: number; deleteBytes: number; contentBase64: string }[]; mode?: number }): Promise<Record<string, unknown>> {
    const path = quirtPath(input.path, input.workingDirectory);
    if (!/^[a-f0-9]{64}$/u.test(input.expectedDigest) || !Array.isArray(input.edits) || input.edits.length < 1 || input.edits.length > 10_000) throw new QuirtError("invalid_request", "Quirt patch is invalid");
    try {
      const current = await this.readWhole(path, QUIRT_FILE_PATCH_MAX);
      const actual = createHash("sha256").update(current).digest("hex");
      if (actual !== input.expectedDigest) throw new QuirtError("digest_mismatch", "Quirt patch base digest does not match", false, { expected: input.expectedDigest, actual });
      const edits = input.edits.map(edit => {
        if (!Number.isSafeInteger(edit.start) || edit.start < 0 || !Number.isSafeInteger(edit.deleteBytes) || edit.deleteBytes < 0 || edit.start + edit.deleteBytes > current.length || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(edit.contentBase64)) throw new QuirtError("invalid_request", "Quirt patch edit is invalid");
        const content = Buffer.from(edit.contentBase64, "base64"); if (content.toString("base64") !== edit.contentBase64) throw new QuirtError("invalid_request", "Quirt patch content is not canonical base64");
        return { ...edit, content };
      }).sort((left, right) => left.start - right.start);
      for (let index = 1; index < edits.length; index += 1) if (edits[index - 1]!.start + edits[index - 1]!.deleteBytes > edits[index]!.start) throw new QuirtError("conflict", "Quirt patch edits overlap");
      const parts: Buffer[] = []; let cursor = 0;
      for (const edit of edits) { parts.push(current.subarray(cursor, edit.start), edit.content); cursor = edit.start + edit.deleteBytes; }
      parts.push(current.subarray(cursor)); const result = Buffer.concat(parts);
      if (result.length > QUIRT_FILE_PATCH_MAX) throw new QuirtError("result_truncated", "Quirt patch result exceeds the supported atomic patch size");
      return await this.write({ path, content: result, replace: true, atomic: true, expectedDigest: input.expectedDigest, mode: input.mode });
    } catch (cause) { mapError(cause, "patch"); }
  }

  async search(input: { path: string; workingDirectory?: string; name?: string; text?: string; regularExpression?: boolean; caseSensitive?: boolean; recursive?: boolean; followSymlinks?: boolean; maximumMatches?: number; maximumBytes?: number; signal?: AbortSignal }): Promise<Record<string, unknown>> {
    const root = quirtPath(input.path, input.workingDirectory); const maximumMatches = input.maximumMatches ?? 1000; const maximumBytes = input.maximumBytes ?? QUIRT_SEARCH_SCAN_MAX;
    if (!Number.isSafeInteger(maximumMatches) || maximumMatches < 1 || maximumMatches > 10_000 || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > QUIRT_SEARCH_SCAN_MAX) throw new QuirtError("invalid_request", "Quirt search bounds are invalid");
    const flags = input.caseSensitive === false ? "iu" : "u";
    let namePattern: RegExp | null = null; let textPattern: RegExp | null = null;
    try {
      if (input.name !== undefined) namePattern = input.regularExpression === true ? new RegExp(input.name, flags) : new RegExp(input.name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), flags);
      if (input.text !== undefined) textPattern = input.regularExpression === true ? new RegExp(input.text, flags) : new RegExp(input.text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), flags);
    } catch { throw new QuirtError("invalid_request", "Quirt search expression is invalid"); }
    const matches: Record<string, unknown>[] = []; const queue = [root]; const visitedDirectories = new Set<string>(); let queuedPathBytes = Buffer.byteLength(root); let scannedBytes = 0; let scannedEntries = 0; let binaryFilesSkipped = 0; let directoryCyclesSkipped = 0; let truncated = false; let truncationReason: string | null = null;
    try {
      search: while (queue.length > 0) {
        if (input.signal?.aborted === true) throw new QuirtError("request_canceled", "Quirt search was canceled", false);
        const path = queue.shift()!; const raw = input.followSymlinks === true ? await stat(path) : await lstat(path); scannedEntries += 1;
        if (scannedEntries > QUIRT_SEARCH_ENTRY_MAX) { truncated = true; truncationReason = "entry-limit"; break; }
        if (namePattern?.test(basename(path)) === true) matches.push({ path, kind: "name", identity: identity(raw) });
        if (raw.isDirectory() && (path === root || input.recursive !== false)) {
          const directoryIdentity = `${raw.dev}:${raw.ino}`;
          if (visitedDirectories.has(directoryIdentity)) { directoryCyclesSkipped += 1; continue; }
          visitedDirectories.add(directoryIdentity);
          const directory = await opendir(path); try {
            for await (const entry of directory) {
              if (entry.name === "." || entry.name === "..") continue;
              const child = join(path, entry.name); queuedPathBytes += Buffer.byteLength(child);
              if (queuedPathBytes > QUIRT_SEARCH_PATH_BYTES_MAX || scannedEntries + queue.length >= QUIRT_SEARCH_ENTRY_MAX) { truncated = true; truncationReason = queuedPathBytes > QUIRT_SEARCH_PATH_BYTES_MAX ? "path-byte-limit" : "entry-limit"; break search; }
              queue.push(child);
            }
          } finally { await directory.close().catch(() => undefined); }
        } else if (raw.isFile() && textPattern !== null) {
          const remaining = maximumBytes - scannedBytes; if (remaining <= 0) { truncated = true; truncationReason = "byte-limit"; break; } const searched = await this.searchFile(path, remaining, textPattern, input.followSymlinks === true, input.signal); scannedBytes += searched.scannedBytes;
          if (searched.binary) binaryFilesSkipped += 1;
          if (searched.match !== null) matches.push({ path, kind: "text", byteOffset: searched.match.byteOffset, match: searched.match.text, identity: searched.identity, binary: false });
          if (searched.truncated) { truncated = true; truncationReason = "byte-limit"; break; }
        }
        if (matches.length >= maximumMatches) { truncated = queue.length > 0; truncationReason = truncated ? "match-limit" : null; break; }
      }
      return { root, matches: matches.slice(0, maximumMatches), matchCount: Math.min(matches.length, maximumMatches), scannedEntries, scannedBytes, queuedPathBytes, binaryFilesSkipped, directoryCyclesSkipped, binaryBehavior: "skip-on-nul", truncated, truncationReason, cancellationSupported: true, limits: { maximumEntries: QUIRT_SEARCH_ENTRY_MAX, maximumPathBytes: QUIRT_SEARCH_PATH_BYTES_MAX, maximumBytes, maximumMatches } };
    } catch (cause) { mapError(cause, "search"); }
  }

  async remove(input: { path: string; workingDirectory?: string; recursive?: boolean; expectedDevice?: number; expectedInode?: number }): Promise<Record<string, unknown>> {
    const path = quirtPath(input.path, input.workingDirectory);
    try {
      const before = await metadata(path, false); const parent = await parentIdentity(path);
      if (input.expectedDevice !== undefined && before.device !== input.expectedDevice || input.expectedInode !== undefined && before.inode !== input.expectedInode) throw new QuirtError("conflict", "Quirt remove identity precondition failed");
      await verifyParent(parent); await this.hooks.beforeRemoveIsolation?.(path); const current = await metadata(path, false); if (!sameIdentity(before, current) || before.type !== current.type) throw new QuirtError("changed_during_operation", "Quirt remove target changed before isolation", true); const isolated = join(dirname(path), `.${basename(path)}.quirt-${randomUUID()}.remove`); let moved = false;
      try { await rename(path, isolated); moved = true; const isolatedMetadata = await metadata(isolated, false); if (!sameIdentity(before, isolatedMetadata) || before.type !== isolatedMetadata.type) throw new QuirtError("changed_during_operation", "Quirt remove target changed during isolation", true); if (before.type === "directory" && input.recursive !== true) await rmdir(isolated); else await rm(isolated, { recursive: input.recursive === true, force: false }); moved = false; await fsyncDirectory(dirname(path)); }
      catch (cause) { if (moved && !await lstat(path).then(() => true).catch(() => false)) await rename(isolated, path).catch(() => undefined); throw cause; }
      return { removed: true, path, identity: { device: before.device, inode: before.inode }, type: before.type };
    } catch (cause) { mapError(cause, "remove"); }
  }

  async move(input: { source: string; destination: string; workingDirectory?: string; overwrite?: boolean; preserveMetadata?: boolean }): Promise<Record<string, unknown>> {
    const source = quirtPath(input.source, input.workingDirectory); const destination = quirtPath(input.destination, input.workingDirectory);
    try {
      const before = await metadata(source, false); const parent = await parentIdentity(destination);
      let destinationExists = true; try { await lstat(destination); } catch (cause) { if (errno(cause) === "ENOENT") destinationExists = false; else throw cause; }
      if (destinationExists && input.overwrite !== true) throw new QuirtError("already_exists", "Quirt move destination already exists");
      await verifyParent(parent); const current = await metadata(source, false); if (!sameIdentity(before, current) || before.type !== current.type) throw new QuirtError("changed_during_operation", "Quirt move source changed before placement", true);
      let crossDevice = false;
      try { await (this.hooks.moveRename ?? rename)(source, destination); }
      catch (cause) {
        if (errno(cause) !== "EXDEV") throw cause;
        crossDevice = true; await this.copy({ source, destination, overwrite: input.overwrite, preserveMetadata: input.preserveMetadata, recursive: before.type === "directory" }); await this.remove({ path: source, recursive: before.type === "directory", expectedDevice: before.device, expectedInode: before.inode });
      }
      return { source, destination, crossDevice, metadata: await metadata(destination, false) };
    } catch (cause) { mapError(cause, "move"); }
  }

  async copy(input: { source: string; destination: string; workingDirectory?: string; recursive?: boolean; overwrite?: boolean; preserveMetadata?: boolean; followSymlinks?: boolean }): Promise<Record<string, unknown>> {
    const requestedSource = quirtPath(input.source, input.workingDirectory); let source = requestedSource; const destination = quirtPath(input.destination, input.workingDirectory);
    try {
      if (input.followSymlinks === true && (await lstat(source)).isSymbolicLink()) source = await realpath(source);
      const before = await metadata(source, input.followSymlinks ?? false); const parent = await parentIdentity(destination);
      let destinationExists = true; try { await lstat(destination); } catch (cause) { if (errno(cause) === "ENOENT") destinationExists = false; else throw cause; }
      if (destinationExists && input.overwrite !== true) throw new QuirtError("already_exists", "Quirt copy destination already exists");
      await verifyParent(parent); const staging = join(dirname(destination), `.${basename(destination)}.quirt-${randomUUID()}.copy`); let placed = false;
      try {
        if (before.type === "directory") {
          if (input.recursive !== true) throw new QuirtError("invalid_request", "Quirt directory copy requires recursive=true"); await cp(source, staging, { recursive: true, force: false, errorOnExist: true, dereference: input.followSymlinks === true, preserveTimestamps: input.preserveMetadata !== false, verbatimSymlinks: input.followSymlinks !== true });
        } else if (before.type === "file") {
          const sourceHandle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW); const destinationHandle = await open(staging, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, before.mode); try { const opened = await sourceHandle.stat(); if (opened.dev !== before.device || opened.ino !== before.inode) throw new QuirtError("changed_during_operation", "Quirt copy source changed before opening", true); const buffer = Buffer.alloc(1024 * 1024); let offset = 0; while (offset < opened.size) { const read = (await sourceHandle.read(buffer, 0, Math.min(buffer.length, opened.size - offset), offset)).bytesRead; if (read === 0) break; let written = 0; while (written < read) written += (await destinationHandle.write(buffer, written, read - written, offset + written)).bytesWritten; offset += read; } const after = await sourceHandle.stat(); const pathAfter = await metadata(source, false); if (!sameIdentity(identity(opened), identity(after)) || !sameIdentity(identity(after), pathAfter)) throw new QuirtError("changed_during_operation", "Quirt copy source changed while copying", true); if (input.preserveMetadata !== false) await applyHandleMetadata(destinationHandle, { mode: before.mode, uid: before.uid, gid: before.gid, atime: before.atime, mtime: before.mtime }); await destinationHandle.sync(); }
          finally { await sourceHandle.close(); await destinationHandle.close(); }
        } else if (before.type === "symlink" && input.followSymlinks !== true) await symlink(await readlink(source), staging);
        else throw new QuirtError("unsupported_host_capability", "Quirt copy does not support this special file type");
        const sourceAfter = await metadata(source, input.followSymlinks ?? false); if (!sameIdentity(before, sourceAfter) || before.type !== sourceAfter.type) throw new QuirtError("changed_during_operation", "Quirt copy source changed before placement", true); await verifyParent(parent); if (destinationExists && input.overwrite === true && before.type === "directory") await rm(destination, { recursive: true, force: false }); if (destinationExists && input.overwrite === true) await rename(staging, destination); else { await link(staging, destination).catch(async cause => { if (before.type === "directory" || before.type === "symlink") await rename(staging, destination); else throw cause; }); if (await lstat(staging).then(() => true).catch(() => false)) await rm(staging, { recursive: true, force: true }); } placed = true; await fsyncDirectory(dirname(destination));
      } finally { if (!placed) await rm(staging, { recursive: true, force: true }); }
      return { source: requestedSource, resolvedSource: source, destination, metadata: await metadata(destination, false), sparsePreservation: before.type === "file" ? "kernel-dependent" : "not-applicable" };
    } catch (cause) { mapError(cause, "copy"); }
  }

  private async readWhole(path: string, maximum: number): Promise<Buffer> {
    const raw = await stat(path); if (!raw.isFile()) throw new QuirtError("invalid_request", "Quirt operation requires a regular file");
    if (raw.size > maximum) throw new QuirtError("result_truncated", "Quirt file exceeds the bounded operation size");
    const page = await this.read({ path, maximumBytes: Math.max(1, raw.size) }); return page.content;
  }

  private async searchFile(path: string, maximumBytes: number, pattern: RegExp, followSymlinks: boolean, signal?: AbortSignal): Promise<{ scannedBytes: number; truncated: boolean; binary: boolean; identity: QuirtFileIdentity; match: { byteOffset: number; text: string } | null }> {
    const handle = await open(path, constants.O_RDONLY | (followSymlinks ? 0 : constants.O_NOFOLLOW));
    try {
      const beforeStat = await handle.stat(); if (!beforeStat.isFile()) throw new QuirtError("changed_during_operation", "Quirt search target changed type", true); const before = identity(beforeStat); let offset = 0; let scannedBytes = 0; let carry = Buffer.alloc(0); let binary = false; let match: { byteOffset: number; text: string } | null = null;
      while (offset < before.size && scannedBytes < maximumBytes) {
        if (signal?.aborted === true) throw new QuirtError("request_canceled", "Quirt search was canceled"); const length = Math.min(256 * 1024, before.size - offset, maximumBytes - scannedBytes); const chunk = Buffer.alloc(length); const read = (await handle.read(chunk, 0, length, offset)).bytesRead; if (read === 0) break; const bytes = chunk.subarray(0, read); const combined = carry.length === 0 ? bytes : Buffer.concat([carry, bytes]); scannedBytes += read;
        if (combined.includes(0)) { binary = true; offset += read; break; } else { const text = combined.toString("utf8"); const found = text.match(pattern); if (found !== null) { const prefix = Buffer.byteLength(text.slice(0, found.index ?? 0)); match = { byteOffset: Math.max(0, offset - carry.length + prefix), text: found[0].slice(0, 4096) }; offset += read; break; } }
        carry = combined.subarray(Math.max(0, combined.length - 64 * 1024)); offset += read;
      }
      const after = identity(await handle.stat()); const pathAfter = await metadata(path, followSymlinks); if (!sameIdentity(before, after) || !sameIdentity(after, pathAfter)) throw new QuirtError("changed_during_operation", "Quirt search target changed while scanning", true, { before, after, pathAfter });
      return { scannedBytes, truncated: !binary && match === null && offset < before.size, binary, identity: after, match };
    } finally { await handle.close(); }
  }
}
