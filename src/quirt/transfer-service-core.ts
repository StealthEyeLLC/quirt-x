import { createHash, randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { constants } from "node:fs";
import { chmod, chown, copyFile, lchown, lstat, link, lutimes, mkdir, open, readFile, readlink, realpath, rename, rm, stat, symlink, unlink, utimes, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { gunzip, gzip } from "node:zlib";
import { promisify } from "node:util";
import * as tar from "tar";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import { quirtPath } from "./file-service.js";
import type { QuirtTransferRecord } from "./native-state.js";
import type { QuirtStateStore } from "./state.js";

const gzipAsync = promisify(gzip); const gunzipAsync = promisify(gunzip);
const MAX_TRANSFER_CHUNK = 1024 * 1024;

interface SourceIdentity { device: number; inode: number; size: number; mtimeMs: number; type: "file" | "directory" | "symlink"; }
export interface QuirtTransferEvent { transferId: string; event: "transfer.started" | "transfer.progress" | "transfer.completed" | "transfer.canceled" | "transfer.recovered"; status: string; transferredBytes?: number; expectedSize?: number | null; }

function sourceIdentity(value: Awaited<ReturnType<typeof lstat>>): SourceIdentity {
  if (!value.isFile() && !value.isDirectory() && !value.isSymbolicLink()) throw new QuirtError("invalid_request", "Quirt transfer source must be a regular file, directory archive, or symlink");
  return { device: Number(value.dev), inode: Number(value.ino), size: Number(value.size), mtimeMs: Number(value.mtimeMs), type: value.isDirectory() ? "directory" : value.isSymbolicLink() ? "symlink" : "file" };
}

function validDigest(value: string | undefined): string | null {
  if (value === undefined) return null;
  if (!/^[a-f0-9]{64}$/u.test(value)) throw new QuirtError("invalid_request", "Quirt transfer digest is invalid");
  return value;
}

function objectNumber(value: unknown): number | undefined { return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined; }
function objectString(value: unknown): string | undefined { return typeof value === "string" ? value : undefined; }

async function hashFile(path: string): Promise<string> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); const hash = createHash("sha256");
  try {
    const stream = handle.createReadStream({ autoClose: false });
    for await (const chunk of stream) hash.update(chunk as Buffer);
    return hash.digest("hex");
  } finally { await handle.close(); }
}

async function fsyncParent(path: string): Promise<void> { const handle = await open(dirname(path), constants.O_RDONLY); try { await handle.sync(); } finally { await handle.close(); } }
async function linkBytes(path: string): Promise<Buffer> { return Buffer.from(await readlink(path, { encoding: "buffer" })); }
async function parentIdentity(path: string): Promise<{ path: string; real: string; device: number; inode: number }> { const parent = dirname(path); const [raw, actual] = await Promise.all([lstat(parent), realpath(parent)]); if (!raw.isDirectory() || raw.isSymbolicLink()) throw new QuirtError("symlink_conflict", "Quirt transfer destination parent is unsafe"); return { path: parent, real: actual, device: Number(raw.dev), inode: Number(raw.ino) }; }
async function verifyParent(expected: Awaited<ReturnType<typeof parentIdentity>>): Promise<void> { const [raw, actual] = await Promise.all([lstat(expected.path), realpath(expected.path)]); if (!raw.isDirectory() || raw.isSymbolicLink() || actual !== expected.real || Number(raw.dev) !== expected.device || Number(raw.ino) !== expected.inode) throw new QuirtError("changed_during_operation", "Quirt transfer destination parent changed during placement", true); }

export class QuirtTransferService {
  readonly #root: string; readonly #events = new EventEmitter(); readonly #locks = new Map<string, Promise<void>>();
  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore) { this.#root = join(config.stateRoot, "transfers"); }
  onEvent(listener: (event: QuirtTransferEvent) => void): () => void { this.#events.on("event", listener); return () => this.#events.off("event", listener); }

  async begin(input: {
    direction: "upload" | "download"; source?: string; destination?: string; workingDirectory?: string; expectedSize?: number;
    expectedDigest?: string; chunkSize?: number; compression?: "none" | "gzip"; archiveFormat?: "none" | "tar";
    objectType?: "file" | "directory" | "symlink"; overwrite?: boolean; noClobber?: boolean; mode?: number; uid?: number; gid?: number; atime?: string; mtime?: string;
  }, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    const transferId = randomUUID(); const chunkSize = input.chunkSize ?? 256 * 1024;
    if (input.direction !== "upload" && input.direction !== "download") throw new QuirtError("invalid_request", "Quirt transfer direction is invalid");
    if (!Number.isSafeInteger(chunkSize) || chunkSize < 4096 || chunkSize > MAX_TRANSFER_CHUNK) throw new QuirtError("invalid_request", "Quirt transfer chunk size is invalid");
    if (input.expectedSize !== undefined && (!Number.isSafeInteger(input.expectedSize) || input.expectedSize < 0)) throw new QuirtError("invalid_request", "Quirt transfer size is invalid");
    const compression = input.compression ?? "none"; const archiveFormat = input.archiveFormat ?? "none"; if (!(["none", "gzip"] as const).includes(compression) || !(["none", "tar"] as const).includes(archiveFormat) || input.objectType !== undefined && !(["file", "directory", "symlink"] as const).includes(input.objectType)) throw new QuirtError("invalid_request", "Quirt transfer encoding is invalid"); const expectedDigest = validDigest(input.expectedDigest);
    if (input.mode !== undefined && (!Number.isSafeInteger(input.mode) || input.mode < 0 || input.mode > 0o7777) || input.uid !== undefined && (!Number.isSafeInteger(input.uid) || input.uid < 0 || input.uid > 0x7fffffff) || input.gid !== undefined && (!Number.isSafeInteger(input.gid) || input.gid < 0 || input.gid > 0x7fffffff)) throw new QuirtError("invalid_request", "Quirt transfer metadata is invalid");
    for (const value of [input.atime, input.mtime]) if (value !== undefined && !Number.isFinite(Date.parse(value))) throw new QuirtError("invalid_request", "Quirt transfer timestamp is invalid");
    if (input.overwrite === true && input.noClobber === true) throw new QuirtError("invalid_request", "Quirt transfer overwrite and no-clobber policies conflict");
    await mkdir(this.#root, { recursive: true, mode: 0o700 });
    let sourcePath: string | null = null; let destinationPath: string | null = null; let temporaryPath: string | null = null; let expectedSize = input.expectedSize ?? null; let identity: SourceIdentity | null = null;
    if (input.direction === "upload") {
      if (input.destination === undefined) throw new QuirtError("invalid_request", "Quirt upload destination is required");
      if (input.expectedSize === undefined) throw new QuirtError("invalid_request", "Quirt upload expected size is required");
      const objectType = input.objectType ?? (archiveFormat === "tar" ? "directory" : "file"); if (objectType === "directory" && archiveFormat !== "tar" || objectType !== "directory" && archiveFormat === "tar") throw new QuirtError("invalid_request", "Quirt transfer object type and archive format conflict"); if (objectType === "symlink" && input.expectedSize > 4095) throw new QuirtError("invalid_request", "Quirt symlink target exceeds the host path bound");
      destinationPath = quirtPath(input.destination, input.workingDirectory); temporaryPath = join(this.#root, `${transferId}.part`);
      const handle = await open(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); await handle.close();
    } else {
      if (input.source === undefined) throw new QuirtError("invalid_request", "Quirt download source is required");
      sourcePath = quirtPath(input.source, input.workingDirectory); const sourceStat = await lstat(sourcePath); identity = sourceIdentity(sourceStat);
      if (identity.type === "directory") {
        if (archiveFormat !== "tar") throw new QuirtError("invalid_request", "Quirt directory download requires archiveFormat=tar");
        temporaryPath = join(this.#root, `${transferId}.tar`);
        await tar.c({ cwd: sourcePath, file: temporaryPath, portable: true, noMtime: true }, ["."]);
        const archiveStat = await stat(temporaryPath); expectedSize = archiveStat.size;
      } else if (identity.type === "symlink") {
        if (archiveFormat !== "none") throw new QuirtError("invalid_request", "Quirt symlink download requires archiveFormat=none"); const target = await linkBytes(sourcePath); if (target.length > 4095) throw new QuirtError("result_truncated", "Quirt symlink target exceeds the host path bound"); temporaryPath = join(this.#root, `${transferId}.symlink`); await writeFile(temporaryPath, target, { flag: "wx", mode: 0o600 }); expectedSize = target.length;
      } else expectedSize = identity.size;
    }
    const objectType = input.direction === "download" ? identity!.type : input.objectType ?? (archiveFormat === "tar" ? "directory" : "file"); const metadata = Object.freeze({ overwrite: input.overwrite === true, noClobber: input.noClobber !== false, objectType, mode: input.mode, uid: input.uid, gid: input.gid, atime: input.atime, mtime: input.mtime });
    try { const record = this.state.native.createTransfer({ transferId, direction: input.direction, status: "active", ownerPrincipalFingerprint, sourcePath, destinationPath, temporaryPath, expectedSize, chunkSize, digestAlgorithm: "sha256", expectedDigest, compression, archiveFormat, metadata, sourceIdentity: identity as unknown as Readonly<Record<string, unknown>> | null }); this.#emit({ transferId, event: "transfer.started", status: record.status, transferredBytes: 0, expectedSize: record.expectedSize }); return { transfer: this.#public(record), ranges: [], resumable: true, sparsePlacement: "partial-object-supported-final-copy-kernel-dependent" }; }
    catch (cause) { if (input.direction === "upload" && temporaryPath !== null) await rm(temporaryPath, { force: true }); throw cause; }
  }

  async write(input: { transferId: string; offset: number; content: Buffer; chunkDigest?: string }, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    return await this.#exclusive(input.transferId, async () => await this.#write(input, ownerPrincipalFingerprint));
  }

  async #write(input: { transferId: string; offset: number; content: Buffer; chunkDigest?: string }, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    const record = this.state.native.getTransfer(input.transferId, ownerPrincipalFingerprint); this.#active(record, "upload");
    if (!Number.isSafeInteger(input.offset) || input.offset < 0) throw new QuirtError("invalid_offset", "Quirt transfer offset is invalid");
    if (input.content.length < 1 || input.content.length > MAX_TRANSFER_CHUNK * 2) throw new QuirtError("invalid_request", "Quirt transfer chunk size is invalid");
    let bytes: Buffer; try { bytes = record.compression === "gzip" ? await gunzipAsync(input.content, { maxOutputLength: record.chunkSize }) : Buffer.from(input.content); } catch { throw new QuirtError("invalid_request", "Quirt compressed transfer chunk is invalid or exceeds its negotiated bound"); }
    if (bytes.length > record.chunkSize) throw new QuirtError("invalid_request", "Quirt transfer chunk exceeds the negotiated size");
    if (record.expectedSize !== null && input.offset + bytes.length > record.expectedSize) throw new QuirtError("invalid_offset", "Quirt transfer chunk exceeds expected size");
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (input.chunkDigest !== undefined && validDigest(input.chunkDigest) !== digest) throw new QuirtError("digest_mismatch", "Quirt transfer chunk digest does not match");
    const existing = this.state.native.transferRangeAt(record.transferId, input.offset);
    if (existing !== null) {
      if (existing.endOffset !== input.offset + bytes.length || existing.sha256 !== digest) throw new QuirtError("conflict", "Quirt transfer duplicate chunk conflicts");
      return { transfer: this.#public(record), range: existing, duplicate: true };
    }
    if (this.state.native.transferRangeOverlaps(record.transferId, input.offset, input.offset + bytes.length)) throw new QuirtError("conflict", "Quirt transfer chunk overlaps an existing range");
    if (record.temporaryPath === null) throw new QuirtError("internal_error", "Quirt transfer temporary object is unavailable");
    const handle = await open(record.temporaryPath, constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      let cursor = 0; while (cursor < bytes.length) cursor += (await handle.write(bytes, cursor, bytes.length - cursor, input.offset + cursor)).bytesWritten;
      await handle.sync();
    } finally { await handle.close(); }
    const result = this.state.native.putTransferRange({ transferId: record.transferId, startOffset: input.offset, endOffset: input.offset + bytes.length, byteCount: bytes.length, sha256: digest }); const transferredBytes = this.state.native.transferRangeTotals(record.transferId).coveredBytes; this.#emit({ transferId: record.transferId, event: "transfer.progress", status: record.status, transferredBytes, expectedSize: record.expectedSize });
    return { transfer: this.#public(record), range: result.range, duplicate: result.duplicate };
  }

  async read(input: { transferId: string; offset: number; maximumBytes?: number }, ownerPrincipalFingerprint: string): Promise<{ payload: Record<string, unknown>; binary: Buffer }> {
    const record = this.state.native.getTransfer(input.transferId, ownerPrincipalFingerprint); this.#active(record, "download");
    const maximum = input.maximumBytes ?? record.chunkSize;
    if (!Number.isSafeInteger(input.offset) || input.offset < 0) throw new QuirtError("invalid_offset", "Quirt transfer offset is invalid");
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_TRANSFER_CHUNK) throw new QuirtError("invalid_request", "Quirt transfer read size is invalid");
    await this.#verifySource(record);
    const path = record.temporaryPath ?? record.sourcePath; if (path === null) throw new QuirtError("internal_error", "Quirt transfer source is unavailable");
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); let raw: Buffer; let size: number;
    try { const before = await handle.stat(); if (!before.isFile()) throw new QuirtError("source_changed", "Quirt transfer source changed type", true); size = before.size; if (input.offset > size) throw new QuirtError("invalid_offset", "Quirt transfer offset is beyond source size"); const length = Math.min(maximum, size - input.offset); const allocated = Buffer.alloc(length); const count = length === 0 ? 0 : (await handle.read(allocated, 0, length, input.offset)).bytesRead; raw = allocated.subarray(0, count); const after = await handle.stat(); const pathAfter = await lstat(path); if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || after.dev !== pathAfter.dev || after.ino !== pathAfter.ino) throw new QuirtError("source_changed", "Quirt transfer source changed during read", true); }
    finally { await handle.close(); }
    await this.#verifySource(record); const digest = createHash("sha256").update(raw).digest("hex"); const output = record.compression === "gzip" && raw.length > 0 ? await gzipAsync(raw, { level: 6 }) : raw;
    return { payload: { transfer: this.#public(record), offset: input.offset, nextOffset: input.offset + raw.length, rawByteCount: raw.length, byteCount: output.length, chunkSha256: digest, eof: input.offset + raw.length >= size, compression: record.compression }, binary: output };
  }

  status(transferId: string, ownerPrincipalFingerprint: string, page: { afterOffset?: number; maximumRanges?: number } = {}): Record<string, unknown> {
    const record = this.state.native.getTransfer(transferId, ownerPrincipalFingerprint); const ranges = this.state.native.transferRangePage(transferId, page.afterOffset ?? -1, page.maximumRanges ?? 256); const coverage = record.direction === "upload" && record.expectedSize !== null ? this.state.native.transferCoverage(transferId, record.expectedSize) : { rangeCount: 0, coveredBytes: 0, missingRangeCount: 0, missingRanges: [], missingRangesTruncated: false };
    return { transfer: this.#public(record), ranges: ranges.ranges, rangeCount: coverage.rangeCount, coveredBytes: coverage.coveredBytes, rangesTruncated: ranges.truncated, nextRangeOffset: ranges.nextOffset, missingRanges: coverage.missingRanges, missingRangeCount: coverage.missingRangeCount, missingRangesTruncated: coverage.missingRangesTruncated };
  }

  async complete(transferId: string, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    return await this.#exclusive(transferId, async () => await this.#complete(transferId, ownerPrincipalFingerprint));
  }

  async #complete(transferId: string, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    let record = this.state.native.getTransfer(transferId, ownerPrincipalFingerprint);
    if (record.status === "preparing") { await this.#recoverPreparing(record); record = this.state.native.getTransfer(transferId, ownerPrincipalFingerprint); }
    if (record.status === "completed") return { transfer: this.#public(record), duplicate: true, result: record.completion };
    this.#active(record, record.direction);
    if (record.direction === "download") {
      await this.#verifySource(record); const path = record.temporaryPath ?? record.sourcePath; if (path === null) throw new QuirtError("internal_error", "Quirt transfer source is unavailable");
      const size = (await stat(path)).size; const digest = await hashFile(path); await this.#verifySource(record);
      if (record.expectedDigest !== null && record.expectedDigest !== digest) throw new QuirtError("digest_mismatch", "Quirt download digest does not match");
      const completed = this.state.native.updateTransfer(transferId, { status: "completed", completion: { size, sha256: digest, sourceIdentity: record.sourceIdentity } });
      this.#emit({ transferId, event: "transfer.completed", status: completed.status, transferredBytes: size, expectedSize: completed.expectedSize }); return { transfer: this.#public(completed), duplicate: false, result: completed.completion };
    }
    if (record.temporaryPath === null || record.destinationPath === null || record.expectedSize === null) throw new QuirtError("transfer_incomplete", "Quirt upload manifest is incomplete");
    const coverage = this.state.native.transferCoverage(record.transferId, record.expectedSize);
    if (coverage.missingRangeCount > 0) throw new QuirtError("range_gap", "Quirt upload has missing ranges", false, { missingRanges: coverage.missingRanges, missingRangeCount: coverage.missingRangeCount, truncated: coverage.missingRangesTruncated });
    const temporaryStat = await stat(record.temporaryPath); if (temporaryStat.size !== record.expectedSize) throw new QuirtError("transfer_incomplete", "Quirt upload size does not match");
    const digest = await hashFile(record.temporaryPath); if (record.expectedDigest !== null && record.expectedDigest !== digest) throw new QuirtError("digest_mismatch", "Quirt upload digest does not match", false, { expected: record.expectedDigest, actual: digest });
    const finalMetadata = record.metadata; const objectType = objectString(finalMetadata.objectType) ?? (record.archiveFormat === "tar" ? "directory" : "file"); const noClobber = finalMetadata.noClobber !== false; const overwrite = finalMetadata.overwrite === true; const parent = dirname(record.destinationPath); await mkdir(parent, { recursive: true, mode: 0o755 }); const parentWitness = await parentIdentity(record.destinationPath);
    let destinationExists = true; try { await lstat(record.destinationPath); } catch (cause) { if ((cause as NodeJS.ErrnoException).code === "ENOENT") destinationExists = false; else throw cause; } if (destinationExists && (!overwrite || noClobber)) throw new QuirtError("already_exists", "Quirt transfer destination already exists");
    const staging = join(parent, `.${basename(record.destinationPath)}.quirt-${record.transferId}.stage`); await rm(staging, { recursive: true, force: true }); let prepared = false;
    try {
      if (objectType === "directory") { await mkdir(staging, { mode: 0o700 }); await tar.x({ cwd: staging, file: record.temporaryPath, preservePaths: false, strict: true }); }
      else if (objectType === "symlink") { const target = await readFile(record.temporaryPath); if (target.length > 4095 || target.includes(0)) throw new QuirtError("invalid_request", "Quirt symlink target is invalid"); await symlink(target, staging); }
      else { await copyFile(record.temporaryPath, staging, constants.COPYFILE_EXCL); const handle = await open(staging, constants.O_RDWR | constants.O_NOFOLLOW); try { await handle.sync(); } finally { await handle.close(); } if (await hashFile(staging) !== digest) throw new QuirtError("digest_mismatch", "Quirt staged upload integrity check failed"); }
      const mode = objectNumber(finalMetadata.mode); const uid = objectNumber(finalMetadata.uid); const gid = objectNumber(finalMetadata.gid); if (objectType !== "symlink" && mode !== undefined) await chmod(staging, mode); if (uid !== undefined || gid !== undefined) { if (objectType === "symlink") await lchown(staging, uid ?? -1, gid ?? -1); else await chown(staging, uid ?? -1, gid ?? -1); } const atime = objectString(finalMetadata.atime); const mtime = objectString(finalMetadata.mtime); if (atime !== undefined || mtime !== undefined) { const current = await lstat(staging); if (objectType === "symlink") await lutimes(staging, atime === undefined ? current.atime : new Date(atime), mtime === undefined ? current.mtime : new Date(mtime)); else await utimes(staging, atime === undefined ? current.atime : new Date(atime), mtime === undefined ? current.mtime : new Date(mtime)); }
      const staged = await lstat(staging); const intent = { phase: "placing", destination: record.destinationPath, stagePath: staging, stageDevice: Number(staged.dev), stageInode: Number(staged.ino), size: record.expectedSize, sha256: digest, archiveFormat: record.archiveFormat }; this.state.native.updateTransfer(transferId, { status: "preparing", completion: intent }); prepared = true;
      await verifyParent(parentWitness);
      if (objectType === "directory") { if (destinationExists) await rm(record.destinationPath, { recursive: true, force: false }); await rename(staging, record.destinationPath); }
      else if (noClobber || !overwrite) { await link(staging, record.destinationPath); await unlink(staging); }
      else await rename(staging, record.destinationPath);
      await fsyncParent(record.destinationPath); await rm(record.temporaryPath, { recursive: true, force: true });
    } catch (cause) { if (!prepared) await rm(staging, { recursive: true, force: true }); throw cause; }
    const finalStat = await lstat(record.destinationPath); const completion = { destination: record.destinationPath, device: Number(finalStat.dev), inode: Number(finalStat.ino), size: objectType === "file" ? finalStat.size : record.expectedSize, sha256: digest, mode: finalStat.mode & 0o7777, uid: finalStat.uid, gid: finalStat.gid, archiveFormat: record.archiveFormat, objectType, placement: "same-parent-stage" };
    const completed = this.state.native.updateTransfer(transferId, { status: "completed", completion, temporaryPath: null });
    this.#emit({ transferId, event: "transfer.completed", status: completed.status, transferredBytes: record.expectedSize, expectedSize: record.expectedSize }); return { transfer: this.#public(completed), duplicate: false, result: completion };
  }

  async cancel(transferId: string, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    return await this.#exclusive(transferId, async () => await this.#cancel(transferId, ownerPrincipalFingerprint));
  }

  async #cancel(transferId: string, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    const record = this.state.native.getTransfer(transferId, ownerPrincipalFingerprint);
    if (record.status === "completed") throw new QuirtError("conflict", "Completed Quirt transfer cannot be canceled");
    if (record.status === "canceled") return { transfer: this.#public(record), duplicate: true };
    if (record.temporaryPath !== null) await rm(record.temporaryPath, { recursive: true, force: true }); const stagePath = objectString(record.completion?.stagePath); if (stagePath !== undefined) await rm(stagePath, { recursive: true, force: true });
    const canceled = this.state.native.updateTransfer(transferId, { status: "canceled", errorCode: "transfer_canceled", temporaryPath: null });
    this.#emit({ transferId, event: "transfer.canceled", status: canceled.status, expectedSize: canceled.expectedSize }); return { transfer: this.#public(canceled), duplicate: false };
  }

  async recover(): Promise<{ active: number; failed: number; completed: number }> {
    let active = 0; let failed = 0; let completed = 0; let cursor: { afterCreatedAt?: string; afterTransferId?: string } = {};
    while (true) {
      const page = this.state.native.listTransfersPage(this.config.expectedPrincipal.principalFingerprint, { maximum: 1000, ...cursor });
      for (const record of page.records) {
        if (record.status !== "active" && record.status !== "preparing") continue;
        if (record.status === "preparing") { const outcome = await this.#recoverPreparing(record); if (outcome === "completed") completed += 1; else if (outcome === "active") active += 1; else failed += 1; this.#emit({ transferId: record.transferId, event: "transfer.recovered", status: outcome, expectedSize: record.expectedSize }); continue; }
        const path = record.direction === "upload" ? record.temporaryPath : record.sourcePath; if (path !== null && await lstat(path).then(() => true).catch(() => false)) active += 1; else { this.state.native.updateTransfer(record.transferId, { status: "failed", errorCode: "source_changed" }); failed += 1; }
      }
      if (page.next === null) break; cursor = { afterCreatedAt: page.next.createdAt, afterTransferId: page.next.transferId };
    }
    return { active, failed, completed };
  }

  #active(record: QuirtTransferRecord, direction: "upload" | "download"): void {
    if (record.direction !== direction) throw new QuirtError("invalid_request", "Quirt transfer direction does not support this operation");
    if (record.status === "canceled") throw new QuirtError("transfer_canceled", "Quirt transfer was canceled");
    if (record.status !== "active") throw new QuirtError("invalid_request", "Quirt transfer is not active");
  }

  async #recoverPreparing(record: QuirtTransferRecord): Promise<"active" | "completed" | "failed"> {
    const intent = record.completion; const destination = record.destinationPath; const stagePath = objectString(intent?.stagePath); const stageDevice = objectNumber(intent?.stageDevice); const stageInode = objectNumber(intent?.stageInode); const digest = objectString(intent?.sha256);
    if (destination === null || stagePath === undefined || stageDevice === undefined || stageInode === undefined || digest === undefined) { this.state.native.updateTransfer(record.transferId, { status: "failed", errorCode: "changed_during_operation" }); return "failed"; }
    const destinationStat = await lstat(destination).catch(() => null);
    if (destinationStat !== null && Number(destinationStat.dev) === stageDevice && Number(destinationStat.ino) === stageInode) {
      const objectType = objectString(record.metadata.objectType) ?? (record.archiveFormat === "tar" ? "directory" : "file"); const placedDigest = objectType === "symlink" ? createHash("sha256").update(await linkBytes(destination)).digest("hex") : objectType === "file" ? await hashFile(destination) : digest; if (placedDigest !== digest) { this.state.native.updateTransfer(record.transferId, { status: "failed", errorCode: "digest_mismatch" }); return "failed"; }
      await rm(stagePath, { recursive: true, force: true }); if (record.temporaryPath !== null) await rm(record.temporaryPath, { recursive: true, force: true }); const raw = await lstat(destination); const completion = { destination, device: Number(raw.dev), inode: Number(raw.ino), size: objectType === "file" ? raw.size : record.expectedSize, sha256: digest, mode: raw.mode & 0o7777, uid: raw.uid, gid: raw.gid, archiveFormat: record.archiveFormat, objectType, placement: "recovered-same-parent-stage" }; this.state.native.updateTransfer(record.transferId, { status: "completed", completion, temporaryPath: null }); return "completed";
    }
    if (destinationStat !== null) { this.state.native.updateTransfer(record.transferId, { status: "failed", errorCode: "conflict" }); return "failed"; }
    const temporaryExists = record.temporaryPath !== null && await lstat(record.temporaryPath).then(() => true).catch(() => false); if (temporaryExists) { await rm(stagePath, { recursive: true, force: true }); this.state.native.updateTransfer(record.transferId, { status: "active", completion: null }); return "active"; }
    this.state.native.updateTransfer(record.transferId, { status: "failed", errorCode: "source_changed" }); return "failed";
  }

  async #verifySource(record: QuirtTransferRecord): Promise<void> {
    if (record.sourcePath === null || record.sourceIdentity === null) return;
    const current = sourceIdentity(await lstat(record.sourcePath)); const expected = record.sourceIdentity;
    if (current.device !== expected.device || current.inode !== expected.inode || current.mtimeMs !== expected.mtimeMs || current.type !== expected.type || (current.type === "file" || current.type === "symlink") && current.size !== expected.size) throw new QuirtError("source_changed", "Quirt transfer source changed", true);
  }

  #public(record: QuirtTransferRecord): Record<string, unknown> {
    return { transferId: record.transferId, direction: record.direction, status: record.status, source: record.sourcePath, destination: record.destinationPath, expectedSize: record.expectedSize, chunkSize: record.chunkSize, digestAlgorithm: record.digestAlgorithm, expectedDigest: record.expectedDigest, compression: record.compression, archiveFormat: record.archiveFormat, metadata: record.metadata, sourceIdentity: record.sourceIdentity, completion: record.completion, errorCode: record.errorCode, createdAt: record.createdAt, updatedAt: record.updatedAt, completedAt: record.completedAt };
  }

  #emit(event: QuirtTransferEvent): void { this.#events.emit("event", Object.freeze(event)); }

  async #exclusive<T>(transferId: string, action: () => Promise<T>): Promise<T> {
    const prior = this.#locks.get(transferId) ?? Promise.resolve(); let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }); const tail = prior.then(() => gate); this.#locks.set(transferId, tail); await prior;
    try { return await action(); }
    finally { release(); if (this.#locks.get(transferId) === tail) this.#locks.delete(transferId); }
  }
}
