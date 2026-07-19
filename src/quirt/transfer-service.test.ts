import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdtempSync, readFileSync, readlinkSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import { QuirtError } from "./error.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";
import { QuirtTransferService } from "./transfer-service.js";

const roots: string[] = []; const stores: QuirtStateStore[] = [];
afterEach(() => { for (const store of stores.splice(0)) store.close(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function digest(value: Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function fixture(database = false): { root: string; state: QuirtStateStore; service: QuirtTransferService } { const root = mkdtempSync(join(tmpdir(), "quirt-transfer-")); roots.push(root); const config = quirtTestConfig(root); const state = new QuirtStateStore(database ? config.databasePath : ":memory:"); stores.push(state); return { root, state, service: new QuirtTransferService(config, state) }; }
const owner = "a".repeat(64);

describe("Quirt durable binary transfers", () => {
  it("uploads out of order, resumes, accepts identical duplicates, and atomically completes", async () => {
    const f = fixture(); const events: string[] = []; const unsubscribe = f.service.onEvent(event => events.push(event.event)); const content = Buffer.from([0, 1, 2, 3, 255, 5, 6, 7]); const destination = join(f.root, "destination.bin");
    const begun = await f.service.begin({ direction: "upload", destination, expectedSize: content.length, expectedDigest: digest(content), chunkSize: 4096, mode: 0o640 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId;
    await f.service.write({ transferId, offset: 4, content: content.subarray(4), chunkDigest: digest(content.subarray(4)) }, owner);
    const first = await f.service.write({ transferId, offset: 0, content: content.subarray(0, 4) }, owner); assert.equal(first.duplicate, false);
    const duplicate = await f.service.write({ transferId, offset: 0, content: content.subarray(0, 4) }, owner); assert.equal(duplicate.duplicate, true);
    assert.throws(() => readFileSync(destination)); const completed = await f.service.complete(transferId, owner); assert.equal(completed.duplicate, false); assert.deepEqual(readFileSync(destination), content);
    const replay = await f.service.complete(transferId, owner); assert.equal(replay.duplicate, true); assert.equal((replay.result as { sha256: string }).sha256, digest(content)); assert.deepEqual(events, ["transfer.started", "transfer.progress", "transfer.progress", "transfer.completed"]); unsubscribe();
  });

  it("rejects conflicting chunks, missing ranges, and final digest mismatch without exposing partial files", async () => {
    const f = fixture(); const destination = join(f.root, "destination.bin"); const begun = await f.service.begin({ direction: "upload", destination, expectedSize: 8, expectedDigest: digest(Buffer.from("12345678")), chunkSize: 4096 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId;
    await f.service.write({ transferId, offset: 0, content: Buffer.from("1234") }, owner);
    await assert.rejects(f.service.write({ transferId, offset: 0, content: Buffer.from("zzzz") }, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
    await assert.rejects(f.service.complete(transferId, owner), (error: unknown) => error instanceof QuirtError && error.code === "range_gap"); assert.throws(() => readFileSync(destination));
    await f.service.write({ transferId, offset: 4, content: Buffer.from("xxxx") }, owner); await assert.rejects(f.service.complete(transferId, owner), (error: unknown) => error instanceof QuirtError && error.code === "digest_mismatch"); assert.throws(() => readFileSync(destination));
  });

  it("persists ranges across reopen and resumes compressed binary chunks", async () => {
    const f = fixture(true); const content = Buffer.from("restart-safe"); const destination = join(f.root, "resume.txt"); const begun = await f.service.begin({ direction: "upload", destination, expectedSize: content.length, expectedDigest: digest(content), chunkSize: 4096, compression: "gzip" }, owner); const transferId = (begun.transfer as { transferId: string }).transferId;
    await f.service.write({ transferId, offset: 0, content: gzipSync(content.subarray(0, 5)) }, owner); f.state.close(); stores.splice(stores.indexOf(f.state), 1);
    const reopened = new QuirtStateStore(quirtTestConfig(f.root).databasePath); stores.push(reopened); const service = new QuirtTransferService(quirtTestConfig(f.root), reopened); assert.equal((await service.recover()).active, 1);
    await service.write({ transferId, offset: 5, content: gzipSync(content.subarray(5)) }, owner); await service.complete(transferId, owner); assert.deepEqual(readFileSync(destination), content);
  });

  it("downloads bounded resumable ranges and detects source mutation", async () => {
    const f = fixture(); const source = join(f.root, "source.bin"); const content = Buffer.from([0, 255, 1, 2, 3, 4]); writeFileSync(source, content);
    const begun = await f.service.begin({ direction: "download", source, chunkSize: 4096 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId;
    const first = await f.service.read({ transferId, offset: 1, maximumBytes: 3 }, owner); assert.deepEqual(first.binary, content.subarray(1, 4)); assert.equal(first.payload.chunkSha256, digest(content.subarray(1, 4)));
    writeFileSync(source, Buffer.from("changed-source")); await assert.rejects(f.service.read({ transferId, offset: 0 }, owner), (error: unknown) => error instanceof QuirtError && error.code === "source_changed");
  });

  it("cancels partial uploads durably and denies cross-principal access", async () => {
    const f = fixture(); const begun = await f.service.begin({ direction: "upload", destination: join(f.root, "canceled"), expectedSize: 1, chunkSize: 4096 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId;
    assert.throws(() => f.service.status(transferId, "b".repeat(64)), (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed");
    const canceled = await f.service.cancel(transferId, owner); assert.equal((canceled.transfer as { status: string }).status, "canceled"); await assert.rejects(f.service.write({ transferId, offset: 0, content: Buffer.from("x") }, owner), (error: unknown) => error instanceof QuirtError && error.code === "transfer_canceled");
  });

  it("packages and restores directory archives without exposing an incomplete destination", async () => {
    const f = fixture(); const source = join(f.root, "source-directory"); const destination = join(f.root, "restored-directory"); writeFileSync(join(f.root, "seed"), "seed");
    await import("node:fs/promises").then(fs => fs.mkdir(source)); writeFileSync(join(source, "hello.txt"), "hello");
    const download = await f.service.begin({ direction: "download", source, archiveFormat: "tar", chunkSize: 1024 * 1024 }, owner); const downloadId = (download.transfer as { transferId: string }).transferId; const part = await f.service.read({ transferId: downloadId, offset: 0, maximumBytes: 1024 * 1024 }, owner); await f.service.complete(downloadId, owner);
    const upload = await f.service.begin({ direction: "upload", destination, expectedSize: part.payload.rawByteCount as number, expectedDigest: digest(part.binary), archiveFormat: "tar", chunkSize: 1024 * 1024 }, owner); const uploadId = (upload.transfer as { transferId: string }).transferId; await f.service.write({ transferId: uploadId, offset: 0, content: part.binary }, owner); await f.service.complete(uploadId, owner); assert.equal(readFileSync(join(destination, "hello.txt"), "utf8"), "hello");
  });

  it("downloads and atomically restores symlinks without following their targets", async () => {
    const f = fixture(); const source = join(f.root, "source-link"); const destination = join(f.root, "destination-link"); symlinkSync("relative-target", source);
    const download = await f.service.begin({ direction: "download", source, chunkSize: 4096 }, owner); const downloadRecord = download.transfer as { transferId: string; metadata: { objectType: string } }; assert.equal(downloadRecord.metadata.objectType, "symlink"); const page = await f.service.read({ transferId: downloadRecord.transferId, offset: 0 }, owner); assert.deepEqual(page.binary, Buffer.from("relative-target")); await f.service.complete(downloadRecord.transferId, owner);
    const upload = await f.service.begin({ direction: "upload", destination, expectedSize: page.binary.length, expectedDigest: digest(page.binary), chunkSize: 4096, objectType: "symlink" }, owner); const uploadId = (upload.transfer as { transferId: string }).transferId; await f.service.write({ transferId: uploadId, offset: 0, content: page.binary }, owner); assert.equal(existsSync(destination), false); const completed = await f.service.complete(uploadId, owner); assert.equal((completed.result as { objectType: string }).objectType, "symlink"); assert.equal(lstatSync(destination).isSymbolicLink(), true); assert.equal(readlinkSync(destination), "relative-target");
  });

  it("recovers a crash after atomic placement from the durable staged inode intent", async () => {
    const f = fixture(true); const content = Buffer.from("placed-before-response"); const destination = join(f.root, "placed.txt"); const begun = await f.service.begin({ direction: "upload", destination, expectedSize: content.length, expectedDigest: digest(content), chunkSize: 4096 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId; await f.service.write({ transferId, offset: 0, content }, owner); const record = f.state.native.getTransfer(transferId, owner); const stagePath = join(f.root, `.placed.txt.quirt-${transferId}.stage`); copyFileSync(record.temporaryPath!, stagePath); const staged = lstatSync(stagePath); f.state.native.updateTransfer(transferId, { status: "preparing", completion: { phase: "placing", destination, stagePath, stageDevice: Number(staged.dev), stageInode: Number(staged.ino), size: content.length, sha256: digest(content), archiveFormat: "none" } }); renameSync(stagePath, destination); f.state.close(); stores.splice(stores.indexOf(f.state), 1);
    const reopened = new QuirtStateStore(quirtTestConfig(f.root).databasePath); stores.push(reopened); const service = new QuirtTransferService(quirtTestConfig(f.root), reopened); const recovery = await service.recover(); assert.equal(recovery.completed, 1); assert.equal(reopened.native.getTransfer(transferId, owner).status, "completed"); assert.deepEqual(readFileSync(destination), content); assert.equal(existsSync(record.temporaryPath!), false); const replay = await service.complete(transferId, owner); assert.equal(replay.duplicate, true);
  });

  it("completes empty uploads and rejects incomplete manifests and decompression bombs", async () => {
    const f = fixture(); await assert.rejects(f.service.begin({ direction: "upload", destination: join(f.root, "missing-size") }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request"); const emptyPath = join(f.root, "empty"); const empty = await f.service.begin({ direction: "upload", destination: emptyPath, expectedSize: 0, expectedDigest: digest(Buffer.alloc(0)), chunkSize: 4096 }, owner); await f.service.complete((empty.transfer as { transferId: string }).transferId, owner); assert.equal(readFileSync(emptyPath).length, 0);
    const compressed = await f.service.begin({ direction: "upload", destination: join(f.root, "bomb"), expectedSize: 5000, chunkSize: 4096, compression: "gzip" }, owner); await assert.rejects(f.service.write({ transferId: (compressed.transfer as { transferId: string }).transferId, offset: 0, content: gzipSync(Buffer.alloc(5000, 1)) }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request");
  });

  it("streams a large transfer in bounded chunks and enforces no-clobber before explicit overwrite", async () => {
    const f = fixture(); const destination = join(f.root, "large.bin"); const content = Buffer.alloc(3 * 1024 * 1024 + 17, 0x6b); const begun = await f.service.begin({ direction: "upload", destination, expectedSize: content.length, expectedDigest: digest(content), chunkSize: 1024 * 1024, mode: 0o640 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId; for (let offset = 0; offset < content.length; offset += 1024 * 1024) await f.service.write({ transferId, offset, content: content.subarray(offset, Math.min(content.length, offset + 1024 * 1024)) }, owner); await f.service.complete(transferId, owner); assert.deepEqual(readFileSync(destination), content); assert.equal(lstatSync(destination).mode & 0o777, 0o640);
    const replacement = Buffer.from("replacement"); const blocked = await f.service.begin({ direction: "upload", destination, expectedSize: replacement.length, expectedDigest: digest(replacement), chunkSize: 4096 }, owner); const blockedId = (blocked.transfer as { transferId: string }).transferId; await f.service.write({ transferId: blockedId, offset: 0, content: replacement }, owner); await assert.rejects(f.service.complete(blockedId, owner), (error: unknown) => error instanceof QuirtError && error.code === "already_exists"); assert.deepEqual(readFileSync(destination), content); await f.service.cancel(blockedId, owner);
    const allowed = await f.service.begin({ direction: "upload", destination, expectedSize: replacement.length, expectedDigest: digest(replacement), chunkSize: 4096, overwrite: true, noClobber: false }, owner); const allowedId = (allowed.transfer as { transferId: string }).transferId; await f.service.write({ transferId: allowedId, offset: 0, content: replacement }, owner); await f.service.complete(allowedId, owner); assert.deepEqual(readFileSync(destination), replacement);
  });

  it("serializes concurrent writers and pages durable range status", async () => {
    const f = fixture(); const destination = join(f.root, "concurrent.bin"); const content = Buffer.from("abcde"); const begun = await f.service.begin({ direction: "upload", destination, expectedSize: content.length, expectedDigest: digest(content), chunkSize: 4096 }, owner); const transferId = (begun.transfer as { transferId: string }).transferId;
    const [first, conflict] = await Promise.allSettled([f.service.write({ transferId, offset: 0, content: content.subarray(0, 1) }, owner), f.service.write({ transferId, offset: 0, content: Buffer.from("z") }, owner)]); assert.equal(first.status, "fulfilled"); assert.equal(conflict.status, "rejected"); assert.equal(conflict.status === "rejected" && conflict.reason instanceof QuirtError && conflict.reason.code, "conflict");
    for (let offset = 1; offset < content.length; offset += 1) await f.service.write({ transferId, offset, content: content.subarray(offset, offset + 1) }, owner);
    const pageOne = f.service.status(transferId, owner, { maximumRanges: 2 }); assert.equal((pageOne.ranges as unknown[]).length, 2); assert.equal(pageOne.rangesTruncated, true); assert.equal(pageOne.rangeCount, 5); assert.equal(pageOne.coveredBytes, 5); const pageTwo = f.service.status(transferId, owner, { afterOffset: pageOne.nextRangeOffset as number, maximumRanges: 3 }); assert.equal((pageTwo.ranges as unknown[]).length, 3); assert.equal(pageTwo.rangesTruncated, false);
    await f.service.complete(transferId, owner); assert.deepEqual(readFileSync(destination), content);
  });

  it("rejects wrong-direction, invalid-range, overlap, and terminal lifecycle conflicts precisely", async () => {
    const f = fixture(); const upload = await f.service.begin({ direction: "upload", destination: join(f.root, "upload"), expectedSize: 8, chunkSize: 4096 }, owner); const uploadId = (upload.transfer as { transferId: string }).transferId;
    await assert.rejects(f.service.write({ transferId: uploadId, offset: -1, content: Buffer.from("x") }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_offset"); await assert.rejects(f.service.write({ transferId: uploadId, offset: 0, content: Buffer.alloc(0) }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request"); await assert.rejects(f.service.write({ transferId: uploadId, offset: 0, content: Buffer.from("1234"), chunkDigest: "0".repeat(64) }, owner), (error: unknown) => error instanceof QuirtError && error.code === "digest_mismatch");
    await f.service.write({ transferId: uploadId, offset: 0, content: Buffer.from("1234") }, owner); await assert.rejects(f.service.write({ transferId: uploadId, offset: 2, content: Buffer.from("xx") }, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict"); await assert.rejects(f.service.read({ transferId: uploadId, offset: 0 }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request"); const canceled = await f.service.cancel(uploadId, owner); assert.equal(canceled.duplicate, false); assert.equal((await f.service.cancel(uploadId, owner)).duplicate, true);
    const source = join(f.root, "source"); writeFileSync(source, "source"); const download = await f.service.begin({ direction: "download", source, chunkSize: 4096 }, owner); const downloadId = (download.transfer as { transferId: string }).transferId; await assert.rejects(f.service.write({ transferId: downloadId, offset: 0, content: Buffer.from("x") }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request"); await assert.rejects(f.service.read({ transferId: downloadId, offset: 99 }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_offset"); await assert.rejects(f.service.read({ transferId: downloadId, offset: 0, maximumBytes: 0 }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request"); await f.service.complete(downloadId, owner); await assert.rejects(f.service.cancel(downloadId, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
    const compressed = await f.service.begin({ direction: "download", source, chunkSize: 4096, compression: "gzip", expectedDigest: "0".repeat(64) }, owner); const compressedId = (compressed.transfer as { transferId: string }).transferId; const compressedPage = await f.service.read({ transferId: compressedId, offset: 0 }, owner); assert.equal(gunzipSync(compressedPage.binary).toString(), "source"); await assert.rejects(f.service.complete(compressedId, owner), (error: unknown) => error instanceof QuirtError && error.code === "digest_mismatch");
  });
});
