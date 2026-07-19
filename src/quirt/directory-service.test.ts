import assert from "node:assert/strict";
import { mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtDirectoryService } from "./directory-service.js";
import { QuirtStateStore } from "./state.js";

const roots: string[] = []; const stores: QuirtStateStore[] = []; const services: QuirtDirectoryService[] = [];
afterEach(() => { for (const service of services.splice(0)) service.shutdown(); for (const store of stores.splice(0)) store.close(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture(): { root: string; service: QuirtDirectoryService; state: QuirtStateStore } { const root = mkdtempSync(join(tmpdir(), "quirt-directories-")); roots.push(root); const state = new QuirtStateStore(":memory:"); stores.push(state); const service = new QuirtDirectoryService(state); services.push(service); return { root, service, state }; }

describe("Quirt native directory service", () => {
  it("creates recursively and lists hidden entries in stable change-detecting pages", async () => {
    const f = fixture(); const path = join(f.root, "nested", "target"); const created = await f.service.create({ path, recursive: true, mode: 0o750, uid: process.getuid?.(), gid: process.getgid?.() }); assert.equal((created.metadata as { mode: number }).mode, 0o750); assert.equal((created.metadata as { uid: number }).uid, process.getuid?.());
    for (const name of ["z", ".hidden", "a", "m"]) writeFileSync(join(path, name), name);
    const first = await f.service.list({ path, maximumEntries: 2 }); const firstEntries = first.entries as Array<{ name: string }>;
    assert.deepEqual(firstEntries.map(entry => entry.name), [".hidden", "a"]); assert.equal(first.hiddenIncluded, true); assert.equal(typeof first.continuationToken, "string");
    const second = await f.service.list({ path, maximumEntries: 2, continuationToken: first.continuationToken as string }); assert.deepEqual((second.entries as Array<{ name: string }>).map(entry => entry.name), ["m", "z"]); assert.equal(second.continuationToken, null);
  });

  it("watches create, modify, move, and delete with durable sequencing and explicit cancellation", async () => {
    const f = fixture(); const path = join(f.root, "watch"); await f.service.create({ path });
    const started = await f.service.watch({ action: "start", path }, "a".repeat(64)); const watchId = (started.watch as { watchId: string }).watchId;
    const first = join(path, "first"); writeFileSync(first, "one"); await new Promise(resolve => setTimeout(resolve, 100));
    writeFileSync(first, "two"); const second = join(path, "second"); renameSync(first, second); rmSync(second);
    await new Promise(resolve => setTimeout(resolve, 250));
    const page = await f.service.watch({ action: "read", watchId, after: -1, maximumEvents: 100 }, "a".repeat(64)); const events = page.events as Array<{ sequence: number; event: string }>;
    assert.ok(events.length >= 1); assert.deepEqual(events.map(event => event.sequence), events.map((_event, index) => index)); assert.ok(events.every(event => ["create", "modify", "move", "delete"].includes(event.event)));
    const canceled = await f.service.watch({ action: "cancel", watchId }, "a".repeat(64)); assert.equal((canceled.watch as { status: string }).status, "canceled");
  });

  it("classifies active watches as lost and requiring rescan across supervisor restart", async () => {
    const f = fixture(); const path = join(f.root, "watch"); await f.service.create({ path }); const started = await f.service.watch({ path }, "a".repeat(64)); const watchId = (started.watch as { watchId: string }).watchId;
    const recovery = f.service.recover(); assert.equal(recovery.lost, 1); const record = f.state.native.getWatch(watchId, "a".repeat(64)); assert.equal(record.status, "lost"); assert.equal(record.rescanRequired, true); assert.equal(record.lost, true);
  });

  it("rejects malformed and stale continuation tokens and exact no-clobber creation", async () => {
    const f = fixture(); const path = join(f.root, "paged"); await f.service.create({ path, mode: 0o750 }); writeFileSync(join(path, "a"), "a"); writeFileSync(join(path, "b"), "b"); const first = await f.service.list({ path, maximumEntries: 1 }); const token = first.continuationToken as string;
    await assert.rejects(f.service.list({ path, continuationToken: "not-json", maximumEntries: 1 }), /continuation token is invalid/u); await assert.rejects(f.service.create({ path, noClobber: true }), /already exists/u);
    await new Promise(resolve => setTimeout(resolve, 10)); writeFileSync(join(path, "c"), "c"); await assert.rejects(f.service.list({ path, continuationToken: token, maximumEntries: 1 }), /changed between pages/u);
    const filePath = join(f.root, "not-a-directory"); writeFileSync(filePath, "file"); await assert.rejects(f.service.create({ path: filePath }), /not a directory/u);
  });

  it("paginates a large directory without changing raw-byte ordering", async () => {
    const f = fixture(); const path = join(f.root, "large"); await f.service.create({ path }); for (let index = 0; index < 1025; index += 1) writeFileSync(join(path, `entry-${String(index).padStart(4, "0")}`), "x"); let token: string | undefined; const names: string[] = []; do { const page = await f.service.list({ path, maximumEntries: 113, ...(token === undefined ? {} : { continuationToken: token }) }); names.push(...(page.entries as Array<{ name: string }>).map(entry => entry.name)); token = page.continuationToken as string | null ?? undefined; } while (token !== undefined); assert.equal(names.length, 1025); assert.deepEqual(names, [...names].sort((left, right) => Buffer.from(left).compare(Buffer.from(right))));
  });
});
