import assert from "node:assert/strict";
import { mkdtempSync, readlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtError } from "./error.js";
import { QuirtProcessService, type QuirtJournalAdapter, type QuirtJournalPage, type QuirtJournalQuery, type QuirtProcessIdentity } from "./process-service.js";
import type { QuirtJobManager } from "./job-manager.js";
import type { QuirtSessionManager } from "./session-manager.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";

const owner = "a".repeat(64);
const roots: string[] = [];
const stores: QuirtStateStore[] = [];

afterEach(() => {
  for (const store of stores.splice(0)) { try { store.close(); } catch {} }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

class FixtureJournal implements QuirtJournalAdapter {
  readonly queries: QuirtJournalQuery[] = [];
  constructor(readonly pages: Array<QuirtJournalPage | Error>) {}
  async query(input: QuirtJournalQuery): Promise<QuirtJournalPage> {
    this.queries.push(input);
    const value = this.pages.shift();
    if (value === undefined) return { entries: [], cursor: input.afterCursor ?? null, stderr: "" };
    if (value instanceof Error) throw value;
    return value;
  }
}

function managers(input: { pid?: number; session?: boolean } = {}): { sessions: QuirtSessionManager; jobs: QuirtJobManager } {
  const sessions = { list: () => input.session && input.pid !== undefined ? [{ sessionId: "session-1", ptyPid: input.pid }] : [] } as unknown as QuirtSessionManager;
  const jobs = { list: () => !input.session && input.pid !== undefined ? [{ jobId: "job-1", processId: input.pid }] : [] } as unknown as QuirtJobManager;
  return { sessions, jobs };
}

function fixture(journal: QuirtJournalAdapter = new FixtureJournal([]), correlation: { pid?: number; session?: boolean } = {}, killProcess: (pid: number, signal: NodeJS.Signals | 0) => void = process.kill): { root: string; state: QuirtStateStore; service: QuirtProcessService } {
  const root = mkdtempSync(join(tmpdir(), "quirt-process-")); roots.push(root);
  const state = new QuirtStateStore(quirtTestConfig(root).databasePath); stores.push(state);
  const values = managers(correlation);
  return { root, state, service: new QuirtProcessService(quirtTestConfig(root), state, values.sessions, values.jobs, journal, killProcess) };
}

function visiblePid(): number { return Number(readlinkSync("/proc/self")); }

describe("Quirt native process and journald service", () => {
  it("reads exact Linux identity, credentials, cgroup, namespaces, and bounded process lists", async () => {
    const f = fixture();
    const current = await f.service.get({ pid: visiblePid() }, owner);
    const identity = current.identity as QuirtProcessIdentity;
    assert.equal(identity.pid, visiblePid()); assert.ok(identity.startTimeTicks > 0); assert.match(identity.bootId, /^[a-f0-9-]{36}$/u);
    assert.equal(typeof (current.credentials as { uid: number }).uid, "number"); assert.ok(Array.isArray(current.cgroup));
    const namespaces = current.namespaces as Record<string, unknown>; assert.ok("pid" in namespaces); assert.ok("mount" in namespaces);
    const listed = await f.service.list({ maximumProcesses: 1 }, owner);
    assert.ok((listed.processes as unknown[]).length <= 1); assert.equal(listed.bounded, true);
    const none = await f.service.list({ maximumProcesses: 2, uid: 0x7fffffff }, owner); assert.deepEqual(none.processes, []);
  });

  it("signals only an exact non-reused process identity and reports exit races precisely", async () => {
    const signals: Array<NodeJS.Signals | 0> = []; const f = fixture(new FixtureJournal([]), {}, (_pid, signal) => { signals.push(signal); }); const info = await f.service.get({ pid: visiblePid() }, owner); const identity = info.identity as QuirtProcessIdentity;
    const signaled = await f.service.signal({ identity, signal: "SIGCONT" }, owner); assert.equal(signaled.precondition, "exact-identity-matched"); assert.equal(signaled.postcondition, "alive");
    assert.deepEqual(signals, ["SIGCONT", 0]);
    await assert.rejects(f.service.signal({ identity: { ...identity, startTimeTicks: identity.startTimeTicks + 1 }, signal: "SIGCONT" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "pid_reused");
    await assert.rejects(f.service.signal({ identity, signal: "SIGBOGUS" as NodeJS.Signals }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request");
    await assert.rejects(f.service.get({ pid: 0x7fffffff }, owner), (error: unknown) => error instanceof QuirtError && error.code === "process_exited");
    const denied = fixture(new FixtureJournal([]), {}, () => { throw Object.assign(new Error("denied"), { code: "EPERM" }); }); await assert.rejects(denied.service.signal({ identity, signal: "SIGCONT" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed");
    const exited = fixture(new FixtureJournal([]), {}, () => { throw Object.assign(new Error("gone"), { code: "ESRCH" }); }); await assert.rejects(exited.service.signal({ identity, signal: "SIGCONT" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "process_exited");
  });

  it("builds bounded trees and attaches only to exactly correlated Quirt processes", async () => {
    const hostPid = visiblePid(); const probe = fixture(); const info = await probe.service.get({ pid: hostPid }, owner); const identity = info.identity as QuirtProcessIdentity;
    const tree = await probe.service.tree({ pid: hostPid, maximumDepth: 2, maximumProcesses: 8 }, owner); assert.ok((tree.processes as unknown[]).length <= 1); assert.equal(tree.cycleDetected, false);
    await assert.rejects(probe.service.attach({ source: "process", identity }, owner), (error: unknown) => error instanceof QuirtError && error.code === "unsupported_host_capability");
    const correlated = fixture(new FixtureJournal([]), { pid: hostPid }); const attached = await correlated.service.attach({ source: "process", identity }, owner) as Record<string, unknown>; assert.deepEqual(attached.jobs, ["job-1"]); assert.equal(attached.signalSemantics, "existing-process-group");
    assert.equal(correlated.state.native.listObjects("quirt_process_attachments", owner).length, 1);
    const namespace = await correlated.service.namespaces({ pid: hostPid }, owner); assert.equal(namespace.containerized, "not-inferred");
  });

  it("persists bounded machine-readable journal cursors, filters, binary fields, polling, rotation, and cancellation", async () => {
    const journal = new FixtureJournal([
      { entries: [
        { __CURSOR: "cursor-1", __REALTIME_TIMESTAMP: "10", __MONOTONIC_TIMESTAMP: "1", _BOOT_ID: "boot-a", _SYSTEMD_UNIT: "demo.service", _PID: "10", _UID: "0", PRIORITY: "4", MESSAGE: [0, 255] },
        { __CURSOR: "cursor-2", __REALTIME_TIMESTAMP: "20", __MONOTONIC_TIMESTAMP: "2", _BOOT_ID: "boot-a", MESSAGE: "ready" }
      ], cursor: "cursor-2", stderr: "fixture" },
      { entries: [{ __CURSOR: "cursor-3", _BOOT_ID: "boot-b", MESSAGE: "rotated" }], cursor: "cursor-3", stderr: "", rotationDetected: true }
    ]);
    const f = fixture(journal);
    const opened = await f.service.attach({ source: "journal", action: "open", filters: { unit: "demo.service", pid: 10, uid: 0, priority: 4 }, maximumEntries: 2 }, owner) as { payload: Record<string, unknown>; binary: Buffer };
    const attachmentId = opened.payload.attachmentId as string; assert.equal(opened.payload.cursor, "cursor-2"); assert.equal(opened.payload.entryCount, 2); assert.equal(opened.payload.truncated, true); assert.ok(opened.binary.includes(Buffer.from("[0,255]")));
    assert.deepEqual((opened.payload.entries as Array<{ binaryFields: string[] }>)[0]!.binaryFields, ["MESSAGE"]); assert.deepEqual(journal.queries[0]!.filters, { unit: "demo.service", pid: 10, uid: 0, priority: 4 });
    const next = await f.service.attach({ source: "journal", action: "read", attachmentId, maximumEntries: 4 }, owner) as { payload: Record<string, unknown>; binary: Buffer }; assert.equal(journal.queries[1]!.afterCursor, "cursor-2"); assert.equal(next.payload.cursor, "cursor-3"); assert.equal(next.payload.rotationDetected, true);
    const stored = f.state.native.getObject("quirt_journal_cursors", attachmentId, owner); assert.equal(stored.data.cursor, "cursor-3");
    const canceled = await f.service.attach({ source: "journal", action: "cancel", attachmentId }, owner) as { payload: Record<string, unknown>; binary: Buffer }; assert.equal(canceled.payload.status, "canceled"); assert.equal(canceled.binary.length, 0);
    await assert.rejects(f.service.attach({ source: "journal", action: "read", attachmentId }, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
    await assert.rejects(f.service.attach({ source: "journal", action: "read", attachmentId }, "b".repeat(64)), (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed");
  });

  it("maps invalidated and unavailable journal cursors and rejects adapter overrun", async () => {
    const invalid = fixture(new FixtureJournal([new QuirtError("journal_cursor_invalidated", "fixture invalid", true)]));
    await assert.rejects(invalid.service.attach({ source: "journal", action: "open", afterCursor: "gone" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "journal_cursor_invalidated" && error.retryable);
    const unavailable = fixture(new FixtureJournal([new QuirtError("provider_unavailable", "fixture unavailable")]));
    await assert.rejects(unavailable.service.attach({ source: "journal", action: "open" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "provider_unavailable");
    const overrun = fixture(new FixtureJournal([{ entries: [{ __CURSOR: "a" }, { __CURSOR: "b" }], cursor: "b", stderr: "" }]));
    await assert.rejects(overrun.service.attach({ source: "journal", action: "open", maximumEntries: 1 }, owner), (error: unknown) => error instanceof QuirtError && error.code === "result_truncated");
  });
});
