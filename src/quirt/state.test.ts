import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { QuirtError } from "./error.js";
import { QUIRT_STATE_SCHEMA_VERSION, QuirtStateStore } from "./state.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function path(): string { const root = mkdtempSync(join(tmpdir(), "quirt-state-")); roots.push(root); return join(root, "state.sqlite"); }

function removeNativeSchema(database: DatabaseSync): void {
  database.exec(`
    PRAGMA foreign_keys=OFF;
    DELETE FROM quirt_schema_migrations WHERE version>=5;
    DROP TABLE IF EXISTS quirt_transfer_ranges; DROP TABLE IF EXISTS quirt_transfers; DROP TABLE IF EXISTS quirt_native_results;
    DROP TABLE IF EXISTS quirt_watch_events; DROP TABLE IF EXISTS quirt_directory_watches;
    DROP TABLE IF EXISTS quirt_repository_mirrors; DROP TABLE IF EXISTS quirt_materializations; DROP TABLE IF EXISTS quirt_worktrees; DROP TABLE IF EXISTS quirt_git_operations;
    DROP TABLE IF EXISTS quirt_recording_indexes; DROP TABLE IF EXISTS quirt_recording_events; DROP TABLE IF EXISTS quirt_recording_exports; DROP TABLE IF EXISTS quirt_recordings;
    DROP TABLE IF EXISTS quirt_process_attachments; DROP TABLE IF EXISTS quirt_journal_cursors;
    DROP TABLE IF EXISTS quirt_handoffs; DROP TABLE IF EXISTS quirt_session_snapshots;
    DROP TABLE IF EXISTS quirt_capability_probes; DROP TABLE IF EXISTS quirt_cleanup_records;
    PRAGMA foreign_keys=ON;
  `);
}

describe("Quirt durable state", () => {
  it("initializes and reopens the exact schema transactionally", () => {
    const database = path();
    const first = new QuirtStateStore(database); assert.equal(first.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION); first.integrityCheck(); first.close();
    const second = new QuirtStateStore(database); assert.equal(second.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION); second.integrityCheck(); second.close();
  });

  it("upgrades an earlier durable schema idempotently", () => {
    const database = path(); const current = new QuirtStateStore(database); current.close(); const legacy = new DatabaseSync(database);
    legacy.exec(`
      PRAGMA foreign_keys=OFF;
      DELETE FROM quirt_schema_migrations WHERE version>=2;
      DROP TABLE quirt_session_readers; DROP TABLE quirt_request_nonces;
      DROP TABLE quirt_transfer_ranges; DROP TABLE quirt_transfers; DROP TABLE quirt_native_results;
      DROP TABLE quirt_watch_events; DROP TABLE quirt_directory_watches;
      DROP TABLE quirt_repository_mirrors; DROP TABLE quirt_materializations; DROP TABLE quirt_worktrees; DROP TABLE quirt_git_operations;
      DROP TABLE quirt_recording_indexes; DROP TABLE quirt_recording_events; DROP TABLE quirt_recording_exports; DROP TABLE quirt_recordings;
      DROP TABLE quirt_process_attachments; DROP TABLE quirt_journal_cursors;
      DROP TABLE quirt_handoffs; DROP TABLE quirt_session_snapshots;
      DROP TABLE quirt_capability_probes; DROP TABLE quirt_cleanup_records;
      PRAGMA foreign_keys=ON;
    `); legacy.close();
    const upgraded = new QuirtStateStore(database); assert.equal(upgraded.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION); upgraded.integrityCheck(); upgraded.close();
  });

  it("migrates the exact Checkpoint B schema 4 through native schema 12 and power schema 18 without changing core records", () => {
    const database = path(); const owner = "a".repeat(64); const current = new QuirtStateStore(database); current.createSession({ sessionId: "schema-four-session", name: "preserved", tmuxName: null, mode: "direct", shell: "/bin/bash", workingDirectory: "/root", columns: 80, rows: 24, ownerPrincipalFingerprint: owner }); current.close();
    const legacy = new DatabaseSync(database); removeNativeSchema(legacy); assert.equal((legacy.prepare("SELECT MAX(version) AS version FROM quirt_schema_migrations").get() as { version: number }).version, 4); legacy.close();
    const upgraded = new QuirtStateStore(database); assert.equal(upgraded.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION); assert.equal(upgraded.getSession("schema-four-session").name, "preserved");
    upgraded.native.putObject("quirt_session_snapshots", { objectId: "snapshot-after-migration", ownerPrincipalFingerprint: owner, status: "ready", data: { sessionId: "schema-four-session" } }); upgraded.integrityCheck(); upgraded.close();
    const reopened = new QuirtStateStore(database); assert.equal(reopened.native.getObject("quirt_session_snapshots", "snapshot-after-migration", owner).data.sessionId, "schema-four-session"); reopened.close();
  });

  it("rolls a failed native migration back to schema 4 before a safe retry through power schema 18", () => {
    const database = path(); const current = new QuirtStateStore(database); current.close(); const legacy = new DatabaseSync(database); removeNativeSchema(legacy); legacy.exec("CREATE TABLE quirt_transfers(conflict TEXT)"); legacy.close();
    assert.throws(() => new QuirtStateStore(database), /already exists/u);
    const inspected = new DatabaseSync(database); assert.equal((inspected.prepare("SELECT MAX(version) AS version FROM quirt_schema_migrations").get() as { version: number }).version, 4); assert.equal((inspected.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='quirt_native_results'").get() as { count: number }).count, 0); inspected.exec("DROP TABLE quirt_transfers"); inspected.close();
    const retried = new QuirtStateStore(database); assert.equal(retried.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION); retried.integrityCheck(); retried.close();
  });

  it("persists sessions, dimensions, ownership, and recovery", () => {
    const database = path();
    const first = new QuirtStateStore(database);
    const created = first.createSession({ sessionId: "session-1", name: "root", tmuxName: "quirt-session-1", shell: "/bin/bash", workingDirectory: "/root", environment: { TERM: "xterm-256color" }, columns: 120, rows: 40, ownerPrincipalFingerprint: "a".repeat(64) });
    first.updateSession(created.sessionId, { status: "running", ptyPid: 123, columns: 140, recovered: true }); first.close();
    const second = new QuirtStateStore(database); const loaded = second.getSession("session-1");
    assert.equal(loaded.status, "running"); assert.equal(loaded.mode, "tmux"); assert.equal(loaded.executable, "/bin/bash");
    assert.deepEqual(loaded.arguments, []); assert.equal(loaded.loginShell, true); assert.equal(loaded.columns, 140);
    assert.equal(loaded.environment.TERM, "xterm-256color"); assert.ok(loaded.recoveredAt); second.close();
  });

  it("persists independent durable reader cursors across detach and reopen", () => {
    const database = path(); const owner = "a".repeat(64); const first = new QuirtStateStore(database);
    const session = first.createSession({ sessionId: "session-readers", name: "readers", tmuxName: null, mode: "direct", shell: "/bin/bash", workingDirectory: "/root", columns: 80, rows: 24, ownerPrincipalFingerprint: owner });
    first.appendStream(session.outputStreamId, Buffer.from("0123456789"));
    first.attachSessionReader({ readerId: "reader-a", sessionId: session.sessionId, ownerPrincipalFingerprint: owner, after: 2 });
    first.attachSessionReader({ readerId: "reader-b", sessionId: session.sessionId, ownerPrincipalFingerprint: owner, after: 7 });
    first.advanceSessionReader("reader-a", 5); first.detachSessionReader("reader-a"); first.close();
    const second = new QuirtStateStore(database);
    assert.deepEqual({ cursor: second.getSessionReader("reader-a").cursorOffset, attached: second.getSessionReader("reader-a").attached }, { cursor: 5, attached: false });
    assert.equal(second.getSessionReader("reader-b").cursorOffset, 7);
    assert.equal(second.attachSessionReader({ readerId: "reader-a", sessionId: session.sessionId, ownerPrincipalFingerprint: owner }).cursorOffset, 5);
    assert.throws(() => second.advanceSessionReader("reader-a", 4), /cannot move backwards/u);
    second.close();
  });

  it("stores raw bytes with monotonic offsets and independent readers", () => {
    const store = new QuirtStateStore(":memory:", { outputChunkBytes: 3, outputRetentionBytes: 30 });
    const stream = store.createStream("session", "session-1", "terminal", "stream-1");
    assert.deepEqual(store.appendStream(stream.streamId, Buffer.from([0, 1, 2, 255])), { startOffset: 0, endOffset: 4, byteCount: 4 });
    assert.deepEqual(store.appendStream(stream.streamId, Buffer.from("hello")), { startOffset: 4, endOffset: 9, byteCount: 5 });
    const a = store.readStream(stream.streamId, 0, 5); const b = store.readStream(stream.streamId, 4, 10);
    assert.deepEqual(a.bytes, Buffer.from([0, 1, 2, 255, 104])); assert.equal(a.endOffset, 5);
    assert.equal(b.bytes.toString("utf8"), "hello"); assert.equal(b.nextOffset, 9); assert.equal(b.eof, false);
    store.finalizeStream(stream.streamId); assert.equal(store.readStream(stream.streamId, 9, 1).eof, true); store.close();
  });

  it("reports a precise retained-output gap", () => {
    const store = new QuirtStateStore(":memory:", { outputChunkBytes: 4, outputRetentionBytes: 8 });
    const stream = store.createStream("job", "job-1", "stdout"); store.appendStream(stream.streamId, Buffer.from("abcdefghijklmnop"));
    assert.throws(() => store.readStream(stream.streamId, 0, 4), (error: unknown) => error instanceof QuirtError && error.code === "output_gap" && error.details.retainedStartOffset === 8);
    assert.equal(store.readStream(stream.streamId, 8, 8).bytes.toString(), "ijklmnop"); store.close();
  });

  it("persists jobs and terminal outcomes", () => {
    const database = path(); const first = new QuirtStateStore(database);
    const created = first.createJob({ jobId: "job-1", requestId: "request-1", ownerPrincipalFingerprint: "a".repeat(64), command: { executable: "/usr/bin/id", args: ["-u"] }, workingDirectory: "/root" });
    first.updateJob(created.jobId, { status: "running", processId: 456, started: true }); first.appendStream(created.stdoutStreamId, Buffer.from("0\n")); first.updateJob(created.jobId, { status: "exited", exitCode: 0, timedOut: false, finished: true }); first.close();
    const second = new QuirtStateStore(database); const loaded = second.getJob("job-1"); assert.equal(loaded.status, "exited"); assert.equal(loaded.exitCode, 0); assert.equal(loaded.timedOut, false); assert.equal(second.readStream(loaded.stdoutStreamId, 0, 10).bytes.toString(), "0\n"); second.close();
  });

  it("persists idempotency and rejects conflicting IDs and replayed nonces", () => {
    const store = new QuirtStateStore(":memory:");
    const identity = (nonce: string, algorithm: "hmac-sha256" | "ed25519" = "hmac-sha256", keyId: string | null = null) => ({
      gatewayId: "stealtheye-horsey-gateway", algorithm, keyId, nonce
    });
    assert.equal(store.reserveRequest("request-1", "quirt.exec", "a".repeat(64), identity("nonce-1"), "2099-01-01T00:00:00.000Z"), "new");
    assert.equal(store.reserveRequest("request-1", "quirt.exec", "a".repeat(64), identity("nonce-1"), "2099-01-01T00:00:00.000Z"), "replayed");
    assert.equal(store.reserveRequest("request-1", "quirt.exec", "a".repeat(64), identity("nonce-3"), "2099-01-01T00:00:00.000Z"), "replayed");
    assert.throws(() => store.reserveRequest("request-1", "quirt.exec", "b".repeat(64), identity("nonce-2"), "2099-01-01T00:00:00.000Z"), /different work/u);
    assert.throws(() => store.reserveRequest("request-2", "quirt.exec", "a".repeat(64), identity("nonce-1"), "2099-01-01T00:00:00.000Z"), /nonce/u);
    store.completeRequest("request-1", { ok: true }); assert.deepEqual(store.requestResult("request-1")?.response, { ok: true }); store.close();
  });

  it("rolls failed transactions back without leaving protocol state", () => {
    const store = new QuirtStateStore(":memory:");
    store.runRollbackProbe(); store.integrityCheck(); assert.equal(store.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION); store.close();
  });

  it("bounds cleanup of expired handoffs and records the retention outcome", () => {
    let now = new Date("2028-01-01T00:00:00.000Z"); const store = new QuirtStateStore(":memory:", { now: () => now }); const owner = "a".repeat(64); store.native.createHandoff({ handoffId: "expired-handoff", ownerPrincipalFingerprint: owner, status: "ready", targetHost: "host", expiresAt: "2029-01-01T00:00:00.000Z", data: { sessionId: "session" } }); now = new Date("2030-01-01T00:00:00.000Z"); assert.equal(store.native.cleanupExpiredHandoffs(), 1); assert.throws(() => store.native.getHandoff("expired-handoff", owner, "host"), (error: unknown) => error instanceof QuirtError && error.code === "not_found"); assert.equal(store.native.cleanupExpiredHandoffs(), 0); store.close();
  });

  it("fails safely when durable JSON state is malformed", () => {
    const database = path(); const owner = "a".repeat(64); const first = new QuirtStateStore(database); first.createSession({ sessionId: "corrupt-session", name: "corrupt", tmuxName: null, shell: "/bin/bash", workingDirectory: "/root", columns: 80, rows: 24, ownerPrincipalFingerprint: owner }); first.close();
    const raw = new DatabaseSync(database); raw.prepare("UPDATE quirt_sessions SET environment_json='{' WHERE session_id='corrupt-session'").run(); raw.close();
    const reopened = new QuirtStateStore(database); assert.throws(() => reopened.getSession("corrupt-session"), (error: unknown) => error instanceof QuirtError && error.code === "internal_error"); reopened.close();
  });
});
