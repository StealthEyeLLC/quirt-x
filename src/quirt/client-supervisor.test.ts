import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, mkdtempSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Duplex } from "node:stream";
import { afterEach, describe, it } from "node:test";
import { QuirtGatewayClient, type QuirtSocketFactory } from "./client.js";
import { QuirtError } from "./error.js";
import type { QuirtFileService } from "./file-service.js";
import { QuirtJobManager } from "./job-manager.js";
import { QuirtOperationDispatcher } from "./operations.js";
import { QuirtProcessService, type QuirtJournalAdapter, type QuirtJournalPage, type QuirtJournalQuery, type QuirtProcessIdentity } from "./process-service.js";
import type { QuirtPtyExit, QuirtPtyFactory, QuirtPtyProcess, QuirtPtySpawn } from "./pty.js";
import { LinuxProcReader, syntheticProcessIdentity } from "./process-identity.js";
import { encodeFrame, QUIRT_PROTOCOL_VERSION, type QuirtFrame } from "./protocol.js";
import { QuirtSessionManager } from "./session-manager.js";
import { QuirtStateStore } from "./state.js";
import { QuirtSupervisorServer } from "./supervisor.js";
import { linkedDuplexPair, installTestAuthority, quirtTestConfig, TEST_PRINCIPAL, waitFor } from "./test-support.test.js";
import type { QuirtTmuxController } from "./tmux.js";

class FakePty implements QuirtPtyProcess {
  readonly events = new EventEmitter(); readonly writes: Buffer[] = [];
  constructor(readonly pid: number) {}
  write(bytes: Buffer): void { this.writes.push(Buffer.from(bytes)); }
  resize(): void {} signal(signal: NodeJS.Signals = "SIGTERM"): void { this.events.emit("exit", { exitCode: 0, signal: signal === "SIGKILL" ? 9 : signal === "SIGTERM" ? 15 : null } satisfies QuirtPtyExit); } pause(): void {} resume(): void {}
  onData(listener: (bytes: Buffer) => void): () => void { this.events.on("data", listener); return () => this.events.off("data", listener); }
  onExit(listener: (exit: QuirtPtyExit) => void): () => void { this.events.on("exit", listener); return () => this.events.off("exit", listener); }
  output(bytes: Buffer): void { this.events.emit("data", Buffer.from(bytes)); }
}
class FakePtys implements QuirtPtyFactory {
  readonly processes: FakePty[] = [];
  spawn(_input: QuirtPtySpawn): QuirtPtyProcess { const process = new FakePty(500 + this.processes.length); this.processes.push(process); return process; }
}
class NoTmux {
  async version(): Promise<string> { return "tmux-test"; }
  async hasSession(): Promise<boolean> { return false; }
  attach(): never { throw new Error("tmux is not used by this test"); }
  async resize(): Promise<void> {} async signal(): Promise<void> {} async killSession(): Promise<void> {}
}
class SupervisorSockets implements QuirtSocketFactory {
  readonly clients: Duplex[] = []; readonly servers: Duplex[] = [];
  constructor(private readonly supervisor: QuirtSupervisorServer, private readonly uid: number) {}
  async connect(): Promise<Duplex> { const [client, server] = linkedDuplexPair(); this.clients.push(client); this.servers.push(server); this.supervisor.acceptAuthenticatedTestStream(server, { pid: process.pid, uid: this.uid, gid: process.getgid?.() ?? 0 }); return client; }
  disconnectLatest(): void { this.servers.at(-1)?.destroy(); }
  close(): void { for (const stream of [...this.clients, ...this.servers]) stream.destroy(); }
}
class FixtureJournal implements QuirtJournalAdapter {
  readonly queries: QuirtJournalQuery[] = [];
  constructor(private readonly pages: QuirtJournalPage[]) {}
  async query(input: QuirtJournalQuery): Promise<QuirtJournalPage> { this.queries.push(input); return this.pages.shift() ?? { entries: [], cursor: input.afterCursor ?? null, stderr: "" }; }
}

const roots: string[] = []; const clients: QuirtGatewayClient[] = []; const sockets: SupervisorSockets[] = []; const stores: QuirtStateStore[] = []; const sessions: QuirtSessionManager[] = []; const jobs: QuirtJobManager[] = [];
afterEach(() => {
  for (const client of clients.splice(0)) client.close(); for (const socket of sockets.splice(0)) socket.close();
  for (const manager of sessions.splice(0)) manager.shutdown(); for (const manager of jobs.splice(0)) manager.shutdown();
  for (const store of stores.splice(0)) try { store.close(); } catch { /* already closed */ }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(options: { files?: QuirtFileService; journal?: QuirtJournalAdapter } = {}): { root: string; client: QuirtGatewayClient; newClient: () => QuirtGatewayClient; sockets: SupervisorSockets; ptys: FakePtys; state: QuirtStateStore } {
  const root = mkdtempSync(join(tmpdir(), "quirt-protocol-integration-")); roots.push(root); const config = quirtTestConfig(root); const state = new QuirtStateStore(":memory:"); stores.push(state); const authority = installTestAuthority(config, state, root); const ptys = new FakePtys(); const tmux = new NoTmux() as unknown as QuirtTmuxController; const sessionManager = new QuirtSessionManager(config, state, ptys, tmux); const jobManager = new QuirtJobManager(config, state, ptys, { procReader: Object.assign(new LinuxProcReader(), { tryCaptureSync(pid: number) { return pid >= 500 ? syntheticProcessIdentity(pid) : null; } }) }); sessions.push(sessionManager); jobs.push(jobManager);
  const services = {
    ...(options.files === undefined ? {} : { files: options.files }),
    ...(options.journal === undefined ? {} : { processService: new QuirtProcessService(config, state, sessionManager, jobManager, options.journal, (pid, signal) => { if (pid !== Number(readlinkSync("/proc/self")) || signal !== 0 && signal !== "SIGCONT") throw new Error("unexpected test signal"); }) })
  };
  const dispatcher = new QuirtOperationDispatcher(config, state, sessionManager, jobManager, tmux, "test-revision", services); const supervisor = new QuirtSupervisorServer(config, state, authority.supervisorAuthority, dispatcher, sessionManager, jobManager, { read: () => ({ pid: process.pid, uid: config.gatewayUid, gid: process.getgid?.() ?? 0 }) }); const socketFactory = new SupervisorSockets(supervisor, config.gatewayUid); sockets.push(socketFactory);
  const newClient = () => { const value = new QuirtGatewayClient(config, authority.gatewaySigner, socketFactory, { supervisorVerificationKeyRing: authority.supervisorVerificationKeyRing }); clients.push(value); return value; };
  return { root, client: newClient(), newClient, sockets: socketFactory, ptys, state };
}

describe("Quirt Gateway client and root supervisor", () => {
  it("normalizes an unavailable supervisor and bounds reconnect attempts", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-unavailable-")); roots.push(root); const config = quirtTestConfig(root, { QUIRT_MAX_RECONNECT_ATTEMPTS: "2" }); const state = new QuirtStateStore(":memory:"); stores.push(state); const authority = installTestAuthority(config, state, root); let attempts = 0;
    const factory: QuirtSocketFactory = { connect: async () => { attempts += 1; throw new QuirtError("supervisor_unavailable", "private socket unavailable", true); } };
    const client = new QuirtGatewayClient(config, authority.gatewaySigner, factory, { supervisorVerificationKeyRing: authority.supervisorVerificationKeyRing }); clients.push(client);
    await assert.rejects(client.request({ operation: "quirt.status", principal: TEST_PRINCIPAL, requestId: "unavailable-supervisor" }), (cause: unknown) => cause instanceof QuirtError && cause.code === "supervisor_unavailable" && cause.retryable);
    assert.equal(attempts, 2);
  });

  it("negotiates identity, correlates concurrent responses, emits events, replays idempotently, and reconnects", async () => {
    const f = fixture();
    const [version, capabilities, status] = await Promise.all([
      f.client.request({ operation: "quirt.version", principal: TEST_PRINCIPAL, requestId: "concurrent-version" }),
      f.client.request({ operation: "quirt.capabilities", principal: TEST_PRINCIPAL, requestId: "concurrent-capabilities" }),
      f.client.request({ operation: "quirt.status", principal: TEST_PRINCIPAL, requestId: "concurrent-status" })
    ]);
    assert.equal(version.payload.revision, "test-revision"); assert.ok((capabilities.payload.operations as string[]).includes("quirt.exec")); assert.equal(status.payload.transport, "unix-domain-socket"); assert.equal(status.payload.uid, process.getuid?.() ?? null);
    const executed = await f.client.request({ operation: "quirt.exec", payload: { command: "printf gateway-exec" }, principal: TEST_PRINCIPAL, requestId: "gateway-exec" }); assert.equal(executed.binary.toString(), "gateway-exec"); assert.equal((executed.payload.job as { status: string }).status, "exited");
    const replay = await f.client.request({ operation: "quirt.version", principal: TEST_PRINCIPAL, requestId: "concurrent-version" }); assert.equal(replay.replayed, true); assert.equal(replay.payload.replayed, true);
    await assert.rejects(f.client.request({ operation: "quirt.status", principal: TEST_PRINCIPAL, requestId: "concurrent-version" }), /different work/u);
    await assert.rejects(f.client.request({ operation: "quirt.nonexistent", principal: TEST_PRINCIPAL }), /operation is unknown/u);
    const wrong = { ...TEST_PRINCIPAL, subject: "not-jamie" }; await assert.rejects(f.client.request({ operation: "quirt.status", principal: wrong }), /not authorized/u);
    f.sockets.disconnectLatest(); await waitFor(() => f.sockets.servers.at(-1)?.destroyed === true);
    const reconnected = await f.client.request({ operation: "quirt.version", principal: TEST_PRINCIPAL }); assert.equal(reconnected.payload.revision, "test-revision"); assert.ok(f.sockets.clients.length >= 2);
  });

  it("durably records a side effect before a lost response and replays it without executing twice", async () => {
    const f = fixture(); const marker = join(f.root, "effect.txt"); const payload = { command: `sleep 1; printf done >> ${JSON.stringify(marker)}; printf done`, detach: true };
    const started = await f.client.request({ operation: "quirt.exec", payload, principal: TEST_PRINCIPAL, requestId: "disconnect-effect" }); assert.equal((started.payload as { detached: boolean }).detached, true);
    f.sockets.disconnectLatest();
    await waitFor(() => existsSync(marker) && readFileSync(marker, "utf8").includes("done"), 10_000);
    await waitFor(() => f.state.requestResult("disconnect-effect")?.state === "completed", 10_000);
    const replay = await f.client.request({ operation: "quirt.exec", payload, principal: TEST_PRINCIPAL, requestId: "disconnect-effect" });
    assert.equal(replay.replayed, true); assert.equal((replay.payload.job as { jobId: string }).jobId, (started.payload.job as { jobId: string }).jobId); assert.equal(readFileSync(marker, "utf8"), "done"); assert.equal(f.state.listJobs().filter(job => job.requestId === "disconnect-effect").length, 1);
  });

  it("keeps a supervisor-owned PTY alive across Gateway client restart with raw event and offset replay", async () => {
    const f = fixture(); const first = await f.client.request({ operation: "quirt.session.open", payload: { mode: "direct", executable: "/bin/bash", arguments: ["--noprofile", "--norc"], loginShell: false, environment: { TERMINAL_VALUE: "preserved", AUTHORITY_SECRET: "never-return" } }, principal: TEST_PRINCIPAL, requestId: "open-session" }); const publicSession = first.payload.session as { sessionId: string; environmentKeys: string[] }; const sessionId = publicSession.sessionId; assert.ok(publicSession.environmentKeys.includes("TERMINAL_VALUE")); assert.equal(JSON.stringify(first.payload).includes("never-return"), false); const process = f.ptys.processes[0]; assert.ok(process);
    f.client.close(); assert.equal(f.state.getSession(sessionId).status, "running");
    const second = f.newClient(); const loaded = await second.request({ operation: "quirt.session.get", payload: { sessionId }, principal: TEST_PRINCIPAL }); assert.equal((loaded.payload.session as { status: string }).status, "running");
    await second.request({ operation: "quirt.session.write", payload: { sessionId }, binary: Buffer.from([0, 255, 10]), principal: TEST_PRINCIPAL, requestId: "write-session" }); assert.deepEqual(process.writes, [Buffer.from([0, 255, 10])]);
    const events: Buffer[] = []; second.onEvent(event => { if (event.envelope.event === "session.output") events.push(event.binary); }); process.output(Buffer.from([1, 2, 3, 255])); await waitFor(() => events.length === 1); assert.deepEqual(events[0], Buffer.from([1, 2, 3, 255]));
    const read = await second.request({ operation: "quirt.session.read", payload: { sessionId, after: 0, maximumBytes: 2 }, principal: TEST_PRINCIPAL }); assert.deepEqual(read.binary, Buffer.from([1, 2])); assert.equal(read.payload.startOffset, 0); assert.equal(read.payload.endOffset, 2); assert.equal(read.payload.nextOffset, 4);
    const replay = await second.request({ operation: "quirt.session.read", payload: { sessionId, after: 2, maximumBytes: 8 }, principal: TEST_PRINCIPAL }); assert.deepEqual(replay.binary, Buffer.from([3, 255])); assert.equal(replay.payload.endOffset, 4);
  });

  it("routes the complete durable detached-job lifecycle over the framed Gateway protocol", async () => {
    const f = fixture();
    const started = await f.client.request({ operation: "quirt.exec", payload: { command: "sleep 30", pty: true, detach: true, columns: 80, rows: 24 }, principal: TEST_PRINCIPAL, requestId: "gateway-job" }); const jobId = (started.payload.job as { jobId: string }).jobId;
    const listed = await f.client.request({ operation: "quirt.job.list", principal: TEST_PRINCIPAL }); assert.ok((listed.payload.jobs as Array<{ jobId: string }>).some(job => job.jobId === jobId)); const loaded = await f.client.request({ operation: "quirt.job.get", payload: { jobId }, principal: TEST_PRINCIPAL }); assert.equal((loaded.payload.job as { status: string }).status, "running"); const attached = await f.client.request({ operation: "quirt.job.attach", payload: { jobId }, principal: TEST_PRINCIPAL }); assert.equal((attached.payload.job as { jobId: string }).jobId, jobId);
    const input = Buffer.from([0, 255, 10]); await f.client.request({ operation: "quirt.job.input", payload: { jobId, close: false }, binary: input, principal: TEST_PRINCIPAL }); assert.deepEqual(f.ptys.processes.at(-1)!.writes, [input]); f.ptys.processes.at(-1)!.output(Buffer.from("job-output")); const stdout = await f.client.request({ operation: "quirt.job.read", payload: { jobId, stream: "stdout", after: 0, maximumBytes: 4096 }, principal: TEST_PRINCIPAL }); assert.equal(stdout.binary.toString(), "job-output"); const stderr = await f.client.request({ operation: "quirt.job.read", payload: { jobId, stream: "stderr", after: 0, maximumBytes: 4096 }, principal: TEST_PRINCIPAL }); assert.equal(stderr.binary.length, 0);
    const signaled = await f.client.request({ operation: "quirt.job.signal", payload: { jobId, signal: "SIGTERM" }, principal: TEST_PRINCIPAL });
    await waitFor(() => f.state.getJob(jobId).finishedAt !== null, 10_000);
    assert.ok(["exited", "signaled"].includes(f.state.getJob(jobId).status));
    assert.equal((signaled.payload.job as { status: string }).status, "running");
    const cancelStarted = await f.client.request({ operation: "quirt.exec", payload: { command: "sleep 30", pty: true, detach: true }, principal: TEST_PRINCIPAL, requestId: "gateway-job-cancel" }); const cancelId = (cancelStarted.payload.job as { jobId: string }).jobId;
    await f.client.request({ operation: "quirt.job.cancel", payload: { jobId: cancelId, force: true }, principal: TEST_PRINCIPAL });
    await waitFor(() => f.state.getJob(cancelId).finishedAt !== null, 10_000);
    assert.ok(["canceled", "signaled", "exited"].includes(f.state.getJob(cancelId).status));
  });

  it("fails closed on an unsupported supervisor protocol version", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-mismatch-")); roots.push(root); const config = quirtTestConfig(root); const state = new QuirtStateStore(":memory:"); stores.push(state); const authority = installTestAuthority(config, state, root);
    const factory: QuirtSocketFactory = { connect: async () => {
      const [client, server] = linkedDuplexPair(); let replied = false; server.on("data", () => { if (replied) return; replied = true; const frame: QuirtFrame = { envelope: { kind: "welcome", protocolVersion: QUIRT_PROTOCOL_VERSION, connectionId: "wrong", supervisorId: config.supervisorId, challengeResponse: "wrong", capabilities: [], selectedAuthorityAlgorithm: "ed25519", selectedCompression: "none", timestamp: new Date().toISOString(), binaryLength: 0 }, binary: Buffer.alloc(0) }; const bytes = encodeFrame(frame); bytes.writeUInt8(2, 4); server.write(bytes); }); return client;
    } };
    const client = new QuirtGatewayClient(config, authority.gatewaySigner, factory, { supervisorVerificationKeyRing: authority.supervisorVerificationKeyRing }); clients.push(client); await assert.rejects(client.probe(), /disconnected|unsupported|timed out/u);
  });

  it("propagates MCP cancellation through the Gateway protocol into a bounded supervisor operation", async () => {
    let started!: () => void; const began = new Promise<void>(resolve => { started = resolve; });
    const files = { search: async (input: { signal?: AbortSignal }) => { started(); while (input.signal?.aborted !== true) await new Promise(resolve => setImmediate(resolve)); throw new QuirtError("request_canceled", "fixture canceled"); } } as unknown as QuirtFileService;
    const f = fixture({ files }); const controller = new AbortController(); const pending = f.client.request({ operation: "quirt.file.search", payload: { path: f.root }, principal: TEST_PRINCIPAL, requestId: "cancel-native-search", signal: controller.signal }); await began; controller.abort();
    await assert.rejects(pending, (error: unknown) => error instanceof QuirtError && error.code === "request_canceled"); await waitFor(() => f.state.requestResult("cancel-native-search")?.state === "failed"); assert.equal(f.state.requestResult("cancel-native-search")?.error?.code, "request_canceled");
  });

  it("rejects malformed native dispatcher inputs without reaching privileged service side effects", async () => {
    const f = fixture(); const rejected = async (operation: string, payload: Record<string, unknown> = {}, binary = Buffer.alloc(0), code = "invalid_request") => {
      await assert.rejects(f.client.request({ operation, payload, binary, principal: TEST_PRINCIPAL }), (error: unknown) => error instanceof QuirtError && error.code === code, operation);
    };
    await rejected("quirt.not-registered", {}, Buffer.alloc(0), "unknown_operation"); await rejected("quirt.status", {}, Buffer.from("unexpected"));
    await rejected("quirt.session.open", { mode: "container" }); await rejected("quirt.session.open", { columns: 1 }); await rejected("quirt.session.open", { arguments: "not-an-array" }); await rejected("quirt.session.open", { environment: [] }); await rejected("quirt.session.open", { environment: { "invalid-name!": "value" } });
    await rejected("quirt.file.stat", { path: "" }); await rejected("quirt.file.write", { path: "/tmp/quirt-invalid", atomic: "yes" }); await rejected("quirt.file.write", { path: "/tmp/quirt-invalid", mode: 0o10000 }); await rejected("quirt.file.patch", { path: "/tmp/quirt-invalid", expectedDigest: "0".repeat(64), edits: {} });
    await rejected("quirt.directory.create", { path: "/tmp/quirt-invalid", uid: -1 }); await rejected("quirt.directory.watch", { action: "resume" });
    await rejected("quirt.transfer.begin", { direction: "sideways" }); await rejected("quirt.transfer.begin", { direction: "upload", destination: "/tmp/quirt-invalid", expectedSize: 1, compression: "brotli" }); await rejected("quirt.transfer.begin", { direction: "upload", destination: "/tmp/quirt-invalid", expectedSize: 1, archiveFormat: "zip" });
    await rejected("quirt.session.snapshot", { sessionId: "missing", clientMetadata: [] }); await rejected("quirt.git.materialize", { remote: "/tmp/remote", destination: "/tmp/repository", existing: "merge" }); await rejected("quirt.git.worktree", { repository: "/tmp/repository", action: "lock" }); await rejected("quirt.git.verify", { repository: "/tmp/repository", signature: "trust" });
    await rejected("quirt.record.export", { recordingId: "missing", format: "text" }); await rejected("quirt.process.get", { pid: 0 }); await rejected("quirt.process.list", { state: "" }); await rejected("quirt.process.signal", { identity: null, signal: "SIGTERM" }); await rejected("quirt.process.attach", { source: "trace" });
    assert.equal(f.state.native.listTransfers(TEST_PRINCIPAL.principalFingerprint).length, 0); assert.equal(f.state.native.listObjects("quirt_materializations", TEST_PRINCIPAL.principalFingerprint).length, 0);
  });

  it("dispatches native file, transfer, recording, replay, snapshot, and handoff operations through the same binary protocol", async () => {
    const f = fixture(); const bytes = Buffer.from([0, 255, 1, 2, 3]); const path = join(f.root, "native.bin");
    const written = await f.client.request({ operation: "quirt.file.write", payload: { path, create: true, noClobber: true }, binary: bytes, principal: TEST_PRINCIPAL, requestId: "native-file-write" }); assert.equal(written.payload.writtenBytes, bytes.length); const replayedWrite = await f.client.request({ operation: "quirt.file.write", payload: { path, create: true, noClobber: true }, binary: bytes, principal: TEST_PRINCIPAL, requestId: "native-file-write" }); assert.equal(replayedWrite.replayed, true); assert.deepEqual(readFileSync(path), bytes);
    const read = await f.client.request({ operation: "quirt.file.read", payload: { path, maximumBytes: 1024 }, principal: TEST_PRINCIPAL }); assert.deepEqual(read.binary, bytes); assert.equal(read.payload.eof, true);
    const destination = join(f.root, "transfer.bin"); const digest = createHash("sha256").update(bytes).digest("hex"); const begun = await f.client.request({ operation: "quirt.transfer.begin", payload: { direction: "upload", destination, expectedSize: bytes.length, expectedDigest: digest, chunkSize: 4096 }, principal: TEST_PRINCIPAL }); const transferId = ((begun.payload.transfer as { transferId: string }).transferId); await f.client.request({ operation: "quirt.transfer.write", payload: { transferId, offset: 0 }, binary: bytes, principal: TEST_PRINCIPAL }); const completed = await f.client.request({ operation: "quirt.transfer.complete", payload: { transferId }, principal: TEST_PRINCIPAL }); assert.equal((completed.payload.result as { sha256: string }).sha256, digest); assert.deepEqual(readFileSync(destination), bytes);
    const opened = await f.client.request({ operation: "quirt.session.open", payload: { mode: "direct", executable: "/bin/bash", loginShell: false }, principal: TEST_PRINCIPAL }); const sessionId = (opened.payload.session as { sessionId: string }).sessionId; const recording = await f.client.request({ operation: "quirt.record.start", payload: { sessionId }, principal: TEST_PRINCIPAL }); const recordingId = recording.payload.recordingId as string; f.ptys.processes.at(-1)!.output(Buffer.from("native recording\n")); await f.client.request({ operation: "quirt.record.stop", payload: { recordingId }, principal: TEST_PRINCIPAL }); const replay = await f.client.request({ operation: "quirt.record.replay", payload: { recordingId, maximumEvents: 100 }, principal: TEST_PRINCIPAL }); assert.ok(replay.binary.includes(Buffer.from("native recording")));
    const attached = await f.client.request({ operation: "quirt.session.attach", payload: { sessionId, after: 0 }, principal: TEST_PRINCIPAL }); const readerId = (attached.payload.reader as { readerId: string }).readerId; const snapshot = await f.client.request({ operation: "quirt.session.snapshot", payload: { sessionId, readerId, createHandoff: true, clientMetadata: { workspaceId: null, client: "gateway-integration" } }, principal: TEST_PRINCIPAL }); const handoffId = (snapshot.payload.handoff as { handoffId: string }).handoffId; const resumed = await f.client.request({ operation: "quirt.session.attach", payload: { handoffId }, principal: TEST_PRINCIPAL }); assert.equal((resumed.payload.session as { sessionId: string }).sessionId, sessionId); assert.equal(resumed.payload.replacementShellOpened, false);
  });

  it("routes the remaining native file, directory, transfer, recording, session, process, and journal operations through the Gateway", async () => {
    const journal = new FixtureJournal([
      { entries: [{ __CURSOR: "gateway-cursor-1", _BOOT_ID: "boot-a", _SYSTEMD_UNIT: "demo.service", MESSAGE: [0, 255] }], cursor: "gateway-cursor-1", stderr: "" },
      { entries: [{ __CURSOR: "gateway-cursor-2", _BOOT_ID: "boot-a", MESSAGE: "continued" }], cursor: "gateway-cursor-2", stderr: "" }
    ]);
    const f = fixture({ journal }); const directory = join(f.root, "native", "directory");
    await f.client.request({ operation: "quirt.directory.create", payload: { path: directory, recursive: true, mode: 0o750, noClobber: true }, principal: TEST_PRINCIPAL });
    const source = join(directory, "source.txt"); const initial = Buffer.from("alpha needle omega"); await f.client.request({ operation: "quirt.file.write", payload: { path: source, create: true, noClobber: true, mode: 0o640, durable: true }, binary: initial, principal: TEST_PRINCIPAL });
    const stat = await f.client.request({ operation: "quirt.file.stat", payload: { path: source, digest: true }, principal: TEST_PRINCIPAL }); const initialDigest = stat.payload.sha256 as string;
    await f.client.request({ operation: "quirt.file.patch", payload: { path: source, expectedDigest: initialDigest, edits: [{ start: 6, deleteBytes: 6, contentBase64: Buffer.from("native").toString("base64") }] }, principal: TEST_PRINCIPAL });
    const searched = await f.client.request({ operation: "quirt.file.search", payload: { path: directory, text: "native", name: "source", regularExpression: false, caseSensitive: true, recursive: true, maximumMatches: 10, maximumBytes: 1024 * 1024 }, principal: TEST_PRINCIPAL }); assert.ok((searched.payload.matchCount as number) >= 1);
    const copied = join(directory, "copied.txt"); const moved = join(directory, "moved.txt"); await f.client.request({ operation: "quirt.file.copy", payload: { source, destination: copied, preserveMetadata: true }, principal: TEST_PRINCIPAL }); await f.client.request({ operation: "quirt.file.move", payload: { source: copied, destination: moved, overwrite: false }, principal: TEST_PRINCIPAL });
    const listed = await f.client.request({ operation: "quirt.directory.list", payload: { path: directory, maximumEntries: 10 }, principal: TEST_PRINCIPAL }); assert.ok((listed.payload.entries as unknown[]).length >= 2);
    const watched = await f.client.request({ operation: "quirt.directory.watch", payload: { action: "start", path: directory }, principal: TEST_PRINCIPAL }); const watchId = (watched.payload.watch as { watchId: string }).watchId; writeFileSync(join(directory, "watch-event"), "event"); await new Promise(resolve => setTimeout(resolve, 100)); const events = await f.client.request({ operation: "quirt.directory.watch", payload: { action: "read", watchId, after: -1, maximumEvents: 10 }, principal: TEST_PRINCIPAL }); assert.ok(Array.isArray(events.payload.events)); await f.client.request({ operation: "quirt.directory.watch", payload: { action: "cancel", watchId }, principal: TEST_PRINCIPAL });
    await f.client.request({ operation: "quirt.file.remove", payload: { path: moved }, principal: TEST_PRINCIPAL }); assert.equal(existsSync(moved), false);

    const download = await f.client.request({ operation: "quirt.transfer.begin", payload: { direction: "download", source, chunkSize: 4096 }, principal: TEST_PRINCIPAL }); const downloadId = (download.payload.transfer as { transferId: string }).transferId; const transferStatus = await f.client.request({ operation: "quirt.transfer.status", payload: { transferId: downloadId }, principal: TEST_PRINCIPAL }); assert.equal((transferStatus.payload.transfer as { status: string }).status, "active"); const downloaded = await f.client.request({ operation: "quirt.transfer.read", payload: { transferId: downloadId, offset: 0, maximumBytes: 4096 }, principal: TEST_PRINCIPAL }); assert.deepEqual(downloaded.binary, readFileSync(source)); await f.client.request({ operation: "quirt.transfer.complete", payload: { transferId: downloadId }, principal: TEST_PRINCIPAL });
    const cancelDestination = join(directory, "cancel.bin"); const cancelTransfer = await f.client.request({ operation: "quirt.transfer.begin", payload: { direction: "upload", destination: cancelDestination, expectedSize: 1, chunkSize: 4096 }, principal: TEST_PRINCIPAL }); const cancelId = (cancelTransfer.payload.transfer as { transferId: string }).transferId; await f.client.request({ operation: "quirt.transfer.cancel", payload: { transferId: cancelId }, principal: TEST_PRINCIPAL }); assert.equal(existsSync(cancelDestination), false);

    const opened = await f.client.request({ operation: "quirt.session.open", payload: { mode: "direct", executable: "/bin/bash", loginShell: false, columns: 80, rows: 24 }, principal: TEST_PRINCIPAL }); const sessionId = (opened.payload.session as { sessionId: string }).sessionId; const attached = await f.client.request({ operation: "quirt.session.attach", payload: { sessionId, after: 0 }, principal: TEST_PRINCIPAL }); const readerId = (attached.payload.reader as { readerId: string }).readerId;
    const recording = await f.client.request({ operation: "quirt.record.start", payload: { sessionId, name: "gateway-native" }, principal: TEST_PRINCIPAL }); const recordingId = recording.payload.recordingId as string; await f.client.request({ operation: "quirt.record.start", payload: { recordingId, marker: "checkpoint", bookmark: "bookmark" }, principal: TEST_PRINCIPAL }); f.ptys.processes.at(-1)!.output(Buffer.from("\u001b[31mnative session\u001b[0m\n"));
    const sessionsList = await f.client.request({ operation: "quirt.session.list", principal: TEST_PRINCIPAL }); assert.ok((sessionsList.payload.sessions as unknown[]).length >= 1); await f.client.request({ operation: "quirt.session.get", payload: { sessionId }, principal: TEST_PRINCIPAL }); await f.client.request({ operation: "quirt.session.resize", payload: { sessionId, columns: 100, rows: 30 }, principal: TEST_PRINCIPAL });
    const sessionSearch = await f.client.request({ operation: "quirt.session.search", payload: { sessionId, query: "native", regularExpression: false, caseSensitive: true, maximumMatches: 10, maximumBytes: 4096, includeRecordings: true }, principal: TEST_PRINCIPAL }); assert.equal((sessionSearch.payload.matches as unknown[]).length, 1); const rendered = await f.client.request({ operation: "quirt.session.render", payload: { sessionId, maximumBytes: 4096, rows: 30, columns: 100 }, principal: TEST_PRINCIPAL }); assert.equal(rendered.payload.pixelPerfect, false); const snapshot = await f.client.request({ operation: "quirt.session.snapshot", payload: { sessionId, readerId, createHandoff: false }, principal: TEST_PRINCIPAL }); assert.equal(snapshot.payload.handoff, null);
    const recordList = await f.client.request({ operation: "quirt.record.list", principal: TEST_PRINCIPAL }); assert.ok((recordList.payload.recordings as unknown[]).length >= 1); const recordSearch = await f.client.request({ operation: "quirt.record.search", payload: { recordingId, query: "native", regularExpression: false, caseSensitive: true, maximumMatches: 10 }, principal: TEST_PRINCIPAL }); assert.equal((recordSearch.payload.matches as unknown[]).length, 1); await f.client.request({ operation: "quirt.record.stop", payload: { recordingId }, principal: TEST_PRINCIPAL }); const exported = await f.client.request({ operation: "quirt.record.export", payload: { recordingId, format: "asciinema-v2", offset: 0, maximumBytes: 4096 }, principal: TEST_PRINCIPAL }); assert.ok(exported.binary.length > 0); await f.client.request({ operation: "quirt.session.detach", payload: { sessionId, readerId }, principal: TEST_PRINCIPAL }); await f.client.request({ operation: "quirt.session.close", payload: { sessionId, signal: "SIGHUP" }, principal: TEST_PRINCIPAL });

    const visiblePid = Number(readlinkSync("/proc/self")); const processInfo = await f.client.request({ operation: "quirt.process.get", payload: { pid: visiblePid }, principal: TEST_PRINCIPAL }); const identity = processInfo.payload.identity as unknown as QuirtProcessIdentity; const processes = await f.client.request({ operation: "quirt.process.list", payload: { afterPid: 0, maximumProcesses: 2, uid: process.getuid?.() ?? 0 }, principal: TEST_PRINCIPAL }); assert.ok((processes.payload.processes as unknown[]).length <= 2); await f.client.request({ operation: "quirt.process.tree", payload: { pid: visiblePid, maximumDepth: 1, maximumProcesses: 8 }, principal: TEST_PRINCIPAL }); await f.client.request({ operation: "quirt.process.namespaces", payload: { pid: visiblePid }, principal: TEST_PRINCIPAL }); const signaled = await f.client.request({ operation: "quirt.process.signal", payload: { identity, signal: "SIGCONT" }, principal: TEST_PRINCIPAL }); assert.equal(signaled.payload.precondition, "exact-identity-matched"); await assert.rejects(f.client.request({ operation: "quirt.process.attach", payload: { source: "process", identity }, principal: TEST_PRINCIPAL }), (error: unknown) => error instanceof QuirtError && error.code === "unsupported_host_capability");
    const journalOpen = await f.client.request({ operation: "quirt.process.attach", payload: { source: "journal", action: "open", filters: { unit: "demo.service" }, maximumEntries: 1 }, principal: TEST_PRINCIPAL }); const attachmentId = journalOpen.payload.attachmentId as string; assert.ok(journalOpen.binary.includes(Buffer.from("gateway-cursor-1"))); const journalRead = await f.client.request({ operation: "quirt.process.attach", payload: { source: "journal", action: "read", attachmentId, maximumEntries: 1 }, principal: TEST_PRINCIPAL }); assert.equal(journalRead.payload.cursor, "gateway-cursor-2"); await f.client.request({ operation: "quirt.process.attach", payload: { source: "journal", action: "cancel", attachmentId }, principal: TEST_PRINCIPAL }); assert.equal(journal.queries.length, 2);
  });

  it("materializes an exact local Git commit and tree through the trusted Gateway binding", async () => {
    const f = fixture(); const seed = join(f.root, "seed"); const remote = join(f.root, "remote.git"); execFileSync("/usr/bin/git", ["init", "--initial-branch=main", seed]); execFileSync("/usr/bin/git", ["config", "user.name", "Quirt Test"], { cwd: seed }); execFileSync("/usr/bin/git", ["config", "user.email", "quirt@example.invalid"], { cwd: seed }); writeFileSync(join(seed, "README.md"), "gateway git\n"); execFileSync("/usr/bin/git", ["add", "README.md"], { cwd: seed }); execFileSync("/usr/bin/git", ["commit", "-m", "gateway fixture"], { cwd: seed }); execFileSync("/usr/bin/git", ["clone", "--bare", seed, remote]); const commit = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: seed, encoding: "utf8" }).trim(); const tree = execFileSync("/usr/bin/git", ["rev-parse", "HEAD^{tree}"], { cwd: seed, encoding: "utf8" }).trim(); const destination = join(f.root, "materialized"); const result = await f.client.request({ operation: "quirt.git.materialize", payload: { remote, destination, exactCommit: commit, expectedTree: tree }, principal: TEST_PRINCIPAL, requestId: "gateway-materialize" }); assert.equal(result.payload.commit, commit); assert.equal(result.payload.tree, tree); const replay = await f.client.request({ operation: "quirt.git.materialize", payload: { remote, destination, exactCommit: commit, expectedTree: tree }, principal: TEST_PRINCIPAL, requestId: "gateway-materialize" }); assert.equal(replay.replayed, true); assert.equal(f.state.native.listObjects("quirt_materializations", TEST_PRINCIPAL.principalFingerprint).length, 1);
  });
});
