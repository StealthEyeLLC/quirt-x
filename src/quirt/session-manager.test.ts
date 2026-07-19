import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { QuirtPtyExit, QuirtPtyFactory, QuirtPtyProcess, QuirtPtySpawn } from "./pty.js";
import { QuirtSessionManager } from "./session-manager.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig, waitFor } from "./test-support.test.js";
import type { QuirtTmuxController, QuirtTmuxSessionSpec } from "./tmux.js";

class FakePty implements QuirtPtyProcess {
  readonly events = new EventEmitter(); writes: Buffer[] = []; resizes: Array<[number, number]> = []; signals: NodeJS.Signals[] = [];
  constructor(readonly pid: number) {}
  write(bytes: Buffer): void { this.writes.push(Buffer.from(bytes)); }
  resize(columns: number, rows: number): void { this.resizes.push([columns, rows]); }
  signal(signal: NodeJS.Signals): void { this.signals.push(signal); }
  pause(): void {} resume(): void {}
  onData(listener: (bytes: Buffer) => void): () => void { this.events.on("data", listener); return () => this.events.off("data", listener); }
  onExit(listener: (exit: QuirtPtyExit) => void): () => void { this.events.on("exit", listener); return () => this.events.off("exit", listener); }
  output(bytes: Buffer): void { this.events.emit("data", Buffer.from(bytes)); }
  exit(exitCode: number, signal: number | null = null): void { this.events.emit("exit", { exitCode, signal } satisfies QuirtPtyExit); }
}

class FakePtys implements QuirtPtyFactory {
  readonly processes: FakePty[] = []; readonly spawns: QuirtPtySpawn[] = [];
  spawn(input: QuirtPtySpawn): QuirtPtyProcess { this.spawns.push(input); const process = new FakePty(100 + this.processes.length); this.processes.push(process); return process; }
}

class FakeTmux {
  readonly sessions = new Set<string>(); readonly attaches: Array<{ spec: QuirtTmuxSessionSpec; existing: boolean }> = []; readonly resized: Array<[string, number, number]> = []; readonly signals: Array<[string, NodeJS.Signals]> = []; readonly killed: string[] = [];
  constructor(private readonly ptys: FakePtys) {}
  async version(): Promise<string> { return "tmux test"; }
  async hasSession(name: string): Promise<boolean> { return this.sessions.has(name); }
  attach(spec: QuirtTmuxSessionSpec, existing: boolean): QuirtPtyProcess { this.sessions.add(spec.tmuxName); this.attaches.push({ spec, existing }); return this.ptys.spawn({ executable: "/usr/bin/tmux", arguments: [], workingDirectory: spec.workingDirectory, environment: spec.environment, columns: spec.columns, rows: spec.rows }); }
  async resize(name: string, columns: number, rows: number): Promise<void> { this.resized.push([name, columns, rows]); }
  async signal(name: string, signal: NodeJS.Signals): Promise<void> { this.signals.push([name, signal]); }
  async killSession(name: string): Promise<void> { this.killed.push(name); this.sessions.delete(name); }
}

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function root(): string { const value = mkdtempSync(join(tmpdir(), "quirt-session-")); roots.push(value); return value; }

describe("Quirt durable session manager", () => {
  it("keeps tmux-owned sessions alive across Gateway/manager restart and adopts them with exact offset replay", async () => {
    const stateRoot = root(); const database = join(stateRoot, "state.sqlite"); const config = quirtTestConfig(stateRoot); const ptys = new FakePtys(); const tmux = new FakeTmux(ptys);
    const state1 = new QuirtStateStore(database, { outputChunkBytes: 4, outputRetentionBytes: 1024 }); const first = new QuirtSessionManager(config, state1, ptys, tmux as unknown as QuirtTmuxController);
    const opened = await first.open({ name: "root-main", environment: { QUIRT_VISIBLE: "yes", AUTHORITY_SECRET: "not-inherited" }, columns: 100, rows: 30 }, "a".repeat(64));
    assert.equal(opened.mode, "tmux"); assert.equal(opened.status, "running"); assert.equal(tmux.attaches[0]?.existing, false); assert.equal(tmux.attaches[0]?.spec.workingDirectory, "/root");
    ptys.processes[0]?.output(Buffer.from([0, 1, 2, 255])); ptys.processes[0]?.output(Buffer.from("hello"));
    const readerA = await first.attach(opened.sessionId, "a".repeat(64), { readerId: "reader-a", after: 0 }); const readerB = await first.attach(opened.sessionId, "a".repeat(64), { readerId: "reader-b", after: 4 });
    assert.equal((readerA.reader as { cursorOffset: number }).cursorOffset, 0); assert.equal((readerB.reader as { cursorOffset: number }).cursorOffset, 4);
    assert.deepEqual(first.read(opened.sessionId, "a".repeat(64), { readerId: "reader-a", maximumBytes: 4 }).bytes, Buffer.from([0, 1, 2, 255]));
    assert.equal(first.read(opened.sessionId, "a".repeat(64), { readerId: "reader-b", maximumBytes: 20 }).bytes.toString(), "hello");
    first.detach(opened.sessionId, "a".repeat(64), "reader-a"); await first.resize(opened.sessionId, "a".repeat(64), 132, 44); await first.signal(opened.sessionId, "a".repeat(64), "SIGINT");
    assert.deepEqual(tmux.resized.at(-1), [opened.tmuxName, 132, 44]); assert.deepEqual(tmux.signals.at(-1), [opened.tmuxName, "SIGINT"]);
    first.shutdown(); assert.equal(state1.getSession(opened.sessionId).status, "detached"); assert.deepEqual(ptys.processes[0]?.signals, ["SIGHUP"]); state1.close();
    const state2 = new QuirtStateStore(database, { outputChunkBytes: 4, outputRetentionBytes: 1024 }); const second = new QuirtSessionManager(config, state2, ptys, tmux as unknown as QuirtTmuxController);
    assert.deepEqual(await second.recover(), { adopted: 1, lost: 0 }); assert.equal(tmux.attaches.at(-1)?.existing, true); assert.ok(state2.getSession(opened.sessionId).recoveredAt);
    ptys.processes.at(-1)?.output(Buffer.from("after-restart"));
    const replay = second.read(opened.sessionId, "a".repeat(64), { after: 9, maximumBytes: 64 }); assert.equal(replay.startOffset, 9); assert.equal(replay.bytes.toString(), "after-restart"); assert.equal(replay.endOffset, 22);
    const closed = await second.close(opened.sessionId, "a".repeat(64)); assert.equal(closed.status, "closed"); assert.deepEqual(tmux.killed, [opened.tmuxName]); state2.close();
  });

  it("tracks direct PTY exit, forced close, ownership, and lost-session recovery", async () => {
    const stateRoot = root(); const config = quirtTestConfig(stateRoot); const ptys = new FakePtys(); const tmux = new FakeTmux(ptys); const state = new QuirtStateStore(":memory:"); const manager = new QuirtSessionManager(config, state, ptys, tmux as unknown as QuirtTmuxController);
    const direct = await manager.open({ mode: "direct", executable: "/bin/bash", arguments: ["--noprofile"], loginShell: false }, "a".repeat(64));
    assert.equal(direct.mode, "direct"); await manager.write(direct.sessionId, "a".repeat(64), Buffer.from("echo ok\n")); assert.equal(ptys.processes[0]?.writes[0]?.toString(), "echo ok\n");
    assert.throws(() => manager.get(direct.sessionId, "b".repeat(64)), /principal/u); ptys.processes[0]?.exit(7); await waitFor(() => state.getSession(direct.sessionId).status === "exited"); assert.equal(state.getSession(direct.sessionId).exitCode, 7); assert.equal(state.getStream(direct.outputStreamId).status, "finalized");
    const forced = await manager.open({ mode: "direct" }, "a".repeat(64)); await manager.close(forced.sessionId, "a".repeat(64), "SIGKILL"); assert.deepEqual(ptys.processes[1]?.signals, ["SIGKILL"]); assert.equal(state.getSession(forced.sessionId).status, "closed");
    state.createSession({ sessionId: "00000000-0000-0000-0000-000000000001", name: "orphan", tmuxName: "quirt-00000000000000000000000000000001", shell: "/bin/bash", workingDirectory: "/root", columns: 80, rows: 24, ownerPrincipalFingerprint: "a".repeat(64) });
    assert.deepEqual(await manager.recover(), { adopted: 0, lost: 1 }); assert.equal(state.getSession("00000000-0000-0000-0000-000000000001").status, "lost"); state.close();
  });
});
