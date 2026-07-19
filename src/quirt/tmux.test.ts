import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { QuirtPtyFactory, QuirtPtyProcess, QuirtPtySpawn } from "./pty.js";
import { quirtTestConfig } from "./test-support.test.js";
import { QuirtTmuxController, quirtTmuxName } from "./tmux.js";

class CaptureFactory implements QuirtPtyFactory {
  inputs: QuirtPtySpawn[] = [];
  spawn(input: QuirtPtySpawn): QuirtPtyProcess { this.inputs.push(input); return { pid: 123, write() {}, resize() {}, signal() {}, pause() {}, resume() {}, onData: () => () => undefined, onExit: () => () => undefined }; }
}

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe("Quirt tmux ownership layer", () => {
  it("uses a Quirt-private tmux socket and exact create/adopt commands", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-tmux-")); roots.push(root); const factory = new CaptureFactory(); const tmux = new QuirtTmuxController(quirtTestConfig(root), factory); const tmuxName = quirtTmuxName("00000000-0000-0000-0000-000000000001");
    const spec = { sessionId: "00000000-0000-0000-0000-000000000001", tmuxName, executable: "/bin/bash", arguments: ["-l"], workingDirectory: "/root", environment: { TERM: "xterm-256color" }, columns: 120, rows: 40 };
    tmux.attach(spec, false); tmux.attach(spec, true);
    assert.equal(tmux.socketPath, join(root, "sessions", "tmux.sock")); assert.equal(factory.inputs[0]?.executable, "/usr/bin/tmux");
    assert.deepEqual(factory.inputs[0]?.arguments.slice(0, 4), ["-S", tmux.socketPath, "new-session", "-s"]); assert.ok(factory.inputs[0]?.arguments.includes("--"));
    assert.deepEqual(factory.inputs[1]?.arguments, ["-S", tmux.socketPath, "attach-session", "-t", tmuxName]);
  });

  it("probes the actual tmux provider when installed", { skip: !existsSync("/usr/bin/tmux") }, async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-tmux-real-")); roots.push(root); const factory = new CaptureFactory(); const tmux = new QuirtTmuxController(quirtTestConfig(root), factory); assert.match(await tmux.version(), /^tmux /u);
  });
});
