import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { NodePtyFactory, type QuirtPtyProcess } from "./pty.js";
import { waitFor } from "./test-support.test.js";

const roots: string[] = [];
const active: QuirtPtyProcess[] = [];
afterEach(() => {
  for (const pty of active.splice(0)) try { pty.signal("SIGKILL"); } catch { /* already exited */ }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("Quirt real PTY adapter", () => {
  it("preserves interactive shell state, raw bytes, color, UTF-8, resize, and foreground Ctrl-C", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-pty-")); roots.push(root);
    const pty = new NodePtyFactory().spawn({
      executable: "/bin/bash",
      arguments: ["--noprofile", "--norc"],
      workingDirectory: root,
      environment: { HOME: root, PATH: process.env.PATH ?? "/usr/bin:/bin", TERM: "xterm-256color", LANG: "C.UTF-8", QUIRT_PTY_VALUE: "preserved" },
      columns: 80,
      rows: 24
    });
    active.push(pty);
    const chunks: Buffer[] = []; const exits: Array<{ exitCode: number; signal: number | null }> = [];
    const offData = pty.onData(bytes => chunks.push(bytes)); const offExit = pty.onExit(exit => exits.push(exit));
    const output = () => Buffer.concat(chunks);
    pty.write(Buffer.from("stty -echo; PS1=; printf '\\nQUIRT_READY\\n'\n"));
    await waitFor(() => output().includes(Buffer.from("\r\nQUIRT_READY\r\n")));
    pty.write(Buffer.from("cd /; export QUIRT_CHANGED=yes; alias qalias='printf alias-ok'; qfn(){ printf fn-ok; }\nprintf 'uid=%s pwd=%s env=%s changed=%s ' \"$(id -u)\" \"$PWD\" \"$QUIRT_PTY_VALUE\" \"$QUIRT_CHANGED\"; qalias; printf ' '; qfn; printf '\\n'\n"));
    const stateLine = Buffer.from(`uid=${process.getuid?.() ?? -1} pwd=/ env=preserved changed=yes alias-ok fn-ok`);
    await waitFor(() => output().includes(stateLine));
    assert.ok(output().includes(stateLine));
    pty.resize(91, 37); pty.write(Buffer.from("printf 'size='; stty size\n"));
    await waitFor(() => output().includes(Buffer.from("size=37 91")));
    pty.write(Buffer.from("printf '\\001\\002\\303\\251\\033[38;2;1;2;3mcolor\\033[0m\\033[?1049hALT\\033[?1049lEND\\n'\n"));
    await waitFor(() => output().includes(Buffer.from("END")));
    const bytes = output(); assert.ok(bytes.includes(Buffer.from([1, 2]))); assert.ok(bytes.includes(Buffer.from("é"))); assert.ok(bytes.includes(Buffer.from("\u001b[38;2;1;2;3mcolor\u001b[0m"))); assert.ok(bytes.includes(Buffer.from("\u001b[?1049hALT\u001b[?1049l")));
    pty.write(Buffer.from("sleep 20\n")); await new Promise(resolve => setTimeout(resolve, 100)); pty.write(Buffer.from([3])); pty.write(Buffer.from("printf 'CTRL_C_OK\\n'\n"));
    await waitFor(() => output().includes(Buffer.from("CTRL_C_OK")));
    pty.write(Buffer.from("exit 7\n")); await waitFor(() => exits.length === 1);
    assert.equal(exits[0]?.exitCode, 7); offData(); offExit();
  });

  it("delivers an explicit forced-close signal", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-pty-close-")); roots.push(root);
    const pty = new NodePtyFactory().spawn({ executable: "/bin/sleep", arguments: ["999"], workingDirectory: root, environment: { HOME: root, PATH: "/usr/bin:/bin", TERM: "xterm-256color" }, columns: 80, rows: 24 });
    active.push(pty);
    let exited = false; pty.onExit(() => { exited = true; }); pty.signal("SIGTERM"); await waitFor(() => exited, 10_000);
  });
});
