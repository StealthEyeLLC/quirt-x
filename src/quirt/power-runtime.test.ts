import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { QuirtError } from "./error.js";
import { NodePowerRuntime } from "./power-provider.js";

async function eventually(action: () => boolean | Promise<boolean>, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await action()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.fail("condition did not become true before timeout");
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (cause) { return (cause as NodeJS.ErrnoException).code !== "ESRCH"; }
}

test("provider runtime has no implicit timeout", async () => {
  const runtime = new NodePowerRuntime();
  const result = await runtime.run({ executable: process.execPath, arguments: ["-e", "setTimeout(() => process.stdout.write('ok'), 75)"] });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.toString("utf8"), "ok");
});

test("provider timeout terminates the complete detached process group", { skip: process.platform !== "linux" }, async t => {
  const root = await mkdtemp(join(tmpdir(), "quirt-power-group-"));
  t.after(async () => await rm(root, { recursive: true, force: true }));
  const pidPath = join(root, "descendant.pid");
  const runtime = new NodePowerRuntime();
  const command = 'trap "" TERM; sleep 30 & child=$!; printf "%s" "$child" > "$1"; wait';
  await assert.rejects(
    runtime.run({ executable: "/bin/sh", arguments: ["-c", command, "quirt-provider", pidPath], timeoutMs: 100 }),
    (cause: unknown) => cause instanceof QuirtError && cause.code === "timeout"
  );
  let descendant = 0;
  await eventually(async () => {
    const text = await readFile(pidPath, "utf8").catch(() => "");
    descendant = Number(text);
    return Number.isSafeInteger(descendant) && descendant > 1;
  });
  await eventually(() => !alive(descendant));
});

test("pre-canceled provider execution does not spawn", async () => {
  const runtime = new NodePowerRuntime();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    runtime.run({ executable: "/bin/true", signal: controller.signal }),
    (cause: unknown) => cause instanceof QuirtError && cause.code === "canceled"
  );
});
