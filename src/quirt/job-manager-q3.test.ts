import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { InjectedCoreDumpProbe } from "./core-dump.js";
import { resolveEnvironment } from "./execution-environment.js";
import { digestText } from "./launch-document.js";
import { QuirtJobManager } from "./job-manager.js";
import { captureProcessIdentity, type ProcReader } from "./process-identity.js";
import { NodePtyFactory } from "./pty.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig, waitFor } from "./test-support.test.js";

const roots: string[] = [];
const managers: QuirtJobManager[] = [];
const stores: QuirtStateStore[] = [];
const owner = "a".repeat(64);
const SECRET = "QUIRT-Q3-SECRET-SENTINEL-7f3a9c";

afterEach(() => {
  for (const manager of managers.splice(0)) manager.shutdown();
  for (const store of stores.splice(0)) try { store.close(); } catch { /* already closed */ }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(deps: ConstructorParameters<typeof QuirtJobManager>[3] = {}): { root: string; state: QuirtStateStore; jobs: QuirtJobManager } {
  const root = mkdtempSync(join(tmpdir(), "quirt-q3-"));
  roots.push(root);
  const config = quirtTestConfig(root);
  const state = new QuirtStateStore(":memory:", { outputChunkBytes: 4096, outputRetentionBytes: 2 * 1024 * 1024 });
  stores.push(state);
  const jobs = new QuirtJobManager(config, state, new NodePtyFactory(), deps);
  managers.push(jobs);
  return { root, state, jobs };
}

describe("Quirt Q3 execution kernel", () => {
  it("executes exact argv with literal shell metacharacters without shell interpretation", async () => {
    const { jobs } = harness();
    const result = await jobs.exec("q3-exact-argv", owner, {
      executable: process.execPath,
      arguments: ["-e", "process.stdout.write(process.argv.slice(1).join('|'))", "$HOME", "; rm -rf /", "`id`"]
    });
    assert.equal(result.job.status, "exited");
    assert.equal(result.stdout.toString(), "$HOME|; rm -rf /|`id`");
    assert.ok(result.receiptId);
  });

  it("supports environment override, deletion, replacement, and redacts secrets from receipts", async () => {
    const { jobs, state } = harness();
    const resolved = resolveEnvironment("/bin/bash", {
      environment: { QUIRT_VISIBLE: "ok", QUIRT_SECRET: SECRET },
      unsetEnvironment: ["COLORTERM"],
      replaceEnvironment: false
    });
    assert.equal(resolved.values.QUIRT_SECRET, SECRET);
    assert.equal("COLORTERM" in resolved.values, false);
    const replaced = resolveEnvironment("/bin/bash", { environment: { QUIRT_ONLY: "1" }, replaceEnvironment: true });
    assert.equal(replaced.values.HOME, undefined);
    const result = await jobs.exec("q3-env", owner, {
      command: "printf ok",
      environmentPolicy: { environment: { QUIRT_SECRET: SECRET }, unsetEnvironment: ["COLORTERM"] }
    });
    const receipt = state.getExecutionReceipt(result.receiptId!);
    const serialized = JSON.stringify(receipt.receipt);
    assert.equal(serialized.includes(SECRET), false);
    assert.ok(receipt.receipt.environmentKeys);
  });

  it("preserves separate stdout and stderr streams and binary stdin", async () => {
    const { jobs } = harness();
    const result = await jobs.exec("q3-binary", owner, {
      executable: process.execPath,
      arguments: ["-e", "process.stdout.write(Buffer.from([0,1,2])); process.stderr.write(Buffer.from([3,4]))"],
      input: Buffer.from([9, 0, 255])
    });
    assert.deepEqual(result.stdout, Buffer.from([0, 1, 2]));
    assert.deepEqual(result.stderr, Buffer.from([3, 4]));
    assert.equal(result.compatibilityCombinedOutput.equals(Buffer.concat([result.stdout, result.stderr])), true);
  });

  it("classifies explicit timeout without default timeout when omitted", async () => {
    const { jobs } = harness();
    const timed = await jobs.exec("q3-timeout", owner, { command: "sleep 3", timeoutMs: 100 });
    assert.equal(timed.timedOut, true);
    assert.equal(timed.job.status, "timed_out");
    const noTimeout = await jobs.exec("q3-no-timeout", owner, { command: "sleep 0.2" });
    assert.equal(noTimeout.job.timedOut, false);
    assert.equal(noTimeout.job.status, "exited");
  });

  it("prevents duplicate request execution and supports replay lookup", async () => {
    const { jobs } = harness();
    const first = await jobs.exec("q3-dup", owner, { command: "sleep 0.4", detach: true });
    const replay = await jobs.exec("q3-dup", owner, { command: "sleep 0.4", detach: true });
    assert.equal(replay.job.jobId, first.job.jobId);
    const byRequest = jobs.getByRequestId("q3-dup", owner);
    assert.equal(byRequest.jobId, first.job.jobId);
  });

  it("captures process identity and produces immutable receipts exactly once", async () => {
    const { jobs, state } = harness();
    const result = await jobs.exec("q3-receipt", owner, { command: "printf identity" });
    assert.ok(result.job.processIdentity);
    assert.ok(result.job.launchDocumentDigest);
    assert.equal(result.job.receiptId, result.receiptId);
    const receipt = state.getExecutionReceipt(result.receiptId!);
    assert.equal(receipt.receiptDigest, receipt.receipt.receiptDigest);
    assert.throws(() => state.getExecutionReceipt("missing-receipt-id"), /not found/u);
  });

  it("uses injected probes for identity mismatch and core dump metadata", async () => {
    const fakeReader: ProcReader = {
      readBootId: async () => "00000000-0000-4000-8000-000000000001",
      readStat: async () => "1 (node) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
      readStatus: async () => "Name:\tnode\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0",
      readCmdline: async () => Buffer.from("node\0"),
      readCgroup: async () => "0::/user.slice/user-0.slice/session-1.scope",
      readlinkExe: async () => process.execPath,
      readlinkCwd: async () => "/root",
      readNamespace: async () => "4026531836",
      statExe: async () => ({ device: 1, inode: 2 }),
      hashFile: async () => digestText("node")
    };
    const { jobs } = harness({
      procReader: fakeReader,
      coreDumpProbe: new InjectedCoreDumpProbe({ state: "unknown", source: "injected", reason: "test" })
    });
    const result = await jobs.exec("q3-probes", owner, { executable: process.execPath, arguments: ["-e", "process.exit(0)"] });
    assert.equal(result.job.status, "exited");
    assert.ok(result.job.processIdentity);
  });

  it("gracefully cancels running jobs and blocks write-after-close", async () => {
    const { jobs, state } = harness();
    const detached = await jobs.exec("q3-cancel", owner, { command: "sleep 30", detach: true });
    await jobs.cancel(detached.job.jobId, owner);
    await waitFor(() => state.getJob(detached.job.jobId).finishedAt !== null, 10_000);
    assert.equal(["canceled", "timed_out", "signaled", "exited", "failed"].includes(state.getJob(detached.job.jobId).status), true);
    const inputJob = await jobs.exec("q3-input", owner, { command: "cat", detach: true });
    jobs.input(inputJob.job.jobId, owner, Buffer.from("a"), true);
    await waitFor(() => state.getJob(inputJob.job.jobId).finishedAt !== null, 10_000);
    assert.throws(() => jobs.input(inputJob.job.jobId, owner, Buffer.from("b")), /closed|unavailable/u);
  });

  it("migrates state schema 19 to 20 while preserving authority nonces", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-q3-migrate-"));
    roots.push(root);
    const path = join(root, "state.sqlite");
    const legacy = new QuirtStateStore(path);
    assert.equal(legacy.schemaVersion(), 20);
    legacy.reserveRequest("nonce-request", "quirt.exec", "hash", {
      nonce: "nonce-1", gatewayId: "gateway", algorithm: "hmac-sha256", keyId: null
    } as const, new Date(Date.now() + 60_000).toISOString());
    legacy.close();
    const reopened = new QuirtStateStore(path);
    assert.equal(reopened.schemaVersion(), 20);
    assert.equal(reopened.requestResult("nonce-request")?.state, "reserved");
    reopened.close();
  });
});

function TERMINAL(status: string): boolean {
  return ["exited", "failed", "signaled", "canceled", "timed_out", "spawn_failed", "identity_lost", "lost"].includes(status);
}
