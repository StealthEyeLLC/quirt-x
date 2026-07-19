import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtJobManager } from "./job-manager.js";
import { NodePtyFactory } from "./pty.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig, waitFor } from "./test-support.test.js";

const roots: string[] = []; const managers: QuirtJobManager[] = []; const stores: QuirtStateStore[] = [];
afterEach(() => {
  for (const manager of managers.splice(0)) manager.shutdown();
  for (const store of stores.splice(0)) try { store.close(); } catch { /* already closed */ }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(): { root: string; state: QuirtStateStore; jobs: QuirtJobManager } {
  const root = mkdtempSync(join(tmpdir(), "quirt-job-")); roots.push(root); const config = quirtTestConfig(root); const state = new QuirtStateStore(":memory:", { outputChunkBytes: 4096, outputRetentionBytes: 2 * 1024 * 1024 }); stores.push(state); const jobs = new QuirtJobManager(config, state, new NodePtyFactory()); managers.push(jobs); return { root, state, jobs };
}

const owner = "a".repeat(64);

describe("Quirt immediate execution and durable jobs", () => {
  it("captures successful, nonzero, signaled, binary, PTY, working-directory, environment, and large-output results", async () => {
    const { root, jobs } = harness();
    const success = await jobs.exec("request-success", owner, { command: "printf 'stdout'; printf 'stderr' >&2", workingDirectory: root, environment: { QUIRT_JOB_VALUE: "visible" } });
    assert.equal(success.job.status, "exited"); assert.equal(success.job.exitCode, 0); assert.equal(success.stdout.toString(), "stdout"); assert.equal(success.stderr.toString(), "stderr"); assert.equal(success.job.workingDirectory, root); assert.equal(success.job.environment.QUIRT_JOB_VALUE, "visible");
    const nonzero = await jobs.exec("request-failure", owner, { script: "printf fail >&2; exit 7" }); assert.equal(nonzero.job.status, "failed"); assert.equal(nonzero.job.exitCode, 7); assert.equal(nonzero.stderr.toString(), "fail");
    const signaled = await jobs.exec("request-signal", owner, { command: "kill -TERM $$" }); assert.equal(signaled.job.status, "signaled"); assert.equal(signaled.job.exitSignal, "SIGTERM");
    const binary = await jobs.exec("request-binary", owner, { executable: process.execPath, arguments: ["-e", "process.stdout.write(Buffer.from([0,1,2,255]))"] }); assert.deepEqual(binary.stdout, Buffer.from([0, 1, 2, 255]));
    const large = await jobs.exec("request-large", owner, { executable: process.execPath, arguments: ["-e", "process.stdout.write(Buffer.alloc(200000,0x61))"] }); assert.equal(large.stdout.length, 200000); assert.equal(large.stdout[199999], 0x61);
    const pty = await jobs.exec("request-pty", owner, { command: "printf '\\033[32mpty\\033[0m'", pty: true }); assert.equal(pty.job.status, "exited"); assert.ok(pty.stdout.includes(Buffer.from("\u001b[32mpty\u001b[0m"))); assert.equal(pty.stderr.length, 0);
  });

  it("enforces timeouts and persists detached output, input, offsets, attachment, and cancellation", async () => {
    const { jobs, state } = harness();
    const timed = await jobs.exec("request-timeout", owner, { command: "sleep 5", timeoutMs: 100 }); assert.equal(timed.timedOut, true); assert.equal(timed.job.timedOut, true); assert.equal(timed.job.status, "timed_out");
    const detached = await jobs.exec("request-detached", owner, { command: "printf begin; cat; printf end", detach: true }); assert.equal(detached.detached, true); assert.equal(detached.job.status, "running");
    await waitFor(() => state.getStream(detached.job.stdoutStreamId).nextOffset >= 5);
    assert.equal(jobs.read(detached.job.jobId, owner, "stdout", 0, 5).bytes.toString(), "begin");
    assert.deepEqual(jobs.input(detached.job.jobId, owner, Buffer.from([0, 1, 255]), true), { acceptedBytes: 3, closed: true });
    await waitFor(() => state.getJob(detached.job.jobId).status !== "running");
    const complete = jobs.read(detached.job.jobId, owner, "stdout", 5, 32); assert.deepEqual(complete.bytes, Buffer.concat([Buffer.from([0, 1, 255]), Buffer.from("end")])); assert.equal(complete.eof, true);
    const attached = jobs.attach(detached.job.jobId, owner); assert.equal((attached.job as { jobId: string }).jobId, detached.job.jobId); assert.equal(attached.inputAvailable, false);
    const cancel = await jobs.exec("request-cancel", owner, { command: "sleep 30", detach: true }); await jobs.cancel(cancel.job.jobId, owner); await waitFor(() => state.getJob(cancel.job.jobId).finishedAt !== null); assert.equal(["canceled", "signaled", "timed_out"].includes(state.getJob(cancel.job.jobId).status), true);
    assert.throws(() => jobs.get(detached.job.jobId, "b".repeat(64)), /principal/u);
  });

  it("recovers surviving processes as unknown and missing processes as lost", () => {
    const { jobs, state } = harness();
    const alive = state.createJob({ jobId: "job-alive", requestId: "recover-alive", ownerPrincipalFingerprint: owner, command: { command: "external" }, workingDirectory: "/root" }); state.updateJob(alive.jobId, { status: "running", processId: process.pid, started: true });
    const missing = state.createJob({ jobId: "job-missing", requestId: "recover-missing", ownerPrincipalFingerprint: owner, command: { command: "gone" }, workingDirectory: "/root" }); state.updateJob(missing.jobId, { status: "running", processId: 2_000_000_000, started: true });
    assert.deepEqual(jobs.recover(), { unknown: 1, lost: 1 }); assert.equal(state.getJob(alive.jobId).status, "unknown"); assert.equal(state.getJob(missing.jobId).status, "lost"); assert.ok(state.getJob(missing.jobId).finishedAt);
  });
});
