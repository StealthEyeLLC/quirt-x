import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtError } from "./error.js";
import { QuirtJobManager } from "./job-manager.js";
import { isProcessAlive } from "./process-identity.js";
import { DEFAULT_RESOURCE_SAMPLE_INTERVAL_MS, parseProcStatCpuTicks, readResourceSample, ResourceAccumulator, type ResourceProbe } from "./resource-accounting.js";
import { NodePtyFactory } from "./pty.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";

const roots: string[] = [];
const managers: QuirtJobManager[] = [];
const stores: QuirtStateStore[] = [];
const owner = "a".repeat(64);
const otherOwner = "b".repeat(64);

afterEach(() => {
  for (const manager of managers.splice(0)) manager.shutdown();
  for (const store of stores.splice(0)) try { store.close(); } catch { /* closed */ }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(deps: ConstructorParameters<typeof QuirtJobManager>[3] = {}): { root: string; state: QuirtStateStore; jobs: QuirtJobManager } {
  const root = mkdtempSync(join(tmpdir(), "quirt-q3-review-"));
  roots.push(root);
  const config = quirtTestConfig(root);
  const state = new QuirtStateStore(":memory:", { outputChunkBytes: 4096, outputRetentionBytes: 2 * 1024 * 1024 });
  stores.push(state);
  const jobs = new QuirtJobManager(config, state, new NodePtyFactory(), deps);
  managers.push(jobs);
  return { root, state, jobs };
}

describe("Quirt Q3 review regressions", () => {
  it("rejects cross-principal replay of an existing requestId", async () => {
    const { jobs } = harness();
    await jobs.exec("shared-request", owner, { command: "printf ok" });
    await assert.rejects(
      () => jobs.exec("shared-request", otherOwner, { command: "printf ok" }),
      (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed"
    );
  });

  it("allows the owning principal to replay an existing requestId", async () => {
    const { jobs } = harness();
    const first = await jobs.exec("owner-replay", owner, { command: "printf ok" });
    const replay = await jobs.exec("owner-replay", owner, { command: "printf ok" });
    assert.equal(replay.job.jobId, first.job.jobId);
  });

  it("classifies EPERM from kill probe as alive", () => {
    assert.equal(isProcessAlive(42, () => { const error = new Error("not permitted"); (error as NodeJS.ErrnoException).code = "EPERM"; throw error; }), true);
    assert.equal(isProcessAlive(42, () => { const error = new Error("no such process"); (error as NodeJS.ErrnoException).code = "ESRCH"; throw error; }), false);
  });

  it("validates working directories and executables by filesystem type", async () => {
    const { root, jobs } = harness();
    const validDir = join(root, "cwd ok");
    const fileCwd = join(root, "file-cwd");
    const missingDir = join(root, "missing");
    const validExec = join(root, "exec.sh");
    const dirExec = join(root, "dir-exec");
    const missingExec = join(root, "missing-exec");
    const nonExecFile = join(root, "plain.txt");
    const symlinkExec = join(root, "exec-link");
    mkdirSync(validDir);
    writeFileSync(fileCwd, "not a directory");
    writeFileSync(validExec, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    mkdirSync(dirExec);
    writeFileSync(nonExecFile, "plain");
    symlinkSync(process.execPath, symlinkExec);
    await assert.rejects(() => jobs.exec("cwd-file", owner, { command: "true", workingDirectory: fileCwd }), /not a directory/u);
    await assert.rejects(() => jobs.exec("cwd-missing", owner, { command: "true", workingDirectory: missingDir }), /not found/u);
    await assert.rejects(() => jobs.exec("exec-dir", owner, { executable: dirExec, arguments: [] }), /not a file/u);
    await assert.rejects(() => jobs.exec("exec-missing", owner, { executable: missingExec, arguments: [] }), /not found/u);
    await assert.rejects(() => jobs.exec("exec-denied", owner, { executable: nonExecFile, arguments: [] }), /permission was denied/u);
    const ok = await jobs.exec("valid-paths", owner, {
      executable: process.execPath,
      arguments: ["-e", "setTimeout(() => {}, 40)"],
      workingDirectory: validDir
    });
    assert.equal(ok.job.status, "exited");
    const linked = await jobs.exec("valid-symlink", owner, {
      executable: symlinkExec,
      arguments: ["-e", "setTimeout(() => {}, 40)"],
      workingDirectory: validDir
    });
    assert.equal(linked.job.status, "exited");
  });

  it("rejects injected working-directory permission denial without touching root paths", async () => {
    const { jobs } = harness({
      pathValidation: {
        stat: async path => ({
          isDirectory: () => true,
          isFile: () => false
        } as import("node:fs").Stats),
        access: async (_path, mode) => {
          if ((mode & 1) !== 0) {
            const error = new Error("permission denied");
            (error as NodeJS.ErrnoException).code = "EACCES";
            throw error;
          }
        }
      }
    });
    await assert.rejects(() => jobs.exec("cwd-denied", owner, { command: "true", workingDirectory: "/tmp" }), /permission was denied/u);
  });

  it("signals the verified process group or PID without negative PID fallback", async () => {
    const kills: Array<{ pid: number; signal: NodeJS.Signals | number }> = [];
    const { jobs } = harness({
      killProcess: (pid, signal) => { kills.push({ pid, signal }); },
      procReader: {
        readBootId: async () => "boot",
        readStat: async () => "1 (node) S 0 99 99 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        readStatus: async () => "Name:\tnode\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0",
        readCmdline: async () => Buffer.from("sleep"),
        readCgroup: async () => "",
        readlinkExe: async () => "/bin/sleep",
        readlinkCwd: async () => "/root",
        readNamespace: async () => "ns",
        statExe: async () => ({ device: 1, inode: 2 }),
        hashFile: async () => null,
        tryCaptureSync: pid => ({
          pid,
          startTimeTicks: 100,
          bootId: "boot",
          pidNamespace: null,
          executableDevice: 1,
          executableInode: 2,
          processGroupId: 99
        })
      }
    });
    const detached = await jobs.exec("signal-group", owner, { command: "sleep 0.5", detach: true });
    await jobs.signal(detached.job.jobId, owner, "SIGINT");
    assert.deepEqual(kills, [{ pid: -99, signal: "SIGINT" }]);
    await jobs.cancel(detached.job.jobId, owner, true);
    kills.length = 0;
    const { jobs: jobsNoPgid } = harness({
      killProcess: (pid, signal) => { kills.push({ pid, signal }); },
      procReader: {
        readBootId: async () => "boot",
        readStat: async () => "1 (node) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        readStatus: async () => "Name:\tnode",
        readCmdline: async () => Buffer.alloc(0),
        readCgroup: async () => "",
        readlinkExe: async () => "/bin/sleep",
        readlinkCwd: async () => "/root",
        readNamespace: async () => "ns",
        statExe: async () => ({ device: 1, inode: 2 }),
        hashFile: async () => null,
        tryCaptureSync: pid => ({
          pid,
          startTimeTicks: 100,
          bootId: "boot",
          pidNamespace: null,
          executableDevice: 1,
          executableInode: 2
        })
      }
    });
    const detachedPid = await jobsNoPgid.exec("signal-pid", owner, { command: "sleep 0.5", detach: true });
    const pid = detachedPid.job.processId!;
    await jobsNoPgid.signal(detachedPid.job.jobId, owner, "SIGTERM");
    assert.deepEqual(kills, [{ pid, signal: "SIGTERM" }]);
    await jobsNoPgid.cancel(detachedPid.job.jobId, owner, true);
    jobsNoPgid.shutdown();
  });

  it("blocks signaling when process identity no longer matches", async () => {
    let syncReads = 0;
    const { jobs } = harness({
      procReader: {
        readBootId: async () => "boot",
        readStat: async () => "1 (node) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 200 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        readStatus: async () => "Name:\tnode",
        readCmdline: async () => Buffer.alloc(0),
        readCgroup: async () => "",
        readlinkExe: async () => process.execPath,
        readlinkCwd: async () => "/root",
        readNamespace: async () => "ns",
        statExe: async () => ({ device: 1, inode: 2 }),
        hashFile: async () => null,
        tryCaptureSync: pid => {
          syncReads += 1;
          if (syncReads > 1) return null;
          return {
            pid,
            startTimeTicks: 100,
            bootId: "boot",
            pidNamespace: null,
            executableDevice: 1,
            executableInode: 2,
            processGroupId: pid
          };
        }
      }
    });
    const detached = await jobs.exec("identity-signal", owner, { command: "sleep 0.5", detach: true });
    await assert.rejects(() => jobs.signal(detached.job.jobId, owner, "SIGTERM"), /identity/u);
    await jobs.cancel(detached.job.jobId, owner, true);
  });
});

describe("Quirt resource accounting review regressions", () => {
  it("parses CPU ticks from /proc stat safely", () => {
    const parsed = parseProcStatCpuTicks("42 (my app (v2)) R 0 1 1 0 -1 4194560 0 0 0 0 10 20 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0");
    assert.deepEqual(parsed, { userCpuTicks: 10, systemCpuTicks: 20 });
  });

  it("accumulates live samples and preserves them after post-exit loss", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        sampleCount += 1;
        if (sampleCount >= 3) return null;
        return "VmRSS:\t2048 kB\nVmSize:\t4096 kB\nThreads:\t2\nvoluntary_ctxt_switches:\t3\nnonvoluntary_ctxt_switches:\t1\n";
      },
      readIo: async () => {
        if (sampleCount >= 3) return null;
        return "read_bytes:\t100\nwrite_bytes:\t50\n";
      },
      readStat: async () => {
        if (sampleCount >= 3) return null;
        return "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 5 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
      }
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    await accumulator.start();
    await accumulator.sampleOnce();
    await accumulator.sampleOnce();
    await accumulator.stopAndFinalizeSample();
    const evidence = accumulator.finalize(Date.now() - 500, Date.now());
    assert.equal(evidence.maximumRssBytes.availability, "sampled");
    if (evidence.maximumRssBytes.availability === "sampled") assert.equal(evidence.maximumRssBytes.value, 2048 * 1024);
    assert.equal(evidence.userCpuTicks.availability, "sampled");
    assert.equal(evidence.readBytes.availability, "sampled");
    const afterExit = accumulator.finalize(Date.now() - 500, Date.now());
    assert.equal(afterExit.maximumRssBytes.availability, "sampled");
  });

  it("does not overlap probe calls and stops timers on stop", async () => {
    let active = 0;
    let maxActive = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise(resolve => setTimeout(resolve, 1));
        active -= 1;
        return "VmRSS:\t1024 kB\n";
      },
      readIo: async () => null,
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const accumulator = new ResourceAccumulator(42, probe, 5);
    await accumulator.start();
    await accumulator.sampleOnce();
    await accumulator.sampleOnce();
    await accumulator.stopAndFinalizeSample();
    assert.equal(maxActive, 1);
    assert.equal(DEFAULT_RESOURCE_SAMPLE_INTERVAL_MS, 200);
    const sample = await readResourceSample(42, probe);
    assert.equal(sample.maximumRssBytes, 1024 * 1024);
  });

  it("records unavailable fields when no live sample ever succeeded", async () => {
    const probe: ResourceProbe = {
      readStatus: async () => null,
      readIo: async () => null,
      readStat: async () => null
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    await accumulator.sampleOnce();
    await accumulator.stopAndFinalizeSample();
    const evidence = accumulator.finalize(0, 100);
    assert.equal(evidence.userCpuTicks.availability, "unavailable");
    assert.equal(evidence.maximumRssBytes.availability, "unavailable");
  });
});
