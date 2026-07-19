import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QuirtJobManager } from "./job-manager.js";
import { NodePtyFactory } from "./pty.js";
import {
  ResourceAccumulator,
  type QuirtResourceEvidence,
  type ResourceProbe
} from "./resource-accounting.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";

const roots: string[] = [];
const managers: QuirtJobManager[] = [];
const stores: QuirtStateStore[] = [];
const owner = "a".repeat(64);

afterEach(() => {
  for (const manager of managers.splice(0)) manager.shutdown();
  for (const store of stores.splice(0)) try { store.close(); } catch { /* closed */ }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(deps: ConstructorParameters<typeof QuirtJobManager>[3] = {}): { jobs: QuirtJobManager; state: QuirtStateStore } {
  const root = mkdtempSync(join(tmpdir(), "quirt-finalize-"));
  roots.push(root);
  const state = new QuirtStateStore(":memory:", { outputChunkBytes: 4096, outputRetentionBytes: 2 * 1024 * 1024 });
  stores.push(state);
  const jobs = new QuirtJobManager(quirtTestConfig(root), state, new NodePtyFactory(), deps);
  managers.push(jobs);
  return { jobs, state };
}

function liveProbe(values: { rssKb?: number; userTicks?: number } = {}): ResourceProbe {
  const rssKb = values.rssKb ?? 2048;
  const userTicks = values.userTicks ?? 5;
  return {
    readStatus: async () => `VmRSS:\t${rssKb} kB\nVmSize:\t4096 kB\nThreads:\t2\nvoluntary_ctxt_switches:\t3\nnonvoluntary_ctxt_switches:\t1\n`,
    readIo: async () => "read_bytes:\t100\nwrite_bytes:\t50\n",
    readStat: async () => `1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 ${userTicks} 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0`
  };
}

function resourceEvidence(receipt: Record<string, unknown>): QuirtResourceEvidence {
  return receipt.resourceEvidence as QuirtResourceEvidence;
}

describe("ResourceAccumulator finalization lifecycle", () => {
  it("does not rely on sampleOnce after stop for terminal sampling", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        sampleCount += 1;
        if (sampleCount > 1) return null;
        return "VmRSS:\t1024 kB\n";
      },
      readIo: async () => (sampleCount > 1 ? null : "read_bytes:\t1\n"),
      readStat: async () => (sampleCount > 1 ? null : "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    await accumulator.start();
    await accumulator.sampleOnce();
    accumulator.stop();
    const afterStop = sampleCount;
    await accumulator.sampleOnce();
    assert.equal(sampleCount, afterStop);
    await accumulator.stopAndFinalizeSample();
    assert.equal(sampleCount, afterStop + 1);
    const evidence = accumulator.finalize(0, 100);
    assert.equal(evidence.maximumRssBytes.availability, "sampled");
  });

  it("waits for an in-flight initial sample before permanent closure", async () => {
    let releaseSample!: () => void;
    let sampleStartedResolve!: () => void;
    const sampleStarted = new Promise<void>(resolve => { sampleStartedResolve = resolve; });
    let blockedInitial = false;
    const probe: ResourceProbe = {
      readStatus: async () => {
        sampleStartedResolve();
        if (!blockedInitial) {
          blockedInitial = true;
          await new Promise<void>(resolve => { releaseSample = resolve; });
        }
        return "VmRSS:\t8192 kB\n";
      },
      readIo: async () => "read_bytes:\t10\n",
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 3 4 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    void accumulator.start();
    await sampleStarted;
    let finalized = false;
    const finalizePromise = accumulator.stopAndFinalizeSample().then(() => { finalized = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(finalized, false);
    releaseSample();
    await finalizePromise;
    const evidence = accumulator.finalize(0, 50);
    assert.equal(evidence.maximumRssBytes.availability, "sampled");
    if (evidence.maximumRssBytes.availability === "sampled") assert.equal(evidence.maximumRssBytes.value, 8192 * 1024);
  });

  it("attempts one final sample before marking the accumulator closed", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        sampleCount += 1;
        return sampleCount === 1 ? "VmRSS:\t1024 kB\n" : null;
      },
      readIo: async () => (sampleCount === 1 ? "read_bytes:\t1\n" : null),
      readStat: async () => (sampleCount === 1 ? "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0" : null)
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    await accumulator.start();
    await accumulator.stopAndFinalizeSample();
    assert.equal(sampleCount, 2);
  });

  it("never overlaps an in-flight sample with the terminal final sample", async () => {
    let active = 0;
    let maxActive = 0;
    let releaseFirst!: () => void;
    let firstStarted!: () => void;
    let firstStartedPromise = new Promise<void>(resolve => { firstStarted = resolve; });
    let sampleOrdinal = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        try {
          sampleOrdinal += 1;
          if (sampleOrdinal === 1) {
            firstStarted();
            await new Promise<void>(resolve => { releaseFirst = resolve; });
          }
          return "VmRSS:\t1024 kB\n";
        } finally {
          active -= 1;
        }
      },
      readIo: async () => "read_bytes:\t1\n",
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const accumulator = new ResourceAccumulator(42, probe, 5);
    void accumulator.start();
    await firstStartedPromise;
    const finalizePromise = accumulator.stopAndFinalizeSample();
    releaseFirst();
    await finalizePromise;
    assert.equal(maxActive, 1);
    assert.equal(sampleOrdinal, 2);
  });

  it("retains the previous successful live sample when the post-exit final probe fails", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        sampleCount += 1;
        if (sampleCount >= 3) return null;
        return "VmRSS:\t2048 kB\nVmSize:\t4096 kB\nThreads:\t2\n";
      },
      readIo: async () => (sampleCount >= 3 ? null : "read_bytes:\t100\nwrite_bytes:\t50\n"),
      readStat: async () => (sampleCount >= 3 ? null : "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 5 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    await accumulator.start();
    await accumulator.sampleOnce();
    await accumulator.stopAndFinalizeSample();
    const evidence = accumulator.finalize(0, 100);
    assert.equal(evidence.maximumRssBytes.availability, "sampled");
    if (evidence.maximumRssBytes.availability === "sampled") assert.equal(evidence.maximumRssBytes.value, 2048 * 1024);
    assert.equal(evidence.readBytes.availability, "sampled");
  });

  it("does not mutate evidence after terminal finalization returns", async () => {
    const accumulator = new ResourceAccumulator(42, liveProbe({ rssKb: 1111 }), 10);
    await accumulator.start();
    await accumulator.stopAndFinalizeSample();
    const before = accumulator.finalize(0, 100);
    await accumulator.sampleOnce();
    await accumulator.stopAndFinalizeSample();
    const after = accumulator.finalize(0, 100);
    assert.deepEqual(after, before);
  });

  it("treats duplicate terminal finalization as idempotent", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => { sampleCount += 1; return "VmRSS:\t512 kB\n"; },
      readIo: async () => "read_bytes:\t1\n",
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const accumulator = new ResourceAccumulator(42, probe, 10);
    await accumulator.start();
    await accumulator.stopAndFinalizeSample();
    const afterFirst = sampleCount;
    await accumulator.stopAndFinalizeSample();
    await accumulator.stopAndFinalizeSample();
    assert.equal(sampleCount, afterFirst);
  });

  it("does not schedule further interval samples after finalization", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => { sampleCount += 1; return "VmRSS:\t1024 kB\n"; },
      readIo: async () => "read_bytes:\t1\n",
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const accumulator = new ResourceAccumulator(42, probe, 5);
    await accumulator.start();
    await accumulator.stopAndFinalizeSample();
    const afterFinalize = sampleCount;
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(sampleCount, afterFinalize);
  });

  it("clears interval timers when stop is invoked before finalization", async () => {
    let sampleCount = 0;
    const probe: ResourceProbe = {
      readStatus: async () => { sampleCount += 1; return "VmRSS:\t1024 kB\n"; },
      readIo: async () => "read_bytes:\t1\n",
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const accumulator = new ResourceAccumulator(42, probe, 5);
    await accumulator.start();
    accumulator.stop();
    const afterStop = sampleCount;
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(sampleCount, afterStop);
  });
});

describe("Quirt job manager resource finalization", () => {
  it("waits for the initial in-flight sample before building a short-lived receipt", async () => {
    let releaseSample!: () => void;
    let sampleStartedResolve!: () => void;
    const sampleStarted = new Promise<void>(resolve => { sampleStartedResolve = resolve; });
    let sampleOrdinal = 0;
    const probe: ResourceProbe = {
      readStatus: async () => {
        sampleOrdinal += 1;
        if (sampleOrdinal === 1) sampleStartedResolve();
        if (sampleOrdinal === 1) await new Promise<void>(resolve => { releaseSample = resolve; });
        return "VmRSS:\t4096 kB\nVmSize:\t8192 kB\nThreads:\t1\n";
      },
      readIo: async () => "read_bytes:\t42\nwrite_bytes:\t24\n",
      readStat: async () => "1 (node) R 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 9 11 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    };
    const { jobs } = harness({ resourceProbe: probe });
    const pending = jobs.exec("short-lived", owner, { command: "true" });
    await sampleStarted;
    let settled = false;
    void pending.then(() => { settled = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(settled, false);
    releaseSample();
    const result = await pending;
    assert.equal(result.job.status, "exited");
    assert.ok(result.receiptId);
    const receipt = jobs.getReceipt(result.receiptId!, owner);
    const evidence = resourceEvidence(receipt);
    assert.equal(evidence.maximumRssBytes.availability, "sampled");
    if (evidence.maximumRssBytes.availability === "sampled") assert.equal(evidence.maximumRssBytes.value, 4096 * 1024);
    assert.equal(evidence.readBytes.availability, "sampled");
  });

  it("clears accumulator timers on cancellation and shutdown", async () => {
    const alwaysLive = liveProbe();
    const { jobs: cancelJobs } = harness({ resourceProbe: alwaysLive });
    const detached = await cancelJobs.exec("cancel-timer", owner, { command: "sleep 1", detach: true });
    await cancelJobs.cancel(detached.job.jobId, owner, true);
    cancelJobs.shutdown();
  });
});
