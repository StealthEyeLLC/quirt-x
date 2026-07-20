import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  deliverProcessSignal,
  FakeTerminationClock,
  resolveProcessSignalTarget,
  runTermination
} from "./execution-termination.js";

describe("Quirt execution termination review regressions", () => {
  it("honors the full grace interval before escalating to SIGKILL", async () => {
    const clock = new FakeTerminationClock();
    const signals: Array<{ target: string; signal: NodeJS.Signals }> = [];
    let releaseExit: (() => void) | undefined;
    const exitPromise = new Promise<void>(resolve => { releaseExit = resolve; });
    const run = runTermination({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 42 },
      reason: "timeout",
      pty: false,
      options: { graceIntervalMs: 500, escalate: true },
      verifyIdentity: async () => ({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null }),
      waitForExit: async () => exitPromise,
      signaler: {
        signalProcess: (_pid, signal) => { signals.push({ target: "process", signal }); if (signal === "SIGKILL") releaseExit?.(); },
        signalProcessGroup: (_pgid, signal) => { signals.push({ target: "group", signal }); if (signal === "SIGKILL") releaseExit?.(); }
      },
      clock
    });
    await Promise.resolve();
    assert.deepEqual(signals.map(item => item.signal), ["SIGTERM"]);
    clock.advance(60);
    await Promise.resolve();
    assert.deepEqual(signals.map(item => item.signal), ["SIGTERM"]);
    clock.advance(500);
    await run;
    assert.deepEqual(signals.map(item => item.signal), ["SIGTERM", "SIGKILL"]);
  });

  it("does not send SIGKILL when the process exits during the grace interval", async () => {
    const clock = new FakeTerminationClock();
    const signals: NodeJS.Signals[] = [];
    const evidence = await runTermination({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 42 },
      reason: "graceful_cancel",
      pty: false,
      options: { graceIntervalMs: 500, escalate: true },
      verifyIdentity: async () => ({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null }),
      waitForExit: async () => undefined,
      signaler: {
        signalProcess: (_pid, signal) => { signals.push(signal); },
        signalProcessGroup: (_pgid, signal) => { signals.push(signal); }
      },
      clock
    });
    assert.deepEqual(signals, ["SIGTERM"]);
    assert.equal(evidence.escalated, false);
    assert.equal(evidence.forcedSignal, null);
  });

  it("uses a configured non-default grace interval", async () => {
    const clock = new FakeTerminationClock();
    const signals: NodeJS.Signals[] = [];
    let releaseExit: (() => void) | undefined;
    const run = runTermination({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 42 },
      reason: "timeout",
      pty: false,
      options: { graceIntervalMs: 1_200, escalate: true },
      verifyIdentity: async () => ({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null }),
      waitForExit: async () => new Promise<void>(resolve => { releaseExit = resolve; }),
      signaler: {
        signalProcess: (_pid, signal) => { signals.push(signal); if (signal === "SIGKILL") releaseExit?.(); },
        signalProcessGroup: (_pgid, signal) => { signals.push(signal); if (signal === "SIGKILL") releaseExit?.(); }
      },
      clock
    });
    await Promise.resolve();
    clock.advance(1_100);
    await Promise.resolve();
    assert.deepEqual(signals, ["SIGTERM"]);
    clock.advance(200);
    await run;
    assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  });

  it("stops waiting when abort is signaled", async () => {
    const clock = new FakeTerminationClock();
    const controller = new AbortController();
    const signals: NodeJS.Signals[] = [];
    let releaseExit: (() => void) | undefined;
    const run = runTermination({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 42 },
      reason: "protocol_cancel",
      pty: false,
      options: { graceIntervalMs: 500, escalate: true },
      verifyIdentity: async () => ({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null }),
      waitForExit: async () => new Promise<void>(resolve => { releaseExit = resolve; }),
      signaler: {
        signalProcess: (_pid, signal) => { signals.push(signal); if (signal === "SIGKILL") releaseExit?.(); },
        signalProcessGroup: (_pgid, signal) => { signals.push(signal); if (signal === "SIGKILL") releaseExit?.(); }
      },
      clock,
      abort: controller.signal
    });
    controller.abort();
    await Promise.resolve();
    clock.advance(500);
    await run;
    assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  });

  it("does not produce unhandled rejections when waitForExit rejects", async () => {
    const clock = new FakeTerminationClock();
    const evidence = await runTermination({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 42 },
      reason: "graceful_cancel",
      pty: false,
      options: { graceIntervalMs: 100, escalate: false },
      verifyIdentity: async () => ({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null }),
      waitForExit: async () => { throw new Error("already exited"); },
      signaler: {
        signalProcess: () => undefined,
        signalProcessGroup: () => undefined
      },
      clock
    });
    assert.equal(evidence.reason, "graceful_cancel");
  });

  it("signals the process group when a valid PGID exists", () => {
    const target = resolveProcessSignalTarget({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 99 }, 42);
    assert.deepEqual(target, { mode: "group", pgid: 99 });
    const signals: Array<{ mode: string; value: number; signal: NodeJS.Signals }> = [];
    deliverProcessSignal({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 99 },
      pty: false,
      signal: "SIGTERM",
      signaler: {
        signalProcess: (pid, signal) => { signals.push({ mode: "process", value: pid, signal }); },
        signalProcessGroup: (pgid, signal) => { signals.push({ mode: "group", value: pgid, signal }); }
      }
    });
    assert.deepEqual(signals, [{ mode: "group", value: 99, signal: "SIGTERM" }]);
  });

  it("signals the process directly when PGID is missing", () => {
    const target = resolveProcessSignalTarget({ pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null }, 42);
    assert.deepEqual(target, { mode: "process", pid: 42 });
    const signals: Array<{ mode: string; value: number; signal: NodeJS.Signals }> = [];
    deliverProcessSignal({
      identity: { pid: 42, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null },
      pty: false,
      signal: "SIGINT",
      signaler: {
        signalProcess: (pid, signal) => { signals.push({ mode: "process", value: pid, signal }); },
        signalProcessGroup: (pgid, signal) => { signals.push({ mode: "group", value: pgid, signal }); }
      }
    });
    assert.deepEqual(signals, [{ mode: "process", value: 42, signal: "SIGINT" }]);
  });

  it("rejects PID and PGID values below 2", () => {
    assert.throws(() => resolveProcessSignalTarget({ pid: 1, startTimeTicks: 1, bootId: "boot", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 1 }, 1), /missing process identity/u);
  });
});
