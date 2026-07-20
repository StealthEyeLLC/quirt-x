import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { InjectedCoreDumpProbe } from "./core-dump.js";
import { resolveEnvironment } from "./execution-environment.js";
import { buildLaunchDocument, digestText } from "./launch-document.js";
import { buildExecutionReceipt } from "./execution-receipt.js";
import { RealTerminationClock, runTermination } from "./execution-termination.js";
import { LinuxResourceProbe, sampleResourceEvidence } from "./resource-accounting.js";
import { captureProcessIdentity, commandLineDigest, identitiesMatch } from "./process-identity.js";

describe("Quirt Q3 support modules", () => {
  it("builds stable launch digests and distinguishes argv boundaries", () => {
    const left = buildLaunchDocument({
      form: { kind: "executable", executable: "/bin/echo", arguments: ["a", "b"], shellWrapped: false },
      workingDirectory: "/root",
      environmentPolicyDigest: digestText("env"),
      stdinDigest: null,
      pty: false,
      detach: false,
      timeoutMs: null
    });
    const right = buildLaunchDocument({
      form: { kind: "executable", executable: "/bin/echo", arguments: ["ab"], shellWrapped: false },
      workingDirectory: "/root",
      environmentPolicyDigest: digestText("env"),
      stdinDigest: null,
      pty: false,
      detach: false,
      timeoutMs: null
    });
    assert.notEqual(left.digest, right.digest);
  });

  it("resolves environment replacement and deletion", () => {
    const resolved = resolveEnvironment("/bin/bash", {
      environment: { QUIRT_EMPTY: "", QUIRT_SET: "1" },
      unsetEnvironment: ["COLORTERM"],
      replaceEnvironment: true
    });
    assert.equal(resolved.values.QUIRT_EMPTY, "");
    assert.equal("COLORTERM" in resolved.values, false);
    assert.equal("HOME" in resolved.values, false);
  });

  it("builds canonical execution receipts without secret fields", () => {
    const receipt = buildExecutionReceipt({
      jobId: "job-1",
      requestId: "req-1",
      operationId: "quirt.exec",
      operationVersion: "1.0.0",
      authenticatedSubject: "stealtheye-owner",
      authorityClass: "unrestricted-owner",
      principalFingerprint: "a".repeat(64),
      targetHost: "host",
      createdAt: new Date().toISOString(),
      startedAt: new Date().toISOString(),
      terminalAt: new Date().toISOString(),
      finalClassification: "exited",
      launchForm: { kind: "command", shellPath: "/bin/bash", commandDigest: digestText("printf ok") },
      launchDocumentDigest: digestText("launch"),
      executableRequestedPath: "/bin/bash",
      executableObservedPath: "/bin/bash",
      executableSha256: digestText("bash"),
      interpreterIdentity: "/bin/bash",
      commandOrScriptDigest: digestText("printf ok"),
      workingDirectoryRequested: "/root",
      workingDirectoryObserved: "/root",
      environmentKeys: ["PATH"],
      environmentPolicyDigest: digestText("policy"),
      processIdentity: null,
      cgroupIdentity: null,
      namespaceIdentities: null,
      exitCode: 0,
      exitSignal: null,
      timedOut: false,
      termination: null,
      cancellation: null,
      coreDump: { state: "not_detected", source: "wait_status" },
      stdoutStreamId: "stdout",
      stdoutByteCount: 2,
      stdoutDigest: digestText("ok"),
      stdoutDigestComplete: true,
      stderrStreamId: "stderr",
      stderrByteCount: 0,
      stderrDigest: null,
      stderrDigestComplete: true,
      stdinByteCount: 0,
      stdinDigest: null,
      resourceEvidence: null,
      outputGap: false,
      ptyStreamModel: "separate"
    });
    assert.ok(receipt.receiptDigest);
    assert.equal(JSON.stringify(receipt).includes("printf ok"), false);
  });

  it("samples resource evidence and core dump metadata", async () => {
    const evidence = await sampleResourceEvidence(process.pid, Date.now() - 100, Date.now(), new LinuxResourceProbe());
    assert.equal(evidence.wallClockDurationMs.availability, "measured");
    const core = await new InjectedCoreDumpProbe({ state: "unknown", source: "test", reason: "injected" }).inspect(0, null, process.pid);
    assert.equal(core.state, "unknown");
    const identity = await captureProcessIdentity(process.pid, {
      readBootId: async () => "00000000-0000-4000-8000-000000000001",
      readStat: async (pid) => (await import("node:fs/promises")).readFile(`/proc/${pid}/stat`, "utf8"),
      readStatus: async (pid) => (await import("node:fs/promises")).readFile(`/proc/${pid}/status`, "utf8"),
      readCmdline: async (pid) => (await import("node:fs/promises")).readFile(`/proc/${pid}/cmdline`).catch(() => Buffer.alloc(0)),
      readCgroup: async () => "",
      readlinkExe: async (pid) => (await import("node:fs/promises")).readlink(`/proc/${pid}/exe`).catch(() => null),
      readlinkCwd: async (pid) => (await import("node:fs/promises")).readlink(`/proc/${pid}/cwd`).catch(() => null),
      readNamespace: async (pid) => (await import("node:fs/promises")).readlink(`/proc/${pid}/ns/pid`).catch(() => null),
      statExe: async (pid) => {
        const raw = await (await import("node:fs/promises")).stat(`/proc/${pid}/exe`).catch(() => null);
        return raw === null ? null : { device: Number(raw.dev), inode: Number(raw.ino) };
      },
      hashFile: async () => null
    });
    assert.ok(identitiesMatch(identity, identity));
    assert.ok(commandLineDigest(Buffer.from("a\0b")));
  });

  it("runs graceful termination with injectable clock and signaler", async () => {
    let signaled = 0;
    const evidence = await runTermination({
      identity: { pid: 42, startTimeTicks: 1, bootId: "00000000-0000-4000-8000-000000000001", pidNamespace: null, executableDevice: null, executableInode: null, processGroupId: 42 },
      reason: "timeout",
      pty: false,
      options: { graceIntervalMs: 1, escalate: true },
      verifyIdentity: async () => ({ pid: 42, startTimeTicks: 1, bootId: "00000000-0000-4000-8000-000000000001", pidNamespace: null, executableDevice: null, executableInode: null }),
      waitForExit: async () => undefined,
      signaler: {
        signalProcess: () => { signaled += 1; },
        signalProcessGroup: () => { signaled += 1; }
      },
      clock: new RealTerminationClock()
    });
    assert.ok(signaled >= 1);
    assert.equal(evidence.reason, "timeout");
  });
});
