import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { QUIRT_OPERATIONS, QUIRT_POWER_FOUNDATION_OPERATIONS } from "./catalog.js";
import { QuirtError } from "./error.js";
import {
  POWER_PROVIDER_DEFINITIONS,
  QUIRT_POWER_OPERATIONS,
  QUIRT_POWER_OPERATION_MATRIX,
  type QuirtPowerOperation
} from "./power-catalog.js";
import {
  NodePowerRuntime,
  QuirtPowerProviderRegistry,
  QuirtPowerProviderService,
  safeProviderConfiguration,
  type PowerCommandResult,
  type PowerExecutableProbe,
  type PowerRunInput,
  type QuirtPowerProviderAdapter,
  type QuirtPowerProviderContext,
  type QuirtPowerRuntime
} from "./power-provider.js";
import { QuirtStateStore } from "./state.js";
import { QUIRT_TOOL_NAMES } from "./tools.js";
import { quirtPowerFoundationToolSchemas } from "./power-tools.js";
import {
  absolutePath,
  booleanValue,
  cleanupManagedFailure,
  createInstance,
  credentialReferences,
  integer,
  noBinary,
  objectValue,
  optionalText,
  readJobLogs,
  recoverManaged,
  requiredText,
  requireExecutable,
  runChecked,
  startManagedJob,
  stopManaged,
  stringEnvironment,
  stringList
} from "./providers/provider-helpers.js";
import { quirtTestConfig } from "./test-support.test.js";
import { TmuxPaneProvider } from "./providers/pane-provider.js";
import { PreviewProvider } from "./providers/preview-provider.js";
import { CodeServerProvider } from "./providers/ide-provider.js";
import { PlaywrightBrowserProvider } from "./providers/browser-provider.js";
import { RcloneProvider, ResticProvider, SyncthingProvider } from "./providers/storage-providers.js";
import { LinuxNetworkProvider, LinuxTraceProvider, OpenSshTunnelProvider } from "./providers/network-providers.js";
import { CriuCheckpointProvider, SshFleetProvider, VncDesktopProvider } from "./providers/conditional-providers.js";

const OWNER = "a".repeat(64);
const TARGET = "vps-test-01";
const FIELD = "\u001f";

class DeterministicRuntime implements QuirtPowerRuntime {
  readonly calls: PowerRunInput[] = [];
  available = true;
  versionSupported = true;
  failNext = false;
  failProcessIdentity = false;

  async probeExecutable(path: string, _versionArguments: readonly string[], minimumVersion?: string): Promise<PowerExecutableProbe> {
    return { path, available: this.available, version: this.available ? "tmux 3.4" : null, minimumVersion: minimumVersion ?? null, versionSupported: this.available ? this.versionSupported : null, executableIdentity: this.available ? { device: 1, inode: 2 } : null, reason: this.available ? null : "executable is absent" };
  }

  async run(input: PowerRunInput): Promise<PowerCommandResult> {
    this.calls.push(input);
    if (this.failNext) {
      this.failNext = false;
      return { exitCode: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from("can't find pane"), truncated: false };
    }
    const operation = input.arguments?.[2];
    let stdout = "";
    if (operation === "new-window") stdout = "@2" + FIELD + "%3\n";
    if (operation === "split-window") stdout = "@1" + FIELD + "%4\n";
    if (operation === "list-windows") stdout = "@1" + FIELD + "0" + FIELD + "main" + FIELD + "120" + FIELD + "40" + FIELD + "1" + FIELD + "2\n";
    if (operation === "list-panes") stdout = "%1" + FIELD + "@1" + FIELD + "0" + FIELD + "60" + FIELD + "40" + FIELD + "1" + FIELD + "0" + FIELD + "4242" + FIELD + "bash" + FIELD + "/workspace" + FIELD + "4" + FIELD + "7\n";
    return { exitCode: 0, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0), truncated: false };
  }

  async processIdentity(pid: number): Promise<Readonly<Record<string, unknown>>> {
    if (this.failProcessIdentity) throw new QuirtError("process_exited", "fixture identity vanished");
    return { pid, startTimeTicks: 99, bootId: "boot-test", executablePath: "/bin/bash", executableDevice: 1, executableInode: 2 };
  }
}

function fakeSessionManager(owner = OWNER): unknown {
  return {
    get(sessionId: string, principal: string) {
      if (principal !== owner) throw new QuirtError("authorization_failed", "wrong principal");
      return { sessionId, tmuxName: "quirt-" + "1".repeat(32), mode: "tmux" };
    }
  };
}

function fakeTmux(): unknown {
  return { socketPath: "/tmp/quirt-test-tmux.sock", hasSession: async () => true };
}

function fakeJobs(): {
  value: unknown;
  execCount(): number;
  canceled(): string[];
} {
  let count = 0;
  const canceled: string[] = [];
  const record = {
    jobId: "job-preview-1",
    requestId: "request-preview",
    status: "running",
    ownerPrincipalFingerprint: OWNER,
    command: {},
    workingDirectory: "/workspace",
    environment: {},
    stdinSupported: false,
    processId: 4242,
    stdoutStreamId: "stdout-preview",
    stderrStreamId: "stderr-preview",
    exitCode: null,
    exitSignal: null,
    timedOut: false,
    createdAt: "2026-07-18T00:00:00.000Z",
    updatedAt: "2026-07-18T00:00:00.000Z",
    startedAt: "2026-07-18T00:00:00.000Z",
    finishedAt: null
  };
  return {
    value: {
      async exec() { count += 1; return { job: record, detached: true, timedOut: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }; },
      get(jobId: string, principal: string) { if (jobId !== record.jobId || principal !== OWNER) throw new QuirtError("not_found", "job missing"); return record; },
      read(_jobId: string, _principal: string, _stream: string, after: number) { const bytes = Buffer.from("preview-log"); return { streamId: "stdout-preview", startOffset: after, endOffset: after + bytes.length, nextOffset: after + bytes.length, retainedStartOffset: 0, bytes, eof: false }; },
      cancel(jobId: string) { canceled.push(jobId); return { ...record, status: "canceled" }; }
    },
    execCount: () => count,
    canceled: () => canceled
  };
}

async function fixture(): Promise<{
  root: string;
  state: QuirtStateStore;
  config: ReturnType<typeof quirtTestConfig>;
  runtime: DeterministicRuntime;
  jobs: ReturnType<typeof fakeJobs>;
  context: QuirtPowerProviderContext;
  cleanup(): Promise<void>;
}> {
  const root = await mkdtemp(join(tmpdir(), "quirt-power-"));
  const config = quirtTestConfig(root);
  const state = new QuirtStateStore(config.databasePath);
  const runtime = new DeterministicRuntime();
  const jobs = fakeJobs();
  const registry = new QuirtPowerProviderRegistry(state, runtime);
  registry.register(new TmuxPaneProvider());
  registry.register(new PreviewProvider());
  const context = {
    config,
    state,
    sessions: fakeSessionManager(),
    jobs: jobs.value,
    tmux: fakeTmux(),
    processes: {},
    runtime,
    ownerPrincipalFingerprint: OWNER,
    targetHost: TARGET,
    requestId: "request-test"
  } as unknown as QuirtPowerProviderContext;
  return { root, state, config, runtime, jobs, context, cleanup: async () => { state.close(); await rm(root, { recursive: true, force: true }); } };
}

async function listeningServer(): Promise<{ server: Server; port: number; close(): Promise<void> }> {
  const server = createServer((socket) => { socket.on("error", () => undefined); socket.end("ok"); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");
  return { server, port: address.port, close: async () => await new Promise<void>((resolve) => server.close(() => resolve())) };
}

test("QES-1 power operation matrix is exact, unique, and fully described", () => {
  assert.equal(QUIRT_POWER_OPERATIONS.length, 86);
  assert.equal(new Set(QUIRT_POWER_OPERATIONS).size, 86);
  assert.equal(QUIRT_POWER_OPERATION_MATRIX.length, 86);
  assert.equal(POWER_PROVIDER_DEFINITIONS.length, 13);
  for (const entry of QUIRT_POWER_OPERATION_MATRIX) {
    assert.match(entry.operationId, /^quirt\./u);
    assert.equal(entry.idempotency, "semantic_required");
    assert.notEqual(entry.inputSchema.length, 0);
    assert.notEqual(entry.outputSchema.length, 0);
    assert.notEqual(entry.securityConstraints.length, 0);
    assert.notEqual(entry.deterministicTest.length, 0);
  }
});

test("complete Checkpoint D catalog registers all and only the 86 frozen operations", () => {
  assert.equal(QUIRT_POWER_FOUNDATION_OPERATIONS.length, 86);
  assert.equal(QUIRT_OPERATIONS.length, 148);
  assert.equal(QUIRT_TOOL_NAMES.length, 148);
  assert.deepEqual([...QUIRT_TOOL_NAMES].sort(), [...QUIRT_OPERATIONS].sort());
  assert.deepEqual([...QUIRT_POWER_FOUNDATION_OPERATIONS].sort(), [...QUIRT_POWER_OPERATIONS].sort());
});

test("schema 20 initializes definitions, durable instances, events, replay, rollback, and reopen", async () => {
  const value = await fixture();
  const { state, config } = value;
  try {
    assert.equal(state.schemaVersion(), 20);
    assert.equal(state.power.definitions().length, 13);
    const instance = state.power.putInstance({ providerId: "preview.process", providerVersion: "1", ownerPrincipalFingerprint: OWNER, targetHost: TARGET, state: "creating", credentialReferences: ["credential://preview/auth"], configuration: { bindAddress: "127.0.0.1" } });
    state.power.appendEvent(instance.instanceId, "lifecycle.creating", { progress: 1 });
    state.power.appendEvent(instance.instanceId, "lifecycle.ready", { progress: 2 });
    const page = state.power.readEvents(instance.instanceId, OWNER, TARGET, -1, 1);
    assert.equal(page.events.length, 1);
    assert.equal(page.truncated, true);
    assert.equal(page.nextSequence, 0);
    const reservation = state.power.reserveRequest({ ownerPrincipalFingerprint: OWNER, operation: "quirt.preview.open", idempotencyKey: "same", requestHash: "a".repeat(64), instanceId: instance.instanceId });
    assert.equal(reservation.replay, false);
    state.power.completeRequest({ ownerPrincipalFingerprint: OWNER, operation: "quirt.preview.open", idempotencyKey: "same", instanceId: instance.instanceId, result: { instanceId: instance.instanceId } });
    assert.deepEqual(state.power.reserveRequest({ ownerPrincipalFingerprint: OWNER, operation: "quirt.preview.open", idempotencyKey: "same", requestHash: "a".repeat(64) }), { replay: true, result: { instanceId: instance.instanceId } });
    assert.throws(() => state.power.reserveRequest({ ownerPrincipalFingerprint: OWNER, operation: "quirt.preview.open", idempotencyKey: "same", requestHash: "b".repeat(64) }), (cause: unknown) => cause instanceof QuirtError && cause.code === "idempotency_conflict");
    const before = state.power.listInstances(OWNER).instances.length;
    assert.throws(() => state.power.transaction(() => {
      state.power.putInstance({ providerId: "preview.process", providerVersion: "1", ownerPrincipalFingerprint: OWNER, targetHost: TARGET, state: "creating" });
      throw new Error("rollback-witness");
    }), /rollback-witness/u);
    assert.equal(state.power.listInstances(OWNER).instances.length, before);
    state.power.foreignKeyCheck();
    state.close();
    const reopened = new QuirtStateStore(config.databasePath);
    assert.equal(reopened.schemaVersion(), 20);
    assert.equal(reopened.power.getInstance(instance.instanceId, OWNER, TARGET).credentialReferences[0], "credential://preview/auth");
    reopened.close();
    await rm(value.root, { recursive: true, force: true });
  } catch (cause) {
    try { state.close(); } catch { /* already closed */ }
    await rm(value.root, { recursive: true, force: true });
    throw cause;
  }
});

test("provider registry rejects duplicates and distinguishes source from host availability", async () => {
  const value = await fixture();
  try {
    const registry = new QuirtPowerProviderRegistry(value.state, value.runtime);
    registry.register(new TmuxPaneProvider());
    assert.throws(() => registry.register(new TmuxPaneProvider()), (cause: unknown) => cause instanceof QuirtError && cause.code === "configuration_error");
    const available = await registry.probe(POWER_PROVIDER_DEFINITIONS.find((item) => item.providerId === "terminal.tmux")!);
    assert.equal(available.sourceImplemented, true);
    assert.equal(available.hostAvailable, true);
    value.runtime.available = false;
    const absent = await registry.probe(POWER_PROVIDER_DEFINITIONS.find((item) => item.providerId === "terminal.tmux")!);
    assert.equal(absent.sourceImplemented, true);
    assert.equal(absent.hostAvailable, false);
    assert.equal(absent.classification, "executable_absent");
    registry.register(new PlaywrightBrowserProvider());
    const optional = await registry.probe(POWER_PROVIDER_DEFINITIONS.find((item) => item.providerId === "browser.playwright")!);
    assert.equal(optional.sourceImplemented, true);
    assert.equal(optional.classification, "degraded");
    assert.equal(optional.hostAvailable, false);
    assert.match(optional.reason, /optional provider capabilities/u);
  } finally { await value.cleanup(); }
});

test("managed job launch persists identity before probing and cleans up a lost process identity", async () => {
  const value = await fixture();
  try {
    const record = createInstance(value.context, { providerId: "preview.process", state: "starting" });
    value.runtime.failProcessIdentity = true;
    await assert.rejects(startManagedJob(value.context, record, { executable: "/usr/bin/node", arguments: ["fixture.js"] }), (cause: unknown) => cause instanceof QuirtError && cause.code === "process_exited");
    assert.deepEqual(value.jobs.canceled(), ["job-preview-1"]);
    const failed = value.state.power.getInstance(record.instanceId, OWNER, TARGET);
    assert.equal(failed.state, "failed");
    assert.equal(failed.cleanupStatus, "complete");
    assert.deepEqual(failed.relatedJobs, ["job-preview-1"]);
  } finally { await value.cleanup(); }
});

test("shared provider validation rejects unsafe values and normalizes bounded runtime failures", async () => {
  const invalid = (action: () => unknown): void => {
    assert.throws(action, (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request");
  };

  noBinary(Buffer.alloc(0), "Fixture");
  invalid(() => noBinary(Buffer.from([1]), "Fixture"));
  assert.equal(requiredText("value", "Fixture"), "value");
  for (const value of [undefined, "", "bad\0value", "12345"]) invalid(() => requiredText(value, "Fixture", 4));
  assert.equal(optionalText(undefined, "Fixture"), undefined);
  assert.equal(optionalText("value", "Fixture"), "value");
  assert.equal(integer(undefined, "Fixture", 7, 1, 10), 7);
  assert.equal(integer(5, "Fixture", 7, 1, 10), 5);
  for (const value of ["5", 1.5, Number.MAX_SAFE_INTEGER + 1, 0, 11]) invalid(() => integer(value, "Fixture", 7, 1, 10));
  assert.equal(booleanValue(undefined, "Fixture", true), true);
  assert.equal(booleanValue(false, "Fixture"), false);
  invalid(() => booleanValue("false", "Fixture"));
  assert.deepEqual(stringList(undefined, "Fixture"), []);
  assert.deepEqual(stringList(["a", "b"], "Fixture"), ["a", "b"]);
  for (const value of ["not-an-array", ["a", "b"], [1], ["bad\0value"], ["12345"]]) {
    invalid(() => stringList(value, "Fixture", value === "not-an-array" ? 4 : value.length === 2 ? 1 : 4, 4));
  }
  assert.deepEqual(objectValue({ value: 1 }, "Fixture"), { value: 1 });
  for (const value of [null, [], "object"]) invalid(() => objectValue(value, "Fixture"));
  assert.equal(absolutePath("/tmp/../tmp/fixture", "Fixture"), "/tmp/fixture");
  invalid(() => absolutePath("relative/path", "Fixture"));

  assert.deepEqual(credentialReferences(undefined), {});
  assert.deepEqual(credentialReferences({ authentication: "credential://fixture" }), { authentication: "credential://fixture" });
  invalid(() => credentialReferences(Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`key${index}`, "credential://fixture"]))));
  for (const references of [
    { "1invalid": "credential://fixture" },
    { authentication: 1 },
    { authentication: "" },
    { authentication: "bad\0reference" },
    { authentication: "x".repeat(4097) }
  ]) invalid(() => credentialReferences(references));

  assert.deepEqual(stringEnvironment(undefined, "Environment"), {});
  assert.deepEqual(stringEnvironment({ SAFE_VALUE: "fixture" }, "Environment"), { SAFE_VALUE: "fixture" });
  invalid(() => stringEnvironment(Object.fromEntries(Array.from({ length: 513 }, (_, index) => [`KEY_${index}`, "fixture"])), "Environment"));
  for (const environment of [
    { "1INVALID": "fixture" },
    { API_TOKEN: "reference-is-still-not-allowed-here" },
    { SAFE_VALUE: 1 },
    { SAFE_VALUE: "bad\0value" },
    { SAFE_VALUE: "x".repeat(65_537) }
  ]) invalid(() => stringEnvironment(environment, "Environment"));

  const value = await fixture();
  const runtimeWith = (run: QuirtPowerRuntime["run"]): QuirtPowerProviderContext => ({
    ...value.context,
    runtime: {
      probeExecutable: value.runtime.probeExecutable.bind(value.runtime),
      run,
      processIdentity: value.runtime.processIdentity.bind(value.runtime)
    }
  });
  try {
    await requireExecutable(value.context, "/usr/bin/fixture");
    value.runtime.available = false;
    await assert.rejects(requireExecutable(value.context, "/usr/bin/fixture"), (cause: unknown) => cause instanceof QuirtError && cause.code === "executable_missing");
    value.runtime.available = true;
    value.runtime.versionSupported = false;
    await assert.rejects(requireExecutable(value.context, "/usr/bin/fixture"), (cause: unknown) => cause instanceof QuirtError && cause.code === "executable_version_unsupported");
    value.runtime.versionSupported = true;

    const successful = await runChecked(value.context, { executable: "/usr/bin/fixture" });
    assert.equal(successful.stdout.length, 0);
    await assert.rejects(runChecked(runtimeWith(async () => ({ exitCode: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), truncated: true })), { executable: "/usr/bin/fixture" }), (cause: unknown) => cause instanceof QuirtError && cause.code === "output_truncated");
    await assert.rejects(runChecked(runtimeWith(async () => ({ exitCode: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), truncated: false })), { executable: "/usr/bin/fixture" }), (cause: unknown) => cause instanceof QuirtError && cause.code === "provider_degraded" && cause.message === "Provider command failed");
    await assert.rejects(runChecked(runtimeWith(async () => ({ exitCode: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from("fixture failure\n"), truncated: false })), { executable: "/usr/bin/fixture" }), (cause: unknown) => cause instanceof QuirtError && cause.code === "provider_degraded" && /fixture failure/u.test(cause.message));
    for (const [code, expected] of [["ENOENT", "executable_missing"], ["EACCES", "authorization_failed"], ["EPERM", "authorization_failed"]] as const) {
      await assert.rejects(runChecked(runtimeWith(async () => { throw Object.assign(new Error(code), { code }); }), { executable: "/usr/bin/fixture" }), (cause: unknown) => cause instanceof QuirtError && cause.code === expected);
    }
    const preserved = new QuirtError("canceled", "fixture cancellation");
    await assert.rejects(runChecked(runtimeWith(async () => { throw preserved; }), { executable: "/usr/bin/fixture" }), (cause: unknown) => cause === preserved);
    const unknown = new Error("fixture unknown runtime failure");
    await assert.rejects(runChecked(runtimeWith(async () => { throw unknown; }), { executable: "/usr/bin/fixture" }), (cause: unknown) => cause === unknown);
  } finally { await value.cleanup(); }
});

test("shared provider jobs preserve ownership, idempotent cleanup, and recovery classifications", async () => {
  const value = await fixture();
  try {
    const empty = createInstance(value.context, { providerId: "preview.process", state: "starting" });
    const emptyLogs = readJobLogs(value.context, empty, {}, "Preview");
    assert.equal(emptyLogs.payload.jobId, null);
    assert.equal(emptyLogs.binary?.length, 0);

    const managed = createInstance(value.context, { providerId: "preview.process", state: "ready", relatedJobs: ["job-preview-1"], ports: [{ port: 4400, state: "bound" }] });
    const stdout = readJobLogs(value.context, managed, { maximumBytes: 4096 }, "Preview");
    assert.equal(stdout.payload.stream, "stdout");
    assert.equal(stdout.binary?.toString("utf8"), "preview-log");
    const stderr = readJobLogs(value.context, managed, { stream: "stderr", after: 1, maximumBytes: 8 }, "Preview");
    assert.equal(stderr.payload.stream, "stderr");
    assert.throws(() => readJobLogs(value.context, managed, { jobId: "other-job" }, "Preview"), (cause: unknown) => cause instanceof QuirtError && cause.code === "instance_conflict");
    assert.throws(() => readJobLogs(value.context, managed, { stream: "invalid" }, "Preview"), (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request");

    const stopped = stopManaged(value.context, managed);
    assert.equal(stopped.state, "stopped");
    assert.equal(stopped.ports[0]?.state, "released");
    assert.equal(stopManaged(value.context, stopped, true).cleanupStatus, "complete");

    const recoveryContext = {
      config: value.config,
      state: value.state,
      sessions: value.context.sessions,
      jobs: value.context.jobs,
      tmux: value.context.tmux,
      processes: value.context.processes,
      runtime: value.runtime,
      targetHost: TARGET
    };
    const adopted = createInstance(value.context, { providerId: "preview.process", state: "starting" });
    await recoverManaged(adopted, recoveryContext);
    assert.equal(value.state.power.getInstance(adopted.instanceId, OWNER, TARGET).recoveryClassification, "adopted_durable_identity");
    const lost = createInstance(value.context, { providerId: "preview.process", state: "starting", relatedJobs: ["missing-job"] });
    await recoverManaged(lost, recoveryContext);
    assert.equal(value.state.power.getInstance(lost.instanceId, OWNER, TARGET).recoveryClassification, "managed_process_lost");

    const classified = cleanupManagedFailure(value.context, createInstance(value.context, { providerId: "preview.process", state: "starting" }), new QuirtError("process_exited", "fixture exited"));
    assert.equal(classified.failureClassification, "process_exited");
    const internal = cleanupManagedFailure(value.context, createInstance(value.context, { providerId: "preview.process", state: "starting" }), new Error("fixture internal"));
    assert.equal(internal.failureClassification, "internal_error");
  } finally { await value.cleanup(); }
});

test("tmux pane validation and recovery cover every bounded topology decision", async () => {
  const value = await fixture();
  try {
    const provider = new TmuxPaneProvider();
    const rejected = async (
      operation: QuirtPowerOperation,
      payload: Readonly<Record<string, unknown>>,
      binary = Buffer.alloc(0),
      code = "invalid_request",
      context = value.context
    ): Promise<void> => {
      await assert.rejects(
        provider.execute(operation, payload, binary, context),
        (cause: unknown) => cause instanceof QuirtError && cause.code === code
      );
    };

    for (const sessionId of [undefined, "", "bad\0session", "x".repeat(129)]) {
      await rejected("quirt.pane.list", { sessionId });
    }
    const nonTmux = {
      ...value.context,
      sessions: { get: () => ({ sessionId: "session-1", tmuxName: null, mode: "shell" }) }
    } as unknown as QuirtPowerProviderContext;
    await rejected("quirt.pane.list", { sessionId: "session-1" }, Buffer.alloc(0), "instance_conflict", nonTmux);
    await rejected("quirt.pane.list", { sessionId: "session-1" }, Buffer.from([1]));
    await rejected("quirt.preview.list" as QuirtPowerOperation, { sessionId: "session-1" }, Buffer.alloc(0), "unknown_operation");

    for (const paneId of [undefined, "%bad", "x".repeat(33)]) {
      await rejected("quirt.pane.focus", { sessionId: "session-1", paneId });
    }
    await rejected("quirt.pane.split", { sessionId: "session-1", paneId: "%1", direction: "diagonal" });
    for (const size of ["10", 1.5, 0, 10_001]) {
      await rejected("quirt.pane.split", { sessionId: "session-1", paneId: "%1", size });
    }
    for (const argumentsValue of ["argument", Array.from({ length: 1025 }, () => "x"), [1], ["bad\0argument"], ["x".repeat(65_537)]]) {
      await rejected("quirt.pane.open", { sessionId: "session-1", executable: "/bin/true", arguments: argumentsValue });
    }
    await rejected("quirt.pane.resize", { sessionId: "session-1", paneId: "%1" });
    await rejected("quirt.pane.resize", { sessionId: "session-1", paneId: "%1", width: -1 });
    await rejected("quirt.pane.move", { sessionId: "session-1", sourcePaneId: "%1", destinationPaneId: "%2", action: "copy" });
    await rejected("quirt.pane.broadcast", { sessionId: "session-1", enabled: "yes" });
    await rejected("quirt.pane.broadcast", { sessionId: "session-1", windowId: "@bad" });
    await rejected("quirt.pane.broadcast", { sessionId: "session-1" }, Buffer.alloc(1024 * 1024 + 1), "output_truncated");
    await rejected("quirt.pane.close", { sessionId: "session-1" });
    await rejected("quirt.pane.close", { sessionId: "session-1", paneId: "%1", windowId: "@1" });

    await provider.execute("quirt.pane.open", { sessionId: "session-1", executable: "/bin/true", arguments: ["--fixture"], correlation: "coverage", jobId: "job-preview-1" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.split", { sessionId: "session-1", paneId: "%1", direction: "horizontal", size: 10 }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.resize", { sessionId: "session-1", paneId: "%1", width: 80 }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.resize", { sessionId: "session-1", paneId: "%1", height: 24 }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.move", { sessionId: "session-1", sourcePaneId: "%1", destinationPaneId: "%2", action: "move" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.broadcast", { sessionId: "session-1", windowId: "@1", enabled: false, text: "fixture" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.close", { sessionId: "session-1", windowId: "@1" }, Buffer.alloc(0), value.context);
    value.runtime.failProcessIdentity = true;
    const topology = await provider.execute("quirt.pane.list", { sessionId: "session-1" }, Buffer.alloc(0), value.context);
    assert.equal(((topology.payload.topology as { panes: Array<{ foregroundProcessIdentity: unknown }> }).panes[0]?.foregroundProcessIdentity), null);
    value.runtime.failProcessIdentity = false;

    const runtimeContext = (run: QuirtPowerRuntime["run"]): QuirtPowerProviderContext => ({
      ...value.context,
      runtime: {
        probeExecutable: value.runtime.probeExecutable.bind(value.runtime),
        run,
        processIdentity: value.runtime.processIdentity.bind(value.runtime)
      }
    });
    await rejected(
      "quirt.pane.focus",
      { sessionId: "session-1", paneId: "%1" },
      Buffer.alloc(0),
      "provider_degraded",
      runtimeContext(async () => ({ exitCode: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from("fixture failure"), truncated: false }))
    );
    await rejected(
      "quirt.pane.open",
      { sessionId: "session-1" },
      Buffer.alloc(0),
      "stale_instance",
      runtimeContext(async () => ({ exitCode: 0, signal: null, stdout: Buffer.from("invalid identities"), stderr: Buffer.alloc(0), truncated: false }))
    );

    const recoveryContext = {
      config: value.config, state: value.state, sessions: value.context.sessions, jobs: value.context.jobs,
      tmux: value.context.tmux, processes: value.context.processes, runtime: value.runtime, targetHost: TARGET
    };
    const incomplete = createInstance(value.context, { providerId: "terminal.tmux", state: "starting" });
    await assert.rejects(provider.recover(incomplete, recoveryContext), (cause: unknown) => cause instanceof QuirtError && cause.code === "provider_lost");
    const adopted = createInstance(value.context, { providerId: "terminal.tmux", state: "starting", configuration: { tmuxName: "quirt-fixture" }, relatedSessions: ["session-1"] });
    await provider.recover(adopted, recoveryContext);
    assert.equal(value.state.power.getInstance(adopted.instanceId, OWNER, TARGET).recoveryClassification, "adopted");
    const lost = createInstance(value.context, { providerId: "terminal.tmux", state: "starting", configuration: { tmuxName: "quirt-fixture" }, relatedSessions: ["session-1"] });
    await provider.recover(lost, { ...recoveryContext, tmux: { ...value.context.tmux, hasSession: async () => false } as unknown as typeof recoveryContext.tmux });
    assert.equal(value.state.power.getInstance(lost.instanceId, OWNER, TARGET).recoveryClassification, "tmux_session_absent");
  } finally { await value.cleanup(); }
});

test("tmux pane provider executes all eight frozen operations through the private socket", async () => {
  const value = await fixture();
  try {
    const provider = new TmuxPaneProvider();
    const opened = await provider.execute("quirt.pane.open", { sessionId: "session-1", name: "work" }, Buffer.alloc(0), value.context);
    assert.equal(typeof opened.instanceId, "string");
    const listed = await provider.execute("quirt.pane.list", { sessionId: "session-1" }, Buffer.alloc(0), value.context);
    assert.equal(((listed.payload.topology as { panes: unknown[] }).panes).length, 1);
    await provider.execute("quirt.pane.split", { sessionId: "session-1", paneId: "%1", direction: "vertical" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.focus", { sessionId: "session-1", paneId: "%1" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.resize", { sessionId: "session-1", paneId: "%1", width: 80, height: 24 }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.move", { sessionId: "session-1", sourcePaneId: "%1", destinationPaneId: "%2", action: "swap" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.pane.broadcast", { sessionId: "session-1", paneId: "%1" }, Buffer.from([0, 1, 2, 255]), value.context);
    await provider.execute("quirt.pane.close", { sessionId: "session-1", paneId: "%1", instanceId: opened.instanceId }, Buffer.alloc(0), value.context);
    assert.ok(value.runtime.calls.every((call) => call.arguments?.[0] === "-S" && call.arguments?.[1] === "/tmp/quirt-test-tmux.sock"));
    assert.ok(value.runtime.calls.some((call) => call.arguments?.includes("load-buffer")));
    assert.equal(value.state.power.getInstance(opened.instanceId!, OWNER, TARGET).state, "stopped");
  } finally { await value.cleanup(); }
});

test("tmux pane provider detects stale identities and wrong principals", async () => {
  const value = await fixture();
  try {
    const provider = new TmuxPaneProvider();
    value.runtime.failNext = true;
    await assert.rejects(provider.execute("quirt.pane.focus", { sessionId: "session-1", paneId: "%999" }, Buffer.alloc(0), value.context), (cause: unknown) => cause instanceof QuirtError && cause.code === "stale_instance");
    const wrong = { ...value.context, ownerPrincipalFingerprint: "b".repeat(64) };
    await assert.rejects(provider.execute("quirt.pane.list", { sessionId: "session-1" }, Buffer.alloc(0), wrong), (cause: unknown) => cause instanceof QuirtError && cause.code === "authorization_failed");
  } finally { await value.cleanup(); }
});

test("preview provider registers an existing loopback service and recovers it", async () => {
  const service = await listeningServer();
  const value = await fixture();
  try {
    const provider = new PreviewProvider();
    const opened = await provider.execute("quirt.preview.open", { kind: "existing", bindAddress: "127.0.0.1", port: service.port, readiness: "tcp" }, Buffer.alloc(0), value.context);
    const id = opened.instanceId!;
    assert.equal(value.state.power.getInstance(id, OWNER, TARGET).state, "ready");
    await provider.recover!(value.state.power.getInstance(id), { config: value.config, state: value.state, sessions: value.context.sessions, jobs: value.context.jobs, tmux: value.context.tmux, processes: value.context.processes, runtime: value.runtime, targetHost: TARGET });
    assert.equal(value.state.power.getInstance(id, OWNER, TARGET).recoveryClassification, "adopted_existing_listener");
    const closed = await provider.execute("quirt.preview.close", { instanceId: id }, Buffer.alloc(0), value.context);
    assert.equal((closed.payload.preview as { state: string }).state, "stopped");
  } finally { await value.cleanup(); await service.close(); }
});

test("preview provider starts a managed job, reads bounded logs, and cleans up", async () => {
  const value = await fixture();
  try {
    const provider = new PreviewProvider();
    const opened = await provider.execute("quirt.preview.open", { kind: "managed", executable: "/usr/bin/node", arguments: ["fixture.js"], readiness: "none", bindAddress: "127.0.0.1" }, Buffer.alloc(0), value.context);
    assert.equal(value.jobs.execCount(), 1);
    const logs = await provider.execute("quirt.preview.logs", { instanceId: opened.instanceId, maximumBytes: 4096 }, Buffer.alloc(0), value.context);
    assert.equal(logs.binary?.toString("utf8"), "preview-log");
    await provider.execute("quirt.preview.close", { instanceId: opened.instanceId }, Buffer.alloc(0), value.context);
    assert.deepEqual(value.jobs.canceled(), ["job-preview-1"]);
  } finally { await value.cleanup(); }
});

test("preview provider rejects wildcard listeners and classifies port conflicts", async () => {
  const service = await listeningServer();
  const value = await fixture();
  try {
    const provider = new PreviewProvider();
    await assert.rejects(provider.execute("quirt.preview.open", { kind: "existing", bindAddress: "0.0.0.0", port: service.port, readiness: "tcp" }, Buffer.alloc(0), value.context), (cause: unknown) => cause instanceof QuirtError && cause.code === "unsafe_listener");
    await assert.rejects(provider.execute("quirt.preview.open", { kind: "managed", executable: "/bin/true", bindAddress: "127.0.0.1", port: service.port, readiness: "none" }, Buffer.alloc(0), value.context), (cause: unknown) => cause instanceof QuirtError && cause.code === "port_unavailable");
  } finally { await value.cleanup(); await service.close(); }
});

test("power service replays a lost response without a duplicate preview side effect", async () => {
  const value = await fixture();
  try {
    const registry = new QuirtPowerProviderRegistry(value.state, value.runtime);
    registry.register(new PreviewProvider());
    const power = new QuirtPowerProviderService(value.config, value.state, value.context.sessions, value.context.jobs, value.context.tmux, value.context.processes, registry);
    const input = { operation: "quirt.preview.open" as const, payload: { kind: "managed", executable: "/bin/true", readiness: "none", bindAddress: "127.0.0.1" }, binary: Buffer.alloc(0), requestId: "idempotent-preview", ownerPrincipalFingerprint: OWNER, targetHost: TARGET };
    const first = await power.execute(input);
    const replay = await power.execute(input);
    assert.equal(value.jobs.execCount(), 1);
    assert.deepEqual(replay.payload, first.payload);
    await assert.rejects(power.execute({ ...input, payload: { ...input.payload, readiness: "tcp" } }), (cause: unknown) => cause instanceof QuirtError && cause.code === "idempotency_conflict");
    await assert.rejects(power.execute({ ...input, requestId: "wrong-host", targetHost: "other-host" }), (cause: unknown) => cause instanceof QuirtError && cause.code === "wrong_target_host");
  } finally { await value.cleanup(); }
});

test("Node runtime validates executable identity and bounded output without shell interpretation", async () => {
  const runtime = new NodePowerRuntime();
  const probe = await runtime.probeExecutable(process.execPath, ["--version"]);
  assert.equal(probe.available, true);
  assert.equal(typeof probe.executableIdentity?.inode, "number");
  const result = await runtime.run({ executable: "/bin/sh", arguments: ["-c", "printf 123456789"], maximumOutputBytes: 4 });
  assert.equal(result.stdout.toString("utf8"), "1234");
  assert.equal(result.truncated, true);
});

test("Node runtime classifies versions, rejects unsafe bounds, verifies strong identity, and cancels", async () => {
  const runtime = new NodePowerRuntime();
  const missing = await runtime.probeExecutable("/definitely/missing/quirt-provider", ["--version"]);
  assert.equal(missing.available, false);
  assert.equal(missing.versionSupported, null);
  const silent = await runtime.probeExecutable("/bin/false", []);
  assert.equal(silent.available, true);
  assert.equal(silent.version, null);
  assert.equal(silent.versionSupported, true);
  assert.match(silent.reason ?? "", /version output is unavailable/u);
  const unsupported = await runtime.probeExecutable(process.execPath, ["--version"], "999.0.0");
  assert.equal(unsupported.available, true);
  assert.equal(unsupported.versionSupported, false);
  assert.match(unsupported.reason ?? "", /below the provider minimum/u);
  assert.throws(() => runtime.run({ executable: "/bin/true", maximumOutputBytes: 0 }), (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request");
  assert.throws(() => runtime.run({ executable: "/bin/true", timeoutMs: 0 }), (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request");
  assert.throws(() => runtime.run({ executable: "/bin/true", arguments: ["unsafe\0argument"] }), (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request");
  await assert.rejects(runtime.processIdentity(1), (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request");
  const identity = await runtime.processIdentity(process.pid);
  assert.equal(identity.pid, process.pid);
  assert.equal(typeof identity.startTimeTicks, "number");
  assert.equal(typeof identity.bootId, "string");
  const controller = new AbortController();
  const canceled = runtime.run({ executable: "/bin/sleep", arguments: ["10"], signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(canceled, (cause: unknown) => cause instanceof QuirtError && cause.code === "canceled");
  assert.deepEqual(safeProviderConfiguration({ workspacePath: "/workspace", password: "secret", apiToken: "secret", privateKey: "secret", bytes: Buffer.from("secret") }), { workspacePath: "/workspace" });
});

test("provider registry classifies source, version, host-feature, and live-probe boundaries truthfully", async () => {
  const value = await fixture();
  const definition = POWER_PROVIDER_DEFINITIONS.find((item) => item.providerId === "terminal.tmux")!;
  try {
    const empty = new QuirtPowerProviderRegistry(value.state, value.runtime);
    const sourceMissing = await empty.probe(definition);
    assert.equal(sourceMissing.classification, "dependency_absent");
    assert.equal(sourceMissing.sourceImplemented, false);
    assert.throws(() => empty.adapter("quirt.pane.open"), (cause: unknown) => cause instanceof QuirtError && cause.code === "provider_unavailable");
    assert.throws(() => empty.register({ providerId: "unknown.provider", operationIds: [], execute: async () => ({ payload: {} }) }), (cause: unknown) => cause instanceof QuirtError && cause.code === "configuration_error");
    assert.throws(() => empty.register({ providerId: "terminal.tmux", operationIds: [], execute: async () => ({ payload: {} }) }), (cause: unknown) => cause instanceof QuirtError && cause.code === "configuration_error");

    const registry = new QuirtPowerProviderRegistry(value.state, value.runtime);
    registry.register(new TmuxPaneProvider());
    value.runtime.versionSupported = false;
    const unsupported = await registry.probe(definition);
    assert.equal(unsupported.classification, "executable_version_unsupported");
    value.runtime.versionSupported = true;

    const priorDisplay = process.env.DISPLAY;
    const priorWayland = process.env.WAYLAND_DISPLAY;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    try {
      const hostMissing = await registry.probe({ ...definition, requiredHostFeatures: ["display infrastructure"], requiredKernelFeatures: [] });
      assert.equal(hostMissing.classification, "unsupported_on_current_host");
      const pending = await registry.probe({ ...definition, requiredHostFeatures: ["provider-specific-live-feature"], requiredKernelFeatures: [] });
      assert.equal(pending.classification, "live_validation_pending");
    } finally {
      if (priorDisplay === undefined) delete process.env.DISPLAY; else process.env.DISPLAY = priorDisplay;
      if (priorWayland === undefined) delete process.env.WAYLAND_DISPLAY; else process.env.WAYLAND_DISPLAY = priorWayland;
    }
  } finally { await value.cleanup(); }
});

test("power service preserves binary replay, bounds results, cancellation, and recovery failures", async () => {
  const value = await fixture();
  try {
    let calls = 0;
    const definition = POWER_PROVIDER_DEFINITIONS.find((item) => item.providerId === "preview.process")!;
    const adapter: QuirtPowerProviderAdapter = {
      providerId: definition.providerId,
      operationIds: definition.operationIds,
      async execute(_operation, payload) {
        calls += 1;
        return { payload: { offset: 2 }, binary: payload.oversized === true ? Buffer.alloc(1024 * 1024 + 1) : Buffer.from([0, 255]) };
      },
      async recover() { throw new QuirtError("process_exited", "deterministic recovery failure"); }
    };
    const registry = new QuirtPowerProviderRegistry(value.state, value.runtime);
    registry.register(adapter);
    const service = new QuirtPowerProviderService(value.config, value.state, value.context.sessions, value.context.jobs, value.context.tmux, value.context.processes, registry);
    const input = { operation: "quirt.preview.logs" as const, payload: {}, binary: Buffer.alloc(0), requestId: "binary-replay", ownerPrincipalFingerprint: OWNER, targetHost: TARGET };
    const first = await service.execute(input);
    const replay = await service.execute(input);
    assert.deepEqual(first.binary, Buffer.from([0, 255]));
    assert.deepEqual(replay.binary, first.binary);
    assert.equal(calls, 1);
    await assert.rejects(service.execute({ ...input, payload: { oversized: true }, requestId: "oversized-result" }), (cause: unknown) => cause instanceof QuirtError && cause.code === "output_truncated");
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(service.execute({ ...input, requestId: "pre-canceled", signal: controller.signal }), (cause: unknown) => cause instanceof QuirtError && cause.code === "canceled");

    const missing = value.state.power.putInstance({ providerId: "terminal.tmux", providerVersion: "1", ownerPrincipalFingerprint: OWNER, targetHost: TARGET, state: "starting" });
    const failing = value.state.power.putInstance({ providerId: "preview.process", providerVersion: "1", ownerPrincipalFingerprint: OWNER, targetHost: TARGET, state: "starting" });
    await service.recover();
    assert.equal(value.state.power.getInstance(missing.instanceId, OWNER, TARGET).recoveryClassification, "lost");
    assert.equal(value.state.power.getInstance(failing.instanceId, OWNER, TARGET).failureClassification, "process_exited");
    assert.equal(service.cleanupExpired(), 0);
  } finally { await value.cleanup(); }
});

function allPowerAdapters(): QuirtPowerProviderAdapter[] {
  return [
    new TmuxPaneProvider(), new CodeServerProvider(), new PlaywrightBrowserProvider(async () => { throw new Error("deterministic browser unavailable"); }), new PreviewProvider(),
    new SyncthingProvider(), new RcloneProvider(), new ResticProvider(), new LinuxNetworkProvider(),
    new OpenSshTunnelProvider(), new LinuxTraceProvider(), new CriuCheckpointProvider(),
    new VncDesktopProvider(), new SshFleetProvider()
  ];
}

test("every Checkpoint D provider is registered once and owns every frozen operation", async () => {
  const value = await fixture();
  try {
    const adapters = allPowerAdapters();
    assert.equal(adapters.length, 13);
    assert.equal(adapters.flatMap((adapter) => adapter.operationIds).length, 86);
    assert.deepEqual(adapters.flatMap((adapter) => adapter.operationIds).sort(), [...QUIRT_POWER_OPERATIONS].sort());
    const registry = new QuirtPowerProviderRegistry(value.state, value.runtime);
    for (const adapter of adapters) registry.register(adapter);
    for (const definition of POWER_PROVIDER_DEFINITIONS) {
      const probe = await registry.probe(definition);
      assert.equal(probe.sourceImplemented, true, definition.providerId);
      assert.deepEqual(probe.enabledOperations, definition.operationIds, definition.providerId);
    }
  } finally { await value.cleanup(); }
});

test("every frozen provider operation reaches real adapter logic instead of a placeholder", async () => {
  const value = await fixture();
  try {
    for (const adapter of allPowerAdapters()) {
      for (const operation of adapter.operationIds) {
        try {
          await adapter.execute(operation, {}, Buffer.alloc(0), value.context);
        } catch (cause) {
          assert.ok(cause instanceof QuirtError, operation);
          assert.notEqual(cause.code, "unknown_operation", operation);
          assert.equal(/not implemented/iu.test(cause.message), false, operation);
        }
      }
    }
  } finally { await value.cleanup(); }
});



test("every frozen Checkpoint D Gateway schema accepts a bounded canonical request", () => {
  const pane = { sessionId: "session", paneId: "%1" };
  const instance = { instanceId: "instance" };
  const list = {};
  const examples: Record<QuirtPowerOperation, Record<string, unknown>> = {
    "quirt.pane.open": { sessionId: "session" }, "quirt.pane.list": { sessionId: "session" },
    "quirt.pane.split": pane, "quirt.pane.focus": pane, "quirt.pane.resize": { ...pane, width: 80 },
    "quirt.pane.move": { sessionId: "session", sourcePaneId: "%1", destinationPaneId: "%2" },
    "quirt.pane.broadcast": { ...pane, contentBase64: "AA==" }, "quirt.pane.close": pane,
    "quirt.ide.open": { workspacePath: "/workspace", credentialReferences: { authentication: "/run/credentials/code-server" } },
    "quirt.ide.list": list, "quirt.ide.repository": { ...instance, repositoryPath: "/workspace/repository" }, "quirt.ide.port": instance, "quirt.ide.close": instance,
    "quirt.browser.open": { engine: "chromium", headless: true }, "quirt.browser.list": list,
    "quirt.browser.command": { ...instance, action: "page.new" }, "quirt.browser.screenshot": instance,
    "quirt.browser.video": instance, "quirt.browser.download": { ...instance, downloadId: "download" },
    "quirt.browser.upload": { ...instance, selector: "input[type=file]", path: "/tmp/upload" },
    "quirt.browser.show": instance, "quirt.browser.close": instance,
    "quirt.preview.open": { kind: "managed", executable: "/bin/true" }, "quirt.preview.list": list,
    "quirt.preview.get": instance, "quirt.preview.logs": instance, "quirt.preview.close": instance,
    "quirt.sync.create": { folderPath: "/tmp/sync", deviceIds: ["device"] }, "quirt.sync.list": list,
    "quirt.sync.status": instance, "quirt.sync.pause": instance, "quirt.sync.resume": instance, "quirt.sync.remove": instance,
    "quirt.remote.add": { backend: "local" }, "quirt.remote.list": list,
    "quirt.remote.mount": { ...instance, remotePath: "/tmp/remote", localPath: "/tmp/mount" },
    "quirt.remote.copy": { ...instance, remotePath: "/tmp/remote", localPath: "/tmp/local" },
    "quirt.remote.sync": { ...instance, remotePath: "/tmp/remote", localPath: "/tmp/local" },
    "quirt.remote.serve": { ...instance, remotePath: "/tmp/remote" }, "quirt.remote.unmount": instance,
    "quirt.snapshot.create": { repository: "/tmp/restic", sourcePaths: ["/tmp/source"], credentialReferences: { passwordFile: "/run/credentials/restic" } },
    "quirt.snapshot.list": list, "quirt.snapshot.get": { snapshotId: "snapshot" },
    "quirt.snapshot.diff": { ...instance, leftSnapshotId: "left", rightSnapshotId: "right" },
    "quirt.snapshot.mount": { ...instance, mountPath: "/tmp/mount" },
    "quirt.snapshot.restore": { snapshotId: "snapshot", destination: "/tmp/restore" },
    "quirt.snapshot.unmount": instance, "quirt.snapshot.remove": { snapshotId: "snapshot" },
    "quirt.network.interfaces": list, "quirt.network.routes": list, "quirt.network.connections": list,
    "quirt.network.listeners": list, "quirt.network.firewall": list, "quirt.network.capture": { interface: "lo" },
    "quirt.tunnel.open": { sshHost: "fixture", sshUser: "fixture", localEndpoint: { host: "127.0.0.1", port: 8080 }, remoteEndpoint: { host: "127.0.0.1", port: 80 }, credentialReferences: { identityFile: "/run/credentials/ssh", knownHostsFile: "/run/credentials/known-hosts" } },
    "quirt.tunnel.list": list, "quirt.tunnel.get": instance, "quirt.tunnel.pause": instance,
    "quirt.tunnel.resume": instance, "quirt.tunnel.close": instance,
    "quirt.trace.start": { type: "tcpdump" }, "quirt.trace.list": list, "quirt.trace.follow": instance,
    "quirt.trace.stop": instance, "quirt.trace.report": instance, "quirt.trace.flamegraph": instance,
    "quirt.checkpoint.create": { pid: 1 }, "quirt.checkpoint.list": list, "quirt.checkpoint.get": instance,
    "quirt.checkpoint.restore": instance, "quirt.checkpoint.remove": instance,
    "quirt.desktop.open": { credentialReferences: { passwordFile: "/run/credentials/vnc" } },
    "quirt.desktop.list": list, "quirt.desktop.capture": instance,
    "quirt.desktop.input": { ...instance, action: "key", value: "Return" },
    "quirt.desktop.resize": { ...instance, width: 1280, height: 720 }, "quirt.desktop.close": instance,
    "quirt.host.add": { host: "fixture", user: "fixture", credentialReferences: { identityFile: "/run/credentials/ssh", knownHostsFile: "/run/credentials/known-hosts" } },
    "quirt.host.list": list, "quirt.host.get": instance, "quirt.host.remove": instance,
    "quirt.host.shell": { ...instance, command: ["true"] },
    "quirt.fleet.exec": { instanceIds: ["instance"], command: ["true"] },
    "quirt.fleet.copy": { ...instance, localPath: "/tmp/local", remotePath: "/tmp/remote" },
    "quirt.fleet.playbook": { instanceIds: ["instance"], inventoryPath: "/tmp/inventory", playbookPath: "/tmp/playbook.yml" },
    "quirt.fleet.status": instance
  };
  assert.equal(Object.keys(examples).length, 86);
  assert.deepEqual(Object.keys(examples).sort(), [...QUIRT_POWER_OPERATIONS].sort());
  for (const operation of QUIRT_POWER_OPERATIONS) {
    const parsed = quirtPowerFoundationToolSchemas[operation].safeParse(examples[operation]);
    assert.equal(parsed.success, true, operation + (parsed.success ? "" : ": " + parsed.error.message));
  }
});
