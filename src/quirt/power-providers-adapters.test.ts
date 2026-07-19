import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { QuirtError } from "./error.js";
import {
  type PowerCommandResult,
  type PowerExecutableProbe,
  type PowerRunInput,
  QuirtPowerProviderRegistry,
  type QuirtPowerProviderContext,
  type QuirtPowerRuntime
} from "./power-provider.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";
import { CodeServerProvider } from "./providers/ide-provider.js";
import { PlaywrightBrowserProvider } from "./providers/browser-provider.js";
import { RcloneProvider, ResticProvider, SyncthingProvider } from "./providers/storage-providers.js";
import { LinuxNetworkProvider, LinuxTraceProvider, OpenSshTunnelProvider } from "./providers/network-providers.js";
import { CriuCheckpointProvider, SshFleetProvider, VncDesktopProvider } from "./providers/conditional-providers.js";

const OWNER = "c".repeat(64);
const TARGET = "vps-deterministic-01";

class ScriptedRuntime implements QuirtPowerRuntime {
  readonly calls: PowerRunInput[] = [];
  readonly absent = new Set<string>();
  readonly failureOutput = new Map<string, string>();
  identityGeneration = 1;

  async probeExecutable(path: string, _versionArguments: readonly string[], minimumVersion?: string): Promise<PowerExecutableProbe> {
    const available = !this.absent.has(path);
    return {
      path,
      available,
      version: available ? "fixture 1.0.0" : null,
      minimumVersion: minimumVersion ?? null,
      versionSupported: available,
      executableIdentity: available ? { device: 11, inode: 22 } : null,
      reason: available ? null : "missing executable " + path
    };
  }

  async run(input: PowerRunInput): Promise<PowerCommandResult> {
    this.calls.push(input);
    const args = [...(input.arguments ?? [])];
    const failure = this.failureOutput.get(input.executable);
    if (failure !== undefined) return { exitCode: 1, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from(failure), truncated: false };
    let stdout = Buffer.from("fixture-output\n");
    if (input.executable === "/usr/sbin/ip") stdout = Buffer.from("[]");
    if (input.executable === "/usr/sbin/nft") stdout = Buffer.from('{"nftables":[]}');
    if (input.executable === "/usr/bin/ss") stdout = Buffer.from("tcp LISTEN 0 10 127.0.0.1:1 0.0.0.0:*\n");
    if (input.executable === "/usr/bin/syncthing" && args.includes("system")) stdout = Buffer.from('{"myID":"fixture-device","uptime":10}');
    if (input.executable === "/usr/bin/restic" && args.includes("backup")) stdout = Buffer.from('{"message_type":"summary","snapshot_id":"immutable-snapshot-fixture"}\n');
    if (input.executable === "/usr/bin/perf" && args[0] === "script") stdout = Buffer.from("main;worker\nmain;worker\nmain;idle\n");
    if (input.executable === "/usr/bin/perf" && args[0] === "report") stdout = Buffer.from("fixture perf report\n");
    if (input.executable === "/usr/bin/head") stdout = Buffer.from("fixture trace output\n");
    if (input.executable === "/usr/sbin/criu" && args[0] === "dump") {
      const directory = args[args.indexOf("-D") + 1]!;
      await writeFile(join(directory, "pages.img"), "deterministic-checkpoint", { mode: 0o600 });
    }
    if (input.executable === "/usr/bin/xwd") {
      const outputPath = args[args.indexOf("-out") + 1]!;
      await writeFile(outputPath, "deterministic-xwd", { mode: 0o600 });
    }
    return { exitCode: 0, signal: null, stdout, stderr: Buffer.alloc(0), truncated: false };
  }

  async processIdentity(pid: number): Promise<Readonly<Record<string, unknown>>> {
    return {
      pid,
      startTimeTicks: 1000 + this.identityGeneration,
      bootId: "11111111-1111-4111-8111-111111111111",
      executablePath: "/usr/bin/fixture",
      executableDevice: 11,
      executableInode: 22
    };
  }
}

type ExecHook = (input: Readonly<Record<string, unknown>>) => Promise<void>;

function scriptedJobs(hook?: ExecHook): {
  value: unknown;
  calls: Readonly<Record<string, unknown>>[];
  signals: string[];
  close(): Promise<void>;
} {
  let sequence = 0;
  const calls: Readonly<Record<string, unknown>>[] = [];
  const signals: string[] = [];
  const records = new Map<string, Record<string, unknown>>();
  const servers: Server[] = [];
  const value = {
    async exec(_requestId: string, principal: string, command: Readonly<Record<string, unknown>>) {
      assert.equal(principal, OWNER);
      calls.push(command);
      if (hook !== undefined) await hook(command);
      const jobId = "provider-job-" + (++sequence);
      const record: Record<string, unknown> = {
        jobId,
        requestId: "provider-request-" + sequence,
        status: "running",
        ownerPrincipalFingerprint: OWNER,
        command,
        workingDirectory: command.workingDirectory ?? "/",
        environment: command.environment ?? {},
        stdinSupported: false,
        processId: 5000 + sequence,
        stdoutStreamId: "stdout-" + sequence,
        stderrStreamId: "stderr-" + sequence,
        exitCode: null,
        exitSignal: null,
        timedOut: false,
        createdAt: "2026-07-18T00:00:00.000Z",
        updatedAt: "2026-07-18T00:00:00.000Z",
        startedAt: "2026-07-18T00:00:00.000Z",
        finishedAt: null
      };
      records.set(jobId, record);
      return { job: record, detached: true, timedOut: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    },
    get(jobId: string, principal: string) {
      assert.equal(principal, OWNER);
      const record = records.get(jobId);
      if (record === undefined) throw new QuirtError("not_found", "fixture job missing");
      return record;
    },
    read(jobId: string, principal: string, stream: string, after: number, maximum = 4096) {
      assert.equal(principal, OWNER);
      if (!records.has(jobId)) throw new QuirtError("not_found", "fixture job missing");
      const bytes = Buffer.from(stream === "stderr" ? "" : "deterministic-job-output").subarray(0, maximum);
      return { streamId: stream + "-" + jobId, startOffset: after, endOffset: after + bytes.length, nextOffset: after + bytes.length, retainedStartOffset: 0, bytes, eof: false };
    },
    cancel(jobId: string, principal: string) {
      assert.equal(principal, OWNER);
      const record = records.get(jobId);
      if (record === undefined) throw new QuirtError("not_found", "fixture job missing");
      record.status = "canceled";
      return record;
    },
    signal(jobId: string, principal: string, signal: string) {
      assert.equal(principal, OWNER);
      if (!records.has(jobId)) throw new QuirtError("not_found", "fixture job missing");
      signals.push(signal);
      return records.get(jobId);
    },
    fixtureServer(server: Server) { servers.push(server); }
  };
  return {
    value,
    calls,
    signals,
    close: async () => {
      for (const server of servers) await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
}

async function providerFixture(hook?: ExecHook): Promise<{
  root: string;
  state: QuirtStateStore;
  runtime: ScriptedRuntime;
  jobs: ReturnType<typeof scriptedJobs>;
  context: QuirtPowerProviderContext;
  cleanup(): Promise<void>;
}> {
  const root = await mkdtemp(join(tmpdir(), "quirt-d-adapters-"));
  const config = quirtTestConfig(root);
  const state = new QuirtStateStore(config.databasePath);
  const runtime = new ScriptedRuntime();
  const registry = new QuirtPowerProviderRegistry(state, runtime);
  for (const adapter of [
    new CodeServerProvider(), new PlaywrightBrowserProvider(), new SyncthingProvider(), new RcloneProvider(),
    new ResticProvider(), new LinuxNetworkProvider(), new OpenSshTunnelProvider(), new LinuxTraceProvider(),
    new CriuCheckpointProvider(), new VncDesktopProvider(), new SshFleetProvider()
  ]) registry.register(adapter);
  const jobs = scriptedJobs(hook);
  const context = {
    config,
    state,
    sessions: {},
    jobs: jobs.value,
    tmux: {},
    processes: {},
    runtime,
    ownerPrincipalFingerprint: OWNER,
    targetHost: TARGET,
    requestId: "deterministic-request"
  } as unknown as QuirtPowerProviderContext;
  return {
    root,
    state,
    runtime,
    jobs,
    context,
    cleanup: async () => {
      await jobs.close();
      state.close();
      await rm(root, { recursive: true, force: true });
    }
  };
}

test("code-server adapter executes all five frozen IDE operations with reference-only authentication", async () => {
  let jobsValue: ReturnType<typeof scriptedJobs> | undefined;
  const value = await providerFixture(async (command) => {
    const args = command.arguments as string[];
    const marker = args.indexOf("--bind-addr");
    if (marker < 0) return;
    const address = args[marker + 1]!;
    const separator = address.lastIndexOf(":");
    const host = address.slice(0, separator);
    const port = Number(address.slice(separator + 1));
    const server = createServer((socket) => { socket.on("error", () => undefined); socket.end("ready"); });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, resolve);
    });
    (jobsValue?.value as { fixtureServer(server: Server): void }).fixtureServer(server);
  });
  jobsValue = value.jobs;
  try {
    const provider = new CodeServerProvider();
    const workspacePath = join(value.root, "workspace");
    const repositoryPath = join(value.root, "repository");
    await mkdir(workspacePath);
    await mkdir(repositoryPath);
    const opened = await provider.execute("quirt.ide.open", {
      workspacePath,
      executablePath: "/usr/bin/code-server",
      credentialReferences: { authentication: "/run/credentials/code-server-password" },
      readinessTimeoutMs: 5000
    }, Buffer.alloc(0), value.context);
    const instanceId = opened.instanceId!;
    const listed = await provider.execute("quirt.ide.list", {}, Buffer.alloc(0), value.context);
    assert.equal((listed.payload.instances as unknown[]).length, 1);
    const repository = await provider.execute("quirt.ide.repository", { instanceId, repositoryPath }, Buffer.alloc(0), value.context);
    assert.equal(repository.payload.repositoryPath, repositoryPath);
    const port = await provider.execute("quirt.ide.port", { instanceId }, Buffer.alloc(0), value.context);
    assert.equal(port.payload.listenerVerified, true);
    assert.ok(value.jobs.calls[0] !== undefined);
    const serializedCommand = JSON.stringify(value.jobs.calls[0]);
    assert.match(serializedCommand, /code-server-password/u);
    assert.doesNotMatch(serializedCommand, /plaintext-secret/u);
    const closed = await provider.execute("quirt.ide.close", { instanceId }, Buffer.alloc(0), value.context);
    assert.equal((closed.payload.ide as { state: string }).state, "stopped");
  } finally {
    await value.cleanup();
  }
});

class MockPage {
  currentUrl = "http://fixture.local/";
  closed = false;
  readonly handlers = new Map<string, Array<(...args: unknown[]) => void>>();
  constructor(readonly videoPath: string) {}
  on(event: string, handler: (...args: unknown[]) => void): this {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
    return this;
  }
  once(event: string, handler: (...args: unknown[]) => void): this { return this.on(event, handler); }
  emit(event: string, ...args: unknown[]): void {
    for (const handler of this.handlers.get(event) ?? []) handler(...args);
  }
  url(): string { return this.currentUrl; }
  isClosed(): boolean { return this.closed; }
  locator(_selector: string): {
    waitFor(): Promise<void>;
    click(): Promise<void>;
    fill(): Promise<void>;
    ariaSnapshot(): Promise<string>;
    setInputFiles(): Promise<void>;
  } {
    return {
      waitFor: async () => undefined,
      click: async () => undefined,
      fill: async () => undefined,
      ariaSnapshot: async () => "- document: fixture",
      setInputFiles: async () => undefined
    };
  }
  async goto(url: string): Promise<{ status(): number }> { this.currentUrl = url; return { status: () => 200 }; }
  async waitForTimeout(_milliseconds: number): Promise<void> {}
  readonly keyboard = { press: async (_key: string): Promise<void> => undefined };
  readonly mouse = {
    move: async (_x: number, _y: number): Promise<void> => undefined,
    click: async (_x: number, _y: number): Promise<void> => undefined
  };
  async evaluate(expression: string): Promise<unknown> { return { expression, ok: true }; }
  async content(): Promise<string> { return "<html><body>fixture</body></html>"; }
  async setViewportSize(_viewport: { width: number; height: number }): Promise<void> {}
  async screenshot(options: { path?: string }): Promise<Buffer> {
    const bytes = Buffer.from("fixture-png");
    if (options.path !== undefined) await writeFile(options.path, bytes, { mode: 0o600 });
    return bytes;
  }
  video(): { path(): Promise<string> } { return { path: async () => this.videoPath }; }
  async pdf(options: { path: string }): Promise<Buffer> {
    const bytes = Buffer.from("fixture-pdf");
    await writeFile(options.path, bytes, { mode: 0o600 });
    return bytes;
  }
  async close(): Promise<void> { this.closed = true; this.emit("close"); }
}

class MockBrowserContext {
  readonly handlers = new Map<string, Array<(...args: unknown[]) => void>>();
  constructor(readonly initialPage: MockPage) {}
  pages(): MockPage[] { return [this.initialPage]; }
  on(event: string, handler: (...args: unknown[]) => void): this {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), handler]);
    return this;
  }
  emit(event: string, ...args: unknown[]): void {
    for (const handler of this.handlers.get(event) ?? []) handler(...args);
  }
  async newPage(): Promise<MockPage> {
    const page = new MockPage(this.initialPage.videoPath);
    this.emit("page", page);
    return page;
  }
  async cookies(): Promise<Array<Record<string, unknown>>> { return [{ name: "fixture", value: "redacted-in-audit" }]; }
  async storageState(options: { path: string }): Promise<void> { await writeFile(options.path, "{}", { mode: 0o600 }); }
  async close(): Promise<void> { this.emit("close"); }
}

test("Playwright adapter deterministically executes every browser operation and preserves bounded protected data", async () => {
  const value = await providerFixture();
  try {
    const videoPath = join(value.root, "video.webm");
    const downloadPath = join(value.root, "download.bin");
    await writeFile(videoPath, "video", { mode: 0o600 });
    await writeFile(downloadPath, "download", { mode: 0o600 });
    const page = new MockPage(videoPath);
    const browserContext = new MockBrowserContext(page);
    const provider = new PlaywrightBrowserProvider(async () => ({
      chromium: { launchPersistentContext: async () => browserContext },
      firefox: { launchPersistentContext: async () => browserContext },
      webkit: { launchPersistentContext: async () => browserContext }
    }) as never);
    const opened = await provider.execute("quirt.browser.open", {
      engine: "chromium",
      executablePath: "/usr/bin/chromium",
      headless: true,
      recordVideo: true
    }, Buffer.alloc(0), value.context);
    const instanceId = opened.instanceId!;
    const pageId = (opened.payload.pages as Array<{ pageId: string }>)[0]!.pageId;
    await provider.execute("quirt.browser.list", {}, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "navigate", url: "http://fixture.local/page" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "click", selector: "#button" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "type", selector: "#input", text: "bounded input" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "keyboard", key: "Enter" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "mouse", mouseAction: "click", x: 1, y: 2 }, Buffer.alloc(0), value.context);
    const evaluated = await provider.execute("quirt.browser.command", { instanceId, pageId, action: "evaluate", expression: "1+1", maximumBytes: 1024 }, Buffer.alloc(0), value.context);
    assert.equal((evaluated.payload.result as { truncated: boolean }).truncated, false);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "content" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "accessibility" }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "cookies" }, Buffer.alloc(0), value.context);
    const storagePath = join(value.root, "storage-state.json");
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "storageState", path: storagePath }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "viewport", width: 800, height: 600 }, Buffer.alloc(0), value.context);
    await provider.execute("quirt.browser.command", { instanceId, pageId, action: "pdf", path: join(value.root, "page.pdf") }, Buffer.alloc(0), value.context);
    const screenshot = await provider.execute("quirt.browser.screenshot", { instanceId, pageId }, Buffer.alloc(0), value.context);
    assert.equal(screenshot.binary?.toString("utf8"), "fixture-png");
    const video = await provider.execute("quirt.browser.video", { instanceId, pageId }, Buffer.alloc(0), value.context);
    assert.equal((video.payload as { path: string }).path, videoPath);
    page.emit("console", { type: () => "log", text: () => "fixture console" });
    page.emit("pageerror", new Error("fixture page error"));
    page.emit("request", { url: () => "http://fixture.local/api", method: () => "GET", resourceType: () => "xhr" });
    page.emit("response", { url: () => "http://fixture.local/api", status: () => 200 });
    page.emit("download", { path: async () => downloadPath, suggestedFilename: () => "download.bin" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const events = value.state.power.readEvents(instanceId, OWNER, TARGET, -1, 1000).events;
    const downloadEvent = events.find((event) => typeof (event.payload as Record<string, unknown>).downloadId === "string");
    assert.ok(downloadEvent !== undefined);
    const downloadId = String((downloadEvent.payload as Record<string, unknown>).downloadId);
    const download = await provider.execute("quirt.browser.download", { instanceId, downloadId }, Buffer.alloc(0), value.context);
    assert.equal(download.payload.path, downloadPath);
    const upload = await provider.execute("quirt.browser.upload", { instanceId, pageId, selector: "input[type=file]" }, Buffer.from("upload"), value.context);
    assert.equal(upload.payload.sizeBytes, 6);
    const shown = await provider.execute("quirt.browser.show", { instanceId }, Buffer.alloc(0), value.context);
    assert.equal(shown.payload.available, false);
    const eventRead = await provider.execute("quirt.browser.command", { instanceId, pageId, action: "events", maximumEvents: 1000 }, Buffer.alloc(0), value.context);
    assert.ok(((eventRead.payload.result as { events: unknown[] }).events).length > 0);
    const closed = await provider.execute("quirt.browser.close", { instanceId }, Buffer.alloc(0), value.context);
    assert.equal((closed.payload.browser as { state: string }).state, "stopped");
    const unavailable = new PlaywrightBrowserProvider(async () => { throw new Error("fixture missing dependency"); });
    await assert.rejects(unavailable.execute("quirt.browser.open", {}, Buffer.alloc(0), value.context), (cause: unknown) => cause instanceof QuirtError && cause.code === "provider_unavailable");
  } finally {
    await value.cleanup();
  }
});

test("Syncthing, rclone, and restic adapters execute all 21 frozen storage operations", async () => {
  let jobsValue: ReturnType<typeof scriptedJobs> | undefined;
  const value = await providerFixture(async (command) => {
    const args = command.arguments as string[];
    if (command.executable !== "/usr/bin/rclone" || !args.includes("serve")) return;
    const marker = args.indexOf("--addr");
    const address = args[marker + 1]!;
    const separator = address.lastIndexOf(":");
    const host = address.slice(0, separator);
    const port = Number(address.slice(separator + 1));
    const server = createServer((socket) => { socket.on("error", () => undefined); socket.end("ready"); });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, resolve);
    });
    (jobsValue?.value as { fixtureServer(server: Server): void }).fixtureServer(server);
  });
  jobsValue = value.jobs;
  try {
    const folderPath = join(value.root, "sync-folder");
    const localPath = join(value.root, "local");
    const remotePath = join(value.root, "remote");
    const mountPath = join(value.root, "mount");
    const sourcePath = join(value.root, "snapshot-source");
    await Promise.all([folderPath, localPath, remotePath, mountPath, sourcePath].map((path) => mkdir(path)));

    const sync = new SyncthingProvider();
    const syncOpen = await sync.execute("quirt.sync.create", { folderPath, deviceIds: ["DEVICE-ONE"] }, Buffer.alloc(0), value.context);
    const syncId = syncOpen.instanceId!;
    const syncHome = String(value.state.power.getInstance(syncId, OWNER, TARGET).configuration.home);
    assert.equal((await stat(syncHome)).mode & 0o777, 0o700);
    await sync.execute("quirt.sync.list", {}, Buffer.alloc(0), value.context);
    await sync.execute("quirt.sync.status", { instanceId: syncId }, Buffer.alloc(0), value.context);
    await sync.execute("quirt.sync.pause", { instanceId: syncId }, Buffer.alloc(0), value.context);
    await sync.execute("quirt.sync.resume", { instanceId: syncId }, Buffer.alloc(0), value.context);
    await sync.execute("quirt.sync.remove", { instanceId: syncId }, Buffer.alloc(0), value.context);
    assert.ok(value.runtime.calls.some((call) => call.arguments?.includes("folders") && call.arguments?.includes("add")));

    const remote = new RcloneProvider();
    const remoteOpen = await remote.execute("quirt.remote.add", { backend: "local" }, Buffer.alloc(0), value.context);
    const remoteId = remoteOpen.instanceId!;
    await remote.execute("quirt.remote.list", {}, Buffer.alloc(0), value.context);
    await remote.execute("quirt.remote.copy", { instanceId: remoteId, remotePath, localPath, direction: "upload" }, Buffer.alloc(0), value.context);
    await remote.execute("quirt.remote.sync", { instanceId: remoteId, remotePath, localPath, direction: "download" }, Buffer.alloc(0), value.context);
    await remote.execute("quirt.remote.mount", { instanceId: remoteId, remotePath, localPath: mountPath }, Buffer.alloc(0), value.context);
    const served = await remote.execute("quirt.remote.serve", { instanceId: remoteId, remotePath, bindAddress: "127.0.0.1", port: 0 }, Buffer.alloc(0), value.context);
    assert.deepEqual({ private: (served.payload.route as { private: boolean }).private, listenerVerified: (served.payload.route as { listenerVerified: boolean }).listenerVerified }, { private: true, listenerVerified: true });
    await remote.execute("quirt.remote.unmount", { instanceId: remoteId }, Buffer.alloc(0), value.context);
    assert.ok(value.runtime.calls.filter((call) => call.executable === "/usr/bin/rclone" && (call.arguments?.includes("copy") || call.arguments?.includes("sync"))).every((call) => call.arguments?.includes("--checksum")));

    const snapshot = new ResticProvider();
    const created = await snapshot.execute("quirt.snapshot.create", {
      repository: join(value.root, "restic-repository"),
      sourcePaths: [sourcePath],
      initialize: true,
      credentialReferences: { passwordFile: "/run/credentials/restic-password" }
    }, Buffer.alloc(0), value.context);
    const repositoryId = created.instanceId!;
    const snapshotId = (created.payload.snapshot as { snapshotId: string }).snapshotId;
    await snapshot.execute("quirt.snapshot.list", { instanceId: repositoryId }, Buffer.alloc(0), value.context);
    await snapshot.execute("quirt.snapshot.get", { snapshotId }, Buffer.alloc(0), value.context);
    await snapshot.execute("quirt.snapshot.diff", { instanceId: repositoryId, leftSnapshotId: "left", rightSnapshotId: "right" }, Buffer.alloc(0), value.context);
    await snapshot.execute("quirt.snapshot.mount", { instanceId: repositoryId, mountPath }, Buffer.alloc(0), value.context);
    const restored = await snapshot.execute("quirt.snapshot.restore", { snapshotId, destination: join(value.root, "restore-destination"), preview: true }, Buffer.alloc(0), value.context);
    assert.equal(restored.payload.preview, true);
    await snapshot.execute("quirt.snapshot.unmount", { instanceId: repositoryId }, Buffer.alloc(0), value.context);
    await snapshot.execute("quirt.snapshot.remove", { snapshotId }, Buffer.alloc(0), value.context);
    assert.equal(value.state.power.snapshot(snapshotId, OWNER).manifest.state, "forgotten");
    assert.ok(value.runtime.calls.filter((call) => call.executable === "/usr/bin/restic").every((call) => !Object.values(call.environment ?? {}).includes("plaintext-secret")));
  } finally {
    await value.cleanup();
  }
});

test("network, tunnel, and tracing adapters execute all 18 frozen operations with strict identity and host-key policy", async () => {
  const value = await providerFixture();
  try {
    const network = new LinuxNetworkProvider();
    await network.execute("quirt.network.interfaces", {}, Buffer.alloc(0), value.context);
    await network.execute("quirt.network.routes", {}, Buffer.alloc(0), value.context);
    await network.execute("quirt.network.connections", {}, Buffer.alloc(0), value.context);
    await network.execute("quirt.network.listeners", {}, Buffer.alloc(0), value.context);
    await network.execute("quirt.network.firewall", {}, Buffer.alloc(0), value.context);
    const capture = await network.execute("quirt.network.capture", { interface: "lo", outputPath: join(value.root, "capture.pcap"), packetLimit: 1 }, Buffer.alloc(0), value.context);
    assert.equal((capture.payload.output as { protected: boolean }).protected, true);

    const tunnel = new OpenSshTunnelProvider();
    const opened = await tunnel.execute("quirt.tunnel.open", {
      kind: "local",
      sshHost: "fixture-host",
      sshUser: "fixture-user",
      localEndpoint: { host: "127.0.0.1", port: 42001 },
      remoteEndpoint: { host: "127.0.0.1", port: 8080 },
      credentialReferences: { identityFile: "/run/credentials/ssh-key", knownHostsFile: "/run/credentials/known-hosts" }
    }, Buffer.alloc(0), value.context);
    const tunnelId = opened.instanceId!;
    await tunnel.execute("quirt.tunnel.list", {}, Buffer.alloc(0), value.context);
    await tunnel.execute("quirt.tunnel.get", { instanceId: tunnelId, includeEvents: true }, Buffer.alloc(0), value.context);
    await tunnel.execute("quirt.tunnel.pause", { instanceId: tunnelId }, Buffer.alloc(0), value.context);
    await tunnel.execute("quirt.tunnel.resume", { instanceId: tunnelId }, Buffer.alloc(0), value.context);
    await tunnel.execute("quirt.tunnel.close", { instanceId: tunnelId }, Buffer.alloc(0), value.context);
    assert.deepEqual(value.jobs.signals, ["SIGSTOP", "SIGCONT"]);
    const sshCommand = value.jobs.calls.find((call) => call.executable === "/usr/bin/ssh");
    assert.ok((sshCommand?.arguments as string[]).includes("StrictHostKeyChecking=yes"));
    await assert.rejects(tunnel.execute("quirt.tunnel.open", {
      sshHost: "fixture-host",
      sshUser: "fixture-user",
      localEndpoint: { host: "0.0.0.0", port: 42002 },
      remoteEndpoint: { host: "127.0.0.1", port: 8080 },
      credentialReferences: { identityFile: "/run/credentials/ssh-key", knownHostsFile: "/run/credentials/known-hosts" }
    }, Buffer.alloc(0), value.context), (cause: unknown) => cause instanceof QuirtError && cause.code === "unsafe_listener");

    const trace = new LinuxTraceProvider();
    const traceOpen = await trace.execute("quirt.trace.start", { type: "perf", pid: process.pid, outputPath: join(value.root, "trace.data"), durationSeconds: 1 }, Buffer.alloc(0), value.context);
    const traceId = traceOpen.instanceId!;
    await trace.execute("quirt.trace.list", {}, Buffer.alloc(0), value.context);
    const followed = await trace.execute("quirt.trace.follow", { instanceId: traceId }, Buffer.alloc(0), value.context);
    assert.equal(followed.binary?.toString("utf8"), "deterministic-job-output");
    await trace.execute("quirt.trace.report", { instanceId: traceId }, Buffer.alloc(0), value.context);
    const flame = await trace.execute("quirt.trace.flamegraph", { instanceId: traceId }, Buffer.alloc(0), value.context);
    assert.match(flame.binary?.toString("utf8") ?? "", /^<svg/u);
    await trace.execute("quirt.trace.stop", { instanceId: traceId }, Buffer.alloc(0), value.context);
  } finally {
    await value.cleanup();
  }
});

test("CRIU adapter executes all five frozen checkpoint operations with an integrity manifest", async () => {
  const value = await providerFixture();
  try {
    const provider = new CriuCheckpointProvider();
    const checkpointPath = join(value.root, "checkpoint-images");
    const created = await provider.execute("quirt.checkpoint.create", { pid: process.pid, checkpointPath, leaveRunning: true }, Buffer.alloc(0), value.context);
    const instanceId = created.instanceId!;
    assert.match((created.payload.manifest as { integritySha256: string }).integritySha256, /^[a-f0-9]{64}$/u);
    await provider.execute("quirt.checkpoint.list", {}, Buffer.alloc(0), value.context);
    await provider.execute("quirt.checkpoint.get", { instanceId, includeEvents: true }, Buffer.alloc(0), value.context);
    const restored = await provider.execute("quirt.checkpoint.restore", { instanceId, detach: true }, Buffer.alloc(0), value.context);
    assert.equal(restored.payload.portable, false);
    value.state.power.putInstance({ ...value.state.power.getInstance(instanceId, OWNER, TARGET), state: "stopped" });
    const removed = await provider.execute("quirt.checkpoint.remove", { instanceId }, Buffer.alloc(0), value.context);
    assert.equal((removed.payload.checkpoint as { cleanupStatus: string }).cleanupStatus, "complete");
  } finally {
    await value.cleanup();
  }
});

test("conditional desktop and fleet adapters execute all 15 frozen operations without public listeners or host-key bypass", async () => {
  const value = await providerFixture();
  try {
    const desktop = new VncDesktopProvider();
    const opened = await desktop.execute("quirt.desktop.open", {
      credentialReferences: { passwordFile: "/run/credentials/vnc-password" },
      display: 12,
      port: 5912,
      width: 1024,
      height: 768
    }, Buffer.alloc(0), value.context);
    const desktopId = opened.instanceId!;
    assert.equal((opened.payload.attach as { private: boolean }).private, true);
    await desktop.execute("quirt.desktop.list", {}, Buffer.alloc(0), value.context);
    const captured = await desktop.execute("quirt.desktop.capture", { instanceId: desktopId, outputPath: join(value.root, "desktop.xwd"), inline: true }, Buffer.alloc(0), value.context);
    assert.equal(captured.binary?.toString("utf8"), "deterministic-xwd");
    await desktop.execute("quirt.desktop.input", { instanceId: desktopId, action: "key", value: "Return" }, Buffer.alloc(0), value.context);
    await desktop.execute("quirt.desktop.resize", { instanceId: desktopId, width: 1280, height: 720 }, Buffer.alloc(0), value.context);
    await desktop.execute("quirt.desktop.close", { instanceId: desktopId }, Buffer.alloc(0), value.context);

    const fleet = new SshFleetProvider();
    const host = await fleet.execute("quirt.host.add", {
      host: "fixture-host",
      user: "fixture-user",
      port: 2222,
      credentialReferences: { identityFile: "/run/credentials/fleet-key", knownHostsFile: "/run/credentials/fleet-known-hosts" }
    }, Buffer.alloc(0), value.context);
    const hostId = host.instanceId!;
    await fleet.execute("quirt.host.list", {}, Buffer.alloc(0), value.context);
    await fleet.execute("quirt.host.get", { instanceId: hostId, includeEvents: true }, Buffer.alloc(0), value.context);
    await fleet.execute("quirt.host.shell", { instanceId: hostId, command: ["printf", "%s", "safe"] }, Buffer.alloc(0), value.context);
    const executed = await fleet.execute("quirt.fleet.exec", { instanceIds: [hostId], command: ["true"], maximumBytesPerHost: 4096 }, Buffer.alloc(0), value.context);
    assert.equal(executed.payload.state, "succeeded");
    value.runtime.failureOutput.set("/usr/bin/ssh", "Host key verification failed");
    const rejected = await fleet.execute("quirt.fleet.exec", { instanceIds: [hostId], command: ["true"], maximumBytesPerHost: 4096 }, Buffer.alloc(0), value.context);
    assert.equal((rejected.payload.outcomes as Array<{ errorCode: string }>)[0]?.errorCode, "host_key_mismatch");
    value.runtime.failureOutput.delete("/usr/bin/ssh");
    await fleet.execute("quirt.fleet.copy", { instanceId: hostId, localPath: join(value.root, "copy-source"), remotePath: "/tmp/copy-target" }, Buffer.alloc(0), value.context);
    await fleet.execute("quirt.fleet.playbook", { instanceIds: [hostId], inventoryPath: join(value.root, "inventory.ini"), playbookPath: join(value.root, "playbook.yml") }, Buffer.alloc(0), value.context);
    await fleet.execute("quirt.fleet.status", { instanceId: hostId }, Buffer.alloc(0), value.context);
    await fleet.execute("quirt.host.remove", { instanceId: hostId }, Buffer.alloc(0), value.context);
    const scp = value.runtime.calls.find((call) => call.executable === "/usr/bin/scp");
    assert.ok(scp?.arguments?.includes("-P"));
    assert.equal(scp?.arguments?.includes("-p"), false);
    const ansible = value.runtime.calls.find((call) => call.executable === "/usr/bin/ansible-playbook");
    assert.equal(ansible?.environment?.ANSIBLE_HOST_KEY_CHECKING, "True");
    assert.match(ansible?.environment?.ANSIBLE_SSH_ARGS ?? "", /StrictHostKeyChecking=yes/u);
    const wrongPrincipal = { ...value.context, ownerPrincipalFingerprint: "d".repeat(64) };
    await assert.rejects(fleet.execute("quirt.host.get", { instanceId: hostId }, Buffer.alloc(0), wrongPrincipal), (cause: unknown) => cause instanceof QuirtError);
  } finally {
    await value.cleanup();
  }
});
