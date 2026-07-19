import { createHash } from "node:crypto";
import { chmod, mkdir, stat } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { QUIRT_POWER_OPERATION_GROUPS, type QuirtPowerOperation } from "../power-catalog.js";
import { QuirtError } from "../error.js";
import { publicProviderInstance, type QuirtPowerProviderAdapter, type QuirtPowerProviderContext, type QuirtPowerProviderResult } from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";
import {
  absolutePath, booleanValue, cleanupManagedFailure, createInstance, credentialReferences, integer, noBinary, optionalText,
  providerGet, providerInstance, providerList, recoverManaged, requiredText, requireExecutable,
  runChecked, startManagedJob, stopManaged, stringList
} from "./provider-helpers.js";

function parseJson(text: string, noun: string): unknown {
  if (text.trim().length === 0) return {};
  try { return JSON.parse(text); } catch { throw new QuirtError("provider_degraded", noun + " returned invalid JSON", true); }
}

function referencePath(references: Readonly<Record<string, string>>, name: string, noun: string, required = false): string | undefined {
  const value = references[name];
  if (value === undefined) {
    if (required) throw new QuirtError("credentials_unavailable", noun + " credential reference is required");
    return undefined;
  }
  return absolutePath(value, noun + " credential reference");
}

function providerReferences(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): Record<string, string> {
  return context.state.power.credentialReferences(record.instanceId);
}

async function selectedPort(host: string, requested: number): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.once("error", () => reject(new QuirtError("port_unavailable", "Provider port is unavailable", true)));
    server.listen({ host, port: requested, exclusive: true }, () => {
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      server.close((cause) => cause === undefined ? resolve(port) : reject(new QuirtError("port_unavailable", "Provider port reservation could not be released", true)));
    });
  });
}

async function tcpListening(host: string, port: number): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = connect({ host, port });
    const done = (available: boolean): void => { socket.destroy(); resolve(available); };
    socket.setTimeout(250, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

async function confirmManagedJob(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord, code: "mount_unavailable" | "process_exited", noun: string): Promise<QuirtProviderInstanceRecord> {
  await delay(200, undefined, { signal: context.signal }).catch(() => { throw new QuirtError("canceled", noun + " readiness was canceled", true); });
  const jobId = record.relatedJobs.at(-1);
  let status = "missing";
  if (jobId !== undefined) {
    try { status = context.jobs.get(jobId, context.ownerPrincipalFingerprint).status; } catch { status = "missing"; }
  }
  if (status === "running" || status === "starting") return record;
  context.state.power.putInstance({ ...record, state: "failed", failureClassification: code, health: { state: "failed", jobStatus: status }, cleanupStatus: "complete", ports: record.ports.map((port) => ({ ...port, state: "released" })), lastProbeAt: new Date().toISOString() });
  context.state.power.appendEvent(record.instanceId, "failure", { errorCode: code, jobStatus: status });
  throw new QuirtError(code, noun + " process exited before readiness", true);
}

function pageEvents(record: QuirtProviderInstanceRecord, payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext, noun: string): Record<string, unknown> {
  const page = context.state.power.readEvents(record.instanceId, context.ownerPrincipalFingerprint, context.targetHost,
    integer(payload.after, noun + " event cursor", -1, -1, Number.MAX_SAFE_INTEGER),
    integer(payload.maximumEvents, noun + " event page size", 100, 1, 1000));
  return { events: page.events, nextSequence: page.nextSequence, truncated: page.truncated };
}

export class SyncthingProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "sync.syncthing";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.sync;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Synchronization");
    switch (operation) {
      case "quirt.sync.create": return await this.create(payload, context);
      case "quirt.sync.list": return providerList(context, this.providerId, payload, "Synchronization");
      case "quirt.sync.status": return await this.status(payload, context);
      case "quirt.sync.pause": return await this.setPaused(payload, context, true);
      case "quirt.sync.resume": return await this.setPaused(payload, context, false);
      case "quirt.sync.remove": return this.remove(payload, context);
      default: throw new QuirtError("unknown_operation", "Synchronization operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async create(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/syncthing", ["--version"]);
    const folderPath = absolutePath(payload.folderPath, "Synchronization folder path");
    const devices = stringList(payload.deviceIds, "Synchronization device identities", 256, 4096);
    if (devices.length === 0) throw new QuirtError("configuration_missing", "At least one authenticated synchronization device identity is required");
    const references = credentialReferences(payload.credentialReferences);
    const home = payload.homePath === undefined ? context.config.stateRoot + "/providers/syncthing/" + createHash("sha256").update(context.requestId).digest("hex").slice(0, 24) : absolutePath(payload.homePath, "Syncthing home path");
    await mkdir(home, { recursive: true, mode: 0o700 });
    await chmod(home, 0o700);
    let record = createInstance(context, {
      providerId: this.providerId,
      configuration: { folderPath, devices, home, conflictPolicy: "preserve" },
      credentialReferences: references,
      paths: [folderPath, home],
      state: "starting",
      health: { state: "starting", peersConfigured: true }
    });
    const folderId = createHash("sha256").update(context.ownerPrincipalFingerprint + "\0" + folderPath).digest("hex").slice(0, 32);
    try {
      record = await startManagedJob(context, record, {
      executable: "/usr/bin/syncthing",
      arguments: ["serve", "--no-browser", "--no-restart", "--home", home],
      workingDirectory: folderPath,
      eventType: "synchronization.started"
    });
    const configure = async (argumentsList: string[]): Promise<void> => {
      let final: unknown;
      for (let attempt = 0; attempt < 50; attempt += 1) {
        try { await runChecked(context, { executable: "/usr/bin/syncthing", arguments: ["cli", "--home", home, ...argumentsList], maximumOutputBytes: 256 * 1024, timeoutMs: 5000 }); return; }
        catch (cause) { final = cause; await delay(100, undefined, { signal: context.signal }).catch(() => { throw new QuirtError("canceled", "Synchronization configuration was canceled", true); }); }
      }
      throw final instanceof QuirtError ? final : new QuirtError("readiness_timeout", "Syncthing control endpoint did not become ready", true);
    };
    await configure(["config", "folders", "add", "--id", folderId, "--label", folderId, "--path", folderPath]);
    for (const deviceId of devices) await configure(["config", "folders", folderId, "devices", "add", "--device-id", deviceId]);
    context.state.power.recordSyncFolder(record.instanceId, { folderPath, identity: { folderId, devices }, state: { paused: false, scanState: "scheduled", conflicts: "preserved" } });
    context.state.power.appendSyncEvent(record.instanceId, "folder-added", { folderId, deviceCount: devices.length });
      return { payload: { synchronization: publicProviderInstance(record), folderId }, instanceId: record.instanceId };
    } catch (cause) {
      cleanupManagedFailure(context, record, cause);
      throw cause;
    }
  }

  private async status(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Synchronization identity");
    const home = requiredText(record.configuration.home, "Syncthing home path", 32_768);
    const result = await runChecked(context, { executable: "/usr/bin/syncthing", arguments: ["cli", "--home", home, "show", "system"], maximumOutputBytes: 1024 * 1024, timeoutMs: 15_000 });
    const system = parseJson(result.stdout.toString("utf8"), "Syncthing");
    context.state.power.appendSyncEvent(record.instanceId, "status", { observedAt: new Date().toISOString() });
    return { payload: { synchronization: publicProviderInstance(record), system, ...pageEvents(record, payload, context, "Synchronization") }, instanceId: record.instanceId };
  }

  private async setPaused(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext, paused: boolean): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Synchronization identity");
    const folderPath = requiredText(record.configuration.folderPath, "Synchronization folder path", 32_768);
    const home = requiredText(record.configuration.home, "Syncthing home path", 32_768);
    const folderId = createHash("sha256").update(context.ownerPrincipalFingerprint + "\0" + folderPath).digest("hex").slice(0, 32);
    await runChecked(context, { executable: "/usr/bin/syncthing", arguments: ["cli", "--home", home, "config", "folders", folderId, "paused", "set", String(paused)], maximumOutputBytes: 64 * 1024, timeoutMs: 15_000 });
    context.state.power.recordSyncFolder(record.instanceId, { folderPath, identity: { folderId }, state: { paused, conflicts: "preserved" } });
    context.state.power.appendSyncEvent(record.instanceId, paused ? "paused" : "resumed", { folderId });
    return { payload: { synchronization: publicProviderInstance(record), folderId, paused }, instanceId: record.instanceId };
  }

  private remove(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Synchronization identity");
    const stopped = stopManaged(context, record, payload.force === true);
    context.state.power.appendSyncEvent(record.instanceId, "folder-removed", { destructiveConflictResolution: false });
    return { payload: { synchronization: publicProviderInstance(stopped) }, instanceId: record.instanceId };
  }
}

function remoteSpec(record: QuirtProviderInstanceRecord, remotePathValue: unknown): string {
  const path = requiredText(remotePathValue, "Remote path", 32_768);
  if (path.includes("\0") || path.startsWith("-")) throw new QuirtError("invalid_request", "Remote path is unsafe");
  const backend = requiredText(record.configuration.backend, "Remote backend", 128);
  if (backend === "local") return absolutePath(path, "Local-backend remote path");
  const remoteName = requiredText(record.configuration.remoteName, "Remote identity", 128);
  return remoteName + ":" + path;
}

function rcloneBase(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): string[] {
  const references = providerReferences(context, record);
  const config = referencePath(references, "config", "rclone", record.configuration.backend !== "local");
  return config === undefined ? [] : ["--config", config];
}

export class RcloneProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "storage.rclone";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.remote;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Remote storage");
    switch (operation) {
      case "quirt.remote.add": return await this.add(payload, context);
      case "quirt.remote.list": return providerList(context, this.providerId, payload, "Remote");
      case "quirt.remote.copy": return await this.transfer("copy", payload, context);
      case "quirt.remote.sync": return await this.transfer("sync", payload, context);
      case "quirt.remote.mount": return await this.mount(payload, context);
      case "quirt.remote.serve": return await this.serve(payload, context);
      case "quirt.remote.unmount": return this.unmount(payload, context);
      default: throw new QuirtError("unknown_operation", "Remote storage operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async add(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/rclone", ["version"]);
    const backend = payload.backend === "local" ? "local" : requiredText(payload.backend, "Remote backend", 128);
    const remoteName = backend === "local" ? "local" : requiredText(payload.remoteName, "Remote identity", 128);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(remoteName)) throw new QuirtError("invalid_request", "Remote identity is invalid");
    const references = credentialReferences(payload.credentialReferences);
    if (backend !== "local") referencePath(references, "config", "rclone", true);
    const record = createInstance(context, { providerId: this.providerId, configuration: { backend, remoteName }, credentialReferences: references, state: "ready", health: { state: "healthy", copy: true, mount: null } });
    context.state.power.recordRemoteOperation(record.instanceId, "add", "succeeded", { backend, remoteName });
    return { payload: { remote: publicProviderInstance(record), capabilities: { copy: true, sync: true, mount: null, localDeterministicBackend: backend === "local" } }, instanceId: record.instanceId };
  }

  private async transfer(kind: "copy" | "sync", payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Remote identity");
    const localPath = absolutePath(payload.localPath, "Remote local path");
    const remote = remoteSpec(record, payload.remotePath);
    const direction = payload.direction === "download" ? "download" : payload.direction === "upload" || payload.direction === undefined ? "upload" : (() => { throw new QuirtError("invalid_request", "Remote transfer direction is invalid"); })();
    const operationId = context.state.power.recordRemoteOperation(record.instanceId, kind, "running", { direction, localPath, remotePath: payload.remotePath });
    context.state.power.appendEvent(record.instanceId, "progress", { operationId, state: "running" });
    const source = direction === "upload" ? localPath : remote;
    const destination = direction === "upload" ? remote : localPath;
    try {
      const result = await runChecked(context, { executable: "/usr/bin/rclone", arguments: [...rcloneBase(context, record), kind, source, destination, "--checksum", "--use-json-log", "--stats", "1s"], maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Remote operation timeout", 60 * 60 * 1000, 1000, 7 * 86400 * 1000) });
      const digest = createHash("sha256").update(result.stdout).update(result.stderr).digest("hex");
      context.state.power.recordRemoteOperation(record.instanceId, kind, "succeeded", { direction, localPath, remotePath: payload.remotePath, outputDigest: digest }, operationId);
      context.state.power.appendEvent(record.instanceId, "progress", { operationId, state: "succeeded", outputDigest: digest });
      return { payload: { operationId, state: "succeeded", direction, outputDigest: digest }, instanceId: record.instanceId };
    } catch (cause) {
      context.state.power.recordRemoteOperation(record.instanceId, kind, cause instanceof QuirtError && (cause.code === "canceled" || cause.code === "request_canceled") ? "canceled" : "failed", { direction, localPath, remotePath: payload.remotePath }, operationId);
      throw cause;
    }
  }

  private async mount(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Remote identity");
    const fuse = await context.runtime.probeExecutable("/usr/bin/fusermount3", ["--version"]);
    if (!fuse.available) throw new QuirtError("mount_unavailable", "FUSE mount support is unavailable on this host");
    const localPath = absolutePath(payload.localPath, "Remote mount path");
    const remote = remoteSpec(record, payload.remotePath);
    record = context.state.power.putInstance({ ...record, configuration: { ...record.configuration, localPath, remotePath: payload.remotePath }, paths: [...record.paths, localPath], lastProbeAt: new Date().toISOString() });
    try {
      record = await startManagedJob(context, record, { executable: "/usr/bin/rclone", arguments: [...rcloneBase(context, record), "mount", remote, localPath, "--vfs-cache-mode", "writes"], workingDirectory: localPath, eventType: "mount.process-started" });
    record = await confirmManagedJob(context, record, "mount_unavailable", "Remote mount");
    record = context.state.power.putInstance({ ...record, health: { state: "healthy", processRunning: true, mountVerification: "provider_process" }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordRemoteMount(record.instanceId, localPath, { remotePath: payload.remotePath, backend: record.configuration.backend }, "mounted");
      return { payload: { remote: publicProviderInstance(record), mount: { localPath, state: "mounted" } }, instanceId: record.instanceId };
    } catch (cause) {
      cleanupManagedFailure(context, record, cause);
      throw cause;
    }
  }

  private async serve(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Remote identity");
    const bindAddress = optionalText(payload.bindAddress, "Remote serve bind address", 128) ?? "127.0.0.1";
    if (bindAddress !== "127.0.0.1" && bindAddress !== "::1") throw new QuirtError("unsafe_listener", "Remote storage serving is private by default and wildcard/public binding is not permitted");
    const port = await selectedPort(bindAddress, integer(payload.port, "Remote serve port", 0, 0, 65535));
    const remote = remoteSpec(record, payload.remotePath);
    record = context.state.power.putInstance({ ...record, configuration: { ...record.configuration, remotePath: payload.remotePath, bindAddress, port }, ports: [{ protocol: "tcp", bindAddress, port, state: "reserved" }], lastProbeAt: new Date().toISOString() });
    const address = bindAddress === "::1" ? "[::1]:" + port : bindAddress + ":" + port;
    try {
      record = await startManagedJob(context, record, { executable: "/usr/bin/rclone", arguments: [...rcloneBase(context, record), "serve", "http", remote, "--addr", address], eventType: "serve.process-started" });
    record = await confirmManagedJob(context, record, "process_exited", "Remote serve");
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && !await tcpListening(bindAddress, port)) {
      if (context.signal?.aborted === true) throw new QuirtError("canceled", "Remote serve readiness was canceled", true);
      await delay(100, undefined, { signal: context.signal });
    }
    if (!await tcpListening(bindAddress, port)) throw new QuirtError("readiness_timeout", "Remote serve listener did not become ready", true);
    record = context.state.power.putInstance({ ...record, ports: [{ protocol: "tcp", bindAddress, port, state: "listening" }], health: { state: "healthy", listenerVerified: true, privateBinding: true }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordPort(record.instanceId, { protocol: "tcp", bindAddress, port, state: "listening" });
    context.state.power.appendEvent(record.instanceId, "serve.ready", { bindAddress, port, listenerVerified: true });
      return { payload: { remote: publicProviderInstance(record), route: { scheme: "http", bindAddress, port, private: true, listenerVerified: true } }, instanceId: record.instanceId };
    } catch (cause) {
      cleanupManagedFailure(context, record, cause);
      throw cause;
    }
  }

  private unmount(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Remote identity");
    const stopped = stopManaged(context, record, payload.force === true);
    const localPath = typeof record.configuration.localPath === "string" ? record.configuration.localPath : "/";
    context.state.power.recordRemoteMount(record.instanceId, localPath, { backend: record.configuration.backend }, "unmounted");
    return { payload: { remote: publicProviderInstance(stopped) }, instanceId: record.instanceId };
  }
}

function resticEnvironment(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): Record<string, string> {
  const references = providerReferences(context, record);
  const passwordFile = referencePath(references, "passwordFile", "Restic", true)!;
  const environment: Record<string, string> = { RESTIC_PASSWORD_FILE: passwordFile };
  return environment;
}

function resticArgs(record: QuirtProviderInstanceRecord): string[] {
  return ["-r", requiredText(record.configuration.repository, "Snapshot repository", 32_768)];
}

export class ResticProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "snapshot.restic";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.snapshot;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Snapshot");
    switch (operation) {
      case "quirt.snapshot.create": return await this.create(payload, context);
      case "quirt.snapshot.list": return this.list(payload, context);
      case "quirt.snapshot.get": return this.get(payload, context);
      case "quirt.snapshot.diff": return await this.diff(payload, context);
      case "quirt.snapshot.mount": return await this.mount(payload, context);
      case "quirt.snapshot.restore": return await this.restore(payload, context);
      case "quirt.snapshot.unmount": return this.unmount(payload, context);
      case "quirt.snapshot.remove": return await this.remove(payload, context);
      default: throw new QuirtError("unknown_operation", "Snapshot operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async create(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/restic", ["version"]);
    const repository = requiredText(payload.repository, "Snapshot repository", 32_768);
    if (repository.startsWith("-") || repository.includes("\0")) throw new QuirtError("invalid_request", "Snapshot repository identity is unsafe");
    const sources = stringList(payload.sourcePaths, "Snapshot source paths", 256, 32_768).map((item) => absolutePath(item, "Snapshot source path"));
    if (sources.length === 0) throw new QuirtError("configuration_missing", "Snapshot source paths are required");
    const references = credentialReferences(payload.credentialReferences);
    referencePath(references, "passwordFile", "Restic", true);
    let record = createInstance(context, { providerId: this.providerId, configuration: { repository, sources, includes: stringList(payload.includes, "Snapshot include patterns", 1024, 4096), excludes: stringList(payload.excludes, "Snapshot exclude patterns", 1024, 4096) }, credentialReferences: references, paths: sources, state: "creating", health: { state: "initializing" } });
    context.state.power.recordSnapshotRepository(record.instanceId, { repository, credentialReferences: Object.keys(references) }, "opening");
    const environment = resticEnvironment(context, record);
    if (booleanValue(payload.initialize, "Snapshot initialize", false)) {
      await runChecked(context, { executable: "/usr/bin/restic", arguments: [...resticArgs(record), "init"], environment, maximumOutputBytes: 1024 * 1024, timeoutMs: 60_000 });
    }
    const args = [...resticArgs(record), "backup", "--json", ...sources];
    for (const include of record.configuration.includes as string[]) args.push("--include", include);
    for (const exclude of record.configuration.excludes as string[]) args.push("--exclude", exclude);
    const result = await runChecked(context, { executable: "/usr/bin/restic", arguments: args, environment, maximumOutputBytes: 8 * 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Snapshot timeout", 4 * 60 * 60 * 1000, 1000, 7 * 86400 * 1000) });
    let immutableIdentity: string | undefined;
    for (const line of result.stdout.toString("utf8").split("\n")) {
      if (line.trim().length === 0) continue;
      try { const item = JSON.parse(line) as Record<string, unknown>; if (typeof item.snapshot_id === "string") immutableIdentity = item.snapshot_id; } catch { /* restic may emit bounded non-summary output */ }
    }
    if (immutableIdentity === undefined) throw new QuirtError("provider_degraded", "Restic did not return an immutable snapshot identity", true);
    const outputDigest = createHash("sha256").update(result.stdout).update(result.stderr).digest("hex");
    const snapshotId = context.state.power.recordSnapshot(record.instanceId, immutableIdentity, { repository, sources, includes: record.configuration.includes, excludes: record.configuration.excludes, outputDigest, verified: false });
    record = context.state.power.putInstance({ ...record, state: "ready", health: { state: "healthy" }, cleanupStatus: "active", lastProbeAt: new Date().toISOString() });
    context.state.power.recordSnapshotRepository(record.instanceId, { repository, credentialReferences: Object.keys(references) }, "ready");
    context.state.power.appendEvent(record.instanceId, "snapshot.created", { snapshotId, immutableIdentity, outputDigest });
    return { payload: { repository: publicProviderInstance(record), snapshot: context.state.power.snapshot(snapshotId, context.ownerPrincipalFingerprint) }, instanceId: record.instanceId };
  }

  private list(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const repositoryInstanceId = optionalText(payload.instanceId, "Snapshot repository identity", 128);
    if (repositoryInstanceId !== undefined) providerInstance(context, this.providerId, repositoryInstanceId, "Snapshot repository identity");
    const snapshots = context.state.power.snapshots(context.ownerPrincipalFingerprint, repositoryInstanceId);
    const maximum = integer(payload.maximum, "Snapshot page size", 100, 1, 1000);
    const after = optionalText(payload.afterSnapshotId, "Snapshot cursor", 128);
    const filtered = after === undefined ? snapshots : snapshots.filter((item) => item.snapshotId > after);
    return { payload: { snapshots: filtered.slice(0, maximum), truncated: filtered.length > maximum, nextSnapshotId: filtered.length > maximum ? filtered[maximum - 1]?.snapshotId ?? null : null } };
  }

  private get(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const snapshotId = requiredText(payload.snapshotId, "Snapshot identity", 128);
    const snapshot = context.state.power.snapshot(snapshotId, context.ownerPrincipalFingerprint);
    providerInstance(context, this.providerId, snapshot.instanceId, "Snapshot repository identity");
    return { payload: { snapshot } };
  }

  private async diff(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Snapshot repository identity");
    const left = requiredText(payload.leftSnapshotId, "Left snapshot identity", 128);
    const right = requiredText(payload.rightSnapshotId, "Right snapshot identity", 128);
    const result = await runChecked(context, { executable: "/usr/bin/restic", arguments: [...resticArgs(record), "diff", "--json", left, right], environment: resticEnvironment(context, record), maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 60_000 });
    return { payload: { leftSnapshotId: left, rightSnapshotId: right, truncated: false }, binary: result.stdout, instanceId: record.instanceId };
  }

  private async mount(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Snapshot repository identity");
    const fuse = await context.runtime.probeExecutable("/usr/bin/fusermount3", ["--version"]);
    if (!fuse.available) throw new QuirtError("mount_unavailable", "Snapshot mount requires FUSE support");
    const mountPath = absolutePath(payload.mountPath, "Snapshot mount path");
    record = await startManagedJob(context, record, { executable: "/usr/bin/restic", arguments: [...resticArgs(record), "mount", mountPath], environment: resticEnvironment(context, record), workingDirectory: mountPath, eventType: "snapshot.mount.ready" });
    return { payload: { repository: publicProviderInstance(record), mountPath, state: "mounted" }, instanceId: record.instanceId };
  }

  private async restore(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const snapshotId = requiredText(payload.snapshotId, "Snapshot identity", 128);
    const snapshot = context.state.power.snapshot(snapshotId, context.ownerPrincipalFingerprint);
    const record = providerInstance(context, this.providerId, snapshot.instanceId, "Snapshot repository identity");
    const destination = absolutePath(payload.destination, "Restore destination");
    const policy = payload.conflictPolicy === "overwrite" || payload.conflictPolicy === "skip" || payload.conflictPolicy === "fail" || payload.conflictPolicy === undefined ? (payload.conflictPolicy ?? "fail") as string : (() => { throw new QuirtError("invalid_request", "Restore conflict policy is invalid"); })();
    if (policy === "fail") {
      try { await stat(destination); throw new QuirtError("restore_conflict", "Restore destination already exists; explicit conflict policy is required"); }
      catch (cause) { if (cause instanceof QuirtError) throw cause; if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause; }
    }
    const restoreId = context.state.power.recordRestore(record.instanceId, snapshotId, destination, policy, "running", { preview: payload.preview === true });
    const args = [...resticArgs(record), "restore", snapshot.immutableIdentity, "--target", destination];
    if (payload.preview === true) args.push("--dry-run");
    if (policy === "overwrite") args.push("--overwrite", "always");
    if (policy === "skip") args.push("--overwrite", "never");
    try {
      const result = await runChecked(context, { executable: "/usr/bin/restic", arguments: args, environment: resticEnvironment(context, record), maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Restore timeout", 4 * 60 * 60 * 1000, 1000, 7 * 86400 * 1000) });
      const digest = createHash("sha256").update(result.stdout).update(result.stderr).digest("hex");
      context.state.power.recordRestore(record.instanceId, snapshotId, destination, policy, "succeeded", { preview: payload.preview === true, outputDigest: digest }, restoreId);
      context.state.power.appendEvent(record.instanceId, "restore.succeeded", { restoreId, snapshotId, preview: payload.preview === true });
      return { payload: { restoreId, snapshotId, destination, conflictPolicy: policy, preview: payload.preview === true, state: "succeeded", outputDigest: digest }, instanceId: record.instanceId };
    } catch (cause) {
      context.state.power.recordRestore(record.instanceId, snapshotId, destination, policy, "failed", { errorCode: cause instanceof QuirtError ? cause.code : "internal_error" }, restoreId);
      throw cause;
    }
  }

  private unmount(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Snapshot repository identity");
    const stopped = stopManaged(context, record, payload.force === true);
    return { payload: { repository: publicProviderInstance(stopped), state: "unmounted" }, instanceId: record.instanceId };
  }

  private async remove(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const snapshotId = requiredText(payload.snapshotId, "Snapshot identity", 128);
    const snapshot = context.state.power.snapshot(snapshotId, context.ownerPrincipalFingerprint);
    const record = providerInstance(context, this.providerId, snapshot.instanceId, "Snapshot repository identity");
    await runChecked(context, { executable: "/usr/bin/restic", arguments: [...resticArgs(record), "forget", snapshot.immutableIdentity, ...(payload.prune === true ? ["--prune"] : [])], environment: resticEnvironment(context, record), maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: 4 * 60 * 60 * 1000 });
    context.state.power.recordSnapshot(record.instanceId, snapshot.immutableIdentity, { ...snapshot.manifest, state: "forgotten", forgottenAt: new Date().toISOString(), pruned: payload.prune === true }, snapshot.snapshotId);
    context.state.power.appendEvent(record.instanceId, "snapshot.removed", { snapshotId, immutableIdentity: snapshot.immutableIdentity });
    return { payload: { snapshotId, immutableIdentity: snapshot.immutableIdentity, state: "forgotten" }, instanceId: record.instanceId };
  }
}
