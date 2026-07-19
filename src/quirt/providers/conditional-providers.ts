import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, readdir, readlink, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { QUIRT_POWER_OPERATION_GROUPS, type QuirtPowerOperation } from "../power-catalog.js";
import { QuirtError } from "../error.js";
import { publicProviderInstance, type QuirtPowerProviderAdapter, type QuirtPowerProviderContext, type QuirtPowerProviderResult } from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";
import {
  absolutePath, cleanupManagedFailure, createInstance, credentialReferences, integer, noBinary, optionalText, providerGet,
  providerInstance, providerList, readJobLogs, recoverManaged, requiredText, requireExecutable,
  runChecked, startManagedJob, stopManaged, stringList
} from "./provider-helpers.js";

async function digestFile(path: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function checkpointManifest(path: string): Promise<{ files: Array<{ name: string; sizeBytes: number; sha256: string }>; integritySha256: string }> {
  const names = (await readdir(path)).sort();
  if (names.length > 4096) throw new QuirtError("output_truncated", "Checkpoint contains too many image files for a bounded integrity manifest");
  const files: Array<{ name: string; sizeBytes: number; sha256: string }> = [];
  for (const name of names) {
    if (name.includes("/") || name.includes("\0")) throw new QuirtError("checkpoint_incompatible", "Checkpoint image name is unsafe");
    const full = join(path, name);
    const info = await stat(full);
    if (info.isFile()) files.push({ name, sizeBytes: info.size, sha256: await digestFile(full) });
  }
  const integritySha256 = createHash("sha256").update(JSON.stringify(files)).digest("hex");
  return { files, integritySha256 };
}

async function namespaceIdentity(pid: number): Promise<Record<string, unknown>> {
  const names = ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"];
  const output: Record<string, unknown> = {};
  for (const name of names) {
    try { output[name] = await readlink("/proc/" + pid + "/ns/" + name); } catch { output[name] = null; }
  }
  return output;
}

export class CriuCheckpointProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "checkpoint.criu";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.checkpoint;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Process checkpoint");
    switch (operation) {
      case "quirt.checkpoint.create": return await this.create(payload, context);
      case "quirt.checkpoint.list": return providerList(context, this.providerId, payload, "Checkpoint");
      case "quirt.checkpoint.get": return providerGet(context, this.providerId, payload, "Checkpoint");
      case "quirt.checkpoint.restore": return await this.restore(payload, context);
      case "quirt.checkpoint.remove": return await this.remove(payload, context);
      default: throw new QuirtError("unknown_operation", "Process checkpoint operation is unknown");
    }
  }

  async recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    const path = typeof record.configuration.checkpointPath === "string" ? record.configuration.checkpointPath : undefined;
    let intact = false;
    if (path !== undefined) {
      try { const manifest = await checkpointManifest(path); intact = manifest.integritySha256 === record.configuration.integritySha256; } catch { intact = false; }
    }
    const classification = intact ? "checkpoint_images_preserved" : "checkpoint_images_lost_or_changed";
    context.state.power.putInstance({ ...record, state: intact ? "stopped" : "lost", recoveryClassification: classification, failureClassification: intact ? null : "checkpoint_incompatible", health: { state: intact ? "stored" : "lost", portable: false }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordRecovery(record.instanceId, classification, { checkpointPath: path ?? null });
  }

  private async create(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/sbin/criu", ["--version"]);
    try { await runChecked(context, { executable: "/usr/sbin/criu", arguments: ["check", "--all"], maximumOutputBytes: 1024 * 1024, timeoutMs: 30_000 }); }
    catch (cause) { if (cause instanceof QuirtError) throw new QuirtError("kernel_feature_unavailable", "CRIU compatibility check failed on this host"); throw cause; }
    const pid = integer(payload.pid, "Checkpoint target PID", 0, 1, 4_194_304);
    const identity = await context.runtime.processIdentity(pid);
    const namespaces = await namespaceIdentity(pid);
    let cgroup = "";
    try { cgroup = await readFile("/proc/" + pid + "/cgroup", "utf8"); } catch { throw new QuirtError("process_identity_changed", "Checkpoint target cgroup identity changed"); }
    const checkpointPath = payload.checkpointPath === undefined ? context.config.stateRoot + "/providers/checkpoint/" + context.requestId : absolutePath(payload.checkpointPath, "Checkpoint path");
    await mkdir(checkpointPath, { recursive: false, mode: 0o700 }).catch((cause: NodeJS.ErrnoException) => { if (cause.code === "EEXIST") throw new QuirtError("instance_conflict", "Checkpoint path already exists"); throw cause; });
    let record = createInstance(context, { providerId: this.providerId, configuration: { checkpointPath, processIdentity: identity, namespaces, cgroup, portable: false, limitations: ["open sockets, devices, namespaces, and kernel features may be incompatible"] }, paths: [checkpointPath], state: "creating", health: { state: "compatibility-checked", portable: false } });
    const args = ["dump", "-t", String(pid), "-D", checkpointPath, "--shell-job"];
    if (payload.leaveRunning === true) args.push("--leave-running");
    try { await runChecked(context, { executable: "/usr/sbin/criu", arguments: args, maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Checkpoint timeout", 5 * 60 * 1000, 1000, 60 * 60 * 1000) }); }
    catch (cause) {
      await rm(checkpointPath, { recursive: true, force: true });
      context.state.power.putInstance({ ...record, state: "failed", failureClassification: cause instanceof QuirtError ? cause.code : "checkpoint_incompatible", cleanupStatus: "complete", health: { state: "failed" }, lastProbeAt: new Date().toISOString() });
      throw cause instanceof QuirtError ? new QuirtError("checkpoint_incompatible", "Process tree is incompatible with checkpointing on this host") : cause;
    }
    const manifest = await checkpointManifest(checkpointPath);
    const checkpointId = context.state.power.recordCheckpoint(record.instanceId, { processIdentity: identity, namespaces, cgroup: { raw: cgroup }, manifest: { files: manifest.files, checkpointPath, portable: false }, integritySha256: manifest.integritySha256, state: "stored" });
    record = context.state.power.putInstance({ ...record, state: "stopped", configuration: { ...record.configuration, checkpointId, integritySha256: manifest.integritySha256 }, health: { state: "stored", fileCount: manifest.files.length, portable: false }, cleanupStatus: "active", lastProbeAt: new Date().toISOString() });
    context.state.power.appendEvent(record.instanceId, "checkpoint.created", { checkpointId, integritySha256: manifest.integritySha256, portable: false });
    return { payload: { checkpoint: publicProviderInstance(record), checkpointId, manifest }, instanceId: record.instanceId };
  }

  private async restore(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Checkpoint identity");
    const path = requiredText(record.configuration.checkpointPath, "Checkpoint path", 32_768);
    const observed = await checkpointManifest(path);
    if (observed.integritySha256 !== record.configuration.integritySha256) throw new QuirtError("snapshot_corrupt", "Checkpoint integrity manifest does not match");
    try { await runChecked(context, { executable: "/usr/sbin/criu", arguments: ["restore", "-D", path, "--shell-job", ...(payload.detach === true ? ["--restore-detached"] : [])], maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Checkpoint restore timeout", 5 * 60 * 1000, 1000, 60 * 60 * 1000) }); }
    catch (cause) { throw cause instanceof QuirtError ? new QuirtError("checkpoint_incompatible", "Checkpoint restore is incompatible with the current host state") : cause; }
    record = context.state.power.putInstance({ ...record, state: "ready", recoveryClassification: "restored_on_same_host_contract", health: { state: "restored", portable: false }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordCheckpoint(record.instanceId, { checkpointId: String(record.configuration.checkpointId), processIdentity: record.configuration.processIdentity as Record<string, unknown>, namespaces: record.configuration.namespaces as Record<string, unknown>, cgroup: { raw: record.configuration.cgroup }, manifest: { files: observed.files, checkpointPath: path, portable: false }, integritySha256: observed.integritySha256, state: "restored" });
    context.state.power.appendEvent(record.instanceId, "checkpoint.restored", { portable: false });
    return { payload: { checkpoint: publicProviderInstance(record), restored: true, portable: false }, instanceId: record.instanceId };
  }

  private async remove(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Checkpoint identity");
    const path = requiredText(record.configuration.checkpointPath, "Checkpoint path", 32_768);
    if (record.state === "ready") throw new QuirtError("instance_conflict", "Stop the restored process before removing its checkpoint images");
    await rm(path, { recursive: true, force: false });
    record = context.state.power.putInstance({ ...record, state: "stopped", health: { state: "removed" }, cleanupStatus: "complete", lastProbeAt: new Date().toISOString() });
    context.state.power.recordCheckpoint(record.instanceId, { checkpointId: String(record.configuration.checkpointId), processIdentity: record.configuration.processIdentity as Record<string, unknown>, namespaces: record.configuration.namespaces as Record<string, unknown>, cgroup: { raw: record.configuration.cgroup }, manifest: { removed: true, checkpointPath: path }, integritySha256: String(record.configuration.integritySha256), state: "removed" });
    context.state.power.appendEvent(record.instanceId, "checkpoint.removed", {});
    return { payload: { checkpoint: publicProviderInstance(record) }, instanceId: record.instanceId };
  }
}

function desktopReferences(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): Record<string, string> {
  return context.state.power.credentialReferences(record.instanceId);
}

export class VncDesktopProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "desktop.vnc";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.desktop;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Desktop");
    switch (operation) {
      case "quirt.desktop.open": return await this.open(payload, context);
      case "quirt.desktop.list": return providerList(context, this.providerId, payload, "Desktop");
      case "quirt.desktop.capture": return await this.capture(payload, context);
      case "quirt.desktop.input": return await this.input(payload, context);
      case "quirt.desktop.resize": return await this.resize(payload, context);
      case "quirt.desktop.close": return this.close(payload, context);
      default: throw new QuirtError("unknown_operation", "Desktop operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async open(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/Xvnc", ["-version"]);
    const references = credentialReferences(payload.credentialReferences);
    const passwordFile = references.passwordFile === undefined ? undefined : absolutePath(references.passwordFile, "Desktop password reference");
    if (passwordFile === undefined) throw new QuirtError("credentials_unavailable", "Authenticated desktop requires a password-file reference");
    const display = integer(payload.display, "Desktop display", 1, 1, 999);
    const port = integer(payload.port, "Desktop port", 5900 + display, 1, 65535);
    const width = integer(payload.width, "Desktop width", 1280, 320, 7680);
    const height = integer(payload.height, "Desktop height", 720, 200, 4320);
    const depth = integer(payload.depth, "Desktop depth", 24, 16, 32);
    const expiresAt = payload.expiresInSeconds === undefined ? new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString() : new Date(Date.now() + integer(payload.expiresInSeconds, "Desktop expiry", 3600, 60, 7 * 86400) * 1000).toISOString();
    let record = createInstance(context, { providerId: this.providerId, configuration: { display, port, width, height, depth, bindAddress: "127.0.0.1" }, credentialReferences: references, ports: [{ protocol: "tcp", bindAddress: "127.0.0.1", port, state: "reserved" }], expiresAt, state: "starting", health: { state: "starting", authenticated: true, private: true } });
    try {
      record = await startManagedJob(context, record, { executable: "/usr/bin/Xvnc", arguments: [":" + display, "-localhost", "-rfbauth", passwordFile, "-rfbport", String(port), "-geometry", width + "x" + height, "-depth", String(depth), "-SecurityTypes", "VncAuth"], eventType: "desktop.ready" });
    await delay(200, undefined, { signal: context.signal });
    const jobId = record.relatedJobs.at(-1);
    if (jobId !== undefined) {
      const job = context.jobs.get(jobId, context.ownerPrincipalFingerprint);
      if (job.status !== "running" && job.status !== "starting") {
        const stderr = context.jobs.read(jobId, context.ownerPrincipalFingerprint, "stderr", 0, 4096).bytes.toString("utf8");
        const conflict = /address already in use|cannot bind|failed to bind/iu.test(stderr);
        context.state.power.putInstance({ ...record, state: "failed", failureClassification: conflict ? "port_unavailable" : "desktop_unavailable", health: { state: "failed" }, cleanupStatus: "complete", lastProbeAt: new Date().toISOString() });
        throw new QuirtError(conflict ? "port_unavailable" : "desktop_unavailable", conflict ? "Desktop port is unavailable" : "Desktop process exited before readiness", true);
      }
    }
    record = context.state.power.putInstance({ ...record, ports: record.ports.map((item) => ({ ...item, state: "listening" })), health: { state: "healthy", authenticated: true, private: true }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordDesktop(record.instanceId, ":" + display, { protocol: "vnc", bindAddress: "127.0.0.1", port, authenticated: true, private: true }, { width, height, depth, expiresAt }, "ready");
      return { payload: { desktop: publicProviderInstance(record), attach: { protocol: "vnc", bindAddress: "127.0.0.1", port, private: true, credentialReference: "passwordFile" } }, instanceId: record.instanceId };
    } catch (cause) {
      cleanupManagedFailure(context, record, cause);
      throw cause;
    }
  }

  private async capture(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Desktop identity");
    await requireExecutable(context, "/usr/bin/xwd", ["-version"]);
    const display = ":" + integer(record.configuration.display, "Desktop display", 1, 1, 999);
    const outputPath = payload.outputPath === undefined ? context.config.stateRoot + "/providers/desktop/" + record.instanceId + "-" + Date.now() + ".xwd" : absolutePath(payload.outputPath, "Desktop capture path");
    await mkdir(dirname(outputPath), { recursive: true, mode: 0o700 });
    await runChecked(context, { executable: "/usr/bin/xwd", arguments: ["-root", "-silent", "-display", display, "-out", outputPath], maximumOutputBytes: 1024 * 1024, timeoutMs: 30_000 });
    const info = await stat(outputPath), sha256 = await digestFile(outputPath);
    const inline = payload.inline === true && info.size <= Math.min(context.config.maxFrameBytes - 4096, 4 * 1024 * 1024) ? await readFile(outputPath) : undefined;
    context.state.power.appendEvent(record.instanceId, "desktop.capture", { path: outputPath, sha256, sizeBytes: info.size });
    return { payload: { instanceId: record.instanceId, capture: { path: outputPath, sha256, sizeBytes: info.size, mediaType: "image/x-xwindowdump", inline: inline !== undefined } }, binary: inline, instanceId: record.instanceId };
  }

  private async input(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Desktop identity");
    await requireExecutable(context, "/usr/bin/xdotool", ["version"]);
    const action = payload.action === "key" || payload.action === "type" || payload.action === "mousemove" || payload.action === "click" ? payload.action : (() => { throw new QuirtError("invalid_request", "Desktop input action is invalid"); })();
    const args: string[] = [];
    if (action === "key") args.push("key", requiredText(payload.value, "Desktop key", 256));
    if (action === "type") args.push("type", "--delay", String(integer(payload.delayMs, "Desktop typing delay", 1, 0, 10_000)), requiredText(payload.value, "Desktop text", 65_536));
    if (action === "mousemove") args.push("mousemove", String(integer(payload.x, "Desktop x", 0, 0, 100_000)), String(integer(payload.y, "Desktop y", 0, 0, 100_000)));
    if (action === "click") args.push("click", String(integer(payload.button, "Desktop mouse button", 1, 1, 32)));
    await runChecked(context, { executable: "/usr/bin/xdotool", arguments: args, environment: { DISPLAY: ":" + String(record.configuration.display) }, maximumOutputBytes: 64 * 1024, timeoutMs: 10_000 });
    context.state.power.appendEvent(record.instanceId, "desktop.input", { action });
    return { payload: { instanceId: record.instanceId, action, accepted: true }, instanceId: record.instanceId };
  }

  private async resize(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Desktop identity");
    await requireExecutable(context, "/usr/bin/xrandr", ["--version"]);
    const width = integer(payload.width, "Desktop width", 1280, 320, 7680), height = integer(payload.height, "Desktop height", 720, 200, 4320);
    await runChecked(context, { executable: "/usr/bin/xrandr", arguments: ["--fb", width + "x" + height], environment: { DISPLAY: ":" + String(record.configuration.display) }, maximumOutputBytes: 64 * 1024, timeoutMs: 10_000 });
    record = context.state.power.putInstance({ ...record, configuration: { ...record.configuration, width, height }, health: { state: "healthy", width, height }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordDesktop(record.instanceId, ":" + String(record.configuration.display), { protocol: "vnc", bindAddress: "127.0.0.1", port: record.configuration.port, authenticated: true, private: true }, { width, height, depth: record.configuration.depth, expiresAt: record.expiresAt }, "ready");
    context.state.power.appendEvent(record.instanceId, "desktop.resized", { width, height });
    return { payload: { desktop: publicProviderInstance(record) }, instanceId: record.instanceId };
  }

  private close(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Desktop identity");
    const stopped = stopManaged(context, record, payload.force === true);
    context.state.power.recordDesktop(record.instanceId, ":" + String(record.configuration.display), { protocol: "vnc", bindAddress: "127.0.0.1", port: record.configuration.port, authenticated: true, private: true }, { width: record.configuration.width, height: record.configuration.height, depth: record.configuration.depth }, "closed");
    return { payload: { desktop: publicProviderInstance(stopped) }, instanceId: record.instanceId };
  }
}

function hostReferences(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): { identityFile: string; knownHostsFile: string } {
  const references = context.state.power.credentialReferences(record.instanceId);
  if (references.identityFile === undefined || references.knownHostsFile === undefined) throw new QuirtError("credentials_unavailable", "Fleet SSH credential references are unavailable");
  return { identityFile: absolutePath(references.identityFile, "Fleet SSH identity reference"), knownHostsFile: absolutePath(references.knownHostsFile, "Fleet known-hosts reference") };
}

function sshTarget(record: QuirtProviderInstanceRecord): string {
  const host = requiredText(record.configuration.host, "Fleet host", 1024);
  const user = requiredText(record.configuration.user, "Fleet user", 256);
  if (host.startsWith("-") || user.startsWith("-") || /[\s\0]/u.test(host) || /[\s\0@]/u.test(user)) throw new QuirtError("invalid_request", "Fleet SSH target is invalid");
  return user + "@" + host;
}

function sshOptions(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): string[] {
  const refs = hostReferences(context, record);
  return ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + refs.knownHostsFile, "-o", "IdentitiesOnly=yes", "-i", refs.identityFile, "-p", String(integer(record.configuration.port, "Fleet SSH port", 22, 1, 65535))];
}

function scpOptions(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord): string[] {
  const options = sshOptions(context, record);
  return [...options.slice(0, -2), "-P", options.at(-1)!];
}

function remoteCommand(value: unknown): string {
  const tokens = stringList(value, "Fleet command arguments", 1024, 65_536);
  if (tokens.length === 0) throw new QuirtError("invalid_request", "Fleet command arguments are required");
  return tokens.map((token) => "'" + token.replaceAll("'", "'\\''") + "'").join(" ");
}

function fleetFailure(cause: unknown): QuirtError {
  if (!(cause instanceof QuirtError)) return new QuirtError("provider_degraded", "Fleet provider command failed", true);
  const details = cause.message.toLowerCase();
  if (/host key verification failed|remote host identification has changed|offending .* key/u.test(details)) return new QuirtError("host_key_mismatch", "Fleet target host-key verification failed");
  if (/permission denied|publickey|authentication failed/u.test(details)) return new QuirtError("credentials_rejected", "Fleet target rejected the configured credential references");
  if (/could not resolve hostname|connection refused|connection timed out|operation timed out|no route to host|network is unreachable/u.test(details)) return new QuirtError("fleet_host_unavailable", "Fleet target is unavailable", true);
  return cause;
}

export class SshFleetProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "fleet.ssh";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.fleet;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary, "Fleet");
    switch (operation) {
      case "quirt.host.add": return await this.add(payload, context);
      case "quirt.host.list": return providerList(context, this.providerId, payload, "Host");
      case "quirt.host.get": return providerGet(context, this.providerId, payload, "Host");
      case "quirt.host.remove": return this.remove(payload, context);
      case "quirt.host.shell": return await this.shell(payload, context);
      case "quirt.fleet.exec": return await this.exec(payload, context);
      case "quirt.fleet.copy": return await this.copy(payload, context);
      case "quirt.fleet.playbook": return await this.playbook(payload, context);
      case "quirt.fleet.status": return this.status(payload, context);
      default: throw new QuirtError("unknown_operation", "Fleet operation is unknown");
    }
  }

  recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    return recoverManaged(record, context);
  }

  private async add(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    await requireExecutable(context, "/usr/bin/ssh", ["-V"]);
    const host = requiredText(payload.host, "Fleet host", 1024), user = requiredText(payload.user, "Fleet user", 256);
    const port = integer(payload.port, "Fleet SSH port", 22, 1, 65535);
    const references = credentialReferences(payload.credentialReferences);
    if (references.identityFile === undefined || references.knownHostsFile === undefined) throw new QuirtError("credentials_unavailable", "Fleet host requires identity-file and known-hosts references");
    absolutePath(references.identityFile, "Fleet identity reference"); absolutePath(references.knownHostsFile, "Fleet known-hosts reference");
    const identity = createHash("sha256").update(user + "\0" + host + "\0" + port).digest("hex");
    const record = createInstance(context, { providerId: this.providerId, configuration: { host, user, port, targetIdentity: identity }, credentialReferences: references, state: "ready", health: { state: "configured", hostKeyVerification: "strict", contacted: false } });
    context.state.power.recordFleetInventory(record.instanceId, identity, [{ targetIdentity: identity, host, user, port }]);
    return { payload: { host: publicProviderInstance(record), targetIdentity: identity, contacted: false }, instanceId: record.instanceId };
  }

  private remove(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Host identity");
    const stopped = stopManaged(context, record, payload.force === true);
    context.state.power.appendEvent(record.instanceId, "fleet.host.removed", { targetIdentity: record.configuration.targetIdentity });
    return { payload: { host: publicProviderInstance(stopped) }, instanceId: record.instanceId };
  }

  private async shell(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record = providerInstance(context, this.providerId, payload.instanceId, "Host identity");
    const command = remoteCommand(payload.command);
    record = await startManagedJob(context, record, { executable: "/usr/bin/ssh", arguments: [...sshOptions(context, record), sshTarget(record), "--", command], eventType: "fleet.shell.started" });
    const runId = context.state.power.recordFleetRun(record.instanceId, "shell", "running", { targetIdentity: record.configuration.targetIdentity, jobId: record.relatedJobs.at(-1) });
    context.state.power.appendEvent(record.instanceId, "fleet.run", { runId, operation: "shell", state: "running" });
    return { payload: { runId, host: publicProviderInstance(record), jobId: record.relatedJobs.at(-1) }, instanceId: record.instanceId };
  }

  private targets(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtProviderInstanceRecord[] {
    const ids = stringList(payload.instanceIds, "Fleet target identities", 256, 128);
    if (ids.length === 0) throw new QuirtError("configuration_missing", "Fleet operation requires an explicit target list");
    return ids.map((id) => providerInstance(context, this.providerId, id, "Host identity"));
  }

  private async exec(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const targets = this.targets(payload, context);
    const command = remoteCommand(payload.command);
    const anchor = targets[0]!;
    const runId = context.state.power.recordFleetRun(anchor.instanceId, "exec", "running", { targets: targets.map((item) => item.configuration.targetIdentity), concurrency: 1 });
    const outcomes: Record<string, unknown>[] = [];
    for (const target of targets) {
      const identity = String(target.configuration.targetIdentity);
      try {
        const result = await runChecked(context, { executable: "/usr/bin/ssh", arguments: [...sshOptions(context, target), sshTarget(target), "--", command], maximumOutputBytes: integer(payload.maximumBytesPerHost, "Fleet per-host output bound", 1024 * 1024, 1, 4 * 1024 * 1024), timeoutMs: integer(payload.timeoutMs, "Fleet host timeout", 60_000, 1000, 86400 * 1000) });
        const output = { targetIdentity: identity, state: "succeeded", stdout: result.stdout.toString("utf8"), stderr: result.stderr.toString("utf8"), truncated: result.truncated };
        outcomes.push(output); context.state.power.recordFleetOutcome(runId, identity, "succeeded", output);
      } catch (cause) {
        const failure = fleetFailure(cause);
        const output = { targetIdentity: identity, state: "failed", errorCode: failure.code };
        outcomes.push(output); context.state.power.recordFleetOutcome(runId, identity, "failed", output);
      }
    }
    const state = outcomes.every((item) => item.state === "succeeded") ? "succeeded" : outcomes.some((item) => item.state === "succeeded") ? "partial" : "failed";
    context.state.power.recordFleetRun(anchor.instanceId, "exec", state, { targetCount: targets.length, outcomes }, runId);
    context.state.power.appendEvent(anchor.instanceId, "fleet.run", { runId, operation: "exec", state, targetCount: targets.length });
    return { payload: { runId, state, outcomes, concurrency: 1 }, instanceId: anchor.instanceId };
  }

  private async copy(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const target = providerInstance(context, this.providerId, payload.instanceId, "Host identity");
    await requireExecutable(context, "/usr/bin/scp", ["-V"]);
    const localPath = absolutePath(payload.localPath, "Fleet local path");
    const remotePath = requiredText(payload.remotePath, "Fleet remote path", 32_768);
    if (!/^[A-Za-z0-9_./-]+$/u.test(remotePath) || remotePath.startsWith("-")) throw new QuirtError("invalid_request", "Fleet remote path is unsafe");
    const direction = payload.direction === "download" ? "download" : payload.direction === "upload" || payload.direction === undefined ? "upload" : (() => { throw new QuirtError("invalid_request", "Fleet copy direction is invalid"); })();
    const remote = sshTarget(target) + ":" + remotePath;
    const runId = context.state.power.recordFleetRun(target.instanceId, "copy", "running", { targetIdentity: target.configuration.targetIdentity, direction, localPath, remotePath });
    const args = [...scpOptions(context, target), direction === "upload" ? localPath : remote, direction === "upload" ? remote : localPath];
    try {
      const result = await runChecked(context, { executable: "/usr/bin/scp", arguments: args, maximumOutputBytes: 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Fleet copy timeout", 60 * 60 * 1000, 1000, 7 * 86400 * 1000) });
      const digest = createHash("sha256").update(result.stdout).update(result.stderr).digest("hex");
      context.state.power.recordFleetOutcome(runId, String(target.configuration.targetIdentity), "succeeded", { direction, outputDigest: digest });
      context.state.power.recordFleetRun(target.instanceId, "copy", "succeeded", { direction, outputDigest: digest }, runId);
      return { payload: { runId, state: "succeeded", direction, outputDigest: digest }, instanceId: target.instanceId };
    } catch (cause) {
      const failure = fleetFailure(cause);
      context.state.power.recordFleetOutcome(runId, String(target.configuration.targetIdentity), "failed", { errorCode: failure.code });
      context.state.power.recordFleetRun(target.instanceId, "copy", "failed", { direction, errorCode: failure.code }, runId);
      context.state.power.appendEvent(target.instanceId, "fleet.run", { runId, operation: "copy", state: "failed", errorCode: failure.code });
      throw failure;
    }
  }

  private async playbook(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const targets = this.targets(payload, context), anchor = targets[0]!;
    await requireExecutable(context, "/usr/bin/ansible-playbook", ["--version"]);
    const inventoryPath = absolutePath(payload.inventoryPath, "Fleet inventory path"), playbookPath = absolutePath(payload.playbookPath, "Fleet playbook path");
    const limit = targets.map((item) => requiredText(item.configuration.host, "Fleet host", 1024)).join(",");
    const firstReferences = hostReferences(context, anchor);
    if (/\s/u.test(firstReferences.knownHostsFile)) throw new QuirtError("invalid_request", "Fleet known-hosts reference cannot contain whitespace for the Ansible adapter");
    for (const target of targets) {
      const references = hostReferences(context, target);
      if (references.identityFile !== firstReferences.identityFile || references.knownHostsFile !== firstReferences.knownHostsFile) throw new QuirtError("instance_conflict", "A playbook run requires one shared credential-reference set");
    }
    const runId = context.state.power.recordFleetRun(anchor.instanceId, "playbook", "running", { targets: targets.map((item) => item.configuration.targetIdentity), inventoryPath, playbookPath });
    try {
      const result = await runChecked(context, { executable: "/usr/bin/ansible-playbook", arguments: ["--inventory", inventoryPath, "--limit", limit, "--private-key", firstReferences.identityFile, playbookPath], environment: { ANSIBLE_HOST_KEY_CHECKING: "True", ANSIBLE_SSH_ARGS: "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + firstReferences.knownHostsFile + " -o IdentitiesOnly=yes" }, maximumOutputBytes: 4 * 1024 * 1024, timeoutMs: integer(payload.timeoutMs, "Fleet playbook timeout", 4 * 60 * 60 * 1000, 1000, 7 * 86400 * 1000) });
      const outputDigest = createHash("sha256").update(result.stdout).update(result.stderr).digest("hex");
      for (const target of targets) context.state.power.recordFleetOutcome(runId, String(target.configuration.targetIdentity), "succeeded", { outputDigest });
      context.state.power.recordFleetRun(anchor.instanceId, "playbook", "succeeded", { targetCount: targets.length, outputDigest }, runId);
      context.state.power.appendEvent(anchor.instanceId, "fleet.run", { runId, operation: "playbook", state: "succeeded" });
      return { payload: { runId, state: "succeeded", targetCount: targets.length, outputDigest }, instanceId: anchor.instanceId };
    } catch (cause) {
      const failure = fleetFailure(cause);
      for (const target of targets) context.state.power.recordFleetOutcome(runId, String(target.configuration.targetIdentity), "failed", { errorCode: failure.code });
      context.state.power.recordFleetRun(anchor.instanceId, "playbook", "failed", { targetCount: targets.length, errorCode: failure.code }, runId);
      context.state.power.appendEvent(anchor.instanceId, "fleet.run", { runId, operation: "playbook", state: "failed", errorCode: failure.code });
      throw failure;
    }
  }

  private status(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record = providerInstance(context, this.providerId, payload.instanceId, "Host identity");
    const page = context.state.power.readEvents(record.instanceId, context.ownerPrincipalFingerprint, context.targetHost, integer(payload.after, "Fleet event cursor", -1, -1, Number.MAX_SAFE_INTEGER), integer(payload.maximumEvents, "Fleet event page size", 100, 1, 1000));
    const runId = optionalText(payload.runId, "Fleet run identity", 128);
    const events = runId === undefined ? page.events : page.events.filter((event) => (event.payload as Record<string, unknown>).runId === runId);
    return { payload: { host: publicProviderInstance(record), runId: runId ?? null, events, nextSequence: page.nextSequence, truncated: page.truncated }, instanceId: record.instanceId };
  }
}
