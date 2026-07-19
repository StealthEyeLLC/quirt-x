import { createServer, connect } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { QUIRT_POWER_OPERATION_GROUPS, type QuirtPowerOperation } from "../power-catalog.js";
import { QuirtError } from "../error.js";
import {
  publicProviderInstance,
  safeProviderConfiguration,
  type QuirtPowerProviderAdapter,
  type QuirtPowerProviderContext,
  type QuirtPowerProviderResult
} from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";

const PRIVATE_BINDINGS = new Set(["127.0.0.1", "::1", "localhost"]);
const WILDCARD_BINDINGS = new Set(["0.0.0.0", "::", "*"]);

function text(value: unknown, label: string, options: { optional?: boolean; maximum?: number } = {}): string | undefined {
  if (value === undefined && options.optional) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || Buffer.byteLength(value) > (options.maximum ?? 4096)) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

function integer(value: unknown, label: string, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

function argumentsList(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 1024 || value.some((item) => typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > 64 * 1024)) throw new QuirtError("invalid_request", "Preview arguments are invalid");
  return [...value] as string[];
}

function environment(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new QuirtError("invalid_request", "Preview environment is invalid");
  const result: Record<string, string> = {};
  for (const [name, item] of Object.entries(value as Record<string, unknown>)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || /password|secret|token|private.?key/iu.test(name) || typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > 64 * 1024) throw new QuirtError("invalid_request", "Preview environment is invalid or contains a secret-like key");
    result[name] = item;
  }
  return result;
}

function binding(payload: Readonly<Record<string, unknown>>): { bindAddress: string; publicBinding: boolean } {
  const bindAddress = text(payload.bindAddress, "Preview bind address", { optional: true, maximum: 64 }) ?? "127.0.0.1";
  if (!PRIVATE_BINDINGS.has(bindAddress) && !WILDCARD_BINDINGS.has(bindAddress)) throw new QuirtError("invalid_request", "Preview bind address must be an explicit loopback or wildcard literal");
  const publicBinding = WILDCARD_BINDINGS.has(bindAddress);
  if (publicBinding && payload.allowPublicBinding !== true) throw new QuirtError("unsafe_listener", "Wildcard preview binding requires explicit authorization");
  return { bindAddress: bindAddress === "*" ? "0.0.0.0" : bindAddress, publicBinding };
}

async function selectPort(host: string, requested?: number): Promise<number> {
  const port = requested ?? 0;
  return await new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.once("error", () => reject(new QuirtError("port_unavailable", "Preview port is unavailable", true)));
    server.listen({ host, port, exclusive: true }, () => {
      const address = server.address();
      const selected = typeof address === "object" && address !== null ? address.port : 0;
      server.close((cause) => cause === undefined ? resolve(selected) : reject(new QuirtError("port_unavailable", "Preview port reservation could not be released", true)));
    });
  });
}

async function tcpReady(host: string, port: number, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted === true) throw new QuirtError("canceled", "Preview readiness was canceled", true);
  return await new Promise<boolean>((resolve) => {
    const socket = connect({ host, port });
    const done = (ready: boolean): void => { socket.destroy(); resolve(ready); };
    socket.setTimeout(500, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

async function ready(input: { mode: "none" | "tcp" | "http"; host: string; port: number; path: string; timeoutMs: number; signal?: AbortSignal }): Promise<boolean> {
  if (input.mode === "none") return true;
  const deadline = Date.now() + input.timeoutMs;
  do {
    if (input.signal?.aborted === true) throw new QuirtError("canceled", "Preview readiness was canceled", true);
    try {
      if (input.mode === "tcp" && await tcpReady(input.host, input.port, input.signal)) return true;
      if (input.mode === "http") {
        const response = await fetch("http://" + (input.host === "::1" ? "[::1]" : input.host) + ":" + input.port + input.path, { redirect: "manual", signal: AbortSignal.timeout(1000) });
        if (response.status >= 100 && response.status < 500) return true;
      }
    } catch { /* retry until the bounded deadline */ }
    await delay(100, undefined, { signal: input.signal }).catch(() => { throw new QuirtError("canceled", "Preview readiness was canceled", true); });
  } while (Date.now() < deadline);
  return false;
}

export class PreviewProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "preview.process";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.preview;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    if (binary.length !== 0) throw new QuirtError("invalid_request", "Preview operations do not accept binary input");
    switch (operation) {
      case "quirt.preview.open": return await this.open(payload, context);
      case "quirt.preview.list": return this.list(payload, context);
      case "quirt.preview.get": return this.get(payload, context);
      case "quirt.preview.logs": return this.logs(payload, context);
      case "quirt.preview.close": return this.close(payload, context);
      default: throw new QuirtError("unknown_operation", "Preview operation is unknown");
    }
  }

  async recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    const jobId = record.relatedJobs[0];
    let state: "ready" | "lost" | "degraded" = "lost";
    let classification = "listener_unverified";
    if (jobId !== undefined) {
      try {
        const job = context.jobs.get(jobId, record.ownerPrincipalFingerprint);
        state = job.status === "running" || job.status === "starting" ? "ready" : "lost";
        classification = state === "ready" ? "adopted_job_identity" : "managed_process_exited";
      } catch { state = "lost"; classification = "managed_job_absent"; }
    } else {
      const port = typeof record.configuration.port === "number" ? record.configuration.port : 0;
      const host = typeof record.configuration.bindAddress === "string" ? record.configuration.bindAddress : "127.0.0.1";
      state = port > 0 && await tcpReady(host, port) ? "ready" : "lost";
      classification = state === "ready" ? "adopted_existing_listener" : "existing_listener_absent";
    }
    context.state.power.putInstance({ ...record, state, recoveryClassification: classification, failureClassification: state === "lost" ? "provider_lost" : null, health: { state: state === "ready" ? "healthy" : "lost" }, lastProbeAt: new Date().toISOString() });
    context.state.power.recordRecovery(record.instanceId, classification, { jobId: jobId ?? null });
  }

  private async open(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const kind = payload.kind === "existing" ? "existing" : payload.kind === "managed" || payload.kind === undefined ? "managed" : (() => { throw new QuirtError("invalid_request", "Preview kind is invalid"); })();
    const { bindAddress, publicBinding } = binding(payload);
    const requestedPort = payload.port === undefined ? undefined : integer(payload.port, "Preview port", 0, 1, 65535);
    if (kind === "existing" && requestedPort === undefined) throw new QuirtError("invalid_request", "Existing previews require an explicit port");
    const port = kind === "existing" ? requestedPort! : await selectPort(bindAddress, requestedPort);
    const readiness = payload.readiness === "none" || payload.readiness === "tcp" || payload.readiness === "http" ? payload.readiness : "http";
    const readinessPath = text(payload.readinessPath, "Preview readiness path", { optional: true, maximum: 2048 }) ?? "/";
    if (!readinessPath.startsWith("/") || readinessPath.startsWith("//")) throw new QuirtError("invalid_request", "Preview readiness path is invalid");
    const timeoutMs = integer(payload.readinessTimeoutMs, "Preview readiness timeout", 30_000, 100, 300_000);
    const workingDirectory = text(payload.workingDirectory, "Preview working directory", { optional: true }) ?? "/";
    const expiresAt = payload.expiresInSeconds === undefined ? null : new Date(Date.now() + integer(payload.expiresInSeconds, "Preview expiry", 3600, 60, 7 * 86400) * 1000).toISOString();
    let record = context.state.power.putInstance({
      providerId: this.providerId,
      providerVersion: "1",
      ownerPrincipalFingerprint: context.ownerPrincipalFingerprint,
      targetHost: context.targetHost,
      state: "starting",
      configuration: safeProviderConfiguration({ kind, bindAddress, port, readiness, readinessPath, workingDirectory, publicBinding, route: { scheme: "http", host: bindAddress, port, private: !publicBinding } }),
      ports: [{ protocol: "tcp", bindAddress, port, state: "reserved" }],
      paths: [workingDirectory],
      relatedSessions: typeof payload.sessionId === "string" ? [payload.sessionId] : [],
      relatedJobs: typeof payload.jobId === "string" ? [payload.jobId] : [],
      health: { state: "starting" },
      cleanupStatus: "pending",
      expiresAt
    });
    context.state.power.recordPort(record.instanceId, { protocol: "tcp", bindAddress, port, state: kind === "existing" ? "observed" : "reserved" });
    context.state.power.appendEvent(record.instanceId, "lifecycle.starting", { kind, bindAddress, port, publicBinding });

    let relatedJobs = [...record.relatedJobs];
    let processIdentities: Readonly<Record<string, unknown>>[] = [];
    try {
      if (kind === "managed") {
        const executable = text(payload.executable, "Preview executable", { optional: true });
        const script = text(payload.script, "Preview script", { optional: true, maximum: 1024 * 1024 });
        if ((executable === undefined) === (script === undefined)) throw new QuirtError("invalid_request", "Exactly one preview executable or script is required");
        const command = executable === undefined ? { executable: context.config.shellPath, arguments: ["-lc", script!] } : { executable, arguments: argumentsList(payload.arguments) };
        const launched = await context.jobs.exec(context.requestId + "-preview", context.ownerPrincipalFingerprint, {
          ...command,
          workingDirectory,
          environment: { ...environment(payload.environment), HOST: bindAddress, PORT: String(port) },
          timeoutMs: payload.lifetimeTimeoutMs === undefined ? 24 * 60 * 60 * 1000 : integer(payload.lifetimeTimeoutMs, "Preview lifetime", 0, 1000, 7 * 24 * 60 * 60 * 1000),
          detach: true,
          pty: false,
          shell: false
        });
        relatedJobs = [launched.job.jobId];
        if (launched.job.processId !== null) {
          const identity = await context.runtime.processIdentity(launched.job.processId);
          processIdentities = [identity];
          context.state.power.recordProcess(record.instanceId, identity);
        }
      }
      if (!await ready({ mode: readiness, host: bindAddress, port, path: readinessPath, timeoutMs, signal: context.signal })) throw new QuirtError("readiness_timeout", "Preview did not become ready before the bounded deadline", true);
      record = context.state.power.putInstance({ ...record, state: "ready", relatedJobs, processIdentities, ports: [{ protocol: "tcp", bindAddress, port, state: "listening" }], health: { state: "healthy", readiness, checkedAt: new Date().toISOString() }, cleanupStatus: "active", lastProbeAt: new Date().toISOString() });
      context.state.power.appendEvent(record.instanceId, "lifecycle.ready", { port, readiness });
      return { payload: { preview: publicProviderInstance(record), route: record.configuration.route }, instanceId: record.instanceId };
    } catch (cause) {
      for (const jobId of relatedJobs) { try { context.jobs.cancel(jobId, context.ownerPrincipalFingerprint, true); } catch { /* bounded cleanup */ } }
      record = context.state.power.putInstance({ ...record, state: "failed", relatedJobs, processIdentities, failureClassification: cause instanceof QuirtError ? cause.code : "internal_error", health: { state: "failed" }, cleanupStatus: "complete", lastProbeAt: new Date().toISOString() });
      context.state.power.appendEvent(record.instanceId, "failure", { errorCode: cause instanceof QuirtError ? cause.code : "internal_error" });
      throw cause;
    }
  }

  private list(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const page = context.state.power.listInstances(context.ownerPrincipalFingerprint, {
      providerId: this.providerId,
      maximum: integer(payload.maximum, "Preview page size", 100, 1, 1000),
      afterCreatedAt: text(payload.afterCreatedAt, "Preview created-at cursor", { optional: true, maximum: 64 }),
      afterInstanceId: text(payload.afterInstanceId, "Preview identity cursor", { optional: true, maximum: 128 })
    });
    return { payload: { previews: page.instances.map(publicProviderInstance), truncated: page.truncated, next: page.next } };
  }

  private get(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const instanceId = text(payload.instanceId, "Preview identity", { maximum: 128 })!;
    const record = context.state.power.getInstance(instanceId, context.ownerPrincipalFingerprint, context.targetHost);
    if (record.providerId !== this.providerId) throw new QuirtError("instance_conflict", "Provider instance is not an application preview");
    const events = payload.includeEvents === true ? context.state.power.readEvents(instanceId, context.ownerPrincipalFingerprint, context.targetHost, integer(payload.after, "Preview event cursor", -1, -1, Number.MAX_SAFE_INTEGER), integer(payload.maximumEvents, "Preview event page size", 100, 1, 1000)) : undefined;
    return { payload: { preview: publicProviderInstance(record), events: events?.events ?? [], nextSequence: events?.nextSequence ?? null, eventsTruncated: events?.truncated ?? false } };
  }

  private logs(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const instanceId = text(payload.instanceId, "Preview identity", { maximum: 128 })!;
    const record = context.state.power.getInstance(instanceId, context.ownerPrincipalFingerprint, context.targetHost);
    if (record.providerId !== this.providerId) throw new QuirtError("instance_conflict", "Provider instance is not an application preview");
    const jobId = record.relatedJobs[0];
    if (jobId === undefined) return { payload: { instanceId, stream: null, startOffset: 0, endOffset: 0, nextOffset: 0, retainedStartOffset: 0, byteCount: 0, eof: true }, binary: Buffer.alloc(0) };
    const stream = payload.stream === "stderr" ? "stderr" : payload.stream === "stdout" || payload.stream === undefined ? "stdout" : (() => { throw new QuirtError("invalid_request", "Preview log stream is invalid"); })();
    const page = context.jobs.read(jobId, context.ownerPrincipalFingerprint, stream, integer(payload.after, "Preview log offset", 0, 0, Number.MAX_SAFE_INTEGER), integer(payload.maximumBytes, "Preview log page size", context.config.outputChunkBytes, 1, Math.min(context.config.maxFrameBytes - 4096, 1024 * 1024)));
    return { payload: { instanceId, jobId, stream, startOffset: page.startOffset, endOffset: page.endOffset, nextOffset: page.nextOffset, retainedStartOffset: page.retainedStartOffset, byteCount: page.bytes.length, eof: page.eof }, binary: page.bytes };
  }

  private close(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const instanceId = text(payload.instanceId, "Preview identity", { maximum: 128 })!;
    let record = context.state.power.getInstance(instanceId, context.ownerPrincipalFingerprint, context.targetHost);
    if (record.providerId !== this.providerId) throw new QuirtError("instance_conflict", "Provider instance is not an application preview");
    record = context.state.power.putInstance({ ...record, state: "stopping", health: { state: "stopping" }, lastProbeAt: new Date().toISOString() });
    context.state.power.appendEvent(instanceId, "lifecycle.stopping", {});
    for (const jobId of record.relatedJobs) { try { context.jobs.cancel(jobId, context.ownerPrincipalFingerprint, payload.force === true); } catch (cause) { if (!(cause instanceof QuirtError && cause.code === "process_exited")) throw cause; } }
    record = context.state.power.putInstance({ ...record, state: "stopped", health: { state: "stopped" }, cleanupStatus: "complete", ports: record.ports.map((port) => ({ ...port, state: "released" })), lastProbeAt: new Date().toISOString() });
    context.state.power.appendEvent(instanceId, "cleanup.complete", {});
    return { payload: { preview: publicProviderInstance(record) }, instanceId };
  }
}
