import { isAbsolute, normalize } from "node:path";
import { QuirtError } from "../error.js";
import {
  publicProviderInstance,
  safeProviderConfiguration,
  type QuirtPowerProviderContext,
  type QuirtPowerProviderResult
} from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";

export function noBinary(binary: Buffer, family: string): void {
  if (binary.length !== 0) throw new QuirtError("invalid_request", family + " operations do not accept binary input");
}

export function requiredText(value: unknown, label: string, maximum = 4096): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || Buffer.byteLength(value) > maximum) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

export function optionalText(value: unknown, label: string, maximum = 4096): string | undefined {
  return value === undefined ? undefined : requiredText(value, label, maximum);
}

export function integer(value: unknown, label: string, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

export function booleanValue(value: unknown, label: string, fallback = false): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

export function stringList(value: unknown, label: string, maximumItems = 1024, maximumBytes = 65_536): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maximumItems || value.some((item) => typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > maximumBytes)) throw new QuirtError("invalid_request", label + " is invalid");
  return [...value] as string[];
}

export function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new QuirtError("invalid_request", label + " is invalid");
  return { ...(value as Record<string, unknown>) };
}

export function absolutePath(value: unknown, label: string): string {
  const path = requiredText(value, label, 32_768);
  if (!isAbsolute(path)) throw new QuirtError("invalid_request", label + " must be absolute");
  return normalize(path);
}

export function credentialReferences(value: unknown, label = "Credential references"): Record<string, string> {
  if (value === undefined) return {};
  const source = objectValue(value, label);
  if (Object.keys(source).length > 32) throw new QuirtError("invalid_request", label + " are too large");
  const output: Record<string, string> = {};
  for (const [name, reference] of Object.entries(source)) {
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,63}$/u.test(name) || typeof reference !== "string" || reference.length === 0 || reference.includes("\0") || Buffer.byteLength(reference) > 4096) throw new QuirtError("invalid_request", label + " are invalid");
    output[name] = reference;
  }
  return output;
}

export function stringEnvironment(value: unknown, label: string): Record<string, string> {
  if (value === undefined) return {};
  const source = objectValue(value, label);
  if (Object.keys(source).length > 512) throw new QuirtError("invalid_request", label + " is too large");
  const output: Record<string, string> = {};
  for (const [name, item] of Object.entries(source)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || /password|secret|token|private.?key|credential/iu.test(name) || typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > 65_536) throw new QuirtError("invalid_request", label + " is invalid or contains a secret-like key");
    output[name] = item;
  }
  return output;
}

export function providerInstance(context: QuirtPowerProviderContext, providerId: string, value: unknown, label: string): QuirtProviderInstanceRecord {
  const instanceId = requiredText(value, label, 128);
  const record = context.state.power.getInstance(instanceId, context.ownerPrincipalFingerprint, context.targetHost);
  if (record.providerId !== providerId) throw new QuirtError("instance_conflict", label + " belongs to a different provider");
  return record;
}

export function providerList(context: QuirtPowerProviderContext, providerId: string, payload: Readonly<Record<string, unknown>>, noun: string): QuirtPowerProviderResult {
  const page = context.state.power.listInstances(context.ownerPrincipalFingerprint, {
    providerId,
    maximum: integer(payload.maximum, noun + " page size", 100, 1, 1000),
    afterCreatedAt: optionalText(payload.afterCreatedAt, noun + " created-at cursor", 64),
    afterInstanceId: optionalText(payload.afterInstanceId, noun + " identity cursor", 128)
  });
  return { payload: { instances: page.instances.map(publicProviderInstance), truncated: page.truncated, next: page.next } };
}

export function providerGet(context: QuirtPowerProviderContext, providerId: string, payload: Readonly<Record<string, unknown>>, noun: string): QuirtPowerProviderResult {
  const record = providerInstance(context, providerId, payload.instanceId, noun + " identity");
  const includeEvents = payload.includeEvents === true;
  const page = includeEvents ? context.state.power.readEvents(
    record.instanceId,
    context.ownerPrincipalFingerprint,
    context.targetHost,
    integer(payload.after, noun + " event cursor", -1, -1, Number.MAX_SAFE_INTEGER),
    integer(payload.maximumEvents, noun + " event page size", 100, 1, 1000)
  ) : undefined;
  return { payload: { instance: publicProviderInstance(record), events: page?.events ?? [], nextSequence: page?.nextSequence ?? null, eventsTruncated: page?.truncated ?? false } };
}

export function createInstance(context: QuirtPowerProviderContext, input: {
  providerId: string;
  configuration?: Readonly<Record<string, unknown>>;
  credentialReferences?: Readonly<Record<string, string>>;
  paths?: readonly string[];
  ports?: readonly Readonly<Record<string, unknown>>[];
  relatedSessions?: readonly string[];
  relatedJobs?: readonly string[];
  relatedArtifacts?: readonly string[];
  relatedTransfers?: readonly string[];
  expiresAt?: string | null;
  state?: "creating" | "starting" | "ready" | "degraded" | "stopped" | "unavailable";
  health?: Readonly<Record<string, unknown>>;
}): QuirtProviderInstanceRecord {
  const references = input.credentialReferences ?? {};
  const record = context.state.power.putInstance({
    providerId: input.providerId,
    providerVersion: "1",
    ownerPrincipalFingerprint: context.ownerPrincipalFingerprint,
    targetHost: context.targetHost,
    state: input.state ?? "creating",
    configuration: safeProviderConfiguration(input.configuration ?? {}),
    credentialReferences: Object.values(references),
    paths: input.paths ?? [],
    ports: input.ports ?? [],
    relatedSessions: input.relatedSessions ?? [],
    relatedJobs: input.relatedJobs ?? [],
    relatedArtifacts: input.relatedArtifacts ?? [],
    relatedTransfers: input.relatedTransfers ?? [],
    health: input.health ?? { state: input.state ?? "creating" },
    cleanupStatus: input.state === "stopped" ? "complete" : "pending",
    expiresAt: input.expiresAt ?? null,
    lastProbeAt: new Date().toISOString()
  });
  if (Object.keys(references).length > 0) context.state.power.recordCredentialReferences(record.instanceId, references);
  context.state.power.appendEvent(record.instanceId, "lifecycle." + record.state, { providerId: input.providerId });
  return record;
}

export async function requireExecutable(context: QuirtPowerProviderContext, path: string, versionArguments: readonly string[] = ["--version"], minimumVersion?: string): Promise<void> {
  const probe = await context.runtime.probeExecutable(path, versionArguments, minimumVersion);
  if (!probe.available) throw new QuirtError("executable_missing", "Required provider executable is unavailable");
  if (probe.versionSupported === false) throw new QuirtError("executable_version_unsupported", "Required provider executable version is unsupported");
}

export async function runChecked(context: QuirtPowerProviderContext, input: {
  executable: string;
  arguments?: readonly string[];
  workingDirectory?: string;
  environment?: Readonly<Record<string, string>>;
  maximumOutputBytes?: number;
  timeoutMs?: number;
}): Promise<{ stdout: Buffer; stderr: Buffer; truncated: boolean }> {
  let result;
  try {
    result = await context.runtime.run({ ...input, signal: context.signal });
  } catch (cause) {
    if (cause instanceof QuirtError) throw cause;
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new QuirtError("executable_missing", "Provider executable is unavailable");
    if (code === "EACCES" || code === "EPERM") throw new QuirtError("authorization_failed", "Provider execution permission was denied");
    throw cause;
  }
  if (result.truncated) throw new QuirtError("output_truncated", "Provider output exceeded the bounded result; use events or an artifact");
  if (result.exitCode !== 0) {
    const details = result.stderr.subarray(0, 4096).toString("utf8").replace(/[\r\n]+/gu, " ").slice(0, 512);
    throw new QuirtError("provider_degraded", details.length === 0 ? "Provider command failed" : "Provider command failed: " + details, true);
  }
  return result;
}

export async function startManagedJob(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord, input: {
  executable: string;
  arguments: readonly string[];
  workingDirectory?: string;
  environment?: Readonly<Record<string, string>>;
  timeoutMs?: number;
  eventType?: string;
}): Promise<QuirtProviderInstanceRecord> {
  const launched = await context.jobs.exec(context.requestId + "-" + record.instanceId, context.ownerPrincipalFingerprint, {
    executable: input.executable,
    arguments: [...input.arguments],
    workingDirectory: input.workingDirectory ?? "/",
    environment: { ...(input.environment ?? {}) },
    timeoutMs: input.timeoutMs ?? 7 * 24 * 60 * 60 * 1000,
    detach: true,
    pty: false,
    shell: false
  });
  const relatedJobs = [...record.relatedJobs, launched.job.jobId];
  let updated = context.state.power.putInstance({
    ...record,
    state: "starting",
    relatedJobs,
    health: { state: "starting", durableJobPersisted: true },
    cleanupStatus: "pending",
    lastProbeAt: new Date().toISOString()
  });
  try {
    const processIdentities: Readonly<Record<string, unknown>>[] = [...record.processIdentities];
    if (launched.job.processId !== null) {
      const identity = await context.runtime.processIdentity(launched.job.processId);
      processIdentities.push(identity);
      context.state.power.recordProcess(record.instanceId, identity);
    }
    updated = context.state.power.putInstance({
      ...updated,
      state: "ready",
      processIdentities,
      health: { state: "healthy" },
      cleanupStatus: "active",
      lastProbeAt: new Date().toISOString()
    });
    context.state.power.appendEvent(record.instanceId, input.eventType ?? "lifecycle.ready", { jobId: launched.job.jobId });
    return updated;
  } catch (cause) {
    cleanupManagedFailure(context, updated, cause);
    throw cause;
  }
}

export function readJobLogs(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord, payload: Readonly<Record<string, unknown>>, noun: string): QuirtPowerProviderResult {
  const jobId = optionalText(payload.jobId, noun + " job identity", 128) ?? record.relatedJobs.at(-1);
  if (jobId === undefined) return { payload: { instanceId: record.instanceId, jobId: null, stream: null, startOffset: 0, endOffset: 0, nextOffset: 0, retainedStartOffset: 0, byteCount: 0, eof: true }, binary: Buffer.alloc(0) };
  if (!record.relatedJobs.includes(jobId)) throw new QuirtError("instance_conflict", noun + " job does not belong to the instance");
  const stream = payload.stream === "stderr" ? "stderr" : payload.stream === "stdout" || payload.stream === undefined ? "stdout" : (() => { throw new QuirtError("invalid_request", noun + " log stream is invalid"); })();
  const page = context.jobs.read(jobId, context.ownerPrincipalFingerprint, stream, integer(payload.after, noun + " log offset", 0, 0, Number.MAX_SAFE_INTEGER), integer(payload.maximumBytes, noun + " log page size", context.config.outputChunkBytes, 1, Math.min(context.config.maxFrameBytes - 4096, 1024 * 1024)));
  return { payload: { instanceId: record.instanceId, jobId, stream, startOffset: page.startOffset, endOffset: page.endOffset, nextOffset: page.nextOffset, retainedStartOffset: page.retainedStartOffset, byteCount: page.bytes.length, eof: page.eof }, binary: page.bytes };
}

export function stopManaged(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord, force = false): QuirtProviderInstanceRecord {
  let current = context.state.power.putInstance({ ...record, state: "stopping", health: { state: "stopping" }, lastProbeAt: new Date().toISOString() });
  context.state.power.appendEvent(record.instanceId, "lifecycle.stopping", {});
  for (const jobId of current.relatedJobs) {
    try { context.jobs.cancel(jobId, context.ownerPrincipalFingerprint, force); }
    catch (cause) { if (!(cause instanceof QuirtError && (cause.code === "process_exited" || cause.code === "not_found"))) throw cause; }
  }
  current = context.state.power.putInstance({ ...current, state: "stopped", health: { state: "stopped" }, cleanupStatus: "complete", ports: current.ports.map((port) => ({ ...port, state: "released" })), lastProbeAt: new Date().toISOString() });
  context.state.power.appendEvent(record.instanceId, "cleanup.complete", {});
  return current;
}

export function cleanupManagedFailure(context: QuirtPowerProviderContext, record: QuirtProviderInstanceRecord, cause: unknown): QuirtProviderInstanceRecord {
  let cleaned = record;
  try { cleaned = stopManaged(context, record, true); } catch { /* preserve the original provider failure */ }
  const errorCode = cause instanceof QuirtError ? cause.code : "internal_error";
  const failed = context.state.power.putInstance({
    ...cleaned,
    state: "failed",
    failureClassification: errorCode,
    health: { state: "failed", errorCode },
    cleanupStatus: "complete",
    ports: cleaned.ports.map((port) => ({ ...port, state: "released" })),
    lastProbeAt: new Date().toISOString()
  });
  context.state.power.appendEvent(record.instanceId, "failure", { errorCode, cleanupStatus: "complete" });
  return failed;
}

export async function recoverManaged(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
  const jobs = record.relatedJobs;
  let adopted = jobs.length === 0;
  for (const jobId of jobs) {
    try {
      const job = context.jobs.get(jobId, record.ownerPrincipalFingerprint);
      if (job.status !== "running" && job.status !== "starting") adopted = false;
    } catch { adopted = false; }
  }
  const classification = adopted ? "adopted_durable_identity" : "managed_process_lost";
  context.state.power.putInstance({
    ...record,
    state: adopted ? "ready" : "lost",
    recoveryClassification: classification,
    failureClassification: adopted ? null : "provider_lost",
    health: { state: adopted ? "healthy" : "lost" },
    lastProbeAt: new Date().toISOString()
  });
  context.state.power.recordRecovery(record.instanceId, classification, { relatedJobs: jobs });
}

export function resultFor(record: QuirtProviderInstanceRecord, key = "instance"): QuirtPowerProviderResult {
  return { payload: { [key]: publicProviderInstance(record) }, instanceId: record.instanceId };
}
