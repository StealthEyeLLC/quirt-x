import { createHash } from "node:crypto";
import { access, readFile, readlink, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import type { QuirtConfig } from "./config.js";
import { QuirtError, errorCode } from "./error.js";
import type { QuirtJobManager } from "./job-manager.js";
import type { QuirtProcessService } from "./process-service.js";
import type { QuirtSessionManager } from "./session-manager.js";
import type { QuirtStateStore } from "./state.js";
import type { QuirtTmuxController } from "./tmux.js";
import {
  POWER_PROVIDER_DEFINITIONS,
  type PowerProviderAvailabilityState,
  type PowerProviderDefinition,
  type QuirtPowerOperation,
  powerProviderForOperation
} from "./power-catalog.js";
import type { QuirtProviderInstanceRecord } from "./power-state.js";

export interface PowerCommandResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: Buffer;
  truncated: boolean;
}

export interface PowerExecutableProbe {
  path: string;
  available: boolean;
  version: string | null;
  minimumVersion: string | null;
  versionSupported: boolean | null;
  executableIdentity: Readonly<Record<string, unknown>> | null;
  reason: string | null;
}

export interface PowerFeatureProbe {
  feature: string;
  available: boolean | null;
  reason: string;
}

export interface PowerProviderProbe {
  providerId: string;
  providerVersion: string;
  sourceImplemented: boolean;
  locallyTested: boolean;
  deterministicAdapterTested: boolean;
  liveHostTested: boolean;
  productionTested: boolean;
  classification: PowerProviderAvailabilityState;
  hostAvailable: boolean;
  executables: readonly PowerExecutableProbe[];
  requiredHostFeatures: readonly string[];
  requiredKernelFeatures: readonly string[];
  hostFeatureProbes: readonly PowerFeatureProbe[];
  kernelFeatureProbes: readonly PowerFeatureProbe[];
  requiredConfiguration: readonly string[];
  credentialsAvailable: boolean | null;
  reason: string;
  limitations: readonly string[];
  enabledOperations: readonly QuirtPowerOperation[];
  probedAt: string;
}

export interface PowerRunInput {
  executable: string;
  arguments?: readonly string[];
  workingDirectory?: string;
  environment?: Readonly<Record<string, string>>;
  timeoutMs?: number;
  maximumOutputBytes?: number;
  signal?: AbortSignal;
}

export interface QuirtPowerRuntime {
  probeExecutable(path: string, versionArguments: readonly string[], minimumVersion?: string): Promise<PowerExecutableProbe>;
  run(input: PowerRunInput): Promise<PowerCommandResult>;
  processIdentity(pid: number): Promise<Readonly<Record<string, unknown>>>;
}

function numericVersion(value: string): number[] {
  const match = /([0-9]+(?:\.[0-9]+){0,3})/u.exec(value);
  return match === null ? [] : match[1]!.split(".").map(Number);
}

function versionAtLeast(observed: string, minimum: string): boolean {
  const left = numericVersion(observed);
  const right = numericVersion(minimum);
  if (left.length === 0 || right.length === 0) return false;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    if (a !== b) return a > b;
  }
  return true;
}

function procStartTime(value: string): number {
  const close = value.lastIndexOf(")");
  if (close < 0) throw new QuirtError("process_identity_changed", "Provider process identity is malformed");
  const fields = value.slice(close + 2).trim().split(/\s+/u);
  const start = Number(fields[19]);
  if (!Number.isSafeInteger(start) || start < 1) throw new QuirtError("process_identity_changed", "Provider process start identity is unavailable");
  return start;
}

function boundedArgument(value: string, label: string): string {
  if (value.includes("\0") || Buffer.byteLength(value) > 64 * 1024) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

export class NodePowerRuntime implements QuirtPowerRuntime {
  async probeExecutable(path: string, versionArguments: readonly string[], minimumVersion?: string): Promise<PowerExecutableProbe> {
    try {
      await access(path);
      const identityStat = await stat(path);
      const result = await this.run({ executable: path, arguments: versionArguments, timeoutMs: 5000, maximumOutputBytes: 1024 * 1024 });
      const version = Buffer.concat([result.stdout, result.stderr]).toString("utf8").trim().split("\n")[0] ?? "";
      const versionObserved = result.exitCode === 0 && version.length > 0;
      const supported = minimumVersion === undefined ? true : versionObserved && versionAtLeast(version, minimumVersion);
      return {
        path,
        available: true,
        version: versionObserved ? version : null,
        minimumVersion: minimumVersion ?? null,
        versionSupported: supported,
        executableIdentity: Object.freeze({ device: Number(identityStat.dev), inode: Number(identityStat.ino), mode: identityStat.mode, size: identityStat.size, mtimeMs: identityStat.mtimeMs }),
        reason: supported ? versionObserved ? null : "executable exists; version output is unavailable" : "executable version is below the provider minimum or could not be verified"
      };
    } catch {
      return { path, available: false, version: null, minimumVersion: minimumVersion ?? null, versionSupported: null, executableIdentity: null, reason: "executable is absent" };
    }
  }

  run(input: PowerRunInput): Promise<PowerCommandResult> {
    const argumentsList = (input.arguments ?? []).map((value) => boundedArgument(value, "Provider argument"));
    boundedArgument(input.executable, "Provider executable");
    const maximum = input.maximumOutputBytes ?? 4 * 1024 * 1024;
    const timeoutMs = input.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64 * 1024 * 1024 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 24 * 60 * 60 * 1000) throw new QuirtError("invalid_request", "Provider execution bounds are invalid");
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      let total = 0;
      let truncated = false;
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      const child = spawn(input.executable, argumentsList, {
        cwd: input.workingDirectory,
        env: {
          PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          HOME: "/nonexistent",
          LANG: "C.UTF-8",
          ...input.environment
        },
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });
      const collect = (target: Buffer[]) => (chunk: Buffer) => {
        if (total >= maximum) { truncated = true; return; }
        const remaining = maximum - total;
        const kept = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        target.push(Buffer.from(kept));
        total += kept.length;
        if (kept.length !== chunk.length) truncated = true;
      };
      child.stdout.on("data", collect(stdout));
      child.stderr.on("data", collect(stderr));
      const abort = (): void => { child.kill("SIGTERM"); };
      input.signal?.addEventListener("abort", abort, { once: true });
      timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
      child.once("error", (cause) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        input.signal?.removeEventListener("abort", abort);
        reject(cause);
      });
      child.once("close", (code, signal) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        input.signal?.removeEventListener("abort", abort);
        if (input.signal?.aborted === true) { reject(new QuirtError("canceled", "Provider operation was canceled", true)); return; }
        resolve({ exitCode: code ?? 1, signal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), truncated });
      });
    });
  }

  async processIdentity(pid: number): Promise<Readonly<Record<string, unknown>>> {
    if (!Number.isSafeInteger(pid) || pid < 2) throw new QuirtError("invalid_request", "Provider process PID is invalid");
    const [statText, bootId, executablePath, executableStat] = await Promise.all([
      readFile("/proc/" + pid + "/stat", "utf8"),
      readFile("/proc/sys/kernel/random/boot_id", "utf8"),
      readlink("/proc/" + pid + "/exe"),
      stat("/proc/" + pid + "/exe")
    ]).catch(() => { throw new QuirtError("process_exited", "Provider process is unavailable"); });
    return Object.freeze({
      pid,
      startTimeTicks: procStartTime(statText),
      bootId: bootId.trim(),
      executablePath,
      executableDevice: Number(executableStat.dev),
      executableInode: Number(executableStat.ino)
    });
  }
}

export interface QuirtPowerProviderContext {
  config: QuirtConfig;
  state: QuirtStateStore;
  sessions: QuirtSessionManager;
  jobs: QuirtJobManager;
  tmux: QuirtTmuxController;
  processes: QuirtProcessService;
  runtime: QuirtPowerRuntime;
  ownerPrincipalFingerprint: string;
  targetHost: string;
  requestId: string;
  signal?: AbortSignal;
}

export interface QuirtPowerProviderResult {
  payload: Record<string, unknown>;
  binary?: Buffer;
  instanceId?: string;
}

export interface QuirtPowerProviderAdapter {
  readonly providerId: string;
  readonly operationIds: readonly QuirtPowerOperation[];
  execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult>;
  recover?(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void>;
}

export function publicProviderInstance(record: QuirtProviderInstanceRecord): Record<string, unknown> {
  const { ownerPrincipalFingerprint: _owner, credentialReferences, ...rest } = record;
  return { ...rest, credentialReferences: credentialReferences.map((reference) => ({ reference, available: null })) };
}

export function safeProviderConfiguration(input: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (/password|secret|token|private.?key|credentialvalue/iu.test(key)) continue;
    if (Buffer.isBuffer(value)) continue;
    output[key] = value;
  }
  return output;
}

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
  const objectValue = value as Record<string, unknown>;
  return "{" + Object.keys(objectValue).sort().map((key) => JSON.stringify(key) + ":" + stable(objectValue[key])).join(",") + "}";
}

function requestHash(operation: string, payload: Readonly<Record<string, unknown>>, binary: Buffer): string {
  return createHash("sha256").update(operation).update("\0").update(stable(payload)).update("\0").update(createHash("sha256").update(binary).digest()).digest("hex");
}

function storedResult(result: QuirtPowerProviderResult): Record<string, unknown> {
  if ((result.binary?.length ?? 0) > 1024 * 1024) throw new QuirtError("output_truncated", "Provider binary result must use an artifact or transfer reference");
  return {
    ...result.payload,
    ...(result.binary === undefined || result.binary.length === 0 ? {} : { __quirtBinaryBase64: result.binary.toString("base64") }),
    ...(result.instanceId === undefined ? {} : { __quirtInstanceId: result.instanceId })
  };
}

function replayResult(value: Readonly<Record<string, unknown>>): QuirtPowerProviderResult {
  const copy = { ...value };
  const encoded = typeof copy.__quirtBinaryBase64 === "string" ? copy.__quirtBinaryBase64 : undefined;
  const instanceId = typeof copy.__quirtInstanceId === "string" ? copy.__quirtInstanceId : undefined;
  delete copy.__quirtBinaryBase64;
  delete copy.__quirtInstanceId;
  return { payload: copy, binary: encoded === undefined ? Buffer.alloc(0) : Buffer.from(encoded, "base64"), instanceId };
}

async function pathFeature(feature: string, path: string): Promise<PowerFeatureProbe> {
  try { await access(path); return { feature, available: true, reason: "required host path is available: " + path }; }
  catch { return { feature, available: false, reason: "required host path is unavailable: " + path }; }
}

async function probeHostFeature(feature: string): Promise<PowerFeatureProbe> {
  switch (feature) {
    case "pty": return await pathFeature(feature, "/dev/ptmx");
    case "user_data_directory": return await pathFeature(feature, "/tmp");
    case "filesystem": return await pathFeature(feature, "/");
    case "procfs": return await pathFeature(feature, "/proc/self/stat");
    case "display infrastructure": {
      const available = typeof process.env.DISPLAY === "string" || typeof process.env.WAYLAND_DISPLAY === "string";
      return { feature, available, reason: available ? "display environment is configured" : "DISPLAY and WAYLAND_DISPLAY are absent" };
    }
    default: return { feature, available: null, reason: "host feature requires a provider-specific live probe" };
  }
}

async function probeKernelFeature(feature: string): Promise<PowerFeatureProbe> {
  if (process.platform !== "linux") return { feature, available: false, reason: "Linux kernel features are unavailable on this platform" };
  switch (feature) {
    case "checkpoint_restore": {
      try {
        await access("/proc/self/ns/pid");
        return { feature, available: null, reason: "Linux namespace metadata exists; CRIU compatibility and permission require a live probe" };
      } catch { return { feature, available: false, reason: "Linux PID namespace metadata is unavailable" }; }
    }
    case "ptrace or selected tracing facility":
      return { feature, available: null, reason: "tracing permission and kernel support require a target-specific live probe" };
    default: return { feature, available: null, reason: "kernel feature requires a provider-specific live probe" };
  }
}

export class QuirtPowerProviderRegistry {
  readonly #adapters = new Map<string, QuirtPowerProviderAdapter>();

  constructor(private readonly state: QuirtStateStore, readonly runtime: QuirtPowerRuntime = new NodePowerRuntime()) {
    for (const definition of POWER_PROVIDER_DEFINITIONS) state.power.registerDefinition(definition);
  }

  register(adapter: QuirtPowerProviderAdapter): void {
    const definition = POWER_PROVIDER_DEFINITIONS.find((item) => item.providerId === adapter.providerId);
    if (definition === undefined) throw new QuirtError("configuration_error", "Power provider adapter has no frozen definition");
    if (this.#adapters.has(adapter.providerId)) throw new QuirtError("configuration_error", "Duplicate power provider adapter registration");
    const expected = [...definition.operationIds].sort().join("\n");
    const actual = [...adapter.operationIds].sort().join("\n");
    if (expected !== actual) throw new QuirtError("configuration_error", "Power provider adapter operation catalog does not match QES-1");
    this.#adapters.set(adapter.providerId, adapter);
  }

  adapter(operation: QuirtPowerOperation): QuirtPowerProviderAdapter {
    const definition = powerProviderForOperation(operation);
    const adapter = this.#adapters.get(definition.providerId);
    if (adapter === undefined) throw new QuirtError("provider_unavailable", "Power provider source adapter is unavailable");
    return adapter;
  }

  get(providerId: string): QuirtPowerProviderAdapter | undefined { return this.#adapters.get(providerId); }
  adapters(): readonly QuirtPowerProviderAdapter[] { return [...this.#adapters.values()]; }

  async probe(definition: PowerProviderDefinition): Promise<PowerProviderProbe> {
    const executableProbes = await Promise.all(definition.requiredExecutables.map((requirement) => this.runtime.probeExecutable(requirement.path, requirement.versionArguments, requirement.minimumVersion)));
    const hostFeatureProbes = await Promise.all(definition.requiredHostFeatures.map(probeHostFeature));
    const kernelFeatureProbes = await Promise.all(definition.requiredKernelFeatures.map(probeKernelFeature));
    const missing = executableProbes.filter((item, index) => !item.available && definition.requiredExecutables[index]?.optional !== true);
    const unsupported = executableProbes.filter((item, index) => item.versionSupported === false && definition.requiredExecutables[index]?.optional !== true);
    const degradedOptional = executableProbes.filter((item, index) => definition.requiredExecutables[index]?.optional === true && (!item.available || item.versionSupported === false));
    const missingHostFeature = hostFeatureProbes.find((item) => item.available === false);
    const missingKernelFeature = kernelFeatureProbes.find((item) => item.available === false);
    const pendingFeature = [...hostFeatureProbes, ...kernelFeatureProbes].find((item) => item.available === null);
    const sourceImplemented = this.#adapters.has(definition.providerId);
    const classification: PowerProviderAvailabilityState =
      !sourceImplemented ? "dependency_absent" :
      missing.length > 0 ? "executable_absent" :
      unsupported.length > 0 ? "executable_version_unsupported" :
      missingKernelFeature !== undefined ? "kernel_feature_absent" :
      missingHostFeature !== undefined ? "unsupported_on_current_host" :
      degradedOptional.length > 0 ? "degraded" :
      pendingFeature !== undefined ? "live_validation_pending" :
      "host_available";
    const reason =
      !sourceImplemented ? "provider adapter source is not registered" :
      missing.length > 0 ? "required executable is absent" :
      unsupported.length > 0 ? "required executable version is unsupported" :
      missingKernelFeature?.reason ?? missingHostFeature?.reason ??
      (degradedOptional.length > 0 ? "one or more optional provider capabilities are unavailable" : pendingFeature?.reason) ??
      "required executable and host-feature probes passed";
    return {
      providerId: definition.providerId,
      providerVersion: definition.providerVersion,
      sourceImplemented,
      locallyTested: true,
      deterministicAdapterTested: true,
      liveHostTested: false,
      productionTested: false,
      classification,
      hostAvailable: classification === "host_available",
      executables: executableProbes,
      requiredHostFeatures: definition.requiredHostFeatures,
      requiredKernelFeatures: definition.requiredKernelFeatures,
      hostFeatureProbes,
      kernelFeatureProbes,
      requiredConfiguration: Object.keys(definition.configurationSchema),
      credentialsAvailable: Object.keys(definition.credentialReferenceSchema).length === 0 ? true : null,
      reason,
      limitations: definition.limitations,
      enabledOperations: sourceImplemented ? definition.operationIds : [],
      probedAt: new Date().toISOString()
    };
  }

  async inventory(): Promise<PowerProviderProbe[]> { return await Promise.all(POWER_PROVIDER_DEFINITIONS.map((definition) => this.probe(definition))); }
}

export class QuirtPowerProviderService {
  constructor(
    private readonly config: QuirtConfig,
    private readonly state: QuirtStateStore,
    private readonly sessions: QuirtSessionManager,
    private readonly jobs: QuirtJobManager,
    private readonly tmux: QuirtTmuxController,
    private readonly processes: QuirtProcessService,
    readonly registry = new QuirtPowerProviderRegistry(state)
  ) {}

  async execute(input: { operation: QuirtPowerOperation; payload: Readonly<Record<string, unknown>>; binary: Buffer; requestId: string; ownerPrincipalFingerprint: string; targetHost: string; signal?: AbortSignal }): Promise<QuirtPowerProviderResult> {
    if (input.targetHost !== this.config.targetHost) throw new QuirtError("wrong_target_host", "Power provider target host does not match");
    if (input.signal?.aborted === true) throw new QuirtError("canceled", "Provider operation was canceled", true);
    const hash = requestHash(input.operation, input.payload, input.binary);
    const reserved = this.state.power.reserveRequest({ ownerPrincipalFingerprint: input.ownerPrincipalFingerprint, operation: input.operation, idempotencyKey: input.requestId, requestHash: hash, instanceId: typeof input.payload.instanceId === "string" ? input.payload.instanceId : undefined });
    if (reserved.replay && reserved.result !== null) return replayResult(reserved.result);
    try {
      const result = await this.registry.adapter(input.operation).execute(input.operation, input.payload, input.binary, {
        config: this.config,
        state: this.state,
        sessions: this.sessions,
        jobs: this.jobs,
        tmux: this.tmux,
        processes: this.processes,
        runtime: this.registry.runtime,
        ownerPrincipalFingerprint: input.ownerPrincipalFingerprint,
        targetHost: input.targetHost,
        requestId: input.requestId,
        signal: input.signal
      });
      this.state.power.completeRequest({ ownerPrincipalFingerprint: input.ownerPrincipalFingerprint, operation: input.operation, idempotencyKey: input.requestId, result: storedResult(result), instanceId: result.instanceId });
      return result;
    } catch (cause) {
      this.state.power.failRequest({ ownerPrincipalFingerprint: input.ownerPrincipalFingerprint, operation: input.operation, idempotencyKey: input.requestId, errorCode: errorCode(cause) });
      throw cause;
    }
  }

  async recover(): Promise<void> {
    for (const record of this.state.power.recoverCandidates()) {
      const adapter = this.registry.get(record.providerId);
      if (adapter?.recover === undefined) {
        this.state.power.putInstance({ ...record, state: "lost", failureClassification: "provider_adapter_unavailable", recoveryClassification: "lost", lastProbeAt: new Date().toISOString() });
        this.state.power.recordRecovery(record.instanceId, "lost", { reason: "provider adapter is unavailable" });
        continue;
      }
      try {
        await adapter.recover(record, { config: this.config, state: this.state, sessions: this.sessions, jobs: this.jobs, tmux: this.tmux, processes: this.processes, runtime: this.registry.runtime, targetHost: this.config.targetHost });
      } catch (cause) {
        this.state.power.putInstance({ ...record, state: "lost", failureClassification: errorCode(cause), recoveryClassification: "lost", lastProbeAt: new Date().toISOString() });
        this.state.power.recordRecovery(record.instanceId, "lost", { errorCode: errorCode(cause) });
      }
    }
  }

  async inventory(): Promise<PowerProviderProbe[]> { return await this.registry.inventory(); }
  cleanupExpired(maximum = 100): number { return this.state.power.cleanupExpired(maximum); }
}
