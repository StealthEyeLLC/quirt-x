import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { basename, isAbsolute } from "node:path";
import type { QuirtConfig } from "./config.js";
import { LinuxCoreDumpProbe, type CoreDumpProbe } from "./core-dump.js";
import { resolveEnvironment, type QuirtEnvironmentPolicy } from "./execution-environment.js";
import { buildExecutionReceipt } from "./execution-receipt.js";
import { runTermination, RealTerminationClock, type TerminationClock } from "./execution-termination.js";
import { QuirtError, errorCode } from "./error.js";
import { mutableSpawnEnvironment } from "./environment.js";
import { buildLaunchDocument, digestBuffer, digestText, type QuirtLaunchForm } from "./launch-document.js";
import type { QuirtPtyFactory, QuirtPtyProcess } from "./pty.js";
import {
  assertIdentityMatch,
  captureCgroupIdentity,
  captureNamespaceIdentities,
  captureProcessIdentity,
  captureProcessIdentitySync,
  isProcessAlive,
  LinuxProcReader,
  syntheticProcessIdentity,
  type ProcReader,
  type QuirtProcessIdentity
} from "./process-identity.js";
import { LinuxResourceProbe, sampleResourceEvidence, type ResourceProbe } from "./resource-accounting.js";
import type { QuirtJobRecord, QuirtStateStore, QuirtStreamPage } from "./state.js";

const SIGNALS = new Set<NodeJS.Signals>([
  "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV",
  "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU"
]);

const TERMINAL_STATUSES = new Set<QuirtJobRecord["status"]>([
  "exited", "failed", "signaled", "canceled", "timed_out", "spawn_failed", "identity_lost", "lost"
]);

export interface QuirtExecInput {
  command?: string;
  script?: string;
  executable?: string;
  arguments?: readonly string[];
  shell?: boolean;
  shellPath?: string;
  workingDirectory?: string;
  environment?: Readonly<Record<string, string>>;
  environmentPolicy?: QuirtEnvironmentPolicy;
  input?: Buffer;
  timeoutMs?: number;
  forceTimeout?: boolean;
  pty?: boolean;
  detach?: boolean;
  columns?: number;
  rows?: number;
  gracefulSignal?: NodeJS.Signals;
  graceIntervalMs?: number;
}

export interface QuirtExecResult {
  job: QuirtJobRecord;
  detached: boolean;
  timedOut: boolean;
  stdout: Buffer;
  stderr: Buffer;
  receiptId: string | null;
  compatibilityCombinedOutput: Buffer;
}

export interface QuirtJobEvent {
  event: "job.output" | "job.state";
  jobId: string;
  requestId?: string;
  streamId?: string;
  stream?: "stdout" | "stderr";
  startOffset?: number;
  endOffset?: number;
  bytes?: Buffer;
  status?: QuirtJobRecord["status"];
  receiptId?: string | null;
  priorState?: QuirtJobRecord["status"];
}

interface BaseHandle {
  timedOut: boolean;
  canceled: boolean;
  cancelReason: "protocol" | "explicit" | null;
  timeout: NodeJS.Timeout | null;
  completion: Promise<QuirtJobRecord>;
  resolve: (record: QuirtJobRecord) => void;
  identity: QuirtProcessIdentity | null;
  stdinBytes: number;
  stdinDigest: string | null;
  inputClosed: boolean;
  terminationStarted: boolean;
}

interface ChildHandle extends BaseHandle { kind: "child"; process: ChildProcessWithoutNullStreams; }
interface PtyHandle extends BaseHandle { kind: "pty"; process: QuirtPtyProcess; }
type JobHandle = ChildHandle | PtyHandle;

export interface QuirtJobManagerDependencies {
  procReader?: ProcReader;
  resourceProbe?: ResourceProbe;
  coreDumpProbe?: CoreDumpProbe;
  clock?: TerminationClock;
  spawnProcess?: typeof spawn;
  killProcess?: (pid: number, signal: NodeJS.Signals | number) => void;
}

function boundedCommand(value: string, label: string, maximum = 1024 * 1024): string {
  if (value.length < 1 || Buffer.byteLength(value) > maximum || value.includes("\0")) throw new QuirtError("invalid_request", `${label} is invalid`);
  return value;
}

function shellCommandArguments(shellPath: string, command: string): readonly string[] {
  return basename(shellPath) === "bash" ? ["--noprofile", "--norc", "-c", command] : ["-c", command];
}

function launch(input: QuirtExecInput, shellPath: string): {
  executable: string;
  arguments: readonly string[];
  command: Record<string, unknown>;
  form: QuirtLaunchForm;
  commandOrScriptDigest: string | null;
} {
  const forms = Number(input.command !== undefined) + Number(input.script !== undefined) + Number(input.executable !== undefined);
  if (forms !== 1) throw new QuirtError("invalid_request", "Exactly one Quirt execution form is required");
  if (input.pty === true && input.shell === true) throw new QuirtError("invalid_request", "Quirt PTY and shell-wrap modes are incompatible");
  if (input.script !== undefined) {
    const value = boundedCommand(input.script, "Quirt script");
    return {
      executable: shellPath,
      arguments: shellCommandArguments(shellPath, value),
      command: { kind: "script", shell: shellPath },
      form: { kind: "script", shellPath, scriptDigest: digestText(value) },
      commandOrScriptDigest: digestText(value)
    };
  }
  if (input.command !== undefined) {
    const value = boundedCommand(input.command, "Quirt command");
    return {
      executable: shellPath,
      arguments: shellCommandArguments(shellPath, value),
      command: { kind: "command", shell: shellPath },
      form: { kind: "command", shellPath, commandDigest: digestText(value) },
      commandOrScriptDigest: digestText(value)
    };
  }
  const executable = boundedCommand(input.executable!, "Quirt executable", 4096);
  if (!isAbsolute(executable)) throw new QuirtError("invalid_request", "Quirt executable must be absolute");
  const argumentsList = [...(input.arguments ?? [])];
  if (argumentsList.length > 1024 || argumentsList.some(value => value.includes("\0") || Buffer.byteLength(value) > 64 * 1024)) throw new QuirtError("invalid_request", "Quirt arguments are invalid");
  if (input.shell === true) {
    const quoted = [executable, ...argumentsList].map(value => `'${value.replaceAll("'", `'"'"'`)}'`).join(" ");
    return {
      executable: shellPath,
      arguments: shellCommandArguments(shellPath, quoted),
      command: { kind: "executable", executable, arguments: argumentsList, shell: true },
      form: { kind: "executable", executable, arguments: argumentsList, shellWrapped: true },
      commandOrScriptDigest: null
    };
  }
  return {
    executable,
    arguments: argumentsList,
    command: { kind: "executable", executable, arguments: argumentsList, shell: false },
    form: { kind: "executable", executable, arguments: argumentsList, shellWrapped: false },
    commandOrScriptDigest: null
  };
}

async function validateWorkingDirectory(path: string): Promise<void> {
  if (!isAbsolute(path) || path.includes("\0")) throw new QuirtError("invalid_request", "Quirt working directory is invalid");
  try {
    await access(path, constants.F_OK);
  } catch {
    throw new QuirtError("invalid_request", "Quirt working directory was not found");
  }
  try {
    await access(path, constants.R_OK | constants.X_OK);
  } catch {
    throw new QuirtError("authorization_failed", "Quirt working directory permission was denied");
  }
}

async function validateExecutable(path: string): Promise<void> {
  try {
    await access(path, constants.F_OK);
  } catch {
    throw new QuirtError("executable_missing", "Quirt executable was not found");
  }
  try {
    await access(path, constants.X_OK);
  } catch {
    throw new QuirtError("authorization_failed", "Quirt executable permission was denied");
  }
}

export class QuirtJobManager {
  readonly #handles = new Map<string, JobHandle>();
  readonly #events = new EventEmitter();
  readonly #procReader: ProcReader;
  readonly #resourceProbe: ResourceProbe;
  readonly #coreDumpProbe: CoreDumpProbe;
  readonly #clock: TerminationClock;
  readonly #spawnProcess: typeof spawn;
  readonly #killProcess: (pid: number, signal: NodeJS.Signals | number) => void;

  constructor(
    private readonly config: QuirtConfig,
    private readonly state: QuirtStateStore,
    private readonly ptys: QuirtPtyFactory,
    dependencies: QuirtJobManagerDependencies = {}
  ) {
    this.#procReader = dependencies.procReader ?? new LinuxProcReader();
    this.#resourceProbe = dependencies.resourceProbe ?? new LinuxResourceProbe();
    this.#coreDumpProbe = dependencies.coreDumpProbe ?? new LinuxCoreDumpProbe();
    this.#clock = dependencies.clock ?? new RealTerminationClock();
    this.#spawnProcess = dependencies.spawnProcess ?? spawn;
    this.#killProcess = dependencies.killProcess ?? ((pid, signal) => process.kill(pid, signal));
  }

  onEvent(listener: (event: QuirtJobEvent) => void): () => void {
    this.#events.on("event", listener);
    return () => this.#events.off("event", listener);
  }

  recover(): { unknown: number; lost: number } {
    let unknown = 0;
    let lost = 0;
    for (const record of this.state.listJobs()) {
      if (record.status !== "starting" && record.status !== "running" && record.status !== "terminating") continue;
      let status: QuirtJobRecord["status"] = "lost";
      if (record.processId !== null && isProcessAlive(record.processId, (pid, signal) => this.#killProcess(pid, signal))) {
        status = record.processIdentity === null ? "unknown" : "unknown";
      }
      this.state.updateJob(record.jobId, { status, finished: status !== "unknown" });
      this.state.recordRecovery("job", record.jobId, "probe", status, {
        processId: record.processId,
        outputCaptureRecoverable: false,
        identityAware: record.processIdentity !== null,
        identityMatched: null
      });
      if (status === "unknown") unknown += 1; else lost += 1;
    }
    return { unknown, lost };
  }

  async exec(requestId: string, principalFingerprint: string, input: QuirtExecInput, abortSignal?: AbortSignal): Promise<QuirtExecResult> {
    const existing = this.state.getJobByRequestId(requestId);
    if (existing !== null) return await this.#materializeExecResult(existing);
    if (abortSignal !== undefined && abortSignal.aborted) throw new QuirtError("request_canceled", "Quirt execution was canceled before start");
    const shellPath = input.shellPath ?? this.config.shellPath;
    const launched = launch(input, shellPath);
    const workingDirectory = input.workingDirectory ?? ((process.getuid?.() ?? 0) === 0 ? "/root" : process.cwd());
    await validateWorkingDirectory(workingDirectory);
    await validateExecutable(launched.executable);
    const environmentPolicy: QuirtEnvironmentPolicy = {
      environment: input.environmentPolicy?.environment ?? input.environment,
      unsetEnvironment: input.environmentPolicy?.unsetEnvironment,
      replaceEnvironment: input.environmentPolicy?.replaceEnvironment
    };
    const resolved = resolveEnvironment(shellPath, environmentPolicy);
    const stdinDigest = input.input !== undefined && input.input.length > 0 ? digestBuffer(input.input) : null;
    const launchDocument = buildLaunchDocument({
      form: launched.form,
      workingDirectory,
      environmentPolicyDigest: resolved.policyDigest,
      stdinDigest,
      pty: input.pty === true,
      detach: input.detach === true,
      timeoutMs: input.timeoutMs ?? null
    });
    const job = this.state.createJob({
      requestId,
      ownerPrincipalFingerprint: principalFingerprint,
      command: { ...launched.command, pty: input.pty === true, detach: input.detach === true, timeoutMs: input.timeoutMs ?? null, launchDocumentDigest: launchDocument.digest },
      workingDirectory,
      environment: resolved.values,
      environmentKeys: resolved.keys,
      environmentPolicyDigest: resolved.policyDigest,
      launchDocumentDigest: launchDocument.digest,
      stdinSupported: true,
      ptyStreamModel: input.pty === true ? "combined" : "separate"
    });
    if (abortSignal !== undefined && abortSignal.aborted) {
      this.state.updateJob(job.jobId, { status: "canceled", finished: true });
      throw new QuirtError("request_canceled", "Quirt execution was canceled before spawn");
    }
    const handle = input.pty === true
      ? await this.#spawnPty(job, launched.executable, launched.arguments, workingDirectory, resolved.values, input, launched.form, abortSignal)
      : await this.#spawnChild(job, launched.executable, launched.arguments, workingDirectory, resolved.values, input, launched.form, abortSignal);
    this.#handles.set(job.jobId, handle);
    if (input.input !== undefined && input.input.length > 0) {
      handle.stdinBytes = input.input.length;
      handle.stdinDigest = stdinDigest;
      this.input(job.jobId, principalFingerprint, input.input, input.detach !== true);
    } else if (input.detach !== true && handle.kind === "child") handle.process.stdin.end();
    if (input.detach === true) {
      const current = this.state.getJob(job.jobId);
      return { job: current, detached: true, timedOut: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), receiptId: current.receiptId, compatibilityCombinedOutput: Buffer.alloc(0) };
    }
    const finished = await handle.completion;
    return await this.#materializeExecResult(finished);
  }

  list(principalFingerprint: string, filters: { requestId?: string; status?: QuirtJobRecord["status"] } = {}): QuirtJobRecord[] {
    return this.state.listJobs(principalFingerprint, filters);
  }

  get(jobId: string, principalFingerprint: string): QuirtJobRecord {
    const record = this.state.getJob(jobId);
    if (record.ownerPrincipalFingerprint !== principalFingerprint) throw new QuirtError("authorization_failed", "Quirt job principal does not match");
    return record;
  }

  getByRequestId(requestId: string, principalFingerprint: string): QuirtJobRecord {
    const record = this.state.getJobByRequestId(requestId);
    if (record === null) throw new QuirtError("not_found", "Quirt job was not found");
    return this.get(record.jobId, principalFingerprint);
  }

  read(jobId: string, principalFingerprint: string, stream: "stdout" | "stderr", after: number, maximumBytes: number): QuirtStreamPage {
    const record = this.get(jobId, principalFingerprint);
    return this.state.readStream(stream === "stdout" ? record.stdoutStreamId : record.stderrStreamId, after, maximumBytes);
  }

  input(jobId: string, principalFingerprint: string, bytes: Buffer, close = false): { acceptedBytes: number; closed: boolean } {
    this.get(jobId, principalFingerprint);
    const handle = this.#handles.get(jobId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt job input is unavailable");
    if (handle.inputClosed) throw new QuirtError("invalid_request", "Quirt job input is closed");
    try {
      if (handle.kind === "pty") handle.process.write(bytes);
      else { handle.process.stdin.write(bytes); if (close) handle.process.stdin.end(); }
    } catch {
      throw new QuirtError("invalid_request", "Quirt job input write failed");
    }
    handle.stdinBytes += bytes.length;
    handle.stdinDigest = handle.stdinDigest === null ? digestBuffer(bytes) : digestBuffer(Buffer.concat([Buffer.from(handle.stdinDigest, "hex"), bytes]));
    if (close) handle.inputClosed = true;
    return { acceptedBytes: bytes.length, closed: close && handle.kind === "child" };
  }

  async signal(jobId: string, principalFingerprint: string, signal: NodeJS.Signals): Promise<QuirtJobRecord> {
    const record = this.get(jobId, principalFingerprint);
    if (!SIGNALS.has(signal)) throw new QuirtError("invalid_request", "Quirt job signal is unsupported");
    const handle = this.#handles.get(jobId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt job process is unavailable");
    await this.#verifyHandleIdentity(handle);
    try {
      if (handle.kind === "pty") handle.process.signal(signal);
      else {
        const pgid = handle.identity?.processGroupId ?? handle.process.pid ?? record.processId;
        if (pgid === null || pgid < 2) throw new Error("missing process identity");
        this.#killProcess(-pgid, signal);
      }
    } catch (cause) {
      if (cause instanceof QuirtError) throw cause;
      throw new QuirtError("not_found", "Quirt job process is unavailable");
    }
    return this.state.getJob(jobId);
  }

  async cancel(jobId: string, principalFingerprint: string, force = false): Promise<QuirtJobRecord> {
    const record = this.get(jobId, principalFingerprint);
    if (TERMINAL_STATUSES.has(record.status)) return record;
    const handle = this.#handles.get(jobId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt job process is unavailable");
    if (handle.terminationStarted) return this.state.getJob(jobId);
    handle.canceled = true;
    handle.cancelReason = "explicit";
    handle.terminationStarted = true;
    this.state.updateJob(jobId, { status: "terminating" });
  this.#emitState(record, "terminating");
    await this.#terminate(handle, jobId, force ? "forced_cancel" : "graceful_cancel", { gracefulSignal: "SIGTERM", graceIntervalMs: 5_000, escalate: !force });
    return this.state.getJob(jobId);
  }

  attach(jobId: string, principalFingerprint: string): Record<string, unknown> {
    const job = this.get(jobId, principalFingerprint);
    return { job, stdout: this.state.getStream(job.stdoutStreamId), stderr: this.state.getStream(job.stderrStreamId), inputAvailable: this.#handles.has(jobId) };
  }

  getReceipt(receiptId: string, principalFingerprint: string): Record<string, unknown> {
    const record = this.state.getExecutionReceipt(receiptId);
    if (record.ownerPrincipalFingerprint !== principalFingerprint) throw new QuirtError("authorization_failed", "Quirt receipt principal does not match");
    return record.receipt;
  }

  listReceipts(principalFingerprint: string, maximum = 256): Record<string, unknown>[] {
    return this.state.listExecutionReceipts(principalFingerprint, maximum).map(item => item.receipt);
  }

  shutdown(): void {
    for (const [jobId, handle] of this.#handles) {
      if (handle.timeout !== null) clearTimeout(handle.timeout);
      const record = this.state.getJob(jobId);
      if (!TERMINAL_STATUSES.has(record.status)) {
        this.state.updateJob(jobId, { status: record.processId !== null ? "unknown" : "lost" });
        this.state.recordRecovery("job", jobId, "supervisor-shutdown", "unknown", { processId: record.processId });
      }
    }
    this.#handles.clear();
  }

  async #materializeExecResult(record: QuirtJobRecord): Promise<QuirtExecResult> {
    const maximum = Math.max(1, Math.min(this.config.maxFrameBytes >>> 2, 2 * 1024 * 1024));
    const stdout = this.state.readStream(record.stdoutStreamId, Math.max(0, this.state.getStream(record.stdoutStreamId).nextOffset - maximum), maximum).bytes;
    const stderr = record.ptyStreamModel === "combined" ? Buffer.alloc(0) : this.state.readStream(record.stderrStreamId, Math.max(0, this.state.getStream(record.stderrStreamId).nextOffset - maximum), maximum).bytes;
    return {
      job: record,
      detached: record.command.detach === true,
      timedOut: record.timedOut,
      stdout,
      stderr,
      receiptId: record.receiptId,
      compatibilityCombinedOutput: Buffer.concat([stdout, stderr])
    };
  }

  #baseHandle(timeoutMs: number | undefined): BaseHandle {
    let resolve!: (record: QuirtJobRecord) => void;
    const completion = new Promise<QuirtJobRecord>(value => { resolve = value; });
    const base: BaseHandle = {
      timedOut: false,
      canceled: false,
      cancelReason: null,
      timeout: null,
      completion,
      resolve,
      identity: null,
      stdinBytes: 0,
      stdinDigest: null,
      inputClosed: false,
      terminationStarted: false
    };
    if (timeoutMs !== undefined) {
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 24 * 60 * 60 * 1000) throw new QuirtError("invalid_request", "Quirt execution timeout is invalid");
      base.timeout = setTimeout(() => { base.timedOut = true; }, timeoutMs);
      base.timeout.unref();
    }
    return base;
  }

  async #spawnChild(
    job: QuirtJobRecord,
    executable: string,
    argumentsList: readonly string[],
    cwd: string,
    env: Record<string, string>,
    input: QuirtExecInput,
    form: QuirtLaunchForm,
    abortSignal?: AbortSignal
  ): Promise<ChildHandle> {
    const base = this.#baseHandle(input.timeoutMs);
    let child: ChildProcessWithoutNullStreams;
    try {
      child = this.#spawnProcess(executable, [...argumentsList], { cwd, env: mutableSpawnEnvironment(env), detached: true, stdio: ["pipe", "pipe", "pipe"] });
    } catch {
      this.state.updateJob(job.jobId, { status: "spawn_failed", finished: true });
      throw new QuirtError("internal_error", "Quirt execution could not start");
    }
    const handle: ChildHandle = { ...base, kind: "child", process: child };
    const identityPromise = new Promise<QuirtProcessIdentity>((resolve, reject) => {
      const capture = () => {
        try { resolve(captureProcessIdentitySync(child.pid!, this.#procReader)); }
        catch (cause) { reject(cause); }
      };
      if (child.pid !== undefined && child.pid >= 2) capture();
      else child.once("spawn", capture);
      child.once("error", reject);
    });
    child.stdout.on("data", (bytes: Buffer) => this.#append(job, "stdout", bytes));
    child.stderr.on("data", (bytes: Buffer) => this.#append(job, "stderr", bytes));
    child.once("error", () => void identityPromise.finally(() => this.#finish(job.jobId, handle, null, null, "spawn_failed", form)));
    child.once("close", (code, signal) => void identityPromise.finally(() => this.#finish(job.jobId, handle, code, signal, this.#terminalStatus(handle, code, signal), form)));
    this.#bindAbort(job.jobId, handle, abortSignal);
    if (base.timeout !== null) {
      clearTimeout(base.timeout);
      base.timeout = setTimeout(() => {
        handle.timedOut = true;
        void this.#terminate(handle, job.jobId, "timeout", { gracefulSignal: input.gracefulSignal ?? "SIGTERM", graceIntervalMs: input.graceIntervalMs ?? 5_000, escalate: input.forceTimeout !== true });
      }, input.timeoutMs!);
      base.timeout.unref();
      handle.timeout = base.timeout;
    }
    try {
      const identity = await identityPromise;
      handle.identity = identity;
      this.state.updateJob(job.jobId, {
        status: "running",
        processId: identity.pid,
        processIdentity: identity as unknown as Record<string, unknown>,
        observedExecutable: identity.executablePath ?? null,
        observedWorkingDirectory: identity.workingDirectory ?? null,
        started: true
      });
      this.#emitState(job, "running");
    } catch (cause) {
      this.state.updateJob(job.jobId, { status: "spawn_failed", finished: true });
      throw cause instanceof QuirtError ? cause : new QuirtError("internal_error", "Quirt execution identity capture failed");
    }
    return handle;
  }

  async #spawnPty(
    job: QuirtJobRecord,
    executable: string,
    argumentsList: readonly string[],
    cwd: string,
    env: Record<string, string>,
    input: QuirtExecInput,
    form: QuirtLaunchForm,
    abortSignal?: AbortSignal
  ): Promise<PtyHandle> {
    const base = this.#baseHandle(input.timeoutMs);
    const pty = this.ptys.spawn({ executable, arguments: argumentsList, workingDirectory: cwd, environment: mutableSpawnEnvironment(env), columns: input.columns ?? 120, rows: input.rows ?? 40 });
    const handle: PtyHandle = { ...base, kind: "pty", process: pty };
    this.#bindAbort(job.jobId, handle, abortSignal);
    if (base.timeout !== null) {
      clearTimeout(base.timeout);
      base.timeout = setTimeout(() => {
        handle.timedOut = true;
        void this.#terminate(handle, job.jobId, "timeout", { gracefulSignal: input.gracefulSignal ?? "SIGTERM", graceIntervalMs: input.graceIntervalMs ?? 5_000, escalate: input.forceTimeout !== true });
      }, input.timeoutMs!);
      base.timeout.unref();
      handle.timeout = base.timeout;
    }
    try {
      let identity: QuirtProcessIdentity;
      try {
        identity = captureProcessIdentitySync(pty.pid, this.#procReader);
      } catch (cause) {
        if (errorCode(cause) !== "process_exited") throw cause;
        identity = syntheticProcessIdentity(pty.pid, await this.#procReader.readBootId());
      }
      handle.identity = identity;
      this.state.updateJob(job.jobId, {
        status: "running",
        processId: identity.pid,
        processIdentity: identity as unknown as Record<string, unknown>,
        observedExecutable: identity.executablePath ?? null,
        observedWorkingDirectory: identity.workingDirectory ?? null,
        started: true
      });
      this.#emitState(job, "running");
    } catch (cause) {
      this.state.updateJob(job.jobId, { status: "spawn_failed", finished: true });
      throw cause instanceof QuirtError ? cause : new QuirtError("internal_error", "Quirt execution identity capture failed");
    }
    pty.onData(bytes => this.#append(job, "stdout", bytes));
    pty.onExit(exit => void this.#finish(job.jobId, handle, exit.exitCode, exit.signal === null ? null : String(exit.signal), this.#terminalStatus(handle, exit.exitCode, exit.signal === null ? null : String(exit.signal)), form));
    return handle;
  }

  async #captureIdentityAtSpawn(pid: number): Promise<QuirtProcessIdentity> {
    return await captureProcessIdentity(pid, this.#procReader);
  }
  #bindAbort(jobId: string, handle: JobHandle, abortSignal?: AbortSignal): void {
    if (abortSignal === undefined) return;
    const onAbort = () => {
      if (handle.terminationStarted) return;
      handle.canceled = true;
      handle.cancelReason = "protocol";
      handle.terminationStarted = true;
      this.state.updateJob(jobId, { status: "terminating" });
      void this.#terminate(handle, jobId, "protocol_cancel", { gracefulSignal: "SIGTERM", graceIntervalMs: 5_000, escalate: true });
    };
    if (abortSignal.aborted) onAbort();
    else abortSignal.addEventListener("abort", onAbort, { once: true });
  }

  async #verifyHandleIdentity(handle: JobHandle): Promise<void> {
    if (handle.identity === null) throw new QuirtError("process_identity_changed", "Quirt process identity is unavailable");
    const actual = await captureProcessIdentity(handle.identity.pid, this.#procReader);
    assertIdentityMatch(handle.identity, actual);
  }

  async #terminate(handle: JobHandle, jobId: string, reason: "graceful_cancel" | "forced_cancel" | "timeout" | "protocol_cancel", options: { gracefulSignal?: NodeJS.Signals; graceIntervalMs?: number; escalate?: boolean }): Promise<void> {
    if (handle.identity === null) return;
    try {
      await runTermination({
        identity: handle.identity,
        reason,
        pty: handle.kind === "pty",
        options,
        verifyIdentity: async () => {
          try {
            const actual = await captureProcessIdentity(handle.identity!.pid, this.#procReader);
            assertIdentityMatch(handle.identity!, actual);
            return actual;
          } catch (cause) {
            if (cause instanceof QuirtError && (cause.code === "process_exited" || cause.code === "pid_reused")) return handle.identity!;
            throw cause;
          }
        },
        waitForExit: async () => { await handle.completion; },
        signaler: {
          signalProcess: (pid, signal) => { try { this.#killProcess(pid, signal); } catch { /* ESRCH */ } },
          signalProcessGroup: (pgid, signal) => { try { this.#killProcess(-pgid, signal); } catch { /* ESRCH */ } },
          signalPty: handle.kind === "pty" ? signal => { try { handle.process.signal(signal); } catch { /* exited */ } } : undefined
        },
        clock: this.#clock
      });
    } catch { /* termination races are reconciled by process exit */ }
  }

  #terminalStatus(handle: JobHandle, code: number | null, signal: string | null): QuirtJobRecord["status"] {
    if (handle.timedOut) return "timed_out";
    if (handle.canceled) return "canceled";
    if (signal !== null) return "signaled";
    if (code === 0) return "exited";
    return "failed";
  }

  #append(job: QuirtJobRecord, stream: "stdout" | "stderr", bytes: Buffer): void {
    const streamId = stream === "stdout" ? job.stdoutStreamId : job.stderrStreamId;
    const range = this.state.appendStream(streamId, bytes);
    this.#events.emit("event", { event: "job.output", jobId: job.jobId, requestId: job.requestId, streamId, stream, startOffset: range.startOffset, endOffset: range.endOffset, bytes } satisfies QuirtJobEvent);
  }

  async #finish(jobId: string, handle: JobHandle, exitCode: number | null, signal: string | null, status: QuirtJobRecord["status"], form: QuirtLaunchForm): Promise<void> {
    if (!this.#handles.has(jobId)) return;
    if (handle.timeout !== null) clearTimeout(handle.timeout);
    const before = this.state.getJob(jobId);
    if (TERMINAL_STATUSES.has(before.status) && before.receiptId !== null) {
      handle.resolve(before);
      this.#handles.delete(jobId);
      return;
    }
    for (const streamId of [before.stdoutStreamId, before.stderrStreamId]) if (this.state.getStream(streamId).status === "open") this.state.finalizeStream(streamId);
    const stdoutDigest = this.state.streamDigest(before.stdoutStreamId);
    const stderrDigest = before.ptyStreamModel === "combined" ? { digest: null, complete: false, byteCount: 0 } : this.state.streamDigest(before.stderrStreamId);
    const finishedAt = new Date().toISOString();
    const startedAtMs = before.startedAt === null ? this.#clock.now() : Date.parse(before.startedAt);
    const resourceEvidence = before.processId === null ? null : await sampleResourceEvidence(before.processId, startedAtMs, this.#clock.now(), this.#resourceProbe);
    const coreDump = await this.#coreDumpProbe.inspect(exitCode, signal, before.processId ?? 0);
    const cgroupIdentity = before.processId === null ? null : await captureCgroupIdentity(before.processId, this.#procReader);
    const namespaceIdentities = before.processId === null ? null : await captureNamespaceIdentities(before.processId, this.#procReader);
    const receipt = buildExecutionReceipt({
      jobId,
      requestId: before.requestId,
      operationId: "quirt.exec",
      operationVersion: "1.0.0",
      authenticatedSubject: "stealtheye-owner",
      authorityClass: "unrestricted-owner",
      principalFingerprint: before.ownerPrincipalFingerprint,
      targetHost: this.config.targetHost,
      createdAt: finishedAt,
      startedAt: before.startedAt,
      terminalAt: finishedAt,
      finalClassification: status,
      launchForm: form,
      launchDocumentDigest: before.launchDocumentDigest ?? "",
      executableRequestedPath: form.kind === "executable" ? form.executable : form.shellPath,
      executableObservedPath: before.observedExecutable,
      executableSha256: (before.processIdentity as QuirtProcessIdentity | null)?.executableSha256 ?? null,
      interpreterIdentity: form.kind === "executable" ? null : form.shellPath,
      commandOrScriptDigest: form.kind === "executable" ? null : form.kind === "command" ? form.commandDigest : form.scriptDigest,
      workingDirectoryRequested: before.workingDirectory,
      workingDirectoryObserved: before.observedWorkingDirectory,
      environmentKeys: before.environmentKeys,
      environmentPolicyDigest: before.environmentPolicyDigest ?? "",
      processIdentity: before.processIdentity as QuirtProcessIdentity | null,
      cgroupIdentity,
      namespaceIdentities,
      exitCode,
      exitSignal: signal,
      timedOut: handle.timedOut,
      termination: null,
      cancellation: handle.canceled ? { reason: handle.cancelReason === "protocol" ? "protocol_cancel" : "graceful_cancel", requestedAt: finishedAt, gracefulSignal: "SIGTERM", graceIntervalMs: 5_000, escalated: true, forcedSignal: "SIGKILL", completedAt: finishedAt } : null,
      coreDump,
      stdoutStreamId: before.stdoutStreamId,
      stdoutByteCount: stdoutDigest.byteCount,
      stdoutDigest: stdoutDigest.digest,
      stdoutDigestComplete: stdoutDigest.complete,
      stderrStreamId: before.stderrStreamId,
      stderrByteCount: stderrDigest.byteCount,
      stderrDigest: stderrDigest.digest,
      stderrDigestComplete: stderrDigest.complete,
      stdinByteCount: handle.stdinBytes,
      stdinDigest: handle.stdinDigest,
      resourceEvidence,
      outputGap: stdoutDigest.digest === null || stderrDigest.digest === null,
      ptyStreamModel: before.ptyStreamModel
    });
    const stored = this.state.insertExecutionReceipt({
      receiptId: receipt.receiptId,
      jobId,
      requestId: before.requestId,
      ownerPrincipalFingerprint: before.ownerPrincipalFingerprint,
      receiptDigest: receipt.receiptDigest,
      receipt: receipt as unknown as Record<string, unknown>
    });
    const record = this.state.updateJob(jobId, { status, exitCode, exitSignal: signal, timedOut: handle.timedOut, finished: true, receiptId: stored.receiptId });
    this.#handles.delete(jobId);
    handle.resolve(record);
    this.#emitState(before, status, record.receiptId);
  }

  #emitState(job: QuirtJobRecord, status: QuirtJobRecord["status"], receiptId: string | null = null): void {
    this.#events.emit("event", { event: "job.state", jobId: job.jobId, requestId: job.requestId, priorState: job.status, status, receiptId } satisfies QuirtJobEvent);
  }
}
