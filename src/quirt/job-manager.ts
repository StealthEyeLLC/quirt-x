import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { basename, isAbsolute } from "node:path";
import type { QuirtConfig } from "./config.js";
import { quirtEnvironment } from "./environment.js";
import { QuirtError } from "./error.js";
import type { QuirtPtyFactory, QuirtPtyProcess } from "./pty.js";
import type { QuirtJobRecord, QuirtStateStore, QuirtStreamPage } from "./state.js";

const SIGNALS = new Set<NodeJS.Signals>(["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGKILL", "SIGTSTP", "SIGUSR1", "SIGUSR2"]);

export interface QuirtExecInput {
  command?: string;
  script?: string;
  executable?: string;
  arguments?: readonly string[];
  shell?: boolean;
  workingDirectory?: string;
  environment?: Readonly<Record<string, string>>;
  input?: Buffer;
  timeoutMs?: number;
  pty?: boolean;
  detach?: boolean;
  columns?: number;
  rows?: number;
}

export interface QuirtExecResult {
  job: QuirtJobRecord;
  detached: boolean;
  timedOut: boolean;
  stdout: Buffer;
  stderr: Buffer;
}

export interface QuirtJobEvent {
  event: "job.output" | "job.state";
  jobId: string;
  streamId?: string;
  stream?: "stdout" | "stderr";
  startOffset?: number;
  endOffset?: number;
  bytes?: Buffer;
  status?: QuirtJobRecord["status"];
}

interface BaseHandle {
  timedOut: boolean;
  canceled: boolean;
  timeout: NodeJS.Timeout | null;
  completion: Promise<QuirtJobRecord>;
  resolve: (record: QuirtJobRecord) => void;
}

interface ChildHandle extends BaseHandle { kind: "child"; process: ChildProcessWithoutNullStreams; }
interface PtyHandle extends BaseHandle { kind: "pty"; process: QuirtPtyProcess; }
type JobHandle = ChildHandle | PtyHandle;

function boundedCommand(value: string, label: string, maximum = 1024 * 1024): string {
  if (value.length < 1 || Buffer.byteLength(value) > maximum || value.includes("\0")) throw new QuirtError("invalid_request", `${label} is invalid`);
  return value;
}

function shellCommandArguments(shellPath: string, command: string): readonly string[] {
  return basename(shellPath) === "bash" ? ["--noprofile", "--norc", "-c", command] : ["-c", command];
}

function launch(input: QuirtExecInput, shellPath: string): { executable: string; arguments: readonly string[]; command: Record<string, unknown> } {
  const forms = Number(input.command !== undefined) + Number(input.script !== undefined) + Number(input.executable !== undefined);
  if (forms !== 1) throw new QuirtError("invalid_request", "Exactly one Quirt execution form is required");
  if (input.script !== undefined) {
    const value = boundedCommand(input.script, "Quirt script");
    return { executable: shellPath, arguments: shellCommandArguments(shellPath, value), command: { kind: "script", script: value, shell: shellPath } };
  }
  if (input.command !== undefined) {
    const value = boundedCommand(input.command, "Quirt command");
    return { executable: shellPath, arguments: shellCommandArguments(shellPath, value), command: { kind: "command", command: value, shell: shellPath } };
  }
  const executable = boundedCommand(input.executable!, "Quirt executable", 4096);
  if (!isAbsolute(executable)) throw new QuirtError("invalid_request", "Quirt executable must be absolute");
  const argumentsList = [...(input.arguments ?? [])];
  if (argumentsList.length > 1024 || argumentsList.some(value => value.includes("\0") || Buffer.byteLength(value) > 64 * 1024)) throw new QuirtError("invalid_request", "Quirt arguments are invalid");
  if (input.shell === true) {
    const quoted = [executable, ...argumentsList].map(value => `'${value.replaceAll("'", `'"'"'`)}'`).join(" ");
    return { executable: shellPath, arguments: shellCommandArguments(shellPath, quoted), command: { kind: "executable", executable, arguments: argumentsList, shell: true } };
  }
  return { executable, arguments: argumentsList, command: { kind: "executable", executable, arguments: argumentsList, shell: false } };
}

export class QuirtJobManager {
  readonly #handles = new Map<string, JobHandle>();
  readonly #events = new EventEmitter();

  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore, private readonly ptys: QuirtPtyFactory) {}

  onEvent(listener: (event: QuirtJobEvent) => void): () => void {
    this.#events.on("event", listener);
    return () => this.#events.off("event", listener);
  }

  recover(): { unknown: number; lost: number } {
    let unknown = 0;
    let lost = 0;
    for (const record of this.state.listJobs()) {
      if (record.status !== "starting" && record.status !== "running") continue;
      let alive = false;
      if (record.processId !== null) {
        try { process.kill(record.processId, 0); alive = true; } catch { alive = false; }
      }
      const status = alive ? "unknown" : "lost";
      this.state.updateJob(record.jobId, { status, finished: !alive });
      this.state.recordRecovery("job", record.jobId, "probe", status, { processId: record.processId, outputCaptureRecoverable: false });
      if (alive) unknown += 1; else lost += 1;
    }
    return { unknown, lost };
  }

  async exec(requestId: string, principalFingerprint: string, input: QuirtExecInput): Promise<QuirtExecResult> {
    const command = launch(input, this.config.shellPath);
    const workingDirectory = input.workingDirectory ?? ((process.getuid?.() ?? 0) === 0 ? "/root" : process.cwd());
    if (!isAbsolute(workingDirectory) || workingDirectory.includes("\0")) throw new QuirtError("invalid_request", "Quirt working directory is invalid");
    const environment = { ...quirtEnvironment(this.config.shellPath, input.environment) };
    const job = this.state.createJob({
      requestId,
      ownerPrincipalFingerprint: principalFingerprint,
      command: { ...command.command, pty: input.pty === true, detach: input.detach === true, timeoutMs: input.timeoutMs ?? null },
      workingDirectory,
      environment,
      stdinSupported: true
    });
    const handle = input.pty === true
      ? this.#spawnPty(job, command.executable, command.arguments, workingDirectory, environment, input)
      : this.#spawnChild(job, command.executable, command.arguments, workingDirectory, environment, input);
    this.#handles.set(job.jobId, handle);
    if (input.input !== undefined && input.input.length > 0) this.input(job.jobId, principalFingerprint, input.input, input.detach !== true);
    else if (input.detach !== true && handle.kind === "child") handle.process.stdin.end();
    if (input.detach === true) return { job: this.state.getJob(job.jobId), detached: true, timedOut: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    const finished = await handle.completion;
    const maximum = Math.max(1, Math.min(this.config.maxFrameBytes >>> 2, 2 * 1024 * 1024));
    const stdout = this.state.readStream(finished.stdoutStreamId, Math.max(0, this.state.getStream(finished.stdoutStreamId).nextOffset - maximum), maximum).bytes;
    const stderr = this.state.readStream(finished.stderrStreamId, Math.max(0, this.state.getStream(finished.stderrStreamId).nextOffset - maximum), maximum).bytes;
    return { job: finished, detached: false, timedOut: handle.timedOut, stdout, stderr };
  }

  list(principalFingerprint: string): QuirtJobRecord[] { return this.state.listJobs(principalFingerprint); }

  get(jobId: string, principalFingerprint: string): QuirtJobRecord {
    const record = this.state.getJob(jobId);
    if (record.ownerPrincipalFingerprint !== principalFingerprint) throw new QuirtError("authorization_failed", "Quirt job principal does not match");
    return record;
  }

  read(jobId: string, principalFingerprint: string, stream: "stdout" | "stderr", after: number, maximumBytes: number): QuirtStreamPage {
    const record = this.get(jobId, principalFingerprint);
    return this.state.readStream(stream === "stdout" ? record.stdoutStreamId : record.stderrStreamId, after, maximumBytes);
  }

  input(jobId: string, principalFingerprint: string, bytes: Buffer, close = false): { acceptedBytes: number; closed: boolean } {
    this.get(jobId, principalFingerprint);
    const handle = this.#handles.get(jobId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt job input is unavailable");
    if (handle.kind === "pty") handle.process.write(bytes);
    else { handle.process.stdin.write(bytes); if (close) handle.process.stdin.end(); }
    return { acceptedBytes: bytes.length, closed: close && handle.kind === "child" };
  }

  signal(jobId: string, principalFingerprint: string, signal: NodeJS.Signals): QuirtJobRecord {
    const record = this.get(jobId, principalFingerprint);
    if (!SIGNALS.has(signal)) throw new QuirtError("invalid_request", "Quirt job signal is unsupported");
    const handle = this.#handles.get(jobId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt job process is unavailable");
    try {
      if (handle.kind === "pty") handle.process.signal(signal);
      else {
        const pid = handle.process.pid ?? record.processId;
        if (pid === null || pid < 2) throw new Error("missing process identity");
        process.kill(-pid, signal);
      }
    } catch { throw new QuirtError("not_found", "Quirt job process is unavailable"); }
    return this.state.getJob(jobId);
  }

  cancel(jobId: string, principalFingerprint: string, force = false): QuirtJobRecord {
    const record = this.get(jobId, principalFingerprint);
    const handle = this.#handles.get(jobId);
    if (handle === undefined) {
      if (["exited", "failed", "signaled", "canceled"].includes(record.status)) return record;
      throw new QuirtError("not_found", "Quirt job process is unavailable");
    }
    handle.canceled = true;
    this.signal(jobId, principalFingerprint, force ? "SIGKILL" : "SIGTERM");
    return this.state.updateJob(jobId, { status: "canceled" });
  }

  attach(jobId: string, principalFingerprint: string): Record<string, unknown> {
    const job = this.get(jobId, principalFingerprint);
    return { job, stdout: this.state.getStream(job.stdoutStreamId), stderr: this.state.getStream(job.stderrStreamId), inputAvailable: this.#handles.has(jobId) };
  }

  shutdown(): void {
    for (const [jobId, handle] of this.#handles) {
      if (handle.timeout !== null) clearTimeout(handle.timeout);
      const record = this.state.getJob(jobId);
      this.state.updateJob(jobId, { status: record.processId !== null ? "unknown" : "lost" });
      this.state.recordRecovery("job", jobId, "supervisor-shutdown", "unknown", { processId: record.processId });
    }
    this.#handles.clear();
  }

  #baseHandle(timeoutMs: number | undefined): BaseHandle {
    let resolve!: (record: QuirtJobRecord) => void;
    const completion = new Promise<QuirtJobRecord>(value => { resolve = value; });
    const base: BaseHandle = { timedOut: false, canceled: false, timeout: null, completion, resolve };
    if (timeoutMs !== undefined) {
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 24 * 60 * 60 * 1000) throw new QuirtError("invalid_request", "Quirt execution timeout is invalid");
      base.timeout = setTimeout(() => {
        base.timedOut = true;
      }, timeoutMs);
      base.timeout.unref();
    }
    return base;
  }

  #spawnChild(job: QuirtJobRecord, executable: string, argumentsList: readonly string[], cwd: string, env: Record<string, string>, input: QuirtExecInput): ChildHandle {
    const base = this.#baseHandle(input.timeoutMs);
    let child: ChildProcessWithoutNullStreams;
    try { child = spawn(executable, [...argumentsList], { cwd, env, detached: true, stdio: ["pipe", "pipe", "pipe"] }); }
    catch { this.state.updateJob(job.jobId, { status: "failed", finished: true }); throw new QuirtError("internal_error", "Quirt execution could not start"); }
    const handle: ChildHandle = { ...base, kind: "child", process: child };
    if (base.timeout !== null) {
      clearTimeout(base.timeout);
      const pid = child.pid;
      base.timeout = setTimeout(() => { handle.timedOut = true; if (pid !== undefined && pid >= 2) try { process.kill(-pid, "SIGKILL"); } catch { /* exit event resolves state */ } }, input.timeoutMs!);
      base.timeout.unref();
      handle.timeout = base.timeout;
    }
    this.state.updateJob(job.jobId, { status: "running", processId: child.pid ?? null, started: true });
    child.stdout.on("data", (bytes: Buffer) => this.#append(job, "stdout", bytes));
    child.stderr.on("data", (bytes: Buffer) => this.#append(job, "stderr", bytes));
    child.once("error", () => this.#finish(job.jobId, null, null, "failed"));
    child.once("close", (code, signal) => this.#finish(job.jobId, code, signal, handle.canceled ? "canceled" : signal !== null ? "signaled" : code === 0 ? "exited" : "failed"));
    return handle;
  }

  #spawnPty(job: QuirtJobRecord, executable: string, argumentsList: readonly string[], cwd: string, env: Record<string, string>, input: QuirtExecInput): PtyHandle {
    const base = this.#baseHandle(input.timeoutMs);
    const pty = this.ptys.spawn({ executable, arguments: argumentsList, workingDirectory: cwd, environment: env, columns: input.columns ?? 120, rows: input.rows ?? 40 });
    const handle: PtyHandle = { ...base, kind: "pty", process: pty };
    if (base.timeout !== null) {
      clearTimeout(base.timeout);
      base.timeout = setTimeout(() => { handle.timedOut = true; try { pty.signal("SIGKILL"); } catch { /* exit event resolves state */ } }, input.timeoutMs!);
      base.timeout.unref();
      handle.timeout = base.timeout;
    }
    this.state.updateJob(job.jobId, { status: "running", processId: pty.pid, started: true });
    pty.onData(bytes => this.#append(job, "stdout", bytes));
    pty.onExit(exit => this.#finish(job.jobId, exit.exitCode, exit.signal === null ? null : String(exit.signal), handle.canceled ? "canceled" : exit.signal !== null ? "signaled" : exit.exitCode === 0 ? "exited" : "failed"));
    return handle;
  }

  #append(job: QuirtJobRecord, stream: "stdout" | "stderr", bytes: Buffer): void {
    const streamId = stream === "stdout" ? job.stdoutStreamId : job.stderrStreamId;
    const range = this.state.appendStream(streamId, bytes);
    this.#events.emit("event", { event: "job.output", jobId: job.jobId, streamId, stream, startOffset: range.startOffset, endOffset: range.endOffset, bytes } satisfies QuirtJobEvent);
  }

  #finish(jobId: string, exitCode: number | null, signal: string | null, status: QuirtJobRecord["status"]): void {
    const handle = this.#handles.get(jobId);
    if (handle === undefined) return;
    if (handle.timeout !== null) clearTimeout(handle.timeout);
    const before = this.state.getJob(jobId);
    for (const streamId of [before.stdoutStreamId, before.stderrStreamId]) if (this.state.getStream(streamId).status === "open") this.state.finalizeStream(streamId);
    const record = this.state.updateJob(jobId, { status, exitCode, exitSignal: signal, timedOut: handle.timedOut, finished: true });
    this.#handles.delete(jobId);
    handle.resolve(record);
    this.#events.emit("event", { event: "job.state", jobId, status: record.status } satisfies QuirtJobEvent);
  }
}
