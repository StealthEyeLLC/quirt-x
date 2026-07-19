import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import type { QuirtConfig } from "./config.js";
import { quirtEnvironment } from "./environment.js";
import { QuirtError } from "./error.js";
import type { QuirtPtyFactory, QuirtPtyProcess, QuirtPtyExit } from "./pty.js";
import type { QuirtSessionRecord, QuirtStateStore, QuirtStreamPage } from "./state.js";
import { QuirtTmuxController, quirtTmuxName } from "./tmux.js";

const SIGNALS = new Set<NodeJS.Signals>(["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGKILL", "SIGTSTP", "SIGUSR1", "SIGUSR2"]);

export interface QuirtSessionOpenInput {
  name?: string;
  mode?: "tmux" | "direct";
  executable?: string;
  arguments?: readonly string[];
  workingDirectory?: string;
  environment?: Readonly<Record<string, string>>;
  columns?: number;
  rows?: number;
  loginShell?: boolean;
}

export interface QuirtSessionOutputEvent {
  event: "session.output" | "session.input" | "session.resize" | "session.signal" | "session.exit" | "session.recovered";
  sessionId: string;
  streamId: string;
  startOffset?: number;
  endOffset?: number;
  bytes?: Buffer;
  exitCode?: number | null;
  exitSignal?: number | null;
  columns?: number;
  rows?: number;
  signal?: NodeJS.Signals;
}

interface SessionHandle {
  process: QuirtPtyProcess;
  disposeData: () => void;
  disposeExit: () => void;
  closing: boolean;
}

function executable(value: string): string {
  if (!isAbsolute(value) || value.includes("\0") || Buffer.byteLength(value) > 4096) throw new QuirtError("invalid_request", "Quirt executable path is invalid");
  return value;
}

function argumentsList(value: readonly string[]): readonly string[] {
  if (value.length > 1024 || value.some(item => item.includes("\0") || Buffer.byteLength(item) > 64 * 1024)) throw new QuirtError("invalid_request", "Quirt executable arguments are invalid");
  return Object.freeze([...value]);
}

function sessionName(value: string): string {
  if (value.length < 1 || Buffer.byteLength(value) > 256 || /[\0\r\n]/u.test(value)) throw new QuirtError("invalid_request", "Quirt session name is invalid");
  return value;
}

export class QuirtSessionManager {
  readonly #handles = new Map<string, SessionHandle>();
  readonly #events = new EventEmitter();

  constructor(
    private readonly config: QuirtConfig,
    private readonly state: QuirtStateStore,
    private readonly ptys: QuirtPtyFactory,
    private readonly tmux: QuirtTmuxController
  ) {}

  onEvent(listener: (event: QuirtSessionOutputEvent) => void): () => void {
    this.#events.on("event", listener);
    return () => this.#events.off("event", listener);
  }

  async recover(): Promise<{ adopted: number; lost: number }> {
    let adopted = 0;
    let lost = 0;
    for (const record of this.state.listSessions()) {
      if (!(["creating", "running", "detached"] as const).includes(record.status as "creating" | "running" | "detached")) continue;
      if (record.mode === "tmux" && record.tmuxName !== null && await this.tmux.hasSession(record.tmuxName)) {
        this.#attachProcess(record, true);
        this.state.updateSession(record.sessionId, { status: "running", recovered: true });
        this.state.recordRecovery("session", record.sessionId, "adopt", "adopted", { tmuxName: record.tmuxName, outputGapPossible: true });
        this.#events.emit("event", { event: "session.recovered", sessionId: record.sessionId, streamId: record.outputStreamId } satisfies QuirtSessionOutputEvent);
        adopted += 1;
      } else {
        this.state.updateSession(record.sessionId, { status: "lost", ptyPid: null });
        this.state.recordRecovery("session", record.sessionId, "adopt", "lost", { mode: record.mode, tmuxName: record.tmuxName });
        lost += 1;
      }
    }
    return { adopted, lost };
  }

  async open(input: QuirtSessionOpenInput, principalFingerprint: string): Promise<QuirtSessionRecord> {
    const sessionId = randomUUID();
    const mode = input.mode ?? "tmux";
    const command = executable(input.executable ?? this.config.shellPath);
    const loginShell = input.loginShell ?? input.executable === undefined;
    const args = argumentsList(input.arguments ?? (loginShell ? ["-l"] : []));
    const workingDirectory = input.workingDirectory ?? "/root";
    if (!isAbsolute(workingDirectory) || workingDirectory.includes("\0")) throw new QuirtError("invalid_request", "Quirt working directory is invalid");
    const columns = input.columns ?? 120;
    const rows = input.rows ?? 40;
    const tmuxName = mode === "tmux" ? quirtTmuxName(sessionId) : null;
    const created = this.state.createSession({
      sessionId,
      name: sessionName(input.name ?? `quirt-${sessionId.slice(0, 8)}`),
      tmuxName,
      mode,
      shell: this.config.shellPath,
      executable: command,
      arguments: args,
      loginShell,
      workingDirectory,
      environment: quirtEnvironment(this.config.shellPath, input.environment),
      columns,
      rows,
      ownerPrincipalFingerprint: principalFingerprint
    });
    try {
      if (mode === "tmux") await this.tmux.version();
      this.#attachProcess(created, false);
      return this.state.updateSession(sessionId, { status: "running", ptyPid: this.#handles.get(sessionId)?.process.pid ?? null });
    } catch (cause) {
      this.state.updateSession(sessionId, { status: "lost", ptyPid: null });
      this.state.recordRecovery("session", sessionId, "create", "failed", {});
      throw cause;
    }
  }

  list(principalFingerprint: string): QuirtSessionRecord[] { return this.state.listSessions(principalFingerprint); }

  get(sessionId: string, principalFingerprint: string): QuirtSessionRecord {
    const record = this.state.getSession(sessionId);
    this.#authorize(record, principalFingerprint);
    return record;
  }

  async attach(sessionId: string, principalFingerprint: string, input: { readerId?: string; after?: number } = {}): Promise<Record<string, unknown>> {
    let record = this.get(sessionId, principalFingerprint);
    if (!this.#handles.has(sessionId) && record.mode === "tmux" && record.tmuxName !== null && await this.tmux.hasSession(record.tmuxName)) {
      this.#attachProcess(record, true);
      record = this.state.updateSession(sessionId, { status: "running", ptyPid: this.#handles.get(sessionId)?.process.pid ?? null, recovered: true });
    }
    if (!this.#handles.has(sessionId) && record.status !== "exited" && record.status !== "closed") throw new QuirtError("not_found", "Quirt session is not attachable");
    const reader = this.state.attachSessionReader({ readerId: input.readerId, sessionId, ownerPrincipalFingerprint: principalFingerprint, after: input.after });
    const stream = this.state.getStream(record.outputStreamId);
    return { session: record, reader, stream };
  }

  read(sessionId: string, principalFingerprint: string, input: { after?: number; maximumBytes?: number; readerId?: string }): QuirtStreamPage {
    const record = this.get(sessionId, principalFingerprint);
    let after = input.after ?? 0;
    if (input.readerId !== undefined) {
      const reader = this.state.getSessionReader(input.readerId);
      if (reader.sessionId !== sessionId || reader.ownerPrincipalFingerprint !== principalFingerprint) throw new QuirtError("authorization_failed", "Quirt reader principal does not match");
      after = input.after ?? reader.cursorOffset;
    }
    const page = this.state.readStream(record.outputStreamId, after, input.maximumBytes ?? this.config.outputChunkBytes);
    if (input.readerId !== undefined) this.state.advanceSessionReader(input.readerId, page.endOffset);
    return page;
  }

  async write(sessionId: string, principalFingerprint: string, bytes: Buffer): Promise<{ acceptedBytes: number }> {
    const record = this.get(sessionId, principalFingerprint);
    if (record.status === "closed" || record.status === "exited" || record.status === "lost") throw new QuirtError("invalid_request", "Quirt session is not writable");
    if (!this.#handles.has(sessionId)) await this.attach(sessionId, principalFingerprint);
    const handle = this.#handles.get(sessionId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt session PTY is unavailable");
    handle.process.write(bytes);
    this.#events.emit("event", { event: "session.input", sessionId, streamId: record.outputStreamId, bytes: Buffer.from(bytes) } satisfies QuirtSessionOutputEvent);
    return { acceptedBytes: bytes.length };
  }

  async resize(sessionId: string, principalFingerprint: string, columns: number, rows: number): Promise<QuirtSessionRecord> {
    const record = this.get(sessionId, principalFingerprint);
    const handle = this.#handles.get(sessionId);
    if (handle === undefined) throw new QuirtError("not_found", "Quirt session PTY is unavailable");
    handle.process.resize(columns, rows);
    if (record.mode === "tmux" && record.tmuxName !== null) await this.tmux.resize(record.tmuxName, columns, rows);
    const updated = this.state.updateSession(sessionId, { columns, rows });
    this.#events.emit("event", { event: "session.resize", sessionId, streamId: record.outputStreamId, columns, rows } satisfies QuirtSessionOutputEvent);
    return updated;
  }

  async signal(sessionId: string, principalFingerprint: string, signal: NodeJS.Signals): Promise<QuirtSessionRecord> {
    const record = this.get(sessionId, principalFingerprint);
    if (!SIGNALS.has(signal)) throw new QuirtError("invalid_request", "Quirt terminal signal is unsupported");
    if (record.mode === "tmux" && record.tmuxName !== null) await this.tmux.signal(record.tmuxName, signal);
    else {
      const handle = this.#handles.get(sessionId);
      if (handle === undefined) throw new QuirtError("not_found", "Quirt session PTY is unavailable");
      handle.process.signal(signal);
    }
    this.#events.emit("event", { event: "session.signal", sessionId, streamId: record.outputStreamId, signal } satisfies QuirtSessionOutputEvent);
    return this.state.getSession(sessionId);
  }

  detach(sessionId: string, principalFingerprint: string, readerId?: string): QuirtSessionRecord {
    const record = this.get(sessionId, principalFingerprint);
    if (readerId !== undefined) {
      const reader = this.state.getSessionReader(readerId);
      if (reader.sessionId !== sessionId || reader.ownerPrincipalFingerprint !== principalFingerprint) throw new QuirtError("authorization_failed", "Quirt reader principal does not match");
      this.state.detachSessionReader(readerId);
    }
    return record;
  }

  async close(sessionId: string, principalFingerprint: string, signal: NodeJS.Signals = "SIGHUP"): Promise<QuirtSessionRecord> {
    const record = this.get(sessionId, principalFingerprint);
    const handle = this.#handles.get(sessionId);
    if (handle !== undefined) handle.closing = true;
    if (record.mode === "tmux" && record.tmuxName !== null) await this.tmux.killSession(record.tmuxName);
    else if (handle !== undefined) handle.process.signal(signal);
    this.#dispose(sessionId);
    const stream = this.state.getStream(record.outputStreamId);
    if (stream.status === "open") this.state.finalizeStream(record.outputStreamId);
    return this.state.updateSession(sessionId, { status: "closed", ptyPid: null });
  }

  shutdown(): void {
    for (const [sessionId, handle] of this.#handles) {
      const record = this.state.getSession(sessionId);
      handle.closing = true;
      try { handle.process.signal("SIGHUP"); } catch { /* process may already be gone */ }
      this.#dispose(sessionId);
      this.state.updateSession(sessionId, { status: record.mode === "tmux" ? "detached" : "lost", ptyPid: null });
    }
  }

  #attachProcess(record: QuirtSessionRecord, existing: boolean): void {
    if (this.#handles.has(record.sessionId)) return;
    const processHandle = record.mode === "tmux" && record.tmuxName !== null
      ? this.tmux.attach({
          sessionId: record.sessionId,
          tmuxName: record.tmuxName,
          executable: record.executable,
          arguments: record.arguments,
          workingDirectory: record.workingDirectory,
          environment: record.environment,
          columns: record.columns,
          rows: record.rows
        }, existing)
      : this.ptys.spawn({
          executable: record.executable,
          arguments: record.arguments,
          workingDirectory: record.workingDirectory,
          environment: record.environment,
          columns: record.columns,
          rows: record.rows
        });
    const handle: SessionHandle = { process: processHandle, closing: false, disposeData: () => undefined, disposeExit: () => undefined };
    handle.disposeData = processHandle.onData(bytes => {
      const range = this.state.appendStream(record.outputStreamId, bytes);
      this.#events.emit("event", { event: "session.output", sessionId: record.sessionId, streamId: record.outputStreamId, startOffset: range.startOffset, endOffset: range.endOffset, bytes } satisfies QuirtSessionOutputEvent);
    });
    handle.disposeExit = processHandle.onExit(exit => { void this.#exited(record.sessionId, exit); });
    this.#handles.set(record.sessionId, handle);
    this.state.updateSession(record.sessionId, { status: "running", ptyPid: processHandle.pid });
  }

  async #exited(sessionId: string, exit: QuirtPtyExit): Promise<void> {
    const handle = this.#handles.get(sessionId);
    if (handle === undefined) return;
    const record = this.state.getSession(sessionId);
    const closing = handle.closing;
    this.#dispose(sessionId);
    if (closing || record.status === "closed") return;
    if (record.mode === "tmux" && record.tmuxName !== null) {
      try {
        if (await this.tmux.hasSession(record.tmuxName)) {
          this.state.updateSession(sessionId, { status: "detached", ptyPid: null, exitCode: exit.exitCode, exitSignal: exit.signal });
          return;
        }
      } catch {
        this.state.recordRecovery("session", sessionId, "exit-probe", "failed", { tmuxName: record.tmuxName });
      }
    }
    const stream = this.state.getStream(record.outputStreamId);
    if (stream.status === "open") this.state.finalizeStream(record.outputStreamId);
    this.state.updateSession(sessionId, { status: "exited", ptyPid: null, exitCode: exit.exitCode, exitSignal: exit.signal });
    this.#events.emit("event", { event: "session.exit", sessionId, streamId: record.outputStreamId, exitCode: exit.exitCode, exitSignal: exit.signal } satisfies QuirtSessionOutputEvent);
  }

  #authorize(record: QuirtSessionRecord, principalFingerprint: string): void {
    if (record.ownerPrincipalFingerprint !== principalFingerprint) throw new QuirtError("authorization_failed", "Quirt session principal does not match");
  }

  #dispose(sessionId: string): void {
    const handle = this.#handles.get(sessionId);
    if (handle === undefined) return;
    handle.disposeData();
    handle.disposeExit();
    this.#handles.delete(sessionId);
  }
}
