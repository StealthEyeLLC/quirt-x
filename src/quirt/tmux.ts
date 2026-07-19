import { execFile } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtPtyFactory, QuirtPtyProcess } from "./pty.js";

const execute = promisify(execFile);
const TMUX_NAME = /^quirt-[a-f0-9]{32}$/u;

export interface QuirtTmuxSessionSpec {
  sessionId: string;
  tmuxName: string;
  executable: string;
  arguments: readonly string[];
  workingDirectory: string;
  environment: Readonly<Record<string, string>>;
  columns: number;
  rows: number;
}

function name(value: string): string {
  if (!TMUX_NAME.test(value)) throw new QuirtError("invalid_request", "Quirt tmux identity is invalid");
  return value;
}

function foregroundGroup(pid: number): number {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    if (close < 0) throw new Error("malformed proc stat");
    const fields = stat.slice(close + 2).trim().split(/\s+/u);
    const tpgid = Number(fields[5]);
    return Number.isSafeInteger(tpgid) && tpgid > 0 ? tpgid : pid;
  } catch { return pid; }
}

export class QuirtTmuxController {
  readonly socketPath: string;

  constructor(private readonly config: QuirtConfig, private readonly ptys: QuirtPtyFactory) {
    const sessionsRoot = join(config.stateRoot, "sessions");
    mkdirSync(sessionsRoot, { recursive: true, mode: 0o700 });
    this.socketPath = join(sessionsRoot, "tmux.sock");
    if (Buffer.byteLength(this.socketPath) > 96) throw new QuirtError("configuration_error", "Quirt tmux socket path is too long");
  }

  async version(): Promise<string> {
    try {
      const result = await execute(this.config.tmuxPath, ["-V"], { timeout: this.config.connectionTimeoutMs, maxBuffer: 4096, encoding: "utf8" });
      return result.stdout.trim();
    } catch { throw new QuirtError("configuration_error", "tmux is unavailable"); }
  }

  async hasSession(tmuxName: string): Promise<boolean> {
    try { await this.run(["has-session", "-t", name(tmuxName)]); return true; }
    catch (cause) {
      if (cause instanceof QuirtError && cause.code === "not_found") return false;
      throw cause;
    }
  }

  async listSessionNames(): Promise<string[]> {
    try {
      const output = await this.run(["list-sessions", "-F", "#{session_name}"]);
      return output.split("\n").map(value => value.trim()).filter(value => TMUX_NAME.test(value)).sort();
    } catch (cause) {
      if (cause instanceof QuirtError && cause.code === "not_found") return [];
      throw cause;
    }
  }

  attach(spec: QuirtTmuxSessionSpec, existing: boolean): QuirtPtyProcess {
    name(spec.tmuxName);
    const base = ["-S", this.socketPath];
    const args = existing
      ? [...base, "attach-session", "-t", spec.tmuxName]
      : [...base, "new-session", "-s", spec.tmuxName, "-c", spec.workingDirectory, "-x", String(spec.columns), "-y", String(spec.rows),
          ...Object.entries(spec.environment).flatMap(([key, value]) => ["-e", `${key}=${value}`]), "--", spec.executable, ...spec.arguments];
    return this.ptys.spawn({
      executable: this.config.tmuxPath,
      arguments: args,
      workingDirectory: spec.workingDirectory,
      environment: spec.environment,
      columns: spec.columns,
      rows: spec.rows
    });
  }

  async resize(tmuxName: string, columns: number, rows: number): Promise<void> {
    await this.run(["resize-window", "-t", name(tmuxName), "-x", String(columns), "-y", String(rows)]);
  }

  async signal(tmuxName: string, signal: NodeJS.Signals): Promise<void> {
    const output = await this.run(["display-message", "-p", "-t", name(tmuxName), "#{pane_pid}"]);
    const panePid = Number(output.trim());
    if (!Number.isSafeInteger(panePid) || panePid < 2) throw new QuirtError("not_found", "Quirt tmux pane process is unavailable");
    try { process.kill(-foregroundGroup(panePid), signal); }
    catch { throw new QuirtError("not_found", "Quirt foreground process group is unavailable"); }
  }

  async killSession(tmuxName: string): Promise<void> {
    try { await this.run(["kill-session", "-t", name(tmuxName)]); }
    catch (cause) { if (!(cause instanceof QuirtError && cause.code === "not_found")) throw cause; }
  }

  private async run(argumentsList: readonly string[]): Promise<string> {
    try {
      const result = await execute(this.config.tmuxPath, ["-S", this.socketPath, ...argumentsList], {
        timeout: this.config.requestTimeoutMs,
        maxBuffer: 1024 * 1024,
        encoding: "utf8",
        env: { ...process.env, TMUX: undefined }
      });
      return result.stdout;
    } catch (cause) {
      const code = cause !== null && typeof cause === "object" && "code" in cause ? (cause as { code?: unknown }).code : undefined;
      if (code === 1 || code === "ENOENT") throw new QuirtError(code === "ENOENT" ? "configuration_error" : "not_found", code === "ENOENT" ? "tmux is unavailable" : "Quirt tmux session was not found");
      throw new QuirtError("internal_error", "Quirt tmux control operation failed");
    }
  }
}

export function quirtTmuxName(sessionId: string): string {
  const normalized = sessionId.replaceAll("-", "").toLowerCase();
  if (!/^[a-f0-9]{32}$/u.test(normalized)) throw new QuirtError("invalid_request", "Quirt session identity is invalid");
  return `quirt-${normalized}`;
}
