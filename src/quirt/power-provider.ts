import { spawn } from "node:child_process";
import { access, readFile, readlink, stat } from "node:fs/promises";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtJobManager } from "./job-manager.js";
import type { QuirtProcessService } from "./process-service.js";
import type { QuirtSessionManager } from "./session-manager.js";
import type { QuirtStateStore } from "./state.js";
import type { QuirtTmuxController } from "./tmux.js";
import {
  QuirtPowerProviderRegistry as CoreRegistry,
  QuirtPowerProviderService as CoreService,
  publicProviderInstance,
  safeProviderConfiguration,
  type PowerCommandResult,
  type PowerExecutableProbe,
  type PowerFeatureProbe,
  type PowerProviderProbe,
  type PowerRunInput,
  type QuirtPowerProviderAdapter,
  type QuirtPowerProviderContext,
  type QuirtPowerProviderResult,
  type QuirtPowerRuntime
} from "./power-provider-core.js";

export {
  publicProviderInstance,
  safeProviderConfiguration
};
export type {
  PowerCommandResult,
  PowerExecutableProbe,
  PowerFeatureProbe,
  PowerProviderProbe,
  PowerRunInput,
  QuirtPowerProviderAdapter,
  QuirtPowerProviderContext,
  QuirtPowerProviderResult,
  QuirtPowerRuntime
};

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

/** Linux provider runtime with explicit-only timeouts and process-group cleanup. */
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
    const timeoutMs = input.timeoutMs;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 64 * 1024 * 1024) throw new QuirtError("invalid_request", "Provider output bound is invalid");
    if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 24 * 60 * 60 * 1000)) throw new QuirtError("invalid_request", "Provider timeout is invalid");
    if (input.signal?.aborted === true) return Promise.reject(new QuirtError("canceled", "Provider operation was canceled", true));

    return new Promise((resolve, reject) => {
      let settled = false;
      let timedOut = false;
      let timer: NodeJS.Timeout | undefined;
      let escalation: NodeJS.Timeout | undefined;
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
        detached: true,
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
      const terminate = (signal: NodeJS.Signals): void => {
        const pid = child.pid;
        if (pid !== undefined && pid >= 2) {
          try { process.kill(-pid, signal); return; } catch { /* fall back to the leader */ }
        }
        try { child.kill(signal); } catch { /* close/error settles the operation */ }
      };
      const requestTermination = (): void => {
        terminate("SIGTERM");
        if (escalation === undefined) {
          escalation = setTimeout(() => terminate("SIGKILL"), 500);
          escalation.unref();
        }
      };
      const cleanup = (): void => {
        if (timer !== undefined) clearTimeout(timer);
        if (escalation !== undefined) clearTimeout(escalation);
        input.signal?.removeEventListener("abort", requestTermination);
      };
      child.stdout.on("data", collect(stdout));
      child.stderr.on("data", collect(stderr));
      input.signal?.addEventListener("abort", requestTermination, { once: true });
      if (timeoutMs !== undefined) {
        timer = setTimeout(() => { timedOut = true; requestTermination(); }, timeoutMs);
        timer.unref();
      }
      child.once("error", (cause) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(cause);
      });
      child.once("close", (code, signal) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (input.signal?.aborted === true) { reject(new QuirtError("canceled", "Provider operation was canceled", true)); return; }
        if (timedOut) { reject(new QuirtError("timeout", "Provider operation timed out", true)); return; }
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

export class QuirtPowerProviderRegistry extends CoreRegistry {
  constructor(state: QuirtStateStore, runtime: QuirtPowerRuntime = new NodePowerRuntime()) { super(state, runtime); }
}

export class QuirtPowerProviderService extends CoreService {
  constructor(
    config: QuirtConfig,
    state: QuirtStateStore,
    sessions: QuirtSessionManager,
    jobs: QuirtJobManager,
    tmux: QuirtTmuxController,
    processes: QuirtProcessService,
    registry: QuirtPowerProviderRegistry = new QuirtPowerProviderRegistry(state)
  ) { super(config, state, sessions, jobs, tmux, processes, registry); }
}
