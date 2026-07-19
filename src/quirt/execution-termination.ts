import type { QuirtProcessIdentity } from "./process-identity.js";

export type QuirtTerminationReason = "graceful_cancel" | "forced_cancel" | "timeout" | "protocol_cancel";

export interface QuirtTerminationOptions {
  gracefulSignal?: NodeJS.Signals;
  graceIntervalMs?: number;
  escalate?: boolean;
}

export interface QuirtTerminationEvidence {
  reason: QuirtTerminationReason;
  requestedAt: string;
  gracefulSignal: NodeJS.Signals | null;
  graceIntervalMs: number | null;
  escalated: boolean;
  forcedSignal: NodeJS.Signals | null;
  completedAt: string | null;
}

export interface ProcessSignaler {
  signalProcess(pid: number, signal: NodeJS.Signals): void;
  signalProcessGroup(pgid: number, signal: NodeJS.Signals): void;
  signalPty?(signal: NodeJS.Signals): void;
}

export interface TerminationClock {
  now(): number;
  sleep(ms: number): Promise<void>;
}

export class RealTerminationClock implements TerminationClock {
  now(): number { return Date.now(); }
  async sleep(ms: number): Promise<void> { await new Promise(resolve => setTimeout(resolve, ms)); }
}

interface ScheduledSleep {
  until: number;
  resolve: () => void;
}

export class FakeTerminationClock implements TerminationClock {
  #now = 0;
  readonly #sleepers: ScheduledSleep[] = [];

  now(): number { return this.#now; }

  advance(ms: number): void {
    this.#now += ms;
    for (let index = this.#sleepers.length - 1; index >= 0; index -= 1) {
      const sleeper = this.#sleepers[index]!;
      if (sleeper.until <= this.#now) {
        this.#sleepers.splice(index, 1);
        sleeper.resolve();
      }
    }
  }

  async sleep(ms: number): Promise<void> {
    await new Promise<void>(resolve => {
      this.#sleepers.push({ until: this.#now + ms, resolve });
    });
  }
}

export function resolveProcessSignalTarget(
  identity: QuirtProcessIdentity | null,
  fallbackPid: number | null
): { mode: "group"; pgid: number } | { mode: "process"; pid: number } {
  const pgid = identity?.processGroupId;
  if (pgid !== null && pgid !== undefined && pgid >= 2) return { mode: "group", pgid };
  const pid = identity?.pid ?? fallbackPid;
  if (pid === null || pid < 2) throw new Error("missing process identity");
  return { mode: "process", pid };
}

export function deliverProcessSignal(
  input: {
    identity: QuirtProcessIdentity;
    pty: boolean;
    signal: NodeJS.Signals;
    signaler: ProcessSignaler;
    fallbackPid?: number | null;
  }
): void {
  if (input.pty && input.signaler.signalPty !== undefined) {
    input.signaler.signalPty(input.signal);
    return;
  }
  const target = resolveProcessSignalTarget(input.identity, input.fallbackPid ?? input.identity.pid);
  if (target.mode === "group") input.signaler.signalProcessGroup(target.pgid, input.signal);
  else input.signaler.signalProcess(target.pid, input.signal);
}

export async function runTermination(
  input: {
    identity: QuirtProcessIdentity;
    reason: QuirtTerminationReason;
    pty: boolean;
    options?: QuirtTerminationOptions;
    verifyIdentity: () => Promise<QuirtProcessIdentity>;
    waitForExit: () => Promise<void>;
    signaler: ProcessSignaler;
    clock: TerminationClock;
    abort?: AbortSignal;
  }
): Promise<QuirtTerminationEvidence> {
  const requestedAt = new Date(input.clock.now()).toISOString();
  const gracefulSignal = input.options?.gracefulSignal ?? "SIGTERM";
  const graceIntervalMs = input.options?.graceIntervalMs ?? 5_000;
  const escalate = input.options?.escalate !== false;
  let escalated = false;
  let forcedSignal: NodeJS.Signals | null = null;
  let processExited = false;
  const exitPromise = input.waitForExit().then(() => { processExited = true; }, () => { processExited = true; });
  const deliver = (signal: NodeJS.Signals) => {
    deliverProcessSignal({ identity: input.identity, pty: input.pty, signal, signaler: input.signaler });
  };
  if (input.reason === "forced_cancel") {
    forcedSignal = "SIGKILL";
    await input.verifyIdentity();
    deliver("SIGKILL");
  } else {
    await input.verifyIdentity();
    deliver(gracefulSignal);
    const deadline = input.clock.now() + graceIntervalMs;
    while (input.clock.now() < deadline && !processExited) {
      if (input.abort?.aborted === true) break;
      const remaining = deadline - input.clock.now();
      if (remaining <= 0) break;
      const winner = await Promise.race([
        exitPromise.then(() => "exit" as const),
        input.clock.sleep(Math.min(50, remaining)).then(() => "sleep" as const)
      ]);
      if (winner === "exit" || processExited) break;
    }
    if (!processExited && escalate) {
      try {
        await input.verifyIdentity();
        escalated = true;
        forcedSignal = "SIGKILL";
        deliver("SIGKILL");
      } catch { /* process already exited */ }
    }
  }
  try { await exitPromise; } catch { /* race */ }
  return Object.freeze({
    reason: input.reason,
    requestedAt,
    gracefulSignal: input.reason === "forced_cancel" ? null : gracefulSignal,
    graceIntervalMs: input.reason === "forced_cancel" ? null : graceIntervalMs,
    escalated,
    forcedSignal,
    completedAt: new Date(input.clock.now()).toISOString()
  });
}
