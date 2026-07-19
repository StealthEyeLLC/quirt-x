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
  const deliver = (signal: NodeJS.Signals) => {
    if (input.pty && input.signaler.signalPty !== undefined) input.signaler.signalPty(signal);
    else if (input.identity.processGroupId !== null && input.identity.processGroupId !== undefined && input.identity.processGroupId >= 2) input.signaler.signalProcessGroup(input.identity.processGroupId, signal);
    else input.signaler.signalProcess(input.identity.pid, signal);
  };
  if (input.reason === "forced_cancel") {
    forcedSignal = "SIGKILL";
    await input.verifyIdentity();
    deliver("SIGKILL");
  } else {
    await input.verifyIdentity();
    deliver(gracefulSignal);
    const deadline = input.clock.now() + graceIntervalMs;
    while (input.clock.now() < deadline) {
      if (input.abort?.aborted === true) break;
      try { await Promise.race([input.waitForExit(), input.clock.sleep(Math.min(50, deadline - input.clock.now()))]); break; }
      catch { /* continue waiting */ }
      if (input.clock.now() >= deadline) break;
    }
    if (escalate) {
      try {
        await input.verifyIdentity();
        escalated = true;
        forcedSignal = "SIGKILL";
        deliver("SIGKILL");
      } catch { /* process already exited */ }
    }
  }
  try { await input.waitForExit(); } catch { /* race */ }
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
