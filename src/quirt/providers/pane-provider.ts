import { randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
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

const TMUX_PANE = /^%[0-9]+$/u;
const TMUX_WINDOW = /^@[0-9]+$/u;
const FIELD = "\u001f";

function requiredText(value: unknown, label: string, maximum = 4096): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || Buffer.byteLength(value) > maximum) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

function optionalText(value: unknown, label: string, maximum = 4096): string | undefined {
  return value === undefined ? undefined : requiredText(value, label, maximum);
}

function pane(value: unknown, label = "Tmux pane identity"): string {
  const result = requiredText(value, label, 32);
  if (!TMUX_PANE.test(result)) throw new QuirtError("invalid_request", label + " is invalid");
  return result;
}

function windowIdentity(value: unknown): string {
  const result = requiredText(value, "Tmux window identity", 32);
  if (!TMUX_WINDOW.test(result)) throw new QuirtError("invalid_request", "Tmux window identity is invalid");
  return result;
}

function positiveInteger(value: unknown, label: string, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) throw new QuirtError("invalid_request", label + " is invalid");
  return value;
}

function argumentList(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 1024 || value.some((item) => typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > 64 * 1024)) throw new QuirtError("invalid_request", "Pane process arguments are invalid");
  return [...value] as string[];
}

function sessionTarget(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): { sessionId: string; tmuxName: string } {
  const sessionId = requiredText(payload.sessionId, "Quirt session identity", 128);
  const record = context.sessions.get(sessionId, context.ownerPrincipalFingerprint);
  if (record.tmuxName === null || record.mode !== "tmux") throw new QuirtError("instance_conflict", "Pane topology requires a Quirt-private tmux session");
  return { sessionId, tmuxName: record.tmuxName };
}

function parseNumber(value: string): number | null {
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : null;
}

function parseWindows(output: string): Array<Record<string, unknown>> {
  return output.split("\n").filter(Boolean).map((line) => {
    const [windowId, index, name, width, height, active, paneCount] = line.split(FIELD);
    if (windowId === undefined || !TMUX_WINDOW.test(windowId)) throw new QuirtError("stale_instance", "Tmux returned a stale window identity");
    return { windowId, index: parseNumber(index ?? ""), name: name ?? "", width: parseNumber(width ?? ""), height: parseNumber(height ?? ""), active: active === "1", paneCount: parseNumber(paneCount ?? "") };
  });
}

async function parsePanes(output: string, context: QuirtPowerProviderContext): Promise<Array<Record<string, unknown>>> {
  const result: Array<Record<string, unknown>> = [];
  for (const line of output.split("\n").filter(Boolean)) {
    const [paneId, windowId, index, width, height, active, dead, pid, command, path, cursorX, cursorY] = line.split(FIELD);
    if (paneId === undefined || !TMUX_PANE.test(paneId) || windowId === undefined || !TMUX_WINDOW.test(windowId)) throw new QuirtError("stale_instance", "Tmux returned a stale pane identity");
    const processId = parseNumber(pid ?? "");
    let foregroundProcessIdentity: Readonly<Record<string, unknown>> | null = null;
    if (processId !== null && processId > 1) {
      try { foregroundProcessIdentity = await context.runtime.processIdentity(processId); } catch { foregroundProcessIdentity = null; }
    }
    result.push({
      paneId,
      windowId,
      index: parseNumber(index ?? ""),
      width: parseNumber(width ?? ""),
      height: parseNumber(height ?? ""),
      active: active === "1",
      dead: dead === "1",
      foregroundCommand: command ?? "",
      currentPath: path ?? "",
      cursor: { x: parseNumber(cursorX ?? ""), y: parseNumber(cursorY ?? "") },
      foregroundProcessIdentity
    });
  }
  return result;
}

export class TmuxPaneProvider implements QuirtPowerProviderAdapter {
  readonly providerId = "terminal.tmux";
  readonly operationIds = QUIRT_POWER_OPERATION_GROUPS.panes;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const target = sessionTarget(payload, context);
    if (operation !== "quirt.pane.broadcast" && binary.length !== 0) throw new QuirtError("invalid_request", "This pane operation does not accept binary input");
    switch (operation) {
      case "quirt.pane.open":
        return await this.open(payload, target, context);
      case "quirt.pane.list":
        return await this.list(payload, target, context);
      case "quirt.pane.split":
        return await this.split(payload, target, context);
      case "quirt.pane.focus":
        return await this.focus(payload, target, context);
      case "quirt.pane.resize":
        return await this.resize(payload, target, context);
      case "quirt.pane.move":
        return await this.move(payload, target, context);
      case "quirt.pane.broadcast":
        return await this.broadcast(payload, binary, target, context);
      case "quirt.pane.close":
        return await this.close(payload, target, context);
      default:
        throw new QuirtError("unknown_operation", "Pane operation is unknown");
    }
  }

  async recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext, "ownerPrincipalFingerprint" | "requestId" | "signal">): Promise<void> {
    const sessionId = record.relatedSessions[0];
    const tmuxName = typeof record.configuration.tmuxName === "string" ? record.configuration.tmuxName : null;
    if (sessionId === undefined || tmuxName === null) throw new QuirtError("provider_lost", "Pane recovery metadata is incomplete");
    const available = await context.tmux.hasSession(tmuxName);
    context.state.power.putInstance({ ...record, state: available ? "ready" : "lost", recoveryClassification: available ? "adopted" : "tmux_session_absent", failureClassification: available ? null : "provider_lost", lastProbeAt: new Date().toISOString() });
    context.state.power.recordRecovery(record.instanceId, available ? "adopted" : "lost", { sessionId, tmuxName });
  }

  private async tmux(argumentsList: readonly string[], context: QuirtPowerProviderContext): Promise<string> {
    const result = await context.runtime.run({ executable: context.config.tmuxPath, arguments: ["-S", context.tmux.socketPath, ...argumentsList], timeoutMs: context.config.requestTimeoutMs, maximumOutputBytes: 4 * 1024 * 1024, signal: context.signal });
    if (result.exitCode !== 0) {
      const diagnostic = result.stderr.toString("utf8").slice(0, 4096);
      if (/no server running|can't find|not found/iu.test(diagnostic)) throw new QuirtError("stale_instance", "Tmux topology identity is no longer present");
      throw new QuirtError("provider_degraded", "Tmux topology operation failed", true, { exitCode: result.exitCode, outputTruncated: result.truncated });
    }
    return result.stdout.toString("utf8");
  }

  private async topology(target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<Record<string, unknown>> {
    const [windows, panes] = await Promise.all([
      this.tmux(["list-windows", "-t", target.tmuxName, "-F", "#{window_id}" + FIELD + "#{window_index}" + FIELD + "#{window_name}" + FIELD + "#{window_width}" + FIELD + "#{window_height}" + FIELD + "#{window_active}" + FIELD + "#{window_panes}"], context),
      this.tmux(["list-panes", "-t", target.tmuxName, "-F", "#{pane_id}" + FIELD + "#{window_id}" + FIELD + "#{pane_index}" + FIELD + "#{pane_width}" + FIELD + "#{pane_height}" + FIELD + "#{pane_active}" + FIELD + "#{pane_dead}" + FIELD + "#{pane_pid}" + FIELD + "#{pane_current_command}" + FIELD + "#{pane_current_path}" + FIELD + "#{cursor_x}" + FIELD + "#{cursor_y}"], context)
    ]);
    return { sessionId: target.sessionId, tmuxName: target.tmuxName, windows: parseWindows(windows), panes: await parsePanes(panes, context) };
  }

  private command(payload: Readonly<Record<string, unknown>>): string[] {
    const executable = optionalText(payload.executable, "Pane executable");
    if (executable === undefined) return [];
    return ["--", executable, ...argumentList(payload.arguments)];
  }

  private async createTopologyInstance(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, identity: Record<string, unknown>, context: QuirtPowerProviderContext): Promise<QuirtProviderInstanceRecord> {
    const configuration = safeProviderConfiguration({ tmuxName: target.tmuxName, ...identity, correlation: payload.correlation ?? null });
    const record = context.state.power.putInstance({
      providerId: this.providerId,
      providerVersion: "1",
      ownerPrincipalFingerprint: context.ownerPrincipalFingerprint,
      targetHost: context.targetHost,
      state: "ready",
      configuration,
      relatedSessions: [target.sessionId],
      relatedJobs: typeof payload.jobId === "string" ? [payload.jobId] : [],
      health: { state: "healthy", probe: "tmux-structured-output" },
      cleanupStatus: "active",
      lastProbeAt: new Date().toISOString()
    });
    context.state.power.appendEvent(record.instanceId, "lifecycle.ready", { operation: context.requestId, ...identity });
    return record;
  }

  private async open(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const name = optionalText(payload.name, "Tmux window name", 256) ?? "quirt";
    const output = await this.tmux(["new-window", "-d", "-t", target.tmuxName, "-n", name, "-P", "-F", "#{window_id}" + FIELD + "#{pane_id}", ...this.command(payload)], context);
    const [windowId, paneId] = output.trim().split(FIELD);
    if (windowId === undefined || !TMUX_WINDOW.test(windowId) || paneId === undefined || !TMUX_PANE.test(paneId)) throw new QuirtError("stale_instance", "Tmux did not return durable topology identities");
    const instance = await this.createTopologyInstance(payload, target, { windowId, paneId }, context);
    return { payload: { instance: publicProviderInstance(instance), topology: await this.topology(target, context) }, instanceId: instance.instanceId };
  }

  private async list(_payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const page = context.state.power.listInstances(context.ownerPrincipalFingerprint, { providerId: this.providerId, maximum: 1000 });
    return { payload: { topology: await this.topology(target, context), instances: page.instances.map(publicProviderInstance), truncated: page.truncated, next: page.next } };
  }

  private async split(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const source = pane(payload.paneId);
    const direction = payload.direction === "vertical" ? "vertical" : payload.direction === "horizontal" || payload.direction === undefined ? "horizontal" : (() => { throw new QuirtError("invalid_request", "Pane split direction is invalid"); })();
    const size = payload.size === undefined ? [] : ["-l", String(positiveInteger(payload.size, "Pane split size", 10000))];
    const output = await this.tmux(["split-window", direction === "horizontal" ? "-h" : "-v", "-d", "-t", source, ...size, "-P", "-F", "#{window_id}" + FIELD + "#{pane_id}", ...this.command(payload)], context);
    const [windowId, paneId] = output.trim().split(FIELD);
    if (windowId === undefined || !TMUX_WINDOW.test(windowId) || paneId === undefined || !TMUX_PANE.test(paneId)) throw new QuirtError("stale_instance", "Tmux did not return split identities");
    const instance = await this.createTopologyInstance(payload, target, { windowId, paneId, sourcePaneId: source, direction }, context);
    return { payload: { instance: publicProviderInstance(instance), topology: await this.topology(target, context) }, instanceId: instance.instanceId };
  }

  private async focus(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const paneId = pane(payload.paneId);
    await this.tmux(["select-pane", "-t", paneId], context);
    return { payload: { focused: paneId, topology: await this.topology(target, context) } };
  }

  private async resize(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const paneId = pane(payload.paneId);
    const width = payload.width === undefined ? undefined : positiveInteger(payload.width, "Pane width", 10000);
    const height = payload.height === undefined ? undefined : positiveInteger(payload.height, "Pane height", 10000);
    if (width === undefined && height === undefined) throw new QuirtError("invalid_request", "Pane width or height is required");
    await this.tmux(["resize-pane", "-t", paneId, ...(width === undefined ? [] : ["-x", String(width)]), ...(height === undefined ? [] : ["-y", String(height)])], context);
    return { payload: { resized: paneId, width: width ?? null, height: height ?? null, topology: await this.topology(target, context) } };
  }

  private async move(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const source = pane(payload.sourcePaneId, "Source pane identity");
    const destination = pane(payload.destinationPaneId, "Destination pane identity");
    const action = payload.action === "move" ? "move" : payload.action === "swap" || payload.action === undefined ? "swap" : (() => { throw new QuirtError("invalid_request", "Pane move action is invalid"); })();
    await this.tmux([action === "swap" ? "swap-pane" : "move-pane", "-s", source, "-t", destination], context);
    return { payload: { action, sourcePaneId: source, destinationPaneId: destination, topology: await this.topology(target, context) } };
  }

  private async broadcast(payload: Readonly<Record<string, unknown>>, binary: Buffer, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const windowId = payload.windowId === undefined ? undefined : windowIdentity(payload.windowId);
    const paneId = payload.paneId === undefined ? undefined : pane(payload.paneId);
    const enabled = payload.enabled === undefined ? true : payload.enabled === true;
    if (payload.enabled !== undefined && typeof payload.enabled !== "boolean") throw new QuirtError("invalid_request", "Pane broadcast state is invalid");
    if (windowId !== undefined) await this.tmux(["set-window-option", "-t", windowId, "synchronize-panes", enabled ? "on" : "off"], context);
    const literal = optionalText(payload.text, "Pane broadcast text", 1024 * 1024);
    const bytes = binary.length > 0 ? binary : literal === undefined ? Buffer.alloc(0) : Buffer.from(literal, "utf8");
    if (bytes.length > 1024 * 1024) throw new QuirtError("output_truncated", "Pane broadcast input exceeds the bounded limit");
    if (bytes.length > 0) {
      const directory = join(context.config.stateRoot, "providers", "tmux", "buffers");
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const path = join(directory, randomUUID());
      const bufferName = "quirt-" + randomUUID().replaceAll("-", "");
      try {
        await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
        await this.tmux(["load-buffer", "-b", bufferName, path], context);
        await this.tmux(["paste-buffer", "-b", bufferName, "-d", ...(paneId === undefined ? [] : ["-t", paneId])], context);
      } finally {
        await rm(path, { force: true });
        await this.tmux(["delete-buffer", "-b", bufferName], context).catch(() => undefined);
      }
    }
    return { payload: { windowId: windowId ?? null, paneId: paneId ?? null, enabled, byteCount: bytes.length, topology: await this.topology(target, context) } };
  }

  private async close(payload: Readonly<Record<string, unknown>>, target: { sessionId: string; tmuxName: string }, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const paneId = payload.paneId === undefined ? undefined : pane(payload.paneId);
    const windowId = payload.windowId === undefined ? undefined : windowIdentity(payload.windowId);
    if ((paneId === undefined) === (windowId === undefined)) throw new QuirtError("invalid_request", "Exactly one pane or window identity is required");
    await this.tmux([paneId === undefined ? "kill-window" : "kill-pane", "-t", paneId ?? windowId!], context);
    const instanceId = typeof payload.instanceId === "string" ? payload.instanceId : undefined;
    if (instanceId !== undefined) {
      const record = context.state.power.getInstance(instanceId, context.ownerPrincipalFingerprint, context.targetHost);
      context.state.power.putInstance({ ...record, state: "stopped", cleanupStatus: "complete", health: { state: "stopped" }, lastProbeAt: new Date().toISOString() });
      context.state.power.appendEvent(instanceId, "cleanup.complete", { paneId: paneId ?? null, windowId: windowId ?? null });
    }
    return { payload: { closed: { paneId: paneId ?? null, windowId: windowId ?? null }, topology: await this.topology(target, context) } };
  }
}
