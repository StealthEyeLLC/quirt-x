import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { readdir, readFile, readlink, stat } from "node:fs/promises";
import { constants as osConstants } from "node:os";
import { promisify } from "node:util";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtJobManager } from "./job-manager.js";
import type { QuirtSessionManager } from "./session-manager.js";
import type { QuirtStateStore } from "./state.js";

const execute = promisify(execFile);
const MAX_PROCESS_RESULT = 4 * 1024 * 1024;

import type { QuirtProcessIdentity } from "./process-identity.js";

export type { QuirtProcessIdentity };

interface ProcStat { state: string; parentPid: number; processGroup: number; sessionId: number; ttyNumber: number; userTicks: number; systemTicks: number; startTimeTicks: number; virtualBytes: number; residentPages: number; }

export interface QuirtJournalQuery {
  afterCursor?: string;
  maximumEntries: number;
  filters: Readonly<{ unit?: string; pid?: number; uid?: number; priority?: number }>;
}

export interface QuirtJournalPage {
  entries: readonly Readonly<Record<string, unknown>>[];
  cursor: string | null;
  stderr: string;
  rotationDetected?: boolean;
}

export interface QuirtJournalAdapter { query(input: QuirtJournalQuery): Promise<QuirtJournalPage>; }

export class JournalctlAdapter implements QuirtJournalAdapter {
  async query(input: QuirtJournalQuery): Promise<QuirtJournalPage> {
    const args = ["--output=json", "--no-pager", "--show-cursor", "--lines", String(input.maximumEntries)];
    if (input.afterCursor !== undefined) args.push("--after-cursor", input.afterCursor);
    if (input.filters.unit !== undefined) args.push(`_SYSTEMD_UNIT=${input.filters.unit}`);
    if (input.filters.pid !== undefined) args.push(`_PID=${pid(input.filters.pid)}`);
    if (input.filters.uid !== undefined) args.push(`_UID=${input.filters.uid}`);
    if (input.filters.priority !== undefined) args.push("--priority", String(input.filters.priority));
    try {
      const result = await execute("/usr/bin/journalctl", args, { encoding: "utf8", maxBuffer: MAX_PROCESS_RESULT, timeout: 10_000, env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" } });
      const lines = result.stdout.split("\n");
      const cursorLine = lines.find(line => line.startsWith("-- cursor: "));
      const entries = lines.filter(line => line.startsWith("{")).map(line => {
        try { const value = JSON.parse(line) as unknown; if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("not an object"); return Object.freeze(value as Record<string, unknown>); }
        catch { throw new QuirtError("internal_error", "Quirt journal returned malformed machine data"); }
      });
      return { entries, cursor: cursorLine?.slice(11) ?? (entries.at(-1)?.__CURSOR as string | undefined) ?? input.afterCursor ?? null, stderr: result.stderr.slice(0, 4096) };
    } catch (cause) {
      if (cause instanceof QuirtError) throw cause;
      const error = cause as NodeJS.ErrnoException & { stderr?: string };
      if (error.code === "ENOENT") throw new QuirtError("provider_unavailable", "journald is unavailable on this host");
      if ((error.stderr ?? "").toLocaleLowerCase().includes("cursor")) throw new QuirtError("journal_cursor_invalidated", "Quirt journal cursor was invalidated", true);
      throw new QuirtError("provider_unavailable", "Quirt journal query failed safely");
    }
  }
}

function parseStat(value: string): ProcStat {
  const end = value.lastIndexOf(")"); if (end < 0) throw new QuirtError("process_exited", "Quirt process stat is unavailable"); const fields = value.slice(end + 2).trim().split(/\s+/u); if (fields.length < 22) throw new QuirtError("process_exited", "Quirt process stat is incomplete");
  const number = (index: number) => { const parsed = Number(fields[index]); if (!Number.isSafeInteger(parsed)) throw new QuirtError("internal_error", "Quirt process stat is invalid"); return parsed; };
  return { state: fields[0]!, parentPid: number(1), processGroup: number(2), sessionId: number(3), ttyNumber: number(4), userTicks: number(11), systemTicks: number(12), startTimeTicks: number(19), virtualBytes: number(20), residentPages: number(21) };
}

function parseStatus(value: string): Record<string, string> { return Object.fromEntries(value.split("\n").filter(line => line.includes(":")).map(line => { const index = line.indexOf(":"); return [line.slice(0, index), line.slice(index + 1).trim()]; })); }
function numericList(value: string | undefined): number[] { return (value ?? "").split(/\s+/u).filter(Boolean).map(Number).filter(Number.isFinite); }
function pid(value: unknown): number { if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 0x7fffffff) throw new QuirtError("invalid_request", "Quirt process PID is invalid"); return value; }
function exactIdentity(value: unknown): QuirtProcessIdentity {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new QuirtError("invalid_request", "Quirt process identity is invalid"); const source = value as Record<string, unknown>; const processId = pid(source.pid);
  if (typeof source.startTimeTicks !== "number" || !Number.isSafeInteger(source.startTimeTicks) || source.startTimeTicks < 0 || typeof source.bootId !== "string" || !/^[a-f0-9-]{36}$/iu.test(source.bootId) || source.pidNamespace !== null && typeof source.pidNamespace !== "string") throw new QuirtError("invalid_request", "Quirt process identity is invalid");
  const optionalInteger = (item: unknown) => item === null || typeof item === "number" && Number.isSafeInteger(item) && item >= 0; if (!optionalInteger(source.executableDevice) || !optionalInteger(source.executableInode)) throw new QuirtError("invalid_request", "Quirt process executable identity is invalid");
  return { pid: processId, startTimeTicks: source.startTimeTicks, bootId: source.bootId, pidNamespace: source.pidNamespace, executableDevice: source.executableDevice as number | null, executableInode: source.executableInode as number | null };
}

export class QuirtProcessService {
  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore, private readonly sessions: QuirtSessionManager, private readonly jobs: QuirtJobManager, private readonly journal: QuirtJournalAdapter = new JournalctlAdapter(), private readonly killProcess: (pid: number, signal: NodeJS.Signals | 0) => void = process.kill) {}

  async list(input: { afterPid?: number; maximumProcesses?: number; uid?: number; state?: string }, owner: string): Promise<Record<string, unknown>> {
    const maximum = input.maximumProcesses ?? 256; const afterPid = input.afterPid ?? 0; if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4096 || !Number.isSafeInteger(afterPid) || afterPid < 0 || afterPid > 0x7fffffff || input.uid !== undefined && (!Number.isSafeInteger(input.uid) || input.uid < 0 || input.uid > 0x7fffffff) || input.state !== undefined && (input.state.length < 1 || input.state.length > 16)) throw new QuirtError("invalid_request", "Quirt process list bound is invalid"); const names = (await readdir("/proc")).filter(name => /^\d+$/u.test(name)).map(Number).sort((left, right) => left - right).filter(value => value > afterPid); const processes = [];
    let responseBytes = 0; let truncated = false; for (const value of names) { try { const process = await this.get({ pid: value }, owner); if ((input.uid !== undefined && (process.credentials as { uid: number }).uid !== input.uid) || (input.state !== undefined && process.state !== input.state)) continue; const bytes = Buffer.byteLength(JSON.stringify(process)); if (responseBytes + bytes > MAX_PROCESS_RESULT) { truncated = true; break; } responseBytes += bytes; processes.push(process); if (processes.length >= maximum) { truncated = names.some(candidate => candidate > value); break; } } catch (cause) { if (!(cause instanceof QuirtError && cause.code === "process_exited")) throw cause; } }
    return { processes, nextPid: processes.length === 0 ? input.afterPid ?? 0 : processes.at(-1)!.identity && (processes.at(-1)!.identity as QuirtProcessIdentity).pid, truncated, bounded: true, responseBytes, maximumResponseBytes: MAX_PROCESS_RESULT };
  }

  async get(input: { pid: number }, owner: string): Promise<Record<string, unknown>> {
    const processId = pid(input.pid); const root = `/proc/${processId}`;
    try {
      const [statText, statusText, cmdline, cgroup, bootId, executable, cwd, namespaces] = await Promise.all([
        readFile(`${root}/stat`, "utf8"), readFile(`${root}/status`, "utf8"), readFile(`${root}/cmdline`).catch(() => Buffer.alloc(0)), readFile(`${root}/cgroup`, "utf8").catch(() => ""), this.bootId(), readlink(`${root}/exe`).catch(() => null), readlink(`${root}/cwd`).catch(() => null), this.namespaces({ pid: processId }, owner)
      ]);
      const parsed = parseStat(statText); const status = parseStatus(statusText); const ids = numericList(status.Uid); const gids = numericList(status.Gid); let executableIdentity: { device: number; inode: number } | null = null; if (executable !== null) { const raw = await stat(`${root}/exe`).catch(() => null); if (raw !== null) executableIdentity = { device: Number(raw.dev), inode: Number(raw.ino) }; }
      const identity: QuirtProcessIdentity = { pid: processId, startTimeTicks: parsed.startTimeTicks, bootId, pidNamespace: (namespaces.namespaces as Record<string, { identity: string }>).pid?.identity ?? null, executableDevice: executableIdentity?.device ?? null, executableInode: executableIdentity?.inode ?? null };
      const args = cmdline.length === 0 ? [] : cmdline.toString("utf8").split("\0").filter(Boolean).slice(0, 1024).map(value => value.slice(0, 65_536)); const unit = /\/system\.slice\/([^/]+\.service)/u.exec(cgroup)?.[1] ?? /\/([^/]+\.scope)/u.exec(cgroup)?.[1] ?? null;
      const correlation = { sessions: this.sessions.list(owner).filter(session => session.ptyPid === processId).map(session => session.sessionId), jobs: this.jobs.list(owner).filter(job => job.processId === processId).map(job => job.jobId) };
      return { identity, state: parsed.state, parentPid: parsed.parentPid, processGroup: parsed.processGroup, sessionId: parsed.sessionId, ttyNumber: parsed.ttyNumber, command: status.Name ?? null, executable, arguments: args, workingDirectory: cwd, credentials: { uid: ids[0] ?? null, effectiveUid: ids[1] ?? null, gid: gids[0] ?? null, effectiveGid: gids[1] ?? null }, threads: Number(status.Threads ?? 0), cpu: { userTicks: parsed.userTicks, systemTicks: parsed.systemTicks }, memory: { virtualBytes: parsed.virtualBytes, residentPages: parsed.residentPages, residentText: status.VmRSS ?? null }, cgroup: cgroup.trim().split("\n").filter(Boolean), systemdUnit: unit, namespaces: namespaces.namespaces, correlation };
    } catch (cause) { if (cause instanceof QuirtError) throw cause; const code = cause instanceof Error && "code" in cause ? cause.code : null; if (code === "ENOENT" || code === "ESRCH") throw new QuirtError("process_exited", "Quirt process exited", true); if (code === "EACCES" || code === "EPERM") throw new QuirtError("authorization_failed", "Quirt process inspection was denied"); throw new QuirtError("internal_error", "Quirt process inspection failed safely"); }
  }

  async signal(input: { identity: QuirtProcessIdentity; signal: NodeJS.Signals }, owner: string): Promise<Record<string, unknown>> {
    const identity = exactIdentity(input.identity); const before = await this.get({ pid: identity.pid }, owner); this.#identity(identity, before.identity as QuirtProcessIdentity);
    if (!(input.signal in osConstants.signals)) throw new QuirtError("invalid_request", "Quirt process signal is invalid");
    try { this.killProcess(identity.pid, input.signal); } catch (cause) { const code = cause instanceof Error && "code" in cause ? cause.code : null; if (code === "ESRCH") throw new QuirtError("process_exited", "Quirt process exited before signaling", true); if (code === "EPERM") throw new QuirtError("authorization_failed", "Quirt process signal was denied"); if (code === "EINVAL") throw new QuirtError("invalid_request", "Quirt process signal is invalid"); throw cause; }
    let postcondition: "alive" | "exited" | "unknown" = "unknown"; try { this.killProcess(identity.pid, 0); postcondition = "alive"; } catch { postcondition = "exited"; }
    return { signal: input.signal, targetIdentity: identity, precondition: "exact-identity-matched", postcondition };
  }

  async tree(input: { pid?: number; maximumDepth?: number; maximumProcesses?: number }, owner: string): Promise<Record<string, unknown>> {
    const maximumDepth = input.maximumDepth ?? 16; const maximumProcesses = input.maximumProcesses ?? 1024; if (!Number.isSafeInteger(maximumDepth) || maximumDepth < 0 || maximumDepth > 128 || !Number.isSafeInteger(maximumProcesses) || maximumProcesses < 1 || maximumProcesses > 10_000) throw new QuirtError("invalid_request", "Quirt process tree bounds are invalid"); const rootPid = input.pid === undefined ? undefined : pid(input.pid);
    const listed = (await this.list({ maximumProcesses: 4096 }, owner)).processes as Record<string, unknown>[]; const byParent = new Map<number, Record<string, unknown>[]>(); for (const item of listed) { const parent = item.parentPid as number; const values = byParent.get(parent) ?? []; values.push(item); byParent.set(parent, values); }
    const roots = rootPid === undefined ? listed.filter(item => !listed.some(parent => (parent.identity as QuirtProcessIdentity).pid === item.parentPid)) : listed.filter(item => (item.identity as QuirtProcessIdentity).pid === rootPid); const output: Record<string, unknown>[] = []; const seen = new Set<number>(); const queue = roots.map(item => ({ item, depth: 0 }));
    while (queue.length > 0 && output.length < maximumProcesses) { const current = queue.shift()!; const id = (current.item.identity as QuirtProcessIdentity).pid; if (seen.has(id)) continue; seen.add(id); output.push({ identity: current.item.identity, parentPid: current.item.parentPid, depth: current.depth, command: current.item.command, state: current.item.state }); if (current.depth < maximumDepth) for (const child of byParent.get(id) ?? []) queue.push({ item: child, depth: current.depth + 1 }); }
    return { rootPid: rootPid ?? null, processes: output, truncated: queue.length > 0, cycleDetected: false };
  }

  async namespaces(input: { pid: number }, _owner: string): Promise<Record<string, unknown>> {
    const processId = pid(input.pid); const output: Record<string, unknown> = {}; for (const name of ["mnt", "pid", "net", "user", "ipc", "uts", "cgroup", "time"] as const) { try { const [target, raw] = await Promise.all([readlink(`/proc/${processId}/ns/${name}`), stat(`/proc/${processId}/ns/${name}`)]); output[name === "mnt" ? "mount" : name] = { identity: target, device: Number(raw.dev), inode: Number(raw.ino) }; } catch { output[name === "mnt" ? "mount" : name] = null; } }
    if (Object.values(output).every(value => value === null)) throw new QuirtError("process_exited", "Quirt process namespaces are unavailable", true); return { pid: processId, namespaces: output, containerized: "not-inferred" };
  }

  async attach(input: Record<string, unknown>, owner: string): Promise<Record<string, unknown> | { payload: Record<string, unknown>; binary: Buffer }> {
    if (input.source === "journal") return await this.#journal(input, owner); if (input.source !== undefined && input.source !== "process") throw new QuirtError("invalid_request", "Quirt process attachment source is invalid");
    if (input.action !== undefined && input.action !== "open") throw new QuirtError("unsupported_host_capability", "Quirt-owned process attachment is continued through its existing session or job stream");
    const identity = exactIdentity(input.identity); const processInfo = await this.get({ pid: identity.pid }, owner); this.#identity(identity, processInfo.identity as QuirtProcessIdentity);
    const correlation = processInfo.correlation as { sessions: string[]; jobs: string[] }; if (correlation.sessions.length === 0 && correlation.jobs.length === 0) throw new QuirtError("unsupported_host_capability", "Interactive attachment to this arbitrary process is unavailable without a supported native reattachment provider");
    const attachmentId = randomUUID(); const data = { attachmentId, source: "quirt-process", identity, sessions: correlation.sessions, jobs: correlation.jobs, signalSemantics: "existing-process-group", createdAt: new Date().toISOString() }; this.state.native.putObject("quirt_process_attachments", { objectId: attachmentId, ownerPrincipalFingerprint: owner, status: "attached", data }); return data;
  }

  async bootId(): Promise<string> { try { return (await readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim(); } catch { throw new QuirtError("unsupported_host_capability", "Linux boot identity is unavailable"); } }

  #identity(expected: QuirtProcessIdentity, actual: QuirtProcessIdentity): void { if (expected.pid !== actual.pid || expected.startTimeTicks !== actual.startTimeTicks || expected.bootId !== actual.bootId || expected.pidNamespace !== actual.pidNamespace || (expected.executableDevice !== null && expected.executableDevice !== actual.executableDevice) || (expected.executableInode !== null && expected.executableInode !== actual.executableInode)) throw new QuirtError("pid_reused", "Quirt process identity no longer matches the PID"); }

  async #journal(input: Record<string, unknown>, owner: string): Promise<{ payload: Record<string, unknown>; binary: Buffer }> {
    const action = typeof input.action === "string" ? input.action : "open";
    if (!["open", "read", "cancel"].includes(action)) throw new QuirtError("invalid_request", "Quirt journal action is invalid");
    if (action === "cancel") { const attachmentId = typeof input.attachmentId === "string" ? input.attachmentId : ""; const record = this.state.native.getObject("quirt_journal_cursors", attachmentId, owner); this.state.native.putObject("quirt_journal_cursors", { objectId: attachmentId, ownerPrincipalFingerprint: owner, status: "canceled", data: record.data }); return { payload: { attachmentId, status: "canceled" }, binary: Buffer.alloc(0) }; }
    let attachmentId = typeof input.attachmentId === "string" ? input.attachmentId : randomUUID(); let stored: Record<string, unknown> = {};
    if (action === "read") { const record = this.state.native.getObject("quirt_journal_cursors", attachmentId, owner); if (record.status === "canceled") throw new QuirtError("conflict", "Canceled Quirt journal attachment cannot be resumed"); stored = { ...record.data }; }
    const filters = action === "read" ? stored.filters as Record<string, unknown> ?? {} : input.filters !== null && typeof input.filters === "object" && !Array.isArray(input.filters) ? input.filters as Record<string, unknown> : {};
    const afterCursor = typeof input.afterCursor === "string" ? input.afterCursor : typeof stored.cursor === "string" ? stored.cursor : undefined; const maximum = typeof input.maximumEntries === "number" ? input.maximumEntries : 256; if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1000 || afterCursor !== undefined && (afterCursor.length < 1 || Buffer.byteLength(afterCursor) > 8192 || afterCursor.includes("\0"))) throw new QuirtError("invalid_request", "Quirt journal page bound is invalid");
    if (filters.unit !== undefined && (typeof filters.unit !== "string" || filters.unit.length < 1 || Buffer.byteLength(filters.unit) > 512 || filters.unit.includes("\0")) || filters.pid !== undefined && (typeof filters.pid !== "number" || !Number.isSafeInteger(filters.pid)) || filters.uid !== undefined && (typeof filters.uid !== "number" || !Number.isSafeInteger(filters.uid) || filters.uid < 0 || filters.uid > 0x7fffffff) || filters.priority !== undefined && (typeof filters.priority !== "number" || !Number.isSafeInteger(filters.priority) || filters.priority < 0 || filters.priority > 7)) throw new QuirtError("invalid_request", "Quirt journal filters are invalid");
    const safeFilters = {
      ...(typeof filters.unit === "string" ? { unit: filters.unit } : {}),
      ...(typeof filters.pid === "number" ? { pid: pid(filters.pid) } : {}),
      ...(typeof filters.uid === "number" ? { uid: filters.uid } : {}),
      ...(typeof filters.priority === "number" ? { priority: filters.priority } : {})
    };
    const page = await this.journal.query({ ...(afterCursor === undefined ? {} : { afterCursor }), maximumEntries: maximum, filters: safeFilters }); const entries = [...page.entries]; if (entries.length > maximum) throw new QuirtError("result_truncated", "Quirt journal adapter exceeded the bounded page"); const cursor = page.cursor ?? afterCursor ?? null;
    const bootId = entries.at(-1)?._BOOT_ID ?? null; const rotationDetected = page.rotationDetected === true || (typeof stored.bootId === "string" && typeof bootId === "string" && stored.bootId !== bootId);
    const data = { attachmentId, source: "journal", filters: safeFilters, cursor, bootId, followMode: "bounded-poll", rotationDetected, updatedAt: new Date().toISOString() }; const bytes = Buffer.from(entries.map(entry => JSON.stringify(entry)).join("\n") + (entries.length > 0 ? "\n" : "")); if (bytes.length > MAX_PROCESS_RESULT) throw new QuirtError("result_truncated", "Quirt journal page exceeds the bounded response size"); const record = this.state.native.putObject("quirt_journal_cursors", { objectId: attachmentId, ownerPrincipalFingerprint: owner, status: "active", data });
    return { payload: { attachmentId: record.objectId, status: record.status, cursor, afterCursor: afterCursor ?? null, entries: entries.map(entry => ({ cursor: entry.__CURSOR ?? null, realtimeTimestamp: entry.__REALTIME_TIMESTAMP ?? null, monotonicTimestamp: entry.__MONOTONIC_TIMESTAMP ?? null, bootId: entry._BOOT_ID ?? null, unit: entry._SYSTEMD_UNIT ?? null, pid: entry._PID ?? null, uid: entry._UID ?? null, priority: entry.PRIORITY ?? null, binaryFields: Object.entries(entry).filter(([, value]) => Array.isArray(value)).map(([field]) => field) })), entryCount: entries.length, byteCount: bytes.length, truncated: entries.length >= maximum, rotationDetected, binaryFieldsPreservedInJson: true, followMode: "bounded-poll", stderr: page.stderr.slice(0, 4096) }, binary: bytes };
  }
}
