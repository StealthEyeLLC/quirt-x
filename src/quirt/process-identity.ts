import { createHash } from "node:crypto";
import { readFile, readlink, stat } from "node:fs/promises";
import { readFileSync, readlinkSync, statSync } from "node:fs";
import { QuirtError } from "./error.js";

export interface QuirtProcessIdentity {
  pid: number;
  startTimeTicks: number;
  bootId: string;
  pidNamespace: string | null;
  executableDevice: number | null;
  executableInode: number | null;
  parentPid?: number | null;
  processGroupId?: number | null;
  sessionId?: number | null;
  uid?: number | null;
  gid?: number | null;
  executablePath?: string | null;
  executableSha256?: string | null;
  workingDirectory?: string | null;
  commandLineDigest?: string | null;
  capturedAt?: string;
}

export interface QuirtCgroupIdentity {
  source: "proc_cgroup";
  entries: readonly Readonly<{ hierarchyId: number; controllers: string; path: string }>[];
  capturedAt: string;
}

export interface QuirtNamespaceIdentities {
  mount: string | null;
  pid: string | null;
  network: string | null;
  ipc: string | null;
  uts: string | null;
  user: string | null;
  cgroup: string | null;
  time: string | null;
  capturedAt: string;
}

export interface ProcReader {
  readBootId(): Promise<string>;
  readStat(pid: number): Promise<string>;
  readStatus(pid: number): Promise<string>;
  readCmdline(pid: number): Promise<Buffer>;
  readCgroup(pid: number): Promise<string>;
  readlinkExe(pid: number): Promise<string | null>;
  readlinkCwd(pid: number): Promise<string | null>;
  readNamespace(pid: number, name: string): Promise<string | null>;
  statExe(pid: number): Promise<{ device: number; inode: number } | null>;
  hashFile(path: string): Promise<string | null>;
  tryCaptureSync?(pid: number): QuirtProcessIdentity | null;
}

export function syntheticProcessIdentity(pid: number, bootId = "synthetic-boot"): QuirtProcessIdentity {
  return Object.freeze({
    pid,
    startTimeTicks: 0,
    bootId,
    pidNamespace: null,
    executableDevice: null,
    executableInode: null,
    processGroupId: pid,
    capturedAt: new Date().toISOString()
  });
}

function parseStat(value: string): { parentPid: number; processGroup: number; sessionId: number; startTimeTicks: number } {
  const end = value.lastIndexOf(")");
  if (end < 0) throw new QuirtError("process_exited", "Quirt process stat is unavailable");
  const fields = value.slice(end + 2).trim().split(/\s+/u);
  if (fields.length < 20) throw new QuirtError("process_exited", "Quirt process stat is incomplete");
  const number = (index: number) => {
    const parsed = Number(fields[index]);
    if (!Number.isSafeInteger(parsed)) throw new QuirtError("internal_error", "Quirt process stat is invalid");
    return parsed;
  };
  return { parentPid: number(1), processGroup: number(2), sessionId: number(3), startTimeTicks: number(19) };
}

function parseStatus(value: string): { uid: number | null; gid: number | null } {
  const lines = Object.fromEntries(value.split("\n").filter(line => line.includes(":")).map(line => {
    const index = line.indexOf(":");
    return [line.slice(0, index), line.slice(index + 1).trim()];
  }));
  const first = (key: string) => {
    const raw = lines[key];
    if (raw === undefined) return null;
    const parsed = Number(raw.split(/\s+/u)[0]);
    return Number.isSafeInteger(parsed) ? parsed : null;
  };
  return { uid: first("Uid"), gid: first("Gid") };
}

function parseCgroup(value: string): QuirtCgroupIdentity["entries"] {
  return Object.freeze(value.trim().split("\n").filter(Boolean).map(line => {
    const parts = line.split(":");
    if (parts.length < 3) return { hierarchyId: 0, controllers: "", path: line };
    return { hierarchyId: Number(parts[0]) || 0, controllers: parts[1] ?? "", path: parts.slice(2).join(":") };
  }));
}

export function commandLineDigest(cmdline: Buffer): string | null {
  if (cmdline.length === 0) return null;
  return createHash("sha256").update(cmdline).digest("hex");
}

export function identitiesMatch(expected: QuirtProcessIdentity, actual: QuirtProcessIdentity): boolean {
  return expected.pid === actual.pid
    && expected.startTimeTicks === actual.startTimeTicks
    && expected.bootId === actual.bootId
    && expected.pidNamespace === actual.pidNamespace
    && (expected.executableDevice === null || expected.executableDevice === actual.executableDevice)
    && (expected.executableInode === null || expected.executableInode === actual.executableInode);
}

export function assertIdentityMatch(expected: QuirtProcessIdentity, actual: QuirtProcessIdentity): void {
  if (!identitiesMatch(expected, actual)) throw new QuirtError("pid_reused", "Quirt process identity no longer matches the PID");
}

export class LinuxProcReader implements ProcReader {
  async readBootId(): Promise<string> {
    try { return (await readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim(); }
    catch { throw new QuirtError("unsupported_host_capability", "Linux boot identity is unavailable"); }
  }

  async readStat(pid: number): Promise<string> { return await readFile(`/proc/${pid}/stat`, "utf8"); }
  async readStatus(pid: number): Promise<string> { return await readFile(`/proc/${pid}/status`, "utf8"); }
  async readCmdline(pid: number): Promise<Buffer> { return await readFile(`/proc/${pid}/cmdline`).catch(() => Buffer.alloc(0)); }
  async readCgroup(pid: number): Promise<string> { return await readFile(`/proc/${pid}/cgroup`, "utf8").catch(() => ""); }
  async readlinkExe(pid: number): Promise<string | null> { return await readlink(`/proc/${pid}/exe`).catch(() => null); }
  async readlinkCwd(pid: number): Promise<string | null> { return await readlink(`/proc/${pid}/cwd`).catch(() => null); }
  async readNamespace(pid: number, name: string): Promise<string | null> { return await readlink(`/proc/${pid}/ns/${name}`).catch(() => null); }
  async statExe(pid: number): Promise<{ device: number; inode: number } | null> {
    const raw = await stat(`/proc/${pid}/exe`).catch(() => null);
    return raw === null ? null : { device: Number(raw.dev), inode: Number(raw.ino) };
  }

  async hashFile(path: string): Promise<string | null> {
    try {
      const content = await readFile(path);
      return createHash("sha256").update(content).digest("hex");
    } catch { return null; }
  }
}

function buildIdentity(pid: number, statText: string, statusText: string, cmdline: Buffer, bootId: string, executable: string | null, cwd: string | null, pidNamespace: string | null, exeStat: { dev: number; ino: number } | null, executableSha256: string | null, capturedAt: string): QuirtProcessIdentity {
  const parsed = parseStat(statText);
  const status = parseStatus(statusText);
  return Object.freeze({
    pid,
    parentPid: parsed.parentPid,
    processGroupId: parsed.processGroup,
    sessionId: parsed.sessionId,
    uid: status.uid,
    gid: status.gid,
    startTimeTicks: parsed.startTimeTicks,
    bootId,
    pidNamespace,
    executablePath: executable,
    executableDevice: exeStat === null ? null : Number(exeStat.dev),
    executableInode: exeStat === null ? null : Number(exeStat.ino),
    executableSha256,
    workingDirectory: cwd,
    commandLineDigest: commandLineDigest(cmdline),
    capturedAt
  });
}

export function captureProcessIdentitySync(pid: number, reader: ProcReader, capturedAt: () => string = () => new Date().toISOString()): QuirtProcessIdentity {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new QuirtError("invalid_request", "Quirt process PID is invalid");
  const synthetic = reader.tryCaptureSync?.(pid);
  if (synthetic !== null && synthetic !== undefined) return synthetic;
  try {
    const statText = readFileSync(`/proc/${pid}/stat`, "utf8");
    const statusText = readFileSync(`/proc/${pid}/status`, "utf8");
    const cmdline = (() => { try { return readFileSync(`/proc/${pid}/cmdline`); } catch { return Buffer.alloc(0); } })();
    const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    const executable = (() => { try { return readlinkSync(`/proc/${pid}/exe`); } catch { return null; } })();
    const cwd = (() => { try { return readlinkSync(`/proc/${pid}/cwd`); } catch { return null; } })();
    const pidNamespace = (() => { try { return readlinkSync(`/proc/${pid}/ns/pid`); } catch { return null; } })();
    const exeStat = executable === null ? null : (() => { try { return statSync(`/proc/${pid}/exe`); } catch { return null; } })();
    return buildIdentity(pid, statText, statusText, cmdline, bootId, executable, cwd, pidNamespace, exeStat, null, capturedAt());
  } catch (cause) {
    if (cause instanceof QuirtError) throw cause;
    const code = cause instanceof Error && "code" in cause ? cause.code : null;
    if (code === "ENOENT" || code === "ESRCH") throw new QuirtError("process_exited", "Quirt process exited before identity capture", true);
    throw new QuirtError("internal_error", "Quirt process identity capture failed safely");
  }
}

export async function captureProcessIdentity(pid: number, reader: ProcReader, capturedAt: () => string = () => new Date().toISOString()): Promise<QuirtProcessIdentity> {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new QuirtError("invalid_request", "Quirt process PID is invalid");
  const synthetic = reader.tryCaptureSync?.(pid);
  if (synthetic !== null && synthetic !== undefined) return synthetic;
  try {
    const [statText, statusText, cmdline, bootId, executable, cwd, pidNamespace, exeStat] = await Promise.all([
      reader.readStat(pid), reader.readStatus(pid), reader.readCmdline(pid), reader.readBootId(),
      reader.readlinkExe(pid), reader.readlinkCwd(pid), reader.readNamespace(pid, "pid"), reader.statExe(pid)
    ]);
    const executableSha256 = executable === null ? null : await reader.hashFile(executable);
    return buildIdentity(pid, statText, statusText, cmdline, bootId, executable, cwd, pidNamespace, exeStat === null ? null : { dev: exeStat.device, ino: exeStat.inode }, executableSha256, capturedAt());
  } catch (cause) {
    if (cause instanceof QuirtError) throw cause;
    const code = cause instanceof Error && "code" in cause ? cause.code : null;
    if (code === "ENOENT" || code === "ESRCH") throw new QuirtError("process_exited", "Quirt process exited before identity capture", true);
    throw new QuirtError("internal_error", "Quirt process identity capture failed safely");
  }
}

export async function captureCgroupIdentity(pid: number, reader: ProcReader, capturedAt: () => string = () => new Date().toISOString()): Promise<QuirtCgroupIdentity> {
  const raw = await reader.readCgroup(pid).catch(() => "");
  return Object.freeze({ source: "proc_cgroup", entries: parseCgroup(raw), capturedAt: capturedAt() });
}

export async function captureNamespaceIdentities(pid: number, reader: ProcReader, capturedAt: () => string = () => new Date().toISOString()): Promise<QuirtNamespaceIdentities> {
  const names = ["mnt", "pid", "net", "ipc", "uts", "user", "cgroup", "time"] as const;
  const output: Record<string, string | null> = {};
  for (const name of names) output[name === "mnt" ? "mount" : name] = await reader.readNamespace(pid, name);
  return Object.freeze({ ...output, capturedAt: capturedAt() } as QuirtNamespaceIdentities);
}

export function isProcessAlive(pid: number, killProbe: (pid: number, signal: 0) => void = (value, signal) => process.kill(value, signal)): boolean {
  try {
    killProbe(pid, 0);
    return true;
  } catch (error) {
    return error instanceof Error && "code" in error && error.code === "EPERM";
  }
}
