import { readFile } from "node:fs/promises";

export type QuirtMeasuredField<T> =
  | { availability: "measured"; value: T }
  | { availability: "sampled"; value: T }
  | { availability: "unsupported" }
  | { availability: "unavailable" }
  | { availability: "lost_due_to_race" };

export interface QuirtResourceEvidence {
  wallClockDurationMs: QuirtMeasuredField<number>;
  userCpuTicks: QuirtMeasuredField<number>;
  systemCpuTicks: QuirtMeasuredField<number>;
  maximumRssBytes: QuirtMeasuredField<number>;
  virtualMemoryBytes: QuirtMeasuredField<number>;
  readBytes: QuirtMeasuredField<number>;
  writeBytes: QuirtMeasuredField<number>;
  voluntaryContextSwitches: QuirtMeasuredField<number>;
  involuntaryContextSwitches: QuirtMeasuredField<number>;
  threadCount: QuirtMeasuredField<number>;
  capturedAt: string;
}

export interface ResourceProbe {
  readStatus(pid: number): Promise<string | null>;
  readIo(pid: number): Promise<string | null>;
}

function parseStatus(value: string): Record<string, string> {
  return Object.fromEntries(value.split("\n").filter(line => line.includes(":")).map(line => {
    const index = line.indexOf(":");
    return [line.slice(0, index), line.slice(index + 1).trim()];
  }));
}

function measured<T>(value: T | null, mode: "measured" | "sampled" = "measured"): QuirtMeasuredField<T> {
  return value === null ? { availability: "unavailable" } : { availability: mode, value };
}

export class LinuxResourceProbe implements ResourceProbe {
  async readStatus(pid: number): Promise<string | null> {
    try { return await readFile(`/proc/${pid}/status`, "utf8"); } catch { return null; }
  }

  async readIo(pid: number): Promise<string | null> {
    try { return await readFile(`/proc/${pid}/io`, "utf8"); } catch { return null; }
  }
}

export async function sampleResourceEvidence(
  pid: number,
  startedAtMs: number,
  finishedAtMs: number,
  probe: ResourceProbe,
  capturedAt: () => string = () => new Date().toISOString()
): Promise<QuirtResourceEvidence> {
  const [statusText, ioText] = await Promise.all([probe.readStatus(pid), probe.readIo(pid)]);
  const status = statusText === null ? {} : parseStatus(statusText);
  const io = ioText === null ? {} : parseStatus(ioText);
  const number = (value: string | undefined) => {
    if (value === undefined) return null;
    const parsed = Number(value.split(/\s+/u)[0]);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const rssKb = number(status.VmRSS?.replace(/\s*kB$/u, ""));
  return Object.freeze({
    wallClockDurationMs: measured(Math.max(0, finishedAtMs - startedAtMs)),
    userCpuTicks: measured(number(status.Utime)),
    systemCpuTicks: measured(number(status.Stime)),
    maximumRssBytes: measured(rssKb === null ? null : rssKb * 1024, "sampled"),
    virtualMemoryBytes: measured(number(status.VmSize?.replace(/\s*kB$/u, "")) === null ? null : number(status.VmSize?.replace(/\s*kB$/u, ""))! * 1024, "sampled"),
    readBytes: measured(number(io.read_bytes ?? io.rchar)),
    writeBytes: measured(number(io.write_bytes ?? io.wchar)),
    voluntaryContextSwitches: measured(number(status.voluntary_ctxt_switches)),
    involuntaryContextSwitches: measured(number(status.nonvoluntary_ctxt_switches)),
    threadCount: measured(number(status.Threads)),
    capturedAt: capturedAt()
  });
}
