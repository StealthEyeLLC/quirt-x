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
  readStat(pid: number): Promise<string | null>;
}

export interface ResourceSample {
  userCpuTicks: number | null;
  systemCpuTicks: number | null;
  maximumRssBytes: number | null;
  virtualMemoryBytes: number | null;
  readBytes: number | null;
  writeBytes: number | null;
  voluntaryContextSwitches: number | null;
  involuntaryContextSwitches: number | null;
  threadCount: number | null;
}

export const DEFAULT_RESOURCE_SAMPLE_INTERVAL_MS = 200;

function parseStatus(value: string): Record<string, string> {
  return Object.fromEntries(value.split("\n").filter(line => line.includes(":")).map(line => {
    const index = line.indexOf(":");
    return [line.slice(0, index), line.slice(index + 1).trim()];
  }));
}

function numberField(value: string | undefined): number | null {
  if (value === undefined) return null;
  const parsed = Number(value.split(/\s+/u)[0]);
  return Number.isFinite(parsed) ? parsed : null;
}

export function parseProcStatCpuTicks(statText: string): { userCpuTicks: number | null; systemCpuTicks: number | null } {
  const end = statText.lastIndexOf(")");
  if (end < 0) return { userCpuTicks: null, systemCpuTicks: null };
  const fields = statText.slice(end + 2).trim().split(/\s+/u);
  return {
    userCpuTicks: numberField(fields[11]),
    systemCpuTicks: numberField(fields[12])
  };
}

function measured<T>(value: T | null, mode: "measured" | "sampled" = "measured"): QuirtMeasuredField<T> {
  return value === null ? { availability: "unavailable" } : { availability: mode, value };
}

function mergeLatest(current: number | null, next: number | null, mode: "max" | "latest"): number | null {
  if (next === null) return current;
  if (current === null) return next;
  return mode === "max" ? Math.max(current, next) : next;
}

export class LinuxResourceProbe implements ResourceProbe {
  async readStatus(pid: number): Promise<string | null> {
    try { return await readFile(`/proc/${pid}/status`, "utf8"); } catch { return null; }
  }

  async readIo(pid: number): Promise<string | null> {
    try { return await readFile(`/proc/${pid}/io`, "utf8"); } catch { return null; }
  }

  async readStat(pid: number): Promise<string | null> {
    try { return await readFile(`/proc/${pid}/stat`, "utf8"); } catch { return null; }
  }
}

export async function readResourceSample(pid: number, probe: ResourceProbe): Promise<ResourceSample> {
  const [statusText, ioText, statText] = await Promise.all([probe.readStatus(pid), probe.readIo(pid), probe.readStat(pid)]);
  const status = statusText === null ? {} : parseStatus(statusText);
  const io = ioText === null ? {} : parseStatus(ioText);
  const cpu = statText === null ? { userCpuTicks: null, systemCpuTicks: null } : parseProcStatCpuTicks(statText);
  const rssKb = numberField(status.VmRSS?.replace(/\s*kB$/u, ""));
  const vmKb = numberField(status.VmSize?.replace(/\s*kB$/u, ""));
  return {
    userCpuTicks: cpu.userCpuTicks,
    systemCpuTicks: cpu.systemCpuTicks,
    maximumRssBytes: rssKb === null ? null : rssKb * 1024,
    virtualMemoryBytes: vmKb === null ? null : vmKb * 1024,
    readBytes: numberField(io.read_bytes ?? io.rchar),
    writeBytes: numberField(io.write_bytes ?? io.wchar),
    voluntaryContextSwitches: numberField(status.voluntary_ctxt_switches),
    involuntaryContextSwitches: numberField(status.nonvoluntary_ctxt_switches),
    threadCount: numberField(status.Threads)
  };
}

export class ResourceAccumulator {
  #timer: NodeJS.Timeout | null = null;
  #sampling = false;
  #stopped = false;
  #userCpuTicks: number | null = null;
  #systemCpuTicks: number | null = null;
  #maximumRssBytes: number | null = null;
  #virtualMemoryBytes: number | null = null;
  #readBytes: number | null = null;
  #writeBytes: number | null = null;
  #voluntaryContextSwitches: number | null = null;
  #involuntaryContextSwitches: number | null = null;
  #threadCount: number | null = null;
  #hadSuccessfulSample = false;
  #lastCapturedAt: string | null = null;

  constructor(
    private readonly pid: number,
    private readonly probe: ResourceProbe,
    private readonly intervalMs: number,
    private readonly capturedAt: () => string = () => new Date().toISOString()
  ) {}

  async start(): Promise<void> {
    if (this.#stopped) return;
    void this.#sampleOnce();
    if (this.#stopped) return;
    this.#timer = setInterval(() => { void this.#sampleOnce(); }, this.intervalMs);
    this.#timer.unref();
  }

  stop(): void {
    this.#stopped = true;
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }

  async sampleOnce(): Promise<void> {
    await this.#sampleOnce();
  }

  async #sampleOnce(): Promise<void> {
    if (this.#stopped || this.#sampling) return;
    this.#sampling = true;
    try {
      const sample = await readResourceSample(this.pid, this.probe);
      const anyField = Object.values(sample).some(value => value !== null);
      if (!anyField) return;
      this.#hadSuccessfulSample = true;
      this.#lastCapturedAt = this.capturedAt();
      this.#userCpuTicks = mergeLatest(this.#userCpuTicks, sample.userCpuTicks, "latest");
      this.#systemCpuTicks = mergeLatest(this.#systemCpuTicks, sample.systemCpuTicks, "latest");
      this.#maximumRssBytes = mergeLatest(this.#maximumRssBytes, sample.maximumRssBytes, "max");
      this.#virtualMemoryBytes = mergeLatest(this.#virtualMemoryBytes, sample.virtualMemoryBytes, "max");
      this.#readBytes = mergeLatest(this.#readBytes, sample.readBytes, "latest");
      this.#writeBytes = mergeLatest(this.#writeBytes, sample.writeBytes, "latest");
      this.#voluntaryContextSwitches = mergeLatest(this.#voluntaryContextSwitches, sample.voluntaryContextSwitches, "latest");
      this.#involuntaryContextSwitches = mergeLatest(this.#involuntaryContextSwitches, sample.involuntaryContextSwitches, "latest");
      this.#threadCount = mergeLatest(this.#threadCount, sample.threadCount, "max");
    } catch { /* sampling failures must not fail execution */ }
    finally { this.#sampling = false; }
  }

  finalize(startedAtMs: number, finishedAtMs: number): QuirtResourceEvidence {
    const availability = <T>(value: T | null): QuirtMeasuredField<T> => {
      if (value !== null) return { availability: "sampled", value };
      return { availability: this.#hadSuccessfulSample ? "lost_due_to_race" : "unavailable" };
    };
    return Object.freeze({
      wallClockDurationMs: measured(Math.max(0, finishedAtMs - startedAtMs)),
      userCpuTicks: availability(this.#userCpuTicks),
      systemCpuTicks: availability(this.#systemCpuTicks),
      maximumRssBytes: availability(this.#maximumRssBytes),
      virtualMemoryBytes: availability(this.#virtualMemoryBytes),
      readBytes: availability(this.#readBytes),
      writeBytes: availability(this.#writeBytes),
      voluntaryContextSwitches: availability(this.#voluntaryContextSwitches),
      involuntaryContextSwitches: availability(this.#involuntaryContextSwitches),
      threadCount: availability(this.#threadCount),
      capturedAt: this.#lastCapturedAt ?? this.capturedAt()
    });
  }
}

export async function sampleResourceEvidence(
  pid: number,
  startedAtMs: number,
  finishedAtMs: number,
  probe: ResourceProbe,
  capturedAt: () => string = () => new Date().toISOString()
): Promise<QuirtResourceEvidence> {
  const accumulator = new ResourceAccumulator(pid, probe, DEFAULT_RESOURCE_SAMPLE_INTERVAL_MS, capturedAt);
  await accumulator.sampleOnce();
  accumulator.stop();
  return accumulator.finalize(startedAtMs, finishedAtMs);
}
