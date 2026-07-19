export type QuirtCoreDumpState =
  | { state: "detected"; source: string; metadata: Readonly<Record<string, unknown>> }
  | { state: "not_detected"; source: string }
  | { state: "unknown"; source: string; reason: string };

export interface CoreDumpProbe {
  inspect(exitCode: number | null, signal: string | null, pid: number): Promise<QuirtCoreDumpState>;
}

export class LinuxCoreDumpProbe implements CoreDumpProbe {
  async inspect(exitCode: number | null, signal: string | null, _pid: number): Promise<QuirtCoreDumpState> {
    if (signal === "SIGSEGV" || signal === "SIGABRT" || signal === "SIGBUS" || signal === "SIGILL" || signal === "SIGFPE") {
      return Object.freeze({ state: "unknown", source: "wait_status", reason: "terminating_signal_without_local_core_probe" });
    }
    if (exitCode !== null && (exitCode & 0x80) !== 0) {
      return Object.freeze({ state: "unknown", source: "wait_status", reason: "core_bit_present_without_local_core_probe" });
    }
    return Object.freeze({ state: "not_detected", source: "wait_status" });
  }
}

export class InjectedCoreDumpProbe implements CoreDumpProbe {
  constructor(private readonly result: QuirtCoreDumpState) {}
  async inspect(_exitCode: number | null, _signal: string | null, _pid: number): Promise<QuirtCoreDumpState> { return this.result; }
}
