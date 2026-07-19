import { spawn as spawnPty, type IPty } from "node-pty";
import { QuirtError } from "./error.js";

export interface QuirtPtyExit {
  exitCode: number;
  signal: number | null;
}

export interface QuirtPtySpawn {
  executable: string;
  arguments: readonly string[];
  workingDirectory: string;
  environment: Readonly<Record<string, string>>;
  columns: number;
  rows: number;
  terminal?: string;
}

export interface QuirtPtyProcess {
  readonly pid: number;
  write(bytes: Buffer): void;
  resize(columns: number, rows: number): void;
  signal(signal: NodeJS.Signals): void;
  pause(): void;
  resume(): void;
  onData(listener: (bytes: Buffer) => void): () => void;
  onExit(listener: (exit: QuirtPtyExit) => void): () => void;
}

export interface QuirtPtyFactory {
  spawn(input: QuirtPtySpawn): QuirtPtyProcess;
}

function dimensions(columns: number, rows: number): void {
  if (!Number.isSafeInteger(columns) || columns < 2 || columns > 1000 || !Number.isSafeInteger(rows) || rows < 1 || rows > 1000) {
    throw new QuirtError("invalid_request", "Quirt terminal dimensions are invalid");
  }
}

class NodePtyProcess implements QuirtPtyProcess {
  constructor(private readonly pty: IPty) {}
  get pid(): number { return this.pty.pid; }
  write(bytes: Buffer): void { this.pty.write(bytes); }
  resize(columns: number, rows: number): void { dimensions(columns, rows); this.pty.resize(columns, rows); }
  signal(signal: NodeJS.Signals): void {
    try { this.pty.kill(signal); }
    catch { throw new QuirtError("invalid_request", "Quirt terminal signal could not be delivered"); }
  }
  pause(): void { this.pty.pause(); }
  resume(): void { this.pty.resume(); }
  onData(listener: (bytes: Buffer) => void): () => void {
    // node-pty returns Buffer when encoding is explicitly null, despite its legacy string-only event type.
    const registration = this.pty.onData((value: string) => listener(Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value, "utf8")));
    return () => registration.dispose();
  }
  onExit(listener: (exit: QuirtPtyExit) => void): () => void {
    const registration = this.pty.onExit(value => listener({ exitCode: value.exitCode, signal: typeof value.signal === "number" && value.signal > 0 ? value.signal : null }));
    return () => registration.dispose();
  }
}

export class NodePtyFactory implements QuirtPtyFactory {
  spawn(input: QuirtPtySpawn): QuirtPtyProcess {
    dimensions(input.columns, input.rows);
    try {
      const pty = spawnPty(input.executable, [...input.arguments], {
        cwd: input.workingDirectory,
        env: { ...input.environment },
        name: input.terminal ?? "xterm-256color",
        cols: input.columns,
        rows: input.rows,
        encoding: null
      });
      return new NodePtyProcess(pty);
    } catch { throw new QuirtError("internal_error", "Quirt could not allocate a PTY"); }
  }
}
