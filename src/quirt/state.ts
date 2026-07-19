import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { QuirtError } from "./error.js";
import { migrateQuirtNativeState, QuirtNativeStateStore } from "./native-state.js";
import { migrateQuirtPowerState, QUIRT_POWER_SCHEMA_VERSION, QuirtPowerStateStore } from "./power-state.js";
import type { QuirtRequestReservation } from "./authority.js";

export const QUIRT_STATE_SCHEMA_VERSION = QUIRT_POWER_SCHEMA_VERSION;

export type QuirtSessionStatus = "creating" | "running" | "detached" | "exited" | "closed" | "lost";
export type QuirtJobStatus = "starting" | "running" | "exited" | "failed" | "signaled" | "canceled" | "lost" | "unknown";
export type QuirtStreamOwner = "session" | "job";

export interface QuirtSessionRecord {
  sessionId: string;
  name: string;
  status: QuirtSessionStatus;
  tmuxName: string | null;
  mode: "tmux" | "direct";
  executable: string;
  arguments: readonly string[];
  loginShell: boolean;
  shell: string;
  workingDirectory: string;
  environment: Readonly<Record<string, string>>;
  columns: number;
  rows: number;
  ownerPrincipalFingerprint: string;
  outputStreamId: string;
  ptyPid: number | null;
  exitCode: number | null;
  exitSignal: number | null;
  createdAt: string;
  updatedAt: string;
  recoveredAt: string | null;
}

export interface QuirtSessionReaderRecord {
  readerId: string;
  sessionId: string;
  ownerPrincipalFingerprint: string;
  cursorOffset: number;
  attached: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface QuirtJobRecord {
  jobId: string;
  requestId: string;
  status: QuirtJobStatus;
  ownerPrincipalFingerprint: string;
  command: Readonly<Record<string, unknown>>;
  workingDirectory: string;
  environment: Readonly<Record<string, string>>;
  stdinSupported: boolean;
  processId: number | null;
  stdoutStreamId: string;
  stderrStreamId: string;
  exitCode: number | null;
  exitSignal: string | null;
  timedOut: boolean;
  createdAt: string;
  updatedAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface QuirtStreamRecord {
  streamId: string;
  ownerKind: QuirtStreamOwner;
  ownerId: string;
  name: string;
  status: "open" | "finalized";
  retainedStartOffset: number;
  nextOffset: number;
  createdAt: string;
  finalizedAt: string | null;
}

export interface QuirtStreamPage {
  streamId: string;
  startOffset: number;
  endOffset: number;
  nextOffset: number;
  retainedStartOffset: number;
  bytes: Buffer;
  eof: boolean;
}

interface SessionRow {
  session_id: string;
  name: string;
  status: string;
  tmux_name: string | null;
  mode: string;
  executable: string;
  arguments_json: string;
  login_shell: number;
  shell: string;
  working_directory: string;
  environment_json: string;
  columns_count: number;
  rows_count: number;
  owner_principal_fingerprint: string;
  output_stream_id: string;
  pty_pid: number | null;
  exit_code: number | null;
  exit_signal: number | null;
  created_at: string;
  updated_at: string;
  recovered_at: string | null;
}

interface JobRow {
  job_id: string;
  request_id: string;
  status: string;
  owner_principal_fingerprint: string;
  command_json: string;
  working_directory: string;
  environment_json: string;
  stdin_supported: number;
  process_id: number | null;
  stdout_stream_id: string;
  stderr_stream_id: string;
  exit_code: number | null;
  exit_signal: string | null;
  timed_out: number;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
}

interface StreamRow {
  stream_id: string;
  owner_kind: string;
  owner_id: string;
  name: string;
  status: string;
  retained_start_offset: number;
  next_offset: number;
  created_at: string;
  finalized_at: string | null;
}

function timestamp(now: () => Date): string { return now().toISOString(); }

function parseObject<T extends Record<string, unknown>>(value: string, label: string): T {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not object");
    return parsed as T;
  } catch { throw new QuirtError("internal_error", `Stored ${label} is invalid`); }
}

function session(row: SessionRow): QuirtSessionRecord {
  return Object.freeze({
    sessionId: row.session_id,
    name: row.name,
    status: row.status as QuirtSessionStatus,
    tmuxName: row.tmux_name,
    mode: row.mode as "tmux" | "direct",
    executable: row.executable,
    arguments: Object.freeze(parseArray<string>(row.arguments_json, "session arguments")),
    loginShell: row.login_shell === 1,
    shell: row.shell,
    workingDirectory: row.working_directory,
    environment: Object.freeze(parseObject<Record<string, string>>(row.environment_json, "session environment")),
    columns: row.columns_count,
    rows: row.rows_count,
    ownerPrincipalFingerprint: row.owner_principal_fingerprint,
    outputStreamId: row.output_stream_id,
    ptyPid: row.pty_pid,
    exitCode: row.exit_code,
    exitSignal: row.exit_signal,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    recoveredAt: row.recovered_at
  });
}

function parseArray<T>(value: string, label: string): T[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) throw new Error("not array");
    return parsed as T[];
  } catch { throw new QuirtError("internal_error", `Stored ${label} is invalid`); }
}

function job(row: JobRow): QuirtJobRecord {
  return Object.freeze({
    jobId: row.job_id,
    requestId: row.request_id,
    status: row.status as QuirtJobStatus,
    ownerPrincipalFingerprint: row.owner_principal_fingerprint,
    command: Object.freeze(parseObject<Record<string, unknown>>(row.command_json, "job command")),
    workingDirectory: row.working_directory,
    environment: Object.freeze(parseObject<Record<string, string>>(row.environment_json, "job environment")),
    stdinSupported: row.stdin_supported === 1,
    processId: row.process_id,
    stdoutStreamId: row.stdout_stream_id,
    stderrStreamId: row.stderr_stream_id,
    exitCode: row.exit_code,
    exitSignal: row.exit_signal,
    timedOut: row.timed_out === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at
  });
}

function stream(row: StreamRow): QuirtStreamRecord {
  return Object.freeze({
    streamId: row.stream_id,
    ownerKind: row.owner_kind as QuirtStreamOwner,
    ownerId: row.owner_id,
    name: row.name,
    status: row.status as "open" | "finalized",
    retainedStartOffset: row.retained_start_offset,
    nextOffset: row.next_offset,
    createdAt: row.created_at,
    finalizedAt: row.finalized_at
  });
}

export class QuirtStateStore implements QuirtRequestReservation {
  readonly #db: DatabaseSync;
  readonly #now: () => Date;
  readonly #chunkBytes: number;
  readonly #retentionBytes: number;
  readonly native: QuirtNativeStateStore;
  readonly power: QuirtPowerStateStore;

  constructor(path: string, options: { now?: () => Date; outputChunkBytes?: number; outputRetentionBytes?: number } = {}) {
    this.#now = options.now ?? (() => new Date());
    this.#chunkBytes = options.outputChunkBytes ?? 64 * 1024;
    this.#retentionBytes = options.outputRetentionBytes ?? 256 * 1024 * 1024;
    if (!Number.isSafeInteger(this.#chunkBytes) || this.#chunkBytes < 1 || !Number.isSafeInteger(this.#retentionBytes) || this.#retentionBytes < this.#chunkBytes) throw new QuirtError("configuration_error", "Quirt stream limits are invalid");
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#db = new DatabaseSync(path);
    this.#migrate();
    migrateQuirtNativeState(this.#db, this.#now);
    migrateQuirtPowerState(this.#db, this.#now);
    this.native = new QuirtNativeStateStore(this.#db, this.#now);
    this.power = new QuirtPowerStateStore(this.#db, this.#now);
  }

  #transaction<T>(action: () => T): T {
    this.#db.exec("BEGIN IMMEDIATE");
    try { const value = action(); this.#db.exec("COMMIT"); return value; }
    catch (cause) { try { this.#db.exec("ROLLBACK"); } catch { /* retain the original error */ } throw cause; }
  }

  #migrate(): void {
    this.#db.exec(`
      PRAGMA journal_mode=WAL;
      PRAGMA synchronous=FULL;
      PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS quirt_schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS quirt_protocol_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS quirt_streams(
        stream_id TEXT PRIMARY KEY, owner_kind TEXT NOT NULL CHECK(owner_kind IN ('session','job')), owner_id TEXT NOT NULL,
        name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','finalized')), retained_start_offset INTEGER NOT NULL DEFAULT 0,
        next_offset INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, finalized_at TEXT,
        UNIQUE(owner_kind,owner_id,name)
      );
      CREATE TABLE IF NOT EXISTS quirt_stream_chunks(
        chunk_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL REFERENCES quirt_streams(stream_id) ON DELETE CASCADE,
        start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, byte_count INTEGER NOT NULL, sha256 TEXT NOT NULL,
        content BLOB NOT NULL, created_at TEXT NOT NULL, UNIQUE(stream_id,start_offset),
        CHECK(start_offset>=0 AND end_offset>start_offset AND byte_count=end_offset-start_offset)
      );
      CREATE INDEX IF NOT EXISTS quirt_stream_chunks_lookup ON quirt_stream_chunks(stream_id,end_offset,start_offset);
      CREATE TABLE IF NOT EXISTS quirt_sessions(
        session_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
        tmux_name TEXT, shell TEXT NOT NULL, working_directory TEXT NOT NULL, environment_json TEXT NOT NULL,
        columns_count INTEGER NOT NULL, rows_count INTEGER NOT NULL, owner_principal_fingerprint TEXT NOT NULL,
        output_stream_id TEXT NOT NULL REFERENCES quirt_streams(stream_id), pty_pid INTEGER, exit_code INTEGER, exit_signal INTEGER,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, recovered_at TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS quirt_sessions_tmux_name ON quirt_sessions(tmux_name) WHERE tmux_name IS NOT NULL;
      CREATE TABLE IF NOT EXISTS quirt_jobs(
        job_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, status TEXT NOT NULL, owner_principal_fingerprint TEXT NOT NULL,
        command_json TEXT NOT NULL, working_directory TEXT NOT NULL, environment_json TEXT NOT NULL, stdin_supported INTEGER NOT NULL,
        process_id INTEGER, stdout_stream_id TEXT NOT NULL REFERENCES quirt_streams(stream_id), stderr_stream_id TEXT NOT NULL REFERENCES quirt_streams(stream_id),
        exit_code INTEGER, exit_signal TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT, finished_at TEXT
      );
      CREATE INDEX IF NOT EXISTS quirt_jobs_request ON quirt_jobs(request_id);
      CREATE TABLE IF NOT EXISTS quirt_request_records(
        request_id TEXT PRIMARY KEY, operation TEXT NOT NULL, request_hash TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK(state IN ('reserved','completed','failed')), response_json TEXT, error_json TEXT,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, completed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS quirt_recovery_records(
        recovery_id TEXT PRIMARY KEY, owner_kind TEXT NOT NULL, owner_id TEXT NOT NULL, action TEXT NOT NULL,
        outcome TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL
      );
    `);
    const current = Number((this.#db.prepare("SELECT COALESCE(MAX(version),0) AS version FROM quirt_schema_migrations").get() as { version: number }).version);
    if (current > QUIRT_STATE_SCHEMA_VERSION) throw new QuirtError("configuration_error", "Quirt state schema is newer than this runtime");
    if (current < 1) this.#transaction(() => {
      const at = timestamp(this.#now);
      this.#db.prepare("INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(1,?)").run(at);
      this.#db.prepare("INSERT OR REPLACE INTO quirt_protocol_metadata(key,value,updated_at) VALUES('protocol_version','1',?)").run(at);
    });
    if (current < 2) this.#transaction(() => {
      for (const statement of [
        "ALTER TABLE quirt_sessions ADD COLUMN mode TEXT NOT NULL DEFAULT 'tmux' CHECK(mode IN ('tmux','direct'))",
        "ALTER TABLE quirt_sessions ADD COLUMN executable TEXT NOT NULL DEFAULT '/bin/bash'",
        "ALTER TABLE quirt_sessions ADD COLUMN arguments_json TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE quirt_sessions ADD COLUMN login_shell INTEGER NOT NULL DEFAULT 1 CHECK(login_shell IN (0,1))"
      ]) {
        try { this.#db.exec(statement); }
        catch (cause) { if (!(cause instanceof Error && cause.message.includes("duplicate column"))) throw cause; }
      }
      this.#db.exec(`CREATE TABLE IF NOT EXISTS quirt_session_readers(
        reader_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES quirt_sessions(session_id) ON DELETE CASCADE,
        owner_principal_fingerprint TEXT NOT NULL, cursor_offset INTEGER NOT NULL DEFAULT 0,
        attached INTEGER NOT NULL DEFAULT 1 CHECK(attached IN (0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      ); CREATE INDEX IF NOT EXISTS quirt_session_readers_session ON quirt_session_readers(session_id,updated_at);`);
      this.#db.prepare("INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(2,?)").run(timestamp(this.#now));
    });
    if (current < 3) this.#transaction(() => {
      this.#db.exec(`CREATE TABLE IF NOT EXISTS quirt_request_nonces(
        nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES quirt_request_records(request_id) ON DELETE CASCADE,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL
      ); CREATE INDEX IF NOT EXISTS quirt_request_nonces_expiry ON quirt_request_nonces(expires_at);`);
      this.#db.exec(`INSERT OR IGNORE INTO quirt_request_nonces(nonce,request_id,created_at,expires_at)
        SELECT nonce,request_id,created_at,expires_at FROM quirt_request_records;`);
      this.#db.prepare("INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(3,?)").run(timestamp(this.#now));
    });
    if (current < 4) this.#transaction(() => {
      try { this.#db.exec("ALTER TABLE quirt_jobs ADD COLUMN timed_out INTEGER NOT NULL DEFAULT 0 CHECK(timed_out IN (0,1))"); }
      catch (cause) { if (!(cause instanceof Error && cause.message.includes("duplicate column"))) throw cause; }
      this.#db.prepare("INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(4,?)").run(timestamp(this.#now));
    });
  }

  schemaVersion(): number { return Number((this.#db.prepare("SELECT MAX(version) AS version FROM quirt_schema_migrations").get() as { version: number }).version); }

  integrityCheck(): void {
    const row = this.#db.prepare("PRAGMA integrity_check").get() as { integrity_check: string };
    if (row.integrity_check !== "ok") throw new QuirtError("internal_error", "Quirt state integrity check failed");
  }

  createStream(ownerKind: QuirtStreamOwner, ownerId: string, name: string, streamId: string = randomUUID()): QuirtStreamRecord {
    const at = timestamp(this.#now);
    this.#db.prepare("INSERT INTO quirt_streams(stream_id,owner_kind,owner_id,name,status,created_at) VALUES(?,?,?,?, 'open',?)").run(streamId, ownerKind, ownerId, name, at);
    return this.getStream(streamId);
  }

  getStream(streamId: string): QuirtStreamRecord {
    const row = this.#db.prepare("SELECT * FROM quirt_streams WHERE stream_id=?").get(streamId) as unknown as StreamRow | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt stream was not found");
    return stream(row);
  }

  appendStream(streamId: string, content: Buffer | Uint8Array): { startOffset: number; endOffset: number; byteCount: number } {
    const bytes = Buffer.from(content);
    if (bytes.length === 0) { const current = this.getStream(streamId); return { startOffset: current.nextOffset, endOffset: current.nextOffset, byteCount: 0 }; }
    return this.#transaction(() => {
      const current = this.getStream(streamId);
      if (current.status !== "open") throw new QuirtError("invalid_request", "Quirt stream is finalized");
      const first = current.nextOffset;
      let offset = first;
      for (let index = 0; index < bytes.length; index += this.#chunkBytes) {
        const part = bytes.subarray(index, Math.min(index + this.#chunkBytes, bytes.length));
        const end = offset + part.length;
        const digest = createHash("sha256").update(part).digest("hex");
        this.#db.prepare("INSERT INTO quirt_stream_chunks(chunk_id,stream_id,start_offset,end_offset,byte_count,sha256,content,created_at) VALUES(?,?,?,?,?,?,?,?)").run(randomUUID(), streamId, offset, end, part.length, digest, part, timestamp(this.#now));
        offset = end;
      }
      this.#db.prepare("UPDATE quirt_streams SET next_offset=? WHERE stream_id=?").run(offset, streamId);
      const cutoff = offset - this.#retentionBytes;
      if (cutoff > 0) {
        this.#db.prepare("DELETE FROM quirt_stream_chunks WHERE stream_id=? AND end_offset<=?").run(streamId, cutoff);
        const earliest = this.#db.prepare("SELECT MIN(start_offset) AS start_offset FROM quirt_stream_chunks WHERE stream_id=?").get(streamId) as { start_offset: number | null };
        this.#db.prepare("UPDATE quirt_streams SET retained_start_offset=? WHERE stream_id=?").run(earliest.start_offset ?? offset, streamId);
      }
      return { startOffset: first, endOffset: offset, byteCount: bytes.length };
    });
  }

  readStream(streamId: string, after: number, maximumBytes: number): QuirtStreamPage {
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 8 * 1024 * 1024) throw new QuirtError("invalid_request", "Quirt stream page is invalid");
    const current = this.getStream(streamId);
    if (after < current.retainedStartOffset) throw new QuirtError("output_gap", "Requested Quirt output is no longer retained", false, { retainedStartOffset: current.retainedStartOffset, nextOffset: current.nextOffset });
    if (after > current.nextOffset) throw new QuirtError("invalid_request", "Requested Quirt output offset is beyond the stream");
    const rows = this.#db.prepare("SELECT start_offset,end_offset,content FROM quirt_stream_chunks WHERE stream_id=? AND end_offset>? ORDER BY start_offset ASC").all(streamId, after) as unknown as Array<{ start_offset: number; end_offset: number; content: Uint8Array }>;
    const parts: Buffer[] = [];
    let remaining = maximumBytes;
    let cursor = after;
    for (const row of rows) {
      if (remaining === 0) break;
      if (row.start_offset > cursor) throw new QuirtError("output_gap", "Quirt stream contains a durable output gap", false, { expectedOffset: cursor, actualOffset: row.start_offset });
      const content = Buffer.from(row.content);
      const skip = Math.max(0, cursor - row.start_offset);
      const part = content.subarray(skip, Math.min(content.length, skip + remaining));
      if (part.length > 0) { parts.push(part); remaining -= part.length; cursor += part.length; }
    }
    return Object.freeze({
      streamId,
      startOffset: after,
      endOffset: cursor,
      nextOffset: current.nextOffset,
      retainedStartOffset: current.retainedStartOffset,
      bytes: Buffer.concat(parts),
      eof: current.status === "finalized" && cursor === current.nextOffset
    });
  }

  finalizeStream(streamId: string): QuirtStreamRecord {
    this.#db.prepare("UPDATE quirt_streams SET status='finalized',finalized_at=COALESCE(finalized_at,?) WHERE stream_id=?").run(timestamp(this.#now), streamId);
    return this.getStream(streamId);
  }

  createSession(input: {
    sessionId?: string; name: string; tmuxName: string | null; mode?: "tmux" | "direct"; shell: string;
    executable?: string; arguments?: readonly string[]; loginShell?: boolean; workingDirectory: string;
    environment?: Readonly<Record<string, string>>; columns: number; rows: number; ownerPrincipalFingerprint: string;
  }): QuirtSessionRecord {
    const sessionId = input.sessionId ?? randomUUID();
    const output = this.createStream("session", sessionId, "terminal");
    const at = timestamp(this.#now);
    this.#db.prepare(`INSERT INTO quirt_sessions(
      session_id,name,status,tmux_name,mode,shell,executable,arguments_json,login_shell,working_directory,environment_json,columns_count,rows_count,
      owner_principal_fingerprint,output_stream_id,created_at,updated_at
    ) VALUES(?,?,'creating',?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      sessionId, input.name, input.tmuxName, input.mode ?? (input.tmuxName === null ? "direct" : "tmux"), input.shell,
      input.executable ?? input.shell, JSON.stringify(input.arguments ?? []), input.loginShell === false ? 0 : 1,
      input.workingDirectory, JSON.stringify(input.environment ?? {}), input.columns, input.rows,
      input.ownerPrincipalFingerprint, output.streamId, at, at
    );
    return this.getSession(sessionId);
  }

  getSession(sessionId: string): QuirtSessionRecord {
    const row = this.#db.prepare("SELECT * FROM quirt_sessions WHERE session_id=?").get(sessionId) as unknown as SessionRow | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt session was not found");
    return session(row);
  }

  listSessions(ownerPrincipalFingerprint?: string): QuirtSessionRecord[] {
    const rows = ownerPrincipalFingerprint === undefined
      ? this.#db.prepare("SELECT * FROM quirt_sessions ORDER BY created_at,session_id").all()
      : this.#db.prepare("SELECT * FROM quirt_sessions WHERE owner_principal_fingerprint=? ORDER BY created_at,session_id").all(ownerPrincipalFingerprint);
    return (rows as unknown as SessionRow[]).map(session);
  }

  updateSession(sessionId: string, patch: {
    status?: QuirtSessionStatus; ptyPid?: number | null; columns?: number; rows?: number; workingDirectory?: string;
    exitCode?: number | null; exitSignal?: number | null; recovered?: boolean;
  }): QuirtSessionRecord {
    const current = this.getSession(sessionId);
    const at = timestamp(this.#now);
    this.#db.prepare(`UPDATE quirt_sessions SET status=?,pty_pid=?,columns_count=?,rows_count=?,working_directory=?,
      exit_code=?,exit_signal=?,updated_at=?,recovered_at=? WHERE session_id=?`).run(
      patch.status ?? current.status, patch.ptyPid === undefined ? current.ptyPid : patch.ptyPid,
      patch.columns ?? current.columns, patch.rows ?? current.rows, patch.workingDirectory ?? current.workingDirectory,
      patch.exitCode === undefined ? current.exitCode : patch.exitCode, patch.exitSignal === undefined ? current.exitSignal : patch.exitSignal,
      at, patch.recovered === true ? at : current.recoveredAt, sessionId
    );
    return this.getSession(sessionId);
  }

  attachSessionReader(input: { readerId?: string; sessionId: string; ownerPrincipalFingerprint: string; after?: number }): QuirtSessionReaderRecord {
    const sessionRecord = this.getSession(input.sessionId);
    if (sessionRecord.ownerPrincipalFingerprint !== input.ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Quirt session principal does not match");
    const readerId = input.readerId ?? randomUUID();
    const existing = this.#db.prepare("SELECT session_id,owner_principal_fingerprint,cursor_offset FROM quirt_session_readers WHERE reader_id=?").get(readerId) as { session_id: string; owner_principal_fingerprint: string; cursor_offset: number } | undefined;
    const after = input.after ?? existing?.cursor_offset ?? this.getStream(sessionRecord.outputStreamId).nextOffset;
    if (!Number.isSafeInteger(after) || after < 0) throw new QuirtError("invalid_request", "Quirt reader offset is invalid");
    const at = timestamp(this.#now);
    if (existing !== undefined && (existing.session_id !== input.sessionId || existing.owner_principal_fingerprint !== input.ownerPrincipalFingerprint)) throw new QuirtError("idempotency_conflict", "Quirt reader identity was reused");
    this.#db.prepare(`INSERT INTO quirt_session_readers(reader_id,session_id,owner_principal_fingerprint,cursor_offset,attached,created_at,updated_at)
      VALUES(?,?,?,?,1,?,?) ON CONFLICT(reader_id) DO UPDATE SET attached=1,cursor_offset=excluded.cursor_offset,updated_at=excluded.updated_at`).run(
      readerId, input.sessionId, input.ownerPrincipalFingerprint, after, at, at
    );
    return this.getSessionReader(readerId);
  }

  getSessionReader(readerId: string): QuirtSessionReaderRecord {
    const row = this.#db.prepare("SELECT * FROM quirt_session_readers WHERE reader_id=?").get(readerId) as {
      reader_id: string; session_id: string; owner_principal_fingerprint: string; cursor_offset: number; attached: number; created_at: string; updated_at: string;
    } | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt session reader was not found");
    return Object.freeze({ readerId: row.reader_id, sessionId: row.session_id, ownerPrincipalFingerprint: row.owner_principal_fingerprint, cursorOffset: row.cursor_offset, attached: row.attached === 1, createdAt: row.created_at, updatedAt: row.updated_at });
  }

  advanceSessionReader(readerId: string, cursorOffset: number): QuirtSessionReaderRecord {
    const current = this.getSessionReader(readerId);
    if (!Number.isSafeInteger(cursorOffset) || cursorOffset < current.cursorOffset) throw new QuirtError("invalid_request", "Quirt reader cursor cannot move backwards");
    const stream = this.getStream(this.getSession(current.sessionId).outputStreamId);
    if (cursorOffset > stream.nextOffset) throw new QuirtError("invalid_request", "Quirt reader cursor is beyond the stream");
    this.#db.prepare("UPDATE quirt_session_readers SET cursor_offset=?,updated_at=? WHERE reader_id=?").run(cursorOffset, timestamp(this.#now), readerId);
    return this.getSessionReader(readerId);
  }

  detachSessionReader(readerId: string): QuirtSessionReaderRecord {
    this.getSessionReader(readerId);
    this.#db.prepare("UPDATE quirt_session_readers SET attached=0,updated_at=? WHERE reader_id=?").run(timestamp(this.#now), readerId);
    return this.getSessionReader(readerId);
  }

  createJob(input: {
    jobId?: string; requestId: string; ownerPrincipalFingerprint: string; command: Record<string, unknown>;
    workingDirectory: string; environment?: Readonly<Record<string, string>>; stdinSupported?: boolean;
  }): QuirtJobRecord {
    const jobId = input.jobId ?? randomUUID();
    const stdout = this.createStream("job", jobId, "stdout");
    const stderr = this.createStream("job", jobId, "stderr");
    const at = timestamp(this.#now);
    this.#db.prepare(`INSERT INTO quirt_jobs(
      job_id,request_id,status,owner_principal_fingerprint,command_json,working_directory,environment_json,stdin_supported,
      stdout_stream_id,stderr_stream_id,created_at,updated_at
    ) VALUES(?,?,'starting',?,?,?,?,?,?,?,?,?)`).run(jobId, input.requestId, input.ownerPrincipalFingerprint, JSON.stringify(input.command), input.workingDirectory, JSON.stringify(input.environment ?? {}), input.stdinSupported ? 1 : 0, stdout.streamId, stderr.streamId, at, at);
    return this.getJob(jobId);
  }

  getJob(jobId: string): QuirtJobRecord {
    const row = this.#db.prepare("SELECT * FROM quirt_jobs WHERE job_id=?").get(jobId) as unknown as JobRow | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt job was not found");
    return job(row);
  }

  listJobs(ownerPrincipalFingerprint?: string): QuirtJobRecord[] {
    const rows = ownerPrincipalFingerprint === undefined
      ? this.#db.prepare("SELECT * FROM quirt_jobs ORDER BY created_at,job_id").all()
      : this.#db.prepare("SELECT * FROM quirt_jobs WHERE owner_principal_fingerprint=? ORDER BY created_at,job_id").all(ownerPrincipalFingerprint);
    return (rows as unknown as JobRow[]).map(job);
  }

  updateJob(jobId: string, patch: {
    status?: QuirtJobStatus; processId?: number | null; exitCode?: number | null; exitSignal?: string | null;
    timedOut?: boolean; started?: boolean; finished?: boolean;
  }): QuirtJobRecord {
    const current = this.getJob(jobId);
    const at = timestamp(this.#now);
    this.#db.prepare(`UPDATE quirt_jobs SET status=?,process_id=?,exit_code=?,exit_signal=?,timed_out=?,updated_at=?,
      started_at=?,finished_at=? WHERE job_id=?`).run(
      patch.status ?? current.status, patch.processId === undefined ? current.processId : patch.processId,
      patch.exitCode === undefined ? current.exitCode : patch.exitCode, patch.exitSignal === undefined ? current.exitSignal : patch.exitSignal,
      patch.timedOut === undefined ? current.timedOut ? 1 : 0 : patch.timedOut ? 1 : 0,
      at, patch.started === true ? (current.startedAt ?? at) : current.startedAt, patch.finished === true ? (current.finishedAt ?? at) : current.finishedAt, jobId
    );
    return this.getJob(jobId);
  }

  reserveRequest(requestId: string, operation: string, requestHash: string, nonce: string, expiresAt: string): "new" | "replayed" {
    return this.#transaction(() => {
      const prior = this.#db.prepare("SELECT operation,request_hash,nonce FROM quirt_request_records WHERE request_id=?").get(requestId) as { operation: string; request_hash: string; nonce: string } | undefined;
      if (prior !== undefined) {
        if (prior.operation !== operation || prior.request_hash !== requestHash) throw new QuirtError("idempotency_conflict", "Quirt request ID was reused for different work");
        const nonceOwner = this.#db.prepare("SELECT request_id FROM quirt_request_nonces WHERE nonce=?").get(nonce) as { request_id: string } | undefined;
        if (nonceOwner !== undefined && nonceOwner.request_id !== requestId) throw new QuirtError("duplicate_request", "Quirt request nonce was replayed");
        this.#db.prepare("INSERT OR IGNORE INTO quirt_request_nonces(nonce,request_id,created_at,expires_at) VALUES(?,?,?,?)").run(nonce, requestId, timestamp(this.#now), expiresAt);
        return "replayed";
      }
      const nonceOwner = this.#db.prepare("SELECT request_id FROM quirt_request_nonces WHERE nonce=?").get(nonce) as { request_id: string } | undefined;
      if (nonceOwner !== undefined) throw new QuirtError("duplicate_request", "Quirt request nonce was replayed");
      this.#db.prepare("INSERT INTO quirt_request_records(request_id,operation,request_hash,nonce,state,created_at,expires_at) VALUES(?,?,?,?, 'reserved',?,?)").run(requestId, operation, requestHash, nonce, timestamp(this.#now), expiresAt);
      this.#db.prepare("INSERT INTO quirt_request_nonces(nonce,request_id,created_at,expires_at) VALUES(?,?,?,?)").run(nonce, requestId, timestamp(this.#now), expiresAt);
      return "new";
    });
  }

  completeRequest(requestId: string, response: Record<string, unknown>): void {
    const changed = this.#db.prepare("UPDATE quirt_request_records SET state='completed',response_json=?,completed_at=? WHERE request_id=? AND state='reserved'").run(JSON.stringify(response), timestamp(this.#now), requestId).changes;
    if (changed !== 1) throw new QuirtError("not_found", "Quirt request reservation was not found");
  }

  failRequest(requestId: string, error: Record<string, unknown>): void {
    const changed = this.#db.prepare("UPDATE quirt_request_records SET state='failed',error_json=?,completed_at=? WHERE request_id=? AND state='reserved'").run(JSON.stringify(error), timestamp(this.#now), requestId).changes;
    if (changed !== 1) throw new QuirtError("not_found", "Quirt request reservation was not found");
  }

  requestResult(requestId: string): { state: "reserved" | "completed" | "failed"; response: Record<string, unknown> | null; error: Record<string, unknown> | null } | null {
    const row = this.#db.prepare("SELECT state,response_json,error_json FROM quirt_request_records WHERE request_id=?").get(requestId) as { state: "reserved" | "completed" | "failed"; response_json: string | null; error_json: string | null } | undefined;
    if (row === undefined) return null;
    return { state: row.state, response: row.response_json === null ? null : parseObject(row.response_json, "request response"), error: row.error_json === null ? null : parseObject(row.error_json, "request error") };
  }

  purgeExpiredRequests(): number {
    return Number(this.#db.prepare("DELETE FROM quirt_request_records WHERE expires_at<?").run(timestamp(this.#now)).changes);
  }

  recordRecovery(ownerKind: QuirtStreamOwner, ownerId: string, action: string, outcome: string, details: Record<string, unknown> = {}): string {
    const recoveryId = randomUUID();
    this.#db.prepare("INSERT INTO quirt_recovery_records(recovery_id,owner_kind,owner_id,action,outcome,details_json,created_at) VALUES(?,?,?,?,?,?,?)").run(recoveryId, ownerKind, ownerId, action, outcome, JSON.stringify(details), timestamp(this.#now));
    return recoveryId;
  }

  runRollbackProbe(): void {
    const marker = `rollback-probe-${randomUUID()}`;
    try {
      this.#transaction(() => {
        this.#db.prepare("INSERT INTO quirt_protocol_metadata(key,value,updated_at) VALUES(?,?,?)").run(marker, "temporary", timestamp(this.#now));
        throw new Error("rollback-probe");
      });
    } catch (cause) {
      if (!(cause instanceof Error && cause.message === "rollback-probe")) throw cause;
    }
    const row = this.#db.prepare("SELECT key FROM quirt_protocol_metadata WHERE key=?").get(marker);
    if (row !== undefined) throw new QuirtError("internal_error", "Quirt state transaction rollback failed");
  }

  close(): void { this.#db.close(); }
}
