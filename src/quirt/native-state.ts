import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { QuirtError } from "./error.js";

export const QUIRT_NATIVE_SCHEMA_VERSION = 12 as const;

export type QuirtTransferDirection = "upload" | "download";
export type QuirtTransferStatus = "preparing" | "active" | "completed" | "canceled" | "failed";

export interface QuirtTransferRecord {
  transferId: string;
  direction: QuirtTransferDirection;
  status: QuirtTransferStatus;
  ownerPrincipalFingerprint: string;
  sourcePath: string | null;
  destinationPath: string | null;
  temporaryPath: string | null;
  expectedSize: number | null;
  chunkSize: number;
  digestAlgorithm: "sha256";
  expectedDigest: string | null;
  compression: "none" | "gzip";
  archiveFormat: "none" | "tar";
  metadata: Readonly<Record<string, unknown>>;
  sourceIdentity: Readonly<Record<string, unknown>> | null;
  completion: Readonly<Record<string, unknown>> | null;
  errorCode: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export interface QuirtTransferRangeRecord {
  transferId: string;
  startOffset: number;
  endOffset: number;
  byteCount: number;
  sha256: string;
  createdAt: string;
}

export interface QuirtWatchRecord {
  watchId: string;
  ownerPrincipalFingerprint: string;
  path: string;
  recursive: boolean;
  status: "active" | "canceled" | "lost" | "failed";
  nextSequence: number;
  lost: boolean;
  rescanRequired: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface QuirtWatchEventRecord {
  watchId: string;
  sequence: number;
  event: string;
  path: string;
  details: Readonly<Record<string, unknown>>;
  createdAt: string;
}

export interface QuirtNativeObjectRecord {
  objectId: string;
  ownerPrincipalFingerprint: string;
  status: string;
  data: Readonly<Record<string, unknown>>;
  createdAt: string;
  updatedAt: string;
}

interface TransferRow {
  transfer_id: string;
  direction: string;
  status: string;
  owner_principal_fingerprint: string;
  source_path: string | null;
  destination_path: string | null;
  temporary_path: string | null;
  expected_size: number | null;
  chunk_size: number;
  digest_algorithm: string;
  expected_digest: string | null;
  compression: string;
  archive_format: string;
  metadata_json: string;
  source_identity_json: string | null;
  completion_json: string | null;
  error_code: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

interface WatchRow {
  watch_id: string;
  owner_principal_fingerprint: string;
  path: string;
  recursive: number;
  status: string;
  next_sequence: number;
  lost: number;
  rescan_required: number;
  created_at: string;
  updated_at: string;
}

function parseObject(value: string | null, label: string): Readonly<Record<string, unknown>> | null {
  if (value === null) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return Object.freeze(parsed as Record<string, unknown>);
  } catch {
    throw new QuirtError("internal_error", `Stored ${label} is invalid`);
  }
}

function transfer(row: TransferRow): QuirtTransferRecord {
  return Object.freeze({
    transferId: row.transfer_id,
    direction: row.direction as QuirtTransferDirection,
    status: row.status as QuirtTransferStatus,
    ownerPrincipalFingerprint: row.owner_principal_fingerprint,
    sourcePath: row.source_path,
    destinationPath: row.destination_path,
    temporaryPath: row.temporary_path,
    expectedSize: row.expected_size,
    chunkSize: row.chunk_size,
    digestAlgorithm: "sha256" as const,
    expectedDigest: row.expected_digest,
    compression: row.compression as "none" | "gzip",
    archiveFormat: row.archive_format as "none" | "tar",
    metadata: parseObject(row.metadata_json, "transfer metadata") ?? Object.freeze({}),
    sourceIdentity: parseObject(row.source_identity_json, "transfer source identity"),
    completion: parseObject(row.completion_json, "transfer completion"),
    errorCode: row.error_code,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    completedAt: row.completed_at
  });
}

function watch(row: WatchRow): QuirtWatchRecord {
  return Object.freeze({
    watchId: row.watch_id,
    ownerPrincipalFingerprint: row.owner_principal_fingerprint,
    path: row.path,
    recursive: row.recursive === 1,
    status: row.status as QuirtWatchRecord["status"],
    nextSequence: row.next_sequence,
    lost: row.lost === 1,
    rescanRequired: row.rescan_required === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  });
}

function transaction<T>(database: DatabaseSync, action: () => T): T {
  database.exec("BEGIN IMMEDIATE");
  try {
    const result = action();
    database.exec("COMMIT");
    return result;
  } catch (cause) {
    try { database.exec("ROLLBACK"); } catch { /* preserve the original error */ }
    throw cause;
  }
}

function migration(database: DatabaseSync, version: number, now: () => Date, sql: string): void {
  const current = Number((database.prepare("SELECT COALESCE(MAX(version),0) AS version FROM quirt_schema_migrations").get() as { version: number }).version);
  if (current >= version) return;
  if (current !== version - 1) throw new QuirtError("configuration_error", "Quirt native state migration order is invalid");
  transaction(database, () => {
    database.exec(sql);
    database.prepare("INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(?,?)").run(version, now().toISOString());
  });
}

export function migrateQuirtNativeState(database: DatabaseSync, now: () => Date): void {
  migration(database, 5, now, `
    CREATE TABLE quirt_native_results(
      request_id TEXT PRIMARY KEY, operation TEXT NOT NULL, owner_principal_fingerprint TEXT NOT NULL,
      object_kind TEXT NOT NULL, object_id TEXT, result_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE quirt_transfers(
      transfer_id TEXT PRIMARY KEY, direction TEXT NOT NULL CHECK(direction IN ('upload','download')),
      status TEXT NOT NULL CHECK(status IN ('preparing','active','completed','canceled','failed')),
      owner_principal_fingerprint TEXT NOT NULL, source_path TEXT, destination_path TEXT, temporary_path TEXT,
      expected_size INTEGER, chunk_size INTEGER NOT NULL, digest_algorithm TEXT NOT NULL CHECK(digest_algorithm='sha256'),
      expected_digest TEXT, compression TEXT NOT NULL CHECK(compression IN ('none','gzip')),
      archive_format TEXT NOT NULL CHECK(archive_format IN ('none','tar')), metadata_json TEXT NOT NULL,
      source_identity_json TEXT, completion_json TEXT, error_code TEXT, created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL, completed_at TEXT
    );
    CREATE INDEX quirt_transfers_owner ON quirt_transfers(owner_principal_fingerprint,updated_at);
    CREATE TABLE quirt_transfer_ranges(
      transfer_id TEXT NOT NULL REFERENCES quirt_transfers(transfer_id) ON DELETE CASCADE,
      start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, byte_count INTEGER NOT NULL,
      sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(transfer_id,start_offset), CHECK(start_offset>=0 AND end_offset>start_offset AND byte_count=end_offset-start_offset)
    );
    CREATE INDEX quirt_transfer_ranges_end ON quirt_transfer_ranges(transfer_id,end_offset);
  `);
  migration(database, 6, now, `
    CREATE TABLE quirt_directory_watches(
      watch_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, path TEXT NOT NULL,
      recursive INTEGER NOT NULL CHECK(recursive IN (0,1)), status TEXT NOT NULL CHECK(status IN ('active','canceled','lost','failed')),
      next_sequence INTEGER NOT NULL DEFAULT 0, lost INTEGER NOT NULL DEFAULT 0 CHECK(lost IN (0,1)),
      rescan_required INTEGER NOT NULL DEFAULT 0 CHECK(rescan_required IN (0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX quirt_directory_watches_owner ON quirt_directory_watches(owner_principal_fingerprint,updated_at);
    CREATE TABLE quirt_watch_events(
      watch_id TEXT NOT NULL REFERENCES quirt_directory_watches(watch_id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL, event TEXT NOT NULL, path TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(watch_id,sequence)
    );
  `);
  migration(database, 7, now, `
    CREATE TABLE quirt_repository_mirrors(
      mirror_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE quirt_materializations(
      materialization_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE quirt_worktrees(
      worktree_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE quirt_git_operations(
      operation_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
  `);
  migration(database, 8, now, `
    CREATE TABLE quirt_recordings(
      recording_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX quirt_recordings_owner ON quirt_recordings(owner_principal_fingerprint,updated_at);
    CREATE TABLE quirt_recording_events(
      recording_id TEXT NOT NULL REFERENCES quirt_recordings(recording_id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL, event_type TEXT NOT NULL, stream_offset INTEGER, timestamp_ns INTEGER NOT NULL,
      payload BLOB NOT NULL, metadata_json TEXT NOT NULL, sha256 TEXT NOT NULL,
      PRIMARY KEY(recording_id,sequence)
    );
    CREATE TABLE quirt_recording_indexes(
      recording_id TEXT NOT NULL REFERENCES quirt_recordings(recording_id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL, text_content TEXT NOT NULL, byte_offset INTEGER, created_at TEXT NOT NULL,
      PRIMARY KEY(recording_id,sequence)
    );
    CREATE TABLE quirt_recording_exports(
      export_id TEXT PRIMARY KEY, recording_id TEXT NOT NULL REFERENCES quirt_recordings(recording_id) ON DELETE CASCADE,
      owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
  `);
  migration(database, 9, now, `
    CREATE TABLE quirt_process_attachments(
      attachment_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE quirt_journal_cursors(
      cursor_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
  `);
  migration(database, 10, now, `
    CREATE TABLE quirt_session_snapshots(
      snapshot_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE quirt_handoffs(
      handoff_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      target_host TEXT NOT NULL, expires_at TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX quirt_handoffs_owner ON quirt_handoffs(owner_principal_fingerprint,expires_at);
  `);
  migration(database, 11, now, `
    CREATE TABLE quirt_capability_probes(
      probe_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, status TEXT NOT NULL,
      data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE quirt_cleanup_records(
      cleanup_id TEXT PRIMARY KEY, object_kind TEXT NOT NULL, object_id TEXT NOT NULL,
      outcome TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
  `);
  migration(database, 12, now, `
    CREATE INDEX quirt_transfer_ranges_cover ON quirt_transfer_ranges(transfer_id,start_offset,end_offset);
    CREATE INDEX quirt_recording_events_time ON quirt_recording_events(recording_id,timestamp_ns,sequence);
    CREATE INDEX quirt_recording_indexes_text ON quirt_recording_indexes(recording_id,sequence);
    CREATE INDEX quirt_session_snapshots_owner ON quirt_session_snapshots(owner_principal_fingerprint,updated_at);
  `);
}

export class QuirtNativeStateStore {
  constructor(private readonly database: DatabaseSync, private readonly now: () => Date) {}

  transaction<T>(action: () => T): T { return transaction(this.database, action); }

  recordResult(input: { requestId: string; operation: string; ownerPrincipalFingerprint: string; objectKind: string; objectId?: string; result: Readonly<Record<string, unknown>> }): void {
    this.database.prepare(`INSERT OR IGNORE INTO quirt_native_results(
      request_id,operation,owner_principal_fingerprint,object_kind,object_id,result_json,created_at
    ) VALUES(?,?,?,?,?,?,?)`).run(input.requestId, input.operation, input.ownerPrincipalFingerprint, input.objectKind, input.objectId ?? null, JSON.stringify(input.result), this.now().toISOString());
  }

  createTransfer(input: Omit<QuirtTransferRecord, "createdAt" | "updatedAt" | "completedAt" | "completion" | "errorCode">): QuirtTransferRecord {
    const at = this.now().toISOString();
    this.database.prepare(`INSERT INTO quirt_transfers(
      transfer_id,direction,status,owner_principal_fingerprint,source_path,destination_path,temporary_path,
      expected_size,chunk_size,digest_algorithm,expected_digest,compression,archive_format,metadata_json,
      source_identity_json,created_at,updated_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      input.transferId, input.direction, input.status, input.ownerPrincipalFingerprint, input.sourcePath, input.destinationPath,
      input.temporaryPath, input.expectedSize, input.chunkSize, input.digestAlgorithm, input.expectedDigest, input.compression,
      input.archiveFormat, JSON.stringify(input.metadata), input.sourceIdentity === null ? null : JSON.stringify(input.sourceIdentity), at, at
    );
    return this.getTransfer(input.transferId, input.ownerPrincipalFingerprint);
  }

  getTransfer(transferId: string, ownerPrincipalFingerprint?: string): QuirtTransferRecord {
    const row = this.database.prepare("SELECT * FROM quirt_transfers WHERE transfer_id=?").get(transferId) as unknown as TransferRow | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt transfer was not found");
    if (ownerPrincipalFingerprint !== undefined && row.owner_principal_fingerprint !== ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Quirt transfer principal does not match");
    return transfer(row);
  }

  listTransfers(ownerPrincipalFingerprint: string, maximum?: number): QuirtTransferRecord[] {
    if (maximum !== undefined && (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 10_000)) throw new QuirtError("invalid_request", "Quirt transfer list bound is invalid");
    const statement = this.database.prepare(`SELECT * FROM quirt_transfers WHERE owner_principal_fingerprint=? ORDER BY created_at,transfer_id${maximum === undefined ? "" : " LIMIT ?"}`); const rows = (maximum === undefined ? statement.all(ownerPrincipalFingerprint) : statement.all(ownerPrincipalFingerprint, maximum)) as unknown as TransferRow[];
    return rows.map(transfer);
  }

  listTransfersPage(ownerPrincipalFingerprint: string, input: { maximum: number; afterCreatedAt?: string; afterTransferId?: string }): { records: QuirtTransferRecord[]; next: { createdAt: string; transferId: string } | null } {
    if (!Number.isSafeInteger(input.maximum) || input.maximum < 1 || input.maximum > 1000 || (input.afterCreatedAt === undefined) !== (input.afterTransferId === undefined)) throw new QuirtError("invalid_request", "Quirt transfer list page is invalid"); const cursor = input.afterCreatedAt === undefined ? "" : " AND (created_at>? OR (created_at=? AND transfer_id>?))"; const statement = this.database.prepare(`SELECT * FROM quirt_transfers WHERE owner_principal_fingerprint=?${cursor} ORDER BY created_at,transfer_id LIMIT ?`); const rows = (input.afterCreatedAt === undefined ? statement.all(ownerPrincipalFingerprint, input.maximum + 1) : statement.all(ownerPrincipalFingerprint, input.afterCreatedAt, input.afterCreatedAt, input.afterTransferId!, input.maximum + 1)) as unknown as TransferRow[]; const selected = rows.slice(0, input.maximum).map(transfer); const last = selected.at(-1);
    return { records: selected, next: rows.length > input.maximum && last !== undefined ? { createdAt: last.createdAt, transferId: last.transferId } : null };
  }

  updateTransfer(transferId: string, patch: { status?: QuirtTransferStatus; completion?: Readonly<Record<string, unknown>> | null; errorCode?: string | null; temporaryPath?: string | null }): QuirtTransferRecord {
    const current = this.getTransfer(transferId);
    const at = this.now().toISOString();
    const status = patch.status ?? current.status;
    const completion = patch.completion === undefined ? current.completion : patch.completion;
    const errorCode = patch.errorCode === undefined ? current.errorCode : patch.errorCode;
    const temporaryPath = patch.temporaryPath === undefined ? current.temporaryPath : patch.temporaryPath;
    const completedAt = status === "completed" || status === "canceled" || status === "failed" ? at : current.completedAt;
    this.database.prepare("UPDATE quirt_transfers SET status=?,completion_json=?,error_code=?,temporary_path=?,updated_at=?,completed_at=? WHERE transfer_id=?").run(
      status, completion === null ? null : JSON.stringify(completion), errorCode, temporaryPath, at, completedAt, transferId
    );
    return this.getTransfer(transferId);
  }

  putTransferRange(input: Omit<QuirtTransferRangeRecord, "createdAt">): { duplicate: boolean; range: QuirtTransferRangeRecord } {
    const existing = this.database.prepare("SELECT * FROM quirt_transfer_ranges WHERE transfer_id=? AND start_offset=?").get(input.transferId, input.startOffset) as unknown as { transfer_id: string; start_offset: number; end_offset: number; byte_count: number; sha256: string; created_at: string } | undefined;
    if (existing !== undefined) {
      if (existing.end_offset !== input.endOffset || existing.sha256 !== input.sha256) throw new QuirtError("conflict", "Quirt transfer chunk conflicts with an existing chunk");
      return { duplicate: true, range: Object.freeze({ transferId: existing.transfer_id, startOffset: existing.start_offset, endOffset: existing.end_offset, byteCount: existing.byte_count, sha256: existing.sha256, createdAt: existing.created_at }) };
    }
    const overlap = this.database.prepare("SELECT 1 AS present FROM quirt_transfer_ranges WHERE transfer_id=? AND start_offset<? AND end_offset>? LIMIT 1").get(input.transferId, input.endOffset, input.startOffset) as { present: number } | undefined;
    if (overlap !== undefined) throw new QuirtError("conflict", "Quirt transfer chunk overlaps an existing range");
    const at = this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_transfer_ranges(transfer_id,start_offset,end_offset,byte_count,sha256,created_at) VALUES(?,?,?,?,?,?)").run(input.transferId, input.startOffset, input.endOffset, input.byteCount, input.sha256, at);
    return { duplicate: false, range: Object.freeze({ ...input, createdAt: at }) };
  }

  transferRangeAt(transferId: string, startOffset: number): QuirtTransferRangeRecord | null {
    const row = this.database.prepare("SELECT * FROM quirt_transfer_ranges WHERE transfer_id=? AND start_offset=?").get(transferId, startOffset) as unknown as { transfer_id: string; start_offset: number; end_offset: number; byte_count: number; sha256: string; created_at: string } | undefined;
    return row === undefined ? null : Object.freeze({ transferId: row.transfer_id, startOffset: row.start_offset, endOffset: row.end_offset, byteCount: row.byte_count, sha256: row.sha256, createdAt: row.created_at });
  }

  transferRangeOverlaps(transferId: string, startOffset: number, endOffset: number): boolean {
    return this.database.prepare("SELECT 1 AS present FROM quirt_transfer_ranges WHERE transfer_id=? AND start_offset<? AND end_offset>? LIMIT 1").get(transferId, endOffset, startOffset) !== undefined;
  }

  transferRangePage(transferId: string, afterOffset: number, maximum: number): { ranges: QuirtTransferRangeRecord[]; truncated: boolean; nextOffset: number } {
    if (!Number.isSafeInteger(afterOffset) || afterOffset < -1 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1000) throw new QuirtError("invalid_request", "Quirt transfer range page is invalid");
    const rows = this.database.prepare("SELECT * FROM quirt_transfer_ranges WHERE transfer_id=? AND start_offset>? ORDER BY start_offset LIMIT ?").all(transferId, afterOffset, maximum + 1) as unknown as Array<{ transfer_id: string; start_offset: number; end_offset: number; byte_count: number; sha256: string; created_at: string }>;
    const truncated = rows.length > maximum; const selected = rows.slice(0, maximum); const ranges = selected.map(row => Object.freeze({ transferId: row.transfer_id, startOffset: row.start_offset, endOffset: row.end_offset, byteCount: row.byte_count, sha256: row.sha256, createdAt: row.created_at }));
    return { ranges, truncated, nextOffset: ranges.at(-1)?.startOffset ?? afterOffset };
  }

  transferRangeTotals(transferId: string): { rangeCount: number; coveredBytes: number } {
    const row = this.database.prepare("SELECT COUNT(*) AS range_count,COALESCE(SUM(byte_count),0) AS covered_bytes FROM quirt_transfer_ranges WHERE transfer_id=?").get(transferId) as { range_count: number; covered_bytes: number };
    return { rangeCount: Number(row.range_count), coveredBytes: Number(row.covered_bytes) };
  }

  transferCoverage(transferId: string, expectedSize: number, maximumMissing = 100): { rangeCount: number; coveredBytes: number; missingRangeCount: number; missingRanges: Array<{ startOffset: number; endOffset: number }>; missingRangesTruncated: boolean } {
    if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || !Number.isSafeInteger(maximumMissing) || maximumMissing < 0 || maximumMissing > 1000) throw new QuirtError("invalid_request", "Quirt transfer coverage bound is invalid");
    let afterOffset = -1; let cursor = 0; let rangeCount = 0; let missingRangeCount = 0; const missingRanges: Array<{ startOffset: number; endOffset: number }> = [];
    while (true) {
      const page = this.transferRangePage(transferId, afterOffset, 1000);
      for (const range of page.ranges) {
        if (range.startOffset > cursor) { missingRangeCount += 1; if (missingRanges.length < maximumMissing) missingRanges.push({ startOffset: cursor, endOffset: Math.min(range.startOffset, expectedSize) }); }
        cursor = Math.max(cursor, range.endOffset); rangeCount += 1;
      }
      afterOffset = page.nextOffset;
      if (!page.truncated) break;
    }
    if (cursor < expectedSize) { missingRangeCount += 1; if (missingRanges.length < maximumMissing) missingRanges.push({ startOffset: cursor, endOffset: expectedSize }); }
    const totals = this.transferRangeTotals(transferId); if (totals.rangeCount !== rangeCount) throw new QuirtError("internal_error", "Quirt transfer range accounting changed during coverage inspection");
    return { rangeCount, coveredBytes: totals.coveredBytes, missingRangeCount, missingRanges, missingRangesTruncated: missingRangeCount > missingRanges.length };
  }

  createWatch(input: { watchId?: string; ownerPrincipalFingerprint: string; path: string; recursive: boolean }): QuirtWatchRecord {
    const watchId = input.watchId ?? randomUUID(); const at = this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_directory_watches(watch_id,owner_principal_fingerprint,path,recursive,status,created_at,updated_at) VALUES(?,?,?,?, 'active',?,?)").run(watchId, input.ownerPrincipalFingerprint, input.path, input.recursive ? 1 : 0, at, at);
    return this.getWatch(watchId, input.ownerPrincipalFingerprint);
  }

  getWatch(watchId: string, ownerPrincipalFingerprint?: string): QuirtWatchRecord {
    const row = this.database.prepare("SELECT * FROM quirt_directory_watches WHERE watch_id=?").get(watchId) as unknown as WatchRow | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt directory watch was not found");
    if (ownerPrincipalFingerprint !== undefined && row.owner_principal_fingerprint !== ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Quirt directory watch principal does not match");
    return watch(row);
  }

  updateWatch(watchId: string, patch: { status?: QuirtWatchRecord["status"]; lost?: boolean; rescanRequired?: boolean }): QuirtWatchRecord {
    const current = this.getWatch(watchId);
    this.database.prepare("UPDATE quirt_directory_watches SET status=?,lost=?,rescan_required=?,updated_at=? WHERE watch_id=?").run(patch.status ?? current.status, (patch.lost ?? current.lost) ? 1 : 0, (patch.rescanRequired ?? current.rescanRequired) ? 1 : 0, this.now().toISOString(), watchId);
    return this.getWatch(watchId);
  }

  appendWatchEvent(watchId: string, event: string, path: string, details: Readonly<Record<string, unknown>> = {}): QuirtWatchEventRecord {
    return transaction(this.database, () => {
      const current = this.getWatch(watchId);
      if (current.status !== "active") throw new QuirtError("invalid_request", "Quirt directory watch is not active");
      const sequence = current.nextSequence; const at = this.now().toISOString();
      this.database.prepare("INSERT INTO quirt_watch_events(watch_id,sequence,event,path,details_json,created_at) VALUES(?,?,?,?,?,?)").run(watchId, sequence, event, path, JSON.stringify(details), at);
      this.database.prepare("UPDATE quirt_directory_watches SET next_sequence=?,updated_at=? WHERE watch_id=?").run(sequence + 1, at, watchId);
      return Object.freeze({ watchId, sequence, event, path, details: Object.freeze({ ...details }), createdAt: at });
    });
  }

  readWatchEvents(watchId: string, after: number, maximum: number): QuirtWatchEventRecord[] {
    if (!Number.isSafeInteger(after) || after < -1 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1000) throw new QuirtError("invalid_request", "Quirt watch page is invalid");
    const rows = this.database.prepare("SELECT * FROM quirt_watch_events WHERE watch_id=? AND sequence>? ORDER BY sequence LIMIT ?").all(watchId, after, maximum) as unknown as Array<{ watch_id: string; sequence: number; event: string; path: string; details_json: string; created_at: string }>;
    return rows.map(row => Object.freeze({ watchId: row.watch_id, sequence: row.sequence, event: row.event, path: row.path, details: parseObject(row.details_json, "watch event details") ?? Object.freeze({}), createdAt: row.created_at }));
  }

  watchEventCount(watchId: string): number { return Number((this.database.prepare("SELECT COUNT(*) AS count FROM quirt_watch_events WHERE watch_id=?").get(watchId) as { count: number }).count); }

  recoverWatches(): number {
    const result = this.database.prepare("UPDATE quirt_directory_watches SET status='lost',lost=1,rescan_required=1,updated_at=? WHERE status='active'").run(this.now().toISOString());
    return Number(result.changes);
  }

  putObject(table: "quirt_repository_mirrors" | "quirt_materializations" | "quirt_worktrees" | "quirt_git_operations" | "quirt_recordings" | "quirt_recording_exports" | "quirt_process_attachments" | "quirt_journal_cursors" | "quirt_session_snapshots" | "quirt_capability_probes", input: { objectId: string; ownerPrincipalFingerprint: string; status: string; data: Readonly<Record<string, unknown>> }): QuirtNativeObjectRecord {
    const idColumn = table === "quirt_repository_mirrors" ? "mirror_id" : table === "quirt_materializations" ? "materialization_id" : table === "quirt_worktrees" ? "worktree_id" : table === "quirt_git_operations" ? "operation_id" : table === "quirt_recordings" ? "recording_id" : table === "quirt_recording_exports" ? "export_id" : table === "quirt_process_attachments" ? "attachment_id" : table === "quirt_journal_cursors" ? "cursor_id" : table === "quirt_session_snapshots" ? "snapshot_id" : "probe_id";
    const existing = this.database.prepare(`SELECT owner_principal_fingerprint FROM ${table} WHERE ${idColumn}=?`).get(input.objectId) as { owner_principal_fingerprint: string } | undefined;
    if (existing !== undefined && existing.owner_principal_fingerprint !== input.ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Quirt native object principal does not match");
    const at = this.now().toISOString();
    if (table === "quirt_recording_exports") {
      if (typeof input.data.recordingId !== "string") throw new QuirtError("internal_error", "Quirt recording export identity is missing");
      this.database.prepare(`INSERT INTO quirt_recording_exports(export_id,recording_id,owner_principal_fingerprint,status,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(export_id) DO UPDATE SET status=excluded.status,data_json=excluded.data_json,updated_at=excluded.updated_at`).run(input.objectId, input.data.recordingId, input.ownerPrincipalFingerprint, input.status, JSON.stringify(input.data), at, at);
      return this.getObject(table, input.objectId, input.ownerPrincipalFingerprint);
    }
    this.database.prepare(`INSERT INTO ${table}(${idColumn},owner_principal_fingerprint,status,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(${idColumn}) DO UPDATE SET status=excluded.status,data_json=excluded.data_json,updated_at=excluded.updated_at`).run(input.objectId, input.ownerPrincipalFingerprint, input.status, JSON.stringify(input.data), at, at);
    return this.getObject(table, input.objectId, input.ownerPrincipalFingerprint);
  }

  getObject(table: "quirt_repository_mirrors" | "quirt_materializations" | "quirt_worktrees" | "quirt_git_operations" | "quirt_recordings" | "quirt_recording_exports" | "quirt_process_attachments" | "quirt_journal_cursors" | "quirt_session_snapshots" | "quirt_capability_probes", objectId: string, ownerPrincipalFingerprint?: string): QuirtNativeObjectRecord {
    const idColumn = table === "quirt_repository_mirrors" ? "mirror_id" : table === "quirt_materializations" ? "materialization_id" : table === "quirt_worktrees" ? "worktree_id" : table === "quirt_git_operations" ? "operation_id" : table === "quirt_recordings" ? "recording_id" : table === "quirt_recording_exports" ? "export_id" : table === "quirt_process_attachments" ? "attachment_id" : table === "quirt_journal_cursors" ? "cursor_id" : table === "quirt_session_snapshots" ? "snapshot_id" : "probe_id";
    const row = this.database.prepare(`SELECT ${idColumn} AS object_id,owner_principal_fingerprint,status,data_json,created_at,updated_at FROM ${table} WHERE ${idColumn}=?`).get(objectId) as unknown as { object_id: string; owner_principal_fingerprint: string; status: string; data_json: string; created_at: string; updated_at: string } | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt native object was not found");
    if (ownerPrincipalFingerprint !== undefined && row.owner_principal_fingerprint !== ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Quirt native object principal does not match");
    return Object.freeze({ objectId: row.object_id, ownerPrincipalFingerprint: row.owner_principal_fingerprint, status: row.status, data: parseObject(row.data_json, "native object") ?? Object.freeze({}), createdAt: row.created_at, updatedAt: row.updated_at });
  }

  listObjects(table: "quirt_repository_mirrors" | "quirt_materializations" | "quirt_worktrees" | "quirt_git_operations" | "quirt_recordings" | "quirt_recording_exports" | "quirt_process_attachments" | "quirt_journal_cursors" | "quirt_session_snapshots" | "quirt_capability_probes", ownerPrincipalFingerprint: string, maximum?: number): QuirtNativeObjectRecord[] {
    if (maximum !== undefined && (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 10_000)) throw new QuirtError("invalid_request", "Quirt native object list bound is invalid");
    const idColumn = table === "quirt_repository_mirrors" ? "mirror_id" : table === "quirt_materializations" ? "materialization_id" : table === "quirt_worktrees" ? "worktree_id" : table === "quirt_git_operations" ? "operation_id" : table === "quirt_recordings" ? "recording_id" : table === "quirt_recording_exports" ? "export_id" : table === "quirt_process_attachments" ? "attachment_id" : table === "quirt_journal_cursors" ? "cursor_id" : table === "quirt_session_snapshots" ? "snapshot_id" : "probe_id";
    const statement = this.database.prepare(`SELECT ${idColumn} AS object_id,owner_principal_fingerprint,status,data_json,created_at,updated_at FROM ${table} WHERE owner_principal_fingerprint=? ORDER BY created_at,${idColumn}${maximum === undefined ? "" : " LIMIT ?"}`); const rows = (maximum === undefined ? statement.all(ownerPrincipalFingerprint) : statement.all(ownerPrincipalFingerprint, maximum)) as unknown as Array<{ object_id: string; owner_principal_fingerprint: string; status: string; data_json: string; created_at: string; updated_at: string }>;
    return rows.map(row => Object.freeze({ objectId: row.object_id, ownerPrincipalFingerprint: row.owner_principal_fingerprint, status: row.status, data: parseObject(row.data_json, "native object") ?? Object.freeze({}), createdAt: row.created_at, updatedAt: row.updated_at }));
  }

  listObjectsPage(table: "quirt_repository_mirrors" | "quirt_materializations" | "quirt_worktrees" | "quirt_git_operations" | "quirt_recordings" | "quirt_recording_exports" | "quirt_process_attachments" | "quirt_journal_cursors" | "quirt_session_snapshots" | "quirt_capability_probes", ownerPrincipalFingerprint: string, input: { maximum: number; afterCreatedAt?: string; afterObjectId?: string }): { records: QuirtNativeObjectRecord[]; truncated: boolean; next: { createdAt: string; objectId: string } | null } {
    if (!Number.isSafeInteger(input.maximum) || input.maximum < 1 || input.maximum > 1000 || (input.afterCreatedAt === undefined) !== (input.afterObjectId === undefined)) throw new QuirtError("invalid_request", "Quirt native object page is invalid");
    const idColumn = table === "quirt_repository_mirrors" ? "mirror_id" : table === "quirt_materializations" ? "materialization_id" : table === "quirt_worktrees" ? "worktree_id" : table === "quirt_git_operations" ? "operation_id" : table === "quirt_recordings" ? "recording_id" : table === "quirt_recording_exports" ? "export_id" : table === "quirt_process_attachments" ? "attachment_id" : table === "quirt_journal_cursors" ? "cursor_id" : table === "quirt_session_snapshots" ? "snapshot_id" : "probe_id";
    const cursor = input.afterCreatedAt === undefined ? "" : ` AND (created_at>? OR (created_at=? AND ${idColumn}>?))`; const statement = this.database.prepare(`SELECT ${idColumn} AS object_id,owner_principal_fingerprint,status,data_json,created_at,updated_at FROM ${table} WHERE owner_principal_fingerprint=?${cursor} ORDER BY created_at,${idColumn} LIMIT ?`); const rows = (input.afterCreatedAt === undefined ? statement.all(ownerPrincipalFingerprint, input.maximum + 1) : statement.all(ownerPrincipalFingerprint, input.afterCreatedAt, input.afterCreatedAt, input.afterObjectId!, input.maximum + 1)) as unknown as Array<{ object_id: string; owner_principal_fingerprint: string; status: string; data_json: string; created_at: string; updated_at: string }>;
    const truncated = rows.length > input.maximum; const selected = rows.slice(0, input.maximum); const records = selected.map(row => Object.freeze({ objectId: row.object_id, ownerPrincipalFingerprint: row.owner_principal_fingerprint, status: row.status, data: parseObject(row.data_json, "native object") ?? Object.freeze({}), createdAt: row.created_at, updatedAt: row.updated_at })); const last = records.at(-1);
    return { records, truncated, next: truncated && last !== undefined ? { createdAt: last.createdAt, objectId: last.objectId } : null };
  }

  createHandoff(input: { handoffId: string; ownerPrincipalFingerprint: string; status: string; targetHost: string; expiresAt: string; data: Readonly<Record<string, unknown>> }): QuirtNativeObjectRecord {
    const at = this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_handoffs(handoff_id,owner_principal_fingerprint,status,target_host,expires_at,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").run(input.handoffId, input.ownerPrincipalFingerprint, input.status, input.targetHost, input.expiresAt, JSON.stringify(input.data), at, at);
    return this.getHandoff(input.handoffId, input.ownerPrincipalFingerprint, input.targetHost);
  }

  getHandoff(handoffId: string, ownerPrincipalFingerprint: string, targetHost: string): QuirtNativeObjectRecord {
    const row = this.database.prepare("SELECT handoff_id AS object_id,owner_principal_fingerprint,status,target_host,expires_at,data_json,created_at,updated_at FROM quirt_handoffs WHERE handoff_id=?").get(handoffId) as unknown as { object_id: string; owner_principal_fingerprint: string; status: string; target_host: string; expires_at: string; data_json: string; created_at: string; updated_at: string } | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Quirt handoff was not found");
    if (row.owner_principal_fingerprint !== ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Quirt handoff principal does not match");
    if (row.target_host !== targetHost) throw new QuirtError("authorization_failed", "Quirt handoff target host does not match");
    if (Date.parse(row.expires_at) <= this.now().getTime()) throw new QuirtError("stale_request", "Quirt handoff has expired");
    return Object.freeze({ objectId: row.object_id, ownerPrincipalFingerprint: row.owner_principal_fingerprint, status: row.status, data: parseObject(row.data_json, "handoff") ?? Object.freeze({}), createdAt: row.created_at, updatedAt: row.updated_at });
  }

  cleanupExpiredHandoffs(): number {
    return transaction(this.database, () => {
      const rows = this.database.prepare("SELECT handoff_id FROM quirt_handoffs WHERE expires_at<=? ORDER BY handoff_id LIMIT 1000").all(this.now().toISOString()) as unknown as Array<{ handoff_id: string }>;
      for (const row of rows) { this.database.prepare("DELETE FROM quirt_handoffs WHERE handoff_id=?").run(row.handoff_id); this.database.prepare("INSERT INTO quirt_cleanup_records(cleanup_id,object_kind,object_id,outcome,data_json,created_at) VALUES(?,?,?,?,?,?)").run(randomUUID(), "handoff", row.handoff_id, "expired", "{}", this.now().toISOString()); }
      return rows.length;
    });
  }

  appendRecordingEvent(input: { recordingId: string; sequence: number; eventType: string; streamOffset?: number; timestampNs: number; payload: Buffer; metadata: Readonly<Record<string, unknown>>; sha256: string; text?: string }): void {
    this.database.prepare("INSERT INTO quirt_recording_events(recording_id,sequence,event_type,stream_offset,timestamp_ns,payload,metadata_json,sha256) VALUES(?,?,?,?,?,?,?,?)").run(input.recordingId, input.sequence, input.eventType, input.streamOffset ?? null, input.timestampNs, input.payload, JSON.stringify(input.metadata), input.sha256);
    if (input.text !== undefined) this.database.prepare("INSERT INTO quirt_recording_indexes(recording_id,sequence,text_content,byte_offset,created_at) VALUES(?,?,?,?,?)").run(input.recordingId, input.sequence, input.text, input.streamOffset ?? null, this.now().toISOString());
  }

  recordingEvents(recordingId: string, after: number, maximum: number): Array<{ sequence: number; eventType: string; streamOffset: number | null; timestampNs: number; payload: Buffer; metadata: Readonly<Record<string, unknown>>; sha256: string }> {
    const rows = this.database.prepare("SELECT * FROM quirt_recording_events WHERE recording_id=? AND sequence>? ORDER BY sequence LIMIT ?").all(recordingId, after, maximum) as unknown as Array<{ sequence: number; event_type: string; stream_offset: number | null; timestamp_ns: number; payload: Uint8Array; metadata_json: string; sha256: string }>;
    return rows.map(row => ({ sequence: row.sequence, eventType: row.event_type, streamOffset: row.stream_offset, timestampNs: row.timestamp_ns, payload: Buffer.from(row.payload), metadata: parseObject(row.metadata_json, "recording event") ?? Object.freeze({}), sha256: row.sha256 }));
  }

  recordingEvent(recordingId: string, sequence: number): { sequence: number; eventType: string; streamOffset: number | null; timestampNs: number; payload: Buffer; metadata: Readonly<Record<string, unknown>>; sha256: string } | null {
    const row = this.database.prepare("SELECT * FROM quirt_recording_events WHERE recording_id=? AND sequence=?").get(recordingId, sequence) as unknown as { sequence: number; event_type: string; stream_offset: number | null; timestamp_ns: number; payload: Uint8Array; metadata_json: string; sha256: string } | undefined;
    return row === undefined ? null : { sequence: row.sequence, eventType: row.event_type, streamOffset: row.stream_offset, timestampNs: row.timestamp_ns, payload: Buffer.from(row.payload), metadata: parseObject(row.metadata_json, "recording event") ?? Object.freeze({}), sha256: row.sha256 };
  }

  recordingEventCount(recordingId: string): number { return Number((this.database.prepare("SELECT COUNT(*) AS count FROM quirt_recording_events WHERE recording_id=?").get(recordingId) as { count: number }).count); }
  recordingIndexCount(recordingId: string): number { return Number((this.database.prepare("SELECT COUNT(*) AS count FROM quirt_recording_indexes WHERE recording_id=?").get(recordingId) as { count: number }).count); }

  searchRecording(recordingId: string, query: string, maximum: number): Array<{ sequence: number; text: string; byteOffset: number | null }> {
    const rows = this.database.prepare("SELECT sequence,text_content,byte_offset FROM quirt_recording_indexes WHERE recording_id=? AND instr(text_content,?)>0 ORDER BY sequence LIMIT ?").all(recordingId, query, maximum) as unknown as Array<{ sequence: number; text_content: string; byte_offset: number | null }>;
    return rows.map(row => ({ sequence: row.sequence, text: row.text_content, byteOffset: row.byte_offset }));
  }

  recordingIndexes(recordingId: string, after: number, maximum: number): Array<{ sequence: number; text: string; byteOffset: number | null }> {
    const rows = this.database.prepare("SELECT sequence,text_content,byte_offset FROM quirt_recording_indexes WHERE recording_id=? AND sequence>? ORDER BY sequence LIMIT ?").all(recordingId, after, maximum) as unknown as Array<{ sequence: number; text_content: string; byte_offset: number | null }>;
    return rows.map(row => ({ sequence: row.sequence, text: row.text_content, byteOffset: row.byte_offset }));
  }

  removeRecording(recordingId: string, ownerPrincipalFingerprint: string): void {
    this.getObject("quirt_recordings", recordingId, ownerPrincipalFingerprint);
    transaction(this.database, () => {
      this.database.prepare("DELETE FROM quirt_recordings WHERE recording_id=?").run(recordingId);
      this.database.prepare("INSERT INTO quirt_cleanup_records(cleanup_id,object_kind,object_id,outcome,data_json,created_at) VALUES(?,?,?,?,?,?)").run(randomUUID(), "recording", recordingId, "removed", "{}", this.now().toISOString());
    });
  }
}
