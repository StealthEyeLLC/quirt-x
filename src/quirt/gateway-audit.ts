import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export interface QuirtGatewayAuditStart {
  requestId: string;
  operation: string;
  principalFingerprint: string;
  targetHost: string;
  inputBytes: number;
}

export interface QuirtGatewayAuditFinish {
  outcome: "succeeded" | "failed";
  outputBytes?: number;
  replayed?: boolean;
  safeErrorCode?: string;
}

export class QuirtGatewayAuditStore {
  readonly #db: DatabaseSync;
  constructor(path: string) {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS quirt_gateway_audit(
        correlation_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, operation TEXT NOT NULL,
        principal_fingerprint TEXT NOT NULL, target_host TEXT NOT NULL, input_bytes INTEGER NOT NULL,
        output_bytes INTEGER, outcome TEXT, replayed INTEGER, safe_error_code TEXT,
        started_at TEXT NOT NULL, finished_at TEXT
      ) STRICT;
      CREATE INDEX IF NOT EXISTS quirt_gateway_audit_request ON quirt_gateway_audit(request_id,started_at);
    `);
  }
  begin(input: QuirtGatewayAuditStart): string {
    const correlationId = randomUUID();
    this.#db.prepare(`INSERT INTO quirt_gateway_audit(
      correlation_id,request_id,operation,principal_fingerprint,target_host,input_bytes,started_at
    ) VALUES(?,?,?,?,?,?,?)`).run(correlationId, input.requestId, input.operation, input.principalFingerprint, input.targetHost, input.inputBytes, new Date().toISOString());
    return correlationId;
  }
  finish(correlationId: string, value: QuirtGatewayAuditFinish): void {
    this.#db.prepare(`UPDATE quirt_gateway_audit SET output_bytes=?,outcome=?,replayed=?,safe_error_code=?,finished_at=?
      WHERE correlation_id=?`).run(value.outputBytes ?? null, value.outcome, value.replayed === undefined ? null : value.replayed ? 1 : 0, value.safeErrorCode?.slice(0, 64) ?? null, new Date().toISOString(), correlationId);
  }
  receipt(correlationId: string): Record<string, unknown> | null {
    const row = this.#db.prepare(`SELECT correlation_id,request_id,operation,principal_fingerprint,target_host,input_bytes,
      output_bytes,outcome,replayed,safe_error_code,started_at,finished_at FROM quirt_gateway_audit WHERE correlation_id=?`).get(correlationId) as Record<string, unknown> | undefined;
    return row ?? null;
  }
  latestForRequest(requestId: string): Record<string, unknown> | null {
    const row = this.#db.prepare(`SELECT correlation_id,request_id,operation,principal_fingerprint,target_host,input_bytes,
      output_bytes,outcome,replayed,safe_error_code,started_at,finished_at FROM quirt_gateway_audit WHERE request_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1`).get(requestId) as Record<string, unknown> | undefined;
    return row ?? null;
  }
  close(): void { this.#db.close(); }
}
