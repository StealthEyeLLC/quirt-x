import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { QuirtError } from "./error.js";
import type { PowerProviderDefinition, PowerProviderLifecycleState } from "./power-catalog.js";

export const QUIRT_POWER_SCHEMA_VERSION = 18 as const;

export interface QuirtProviderInstanceRecord {
  instanceId: string;
  providerId: string;
  providerVersion: string;
  ownerPrincipalFingerprint: string;
  targetHost: string;
  state: PowerProviderLifecycleState;
  configuration: Readonly<Record<string, unknown>>;
  credentialReferences: readonly string[];
  processIdentities: readonly Readonly<Record<string, unknown>>[];
  ports: readonly Readonly<Record<string, unknown>>[];
  paths: readonly string[];
  relatedSessions: readonly string[];
  relatedJobs: readonly string[];
  relatedArtifacts: readonly string[];
  relatedTransfers: readonly string[];
  health: Readonly<Record<string, unknown>>;
  failureClassification: string | null;
  recoveryClassification: string | null;
  cleanupStatus: string;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
  lastProbeAt: string | null;
}

export interface QuirtProviderEventRecord {
  instanceId: string;
  sequence: number;
  eventType: string;
  payload: Readonly<Record<string, unknown>>;
  truncated: boolean;
  createdAt: string;
}

interface InstanceRow {
  instance_id: string;
  provider_id: string;
  provider_version: string;
  owner_principal_fingerprint: string;
  target_host: string;
  lifecycle_state: string;
  configuration_json: string;
  credential_references_json: string;
  process_identities_json: string;
  ports_json: string;
  paths_json: string;
  related_sessions_json: string;
  related_jobs_json: string;
  related_artifacts_json: string;
  related_transfers_json: string;
  health_json: string;
  failure_classification: string | null;
  recovery_classification: string | null;
  cleanup_status: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  last_probe_at: string | null;
}

function parseObject(value: string, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return Object.freeze(parsed as Record<string, unknown>);
  } catch {
    throw new QuirtError("internal_error", `Stored ${label} is invalid`);
  }
}

function parseArray(value: string, label: string): readonly unknown[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) throw new Error("not an array");
    return Object.freeze(parsed);
  } catch {
    throw new QuirtError("internal_error", `Stored ${label} is invalid`);
  }
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
  if (current !== version - 1) throw new QuirtError("configuration_error", "Quirt power-provider migration order is invalid");
  transaction(database, () => {
    database.exec(sql);
    database.prepare("INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(?,?)").run(version, now().toISOString());
  });
}

export function migrateQuirtPowerState(database: DatabaseSync, now: () => Date): void {
  migration(database, 13, now, `
    CREATE TABLE IF NOT EXISTS quirt_provider_definitions(
      provider_id TEXT NOT NULL, provider_version TEXT NOT NULL, title TEXT NOT NULL,
      descriptor_json TEXT NOT NULL, registered_at TEXT NOT NULL,
      PRIMARY KEY(provider_id,provider_version)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_instances(
      instance_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, provider_version TEXT NOT NULL,
      owner_principal_fingerprint TEXT NOT NULL, target_host TEXT NOT NULL,
      lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN ('creating','starting','ready','degraded','stopping','stopped','failed','lost','unavailable','unknown')),
      configuration_json TEXT NOT NULL, credential_references_json TEXT NOT NULL,
      process_identities_json TEXT NOT NULL, ports_json TEXT NOT NULL, paths_json TEXT NOT NULL,
      related_sessions_json TEXT NOT NULL, related_jobs_json TEXT NOT NULL,
      related_artifacts_json TEXT NOT NULL, related_transfers_json TEXT NOT NULL,
      health_json TEXT NOT NULL, failure_classification TEXT, recovery_classification TEXT,
      cleanup_status TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_probe_at TEXT,
      FOREIGN KEY(provider_id,provider_version) REFERENCES quirt_provider_definitions(provider_id,provider_version)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_events(
      instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL, event_type TEXT NOT NULL, payload_json TEXT NOT NULL,
      truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0,1)), created_at TEXT NOT NULL,
      PRIMARY KEY(instance_id,sequence)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_requests(
      owner_principal_fingerprint TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
      request_hash TEXT NOT NULL, instance_id TEXT, state TEXT NOT NULL CHECK(state IN ('reserved','completed','failed')),
      result_json TEXT, error_code TEXT, created_at TEXT NOT NULL, completed_at TEXT,
      PRIMARY KEY(owner_principal_fingerprint,operation,idempotency_key),
      FOREIGN KEY(instance_id) REFERENCES quirt_provider_instances(instance_id)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_processes(
      process_record_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE,
      pid INTEGER NOT NULL, start_time_ticks INTEGER NOT NULL, boot_id TEXT NOT NULL,
      executable_path TEXT NOT NULL, executable_device INTEGER, executable_inode INTEGER,
      state TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_ports(
      port_record_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE,
      protocol TEXT NOT NULL, bind_address TEXT NOT NULL, port INTEGER NOT NULL,
      listener_identity_json TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      UNIQUE(protocol,bind_address,port)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_credentials(
      instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE,
      reference_name TEXT NOT NULL, reference_value TEXT NOT NULL, created_at TEXT NOT NULL,
      PRIMARY KEY(instance_id,reference_name)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_health(
      instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL, classification TEXT NOT NULL, details_json TEXT NOT NULL, probed_at TEXT NOT NULL,
      PRIMARY KEY(instance_id,sequence)
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_recovery(
      recovery_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE,
      classification TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS quirt_provider_cleanup(
      cleanup_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, classification TEXT NOT NULL,
      details_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
  `);
  migration(database, 14, now, `
    CREATE TABLE IF NOT EXISTS quirt_pane_topology(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, session_id TEXT, window_id TEXT, pane_id TEXT, topology_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_ide_instances(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, workspace_path TEXT NOT NULL, repository_path TEXT, route_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_previews(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, preview_kind TEXT NOT NULL, readiness_json TEXT NOT NULL, route_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_browsers(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, engine TEXT NOT NULL, user_data_path TEXT NOT NULL, state_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_browser_contexts(context_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_browser_pages(page_id TEXT PRIMARY KEY, context_id TEXT NOT NULL REFERENCES quirt_browser_contexts(context_id) ON DELETE CASCADE, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_browser_events(instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, sequence INTEGER NOT NULL, event_type TEXT NOT NULL, page_id TEXT, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(instance_id,sequence));
  `);
  migration(database, 15, now, `
    CREATE TABLE IF NOT EXISTS quirt_sync_folders(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, folder_path TEXT NOT NULL, folder_identity_json TEXT NOT NULL, state_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_sync_events(instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, sequence INTEGER NOT NULL, event_type TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(instance_id,sequence));
    CREATE TABLE IF NOT EXISTS quirt_sync_conflicts(conflict_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, path TEXT NOT NULL, details_json TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_remote_operations(operation_id TEXT PRIMARY KEY, instance_id TEXT REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, operation TEXT NOT NULL, state TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_remote_mounts(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, local_path TEXT NOT NULL, remote_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_snapshot_repositories(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, repository_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_snapshots(snapshot_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, immutable_identity TEXT NOT NULL, manifest_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_restore_operations(restore_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, snapshot_id TEXT NOT NULL REFERENCES quirt_snapshots(snapshot_id), destination TEXT NOT NULL, conflict_policy TEXT NOT NULL, state TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  `);
  migration(database, 16, now, `
    CREATE TABLE IF NOT EXISTS quirt_tunnels(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, tunnel_type TEXT NOT NULL, local_endpoint_json TEXT NOT NULL, remote_endpoint_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_trace_sessions(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, trace_type TEXT NOT NULL, target_identity_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_trace_events(instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, sequence INTEGER NOT NULL, payload BLOB NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(instance_id,sequence));
    CREATE TABLE IF NOT EXISTS quirt_trace_exports(export_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, path TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_checkpoint_manifests(checkpoint_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, process_identity_json TEXT NOT NULL, namespace_json TEXT NOT NULL, cgroup_json TEXT NOT NULL, manifest_json TEXT NOT NULL, integrity_sha256 TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  `);
  migration(database, 17, now, `
    CREATE TABLE IF NOT EXISTS quirt_desktop_sessions(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, display_identity TEXT NOT NULL, listener_json TEXT NOT NULL, resource_limits_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_fleet_inventories(instance_id TEXT PRIMARY KEY REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, inventory_identity TEXT NOT NULL, targets_json TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_fleet_runs(run_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES quirt_provider_instances(instance_id) ON DELETE CASCADE, operation TEXT NOT NULL, state TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS quirt_fleet_outcomes(run_id TEXT NOT NULL REFERENCES quirt_fleet_runs(run_id) ON DELETE CASCADE, target_identity TEXT NOT NULL, outcome TEXT NOT NULL, output_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(run_id,target_identity));
    CREATE TABLE IF NOT EXISTS quirt_network_diagnostics(operation_id TEXT PRIMARY KEY, owner_principal_fingerprint TEXT NOT NULL, operation TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL);
  `);
  migration(database, 18, now, `
    CREATE INDEX IF NOT EXISTS quirt_provider_instances_owner ON quirt_provider_instances(owner_principal_fingerprint,provider_id,created_at,instance_id);
    CREATE INDEX IF NOT EXISTS quirt_provider_instances_expiry ON quirt_provider_instances(expires_at,instance_id);
    CREATE INDEX IF NOT EXISTS quirt_provider_events_page ON quirt_provider_events(instance_id,sequence);
    CREATE INDEX IF NOT EXISTS quirt_provider_processes_instance ON quirt_provider_processes(instance_id,state);
    CREATE INDEX IF NOT EXISTS quirt_provider_health_instance ON quirt_provider_health(instance_id,sequence);
    CREATE INDEX IF NOT EXISTS quirt_browser_events_page ON quirt_browser_events(instance_id,sequence);
    CREATE INDEX IF NOT EXISTS quirt_sync_events_page ON quirt_sync_events(instance_id,sequence);
    CREATE INDEX IF NOT EXISTS quirt_trace_events_page ON quirt_trace_events(instance_id,sequence);
    CREATE INDEX IF NOT EXISTS quirt_fleet_runs_instance ON quirt_fleet_runs(instance_id,created_at);
  `);
}

function instance(row: InstanceRow): QuirtProviderInstanceRecord {
  return Object.freeze({
    instanceId: row.instance_id,
    providerId: row.provider_id,
    providerVersion: row.provider_version,
    ownerPrincipalFingerprint: row.owner_principal_fingerprint,
    targetHost: row.target_host,
    state: row.lifecycle_state as PowerProviderLifecycleState,
    configuration: parseObject(row.configuration_json, "provider configuration"),
    credentialReferences: parseArray(row.credential_references_json, "provider credential references") as readonly string[],
    processIdentities: parseArray(row.process_identities_json, "provider process identities") as readonly Readonly<Record<string, unknown>>[],
    ports: parseArray(row.ports_json, "provider ports") as readonly Readonly<Record<string, unknown>>[],
    paths: parseArray(row.paths_json, "provider paths") as readonly string[],
    relatedSessions: parseArray(row.related_sessions_json, "related sessions") as readonly string[],
    relatedJobs: parseArray(row.related_jobs_json, "related jobs") as readonly string[],
    relatedArtifacts: parseArray(row.related_artifacts_json, "related artifacts") as readonly string[],
    relatedTransfers: parseArray(row.related_transfers_json, "related transfers") as readonly string[],
    health: parseObject(row.health_json, "provider health"),
    failureClassification: row.failure_classification,
    recoveryClassification: row.recovery_classification,
    cleanupStatus: row.cleanup_status,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastProbeAt: row.last_probe_at
  });
}

export class QuirtPowerStateStore {
  constructor(private readonly database: DatabaseSync, private readonly now: () => Date) {}

  transaction<T>(action: () => T): T { return transaction(this.database, action); }

  registerDefinition(definition: PowerProviderDefinition): void {
    const at = this.now().toISOString();
    const descriptor = JSON.stringify(definition);
    const existing = this.database.prepare("SELECT descriptor_json FROM quirt_provider_definitions WHERE provider_id=? AND provider_version=?").get(definition.providerId, definition.providerVersion) as { descriptor_json: string } | undefined;
    if (existing !== undefined && existing.descriptor_json !== descriptor) throw new QuirtError("configuration_error", "Power provider definition changed without a version change");
    this.database.prepare("INSERT OR IGNORE INTO quirt_provider_definitions(provider_id,provider_version,title,descriptor_json,registered_at) VALUES(?,?,?,?,?)").run(definition.providerId, definition.providerVersion, definition.title, descriptor, at);
  }

  definitions(): Array<{ providerId: string; providerVersion: string; title: string; descriptor: Readonly<Record<string, unknown>>; registeredAt: string }> {
    const rows = this.database.prepare("SELECT * FROM quirt_provider_definitions ORDER BY provider_id,provider_version").all() as unknown as Array<{ provider_id: string; provider_version: string; title: string; descriptor_json: string; registered_at: string }>;
    return rows.map(row => ({ providerId: row.provider_id, providerVersion: row.provider_version, title: row.title, descriptor: parseObject(row.descriptor_json, "provider descriptor"), registeredAt: row.registered_at }));
  }

  putInstance(input: {
    instanceId?: string;
    providerId: string;
    providerVersion: string;
    ownerPrincipalFingerprint: string;
    targetHost: string;
    state: PowerProviderLifecycleState;
    configuration?: Readonly<Record<string, unknown>>;
    credentialReferences?: readonly string[];
    processIdentities?: readonly Readonly<Record<string, unknown>>[];
    ports?: readonly Readonly<Record<string, unknown>>[];
    paths?: readonly string[];
    relatedSessions?: readonly string[];
    relatedJobs?: readonly string[];
    relatedArtifacts?: readonly string[];
    relatedTransfers?: readonly string[];
    health?: Readonly<Record<string, unknown>>;
    failureClassification?: string | null;
    recoveryClassification?: string | null;
    cleanupStatus?: string;
    expiresAt?: string | null;
    lastProbeAt?: string | null;
  }): QuirtProviderInstanceRecord {
    const instanceId = input.instanceId ?? randomUUID();
    const existing = this.database.prepare("SELECT owner_principal_fingerprint,target_host,provider_id,provider_version,created_at FROM quirt_provider_instances WHERE instance_id=?").get(instanceId) as { owner_principal_fingerprint: string; target_host: string; provider_id: string; provider_version: string; created_at: string } | undefined;
    if (existing !== undefined && (existing.owner_principal_fingerprint !== input.ownerPrincipalFingerprint || existing.target_host !== input.targetHost || existing.provider_id !== input.providerId || existing.provider_version !== input.providerVersion)) throw new QuirtError("authorization_failed", "Power provider instance authority does not match");
    const at = this.now().toISOString();
    this.database.prepare(`INSERT INTO quirt_provider_instances(
      instance_id,provider_id,provider_version,owner_principal_fingerprint,target_host,lifecycle_state,
      configuration_json,credential_references_json,process_identities_json,ports_json,paths_json,
      related_sessions_json,related_jobs_json,related_artifacts_json,related_transfers_json,health_json,
      failure_classification,recovery_classification,cleanup_status,expires_at,created_at,updated_at,last_probe_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(instance_id) DO UPDATE SET lifecycle_state=excluded.lifecycle_state,configuration_json=excluded.configuration_json,
      credential_references_json=excluded.credential_references_json,process_identities_json=excluded.process_identities_json,
      ports_json=excluded.ports_json,paths_json=excluded.paths_json,related_sessions_json=excluded.related_sessions_json,
      related_jobs_json=excluded.related_jobs_json,related_artifacts_json=excluded.related_artifacts_json,
      related_transfers_json=excluded.related_transfers_json,health_json=excluded.health_json,
      failure_classification=excluded.failure_classification,recovery_classification=excluded.recovery_classification,
      cleanup_status=excluded.cleanup_status,expires_at=excluded.expires_at,updated_at=excluded.updated_at,last_probe_at=excluded.last_probe_at`).run(
      instanceId,input.providerId,input.providerVersion,input.ownerPrincipalFingerprint,input.targetHost,input.state,
      JSON.stringify(input.configuration ?? {}),JSON.stringify(input.credentialReferences ?? []),JSON.stringify(input.processIdentities ?? []),
      JSON.stringify(input.ports ?? []),JSON.stringify(input.paths ?? []),JSON.stringify(input.relatedSessions ?? []),
      JSON.stringify(input.relatedJobs ?? []),JSON.stringify(input.relatedArtifacts ?? []),JSON.stringify(input.relatedTransfers ?? []),
      JSON.stringify(input.health ?? {}),input.failureClassification ?? null,input.recoveryClassification ?? null,
      input.cleanupStatus ?? "pending",input.expiresAt ?? null,existing?.created_at ?? at,at,input.lastProbeAt ?? null
    );
    return this.getInstance(instanceId, input.ownerPrincipalFingerprint, input.targetHost);
  }

  getInstance(instanceId: string, ownerPrincipalFingerprint?: string, targetHost?: string): QuirtProviderInstanceRecord {
    const row = this.database.prepare("SELECT * FROM quirt_provider_instances WHERE instance_id=?").get(instanceId) as unknown as InstanceRow | undefined;
    if (row === undefined) throw new QuirtError("not_found", "Power provider instance was not found");
    if (ownerPrincipalFingerprint !== undefined && row.owner_principal_fingerprint !== ownerPrincipalFingerprint) throw new QuirtError("authorization_failed", "Power provider instance principal does not match");
    if (targetHost !== undefined && row.target_host !== targetHost) throw new QuirtError("authorization_failed", "Power provider instance target host does not match");
    return instance(row);
  }

  listInstances(ownerPrincipalFingerprint: string, input: { providerId?: string; maximum?: number; afterCreatedAt?: string; afterInstanceId?: string } = {}): { instances: QuirtProviderInstanceRecord[]; truncated: boolean; next: { createdAt: string; instanceId: string } | null } {
    const maximum = input.maximum ?? 100;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1000 || (input.afterCreatedAt === undefined) !== (input.afterInstanceId === undefined)) throw new QuirtError("invalid_request", "Power provider instance page is invalid");
    const provider = input.providerId === undefined ? "" : " AND provider_id=?";
    const cursor = input.afterCreatedAt === undefined ? "" : " AND (created_at>? OR (created_at=? AND instance_id>?))";
    const args: Array<string | number> = [ownerPrincipalFingerprint];
    if (input.providerId !== undefined) args.push(input.providerId);
    if (input.afterCreatedAt !== undefined) args.push(input.afterCreatedAt,input.afterCreatedAt,input.afterInstanceId!);
    args.push(maximum + 1);
    const rows = this.database.prepare(`SELECT * FROM quirt_provider_instances WHERE owner_principal_fingerprint=?${provider}${cursor} ORDER BY created_at,instance_id LIMIT ?`).all(...args) as unknown as InstanceRow[];
    const truncated = rows.length > maximum;
    const instances = rows.slice(0, maximum).map(instance);
    const last = instances.at(-1);
    return { instances, truncated, next: truncated && last !== undefined ? { createdAt: last.createdAt, instanceId: last.instanceId } : null };
  }

  appendEvent(instanceId: string, eventType: string, payload: Readonly<Record<string, unknown>>, truncated = false): QuirtProviderEventRecord {
    return transaction(this.database, () => {
      this.getInstance(instanceId);
      const sequence = Number((this.database.prepare("SELECT COALESCE(MAX(sequence),-1)+1 AS sequence FROM quirt_provider_events WHERE instance_id=?").get(instanceId) as { sequence: number }).sequence);
      const at = this.now().toISOString();
      this.database.prepare("INSERT INTO quirt_provider_events(instance_id,sequence,event_type,payload_json,truncated,created_at) VALUES(?,?,?,?,?,?)").run(instanceId,sequence,eventType,JSON.stringify(payload),truncated?1:0,at);
      return Object.freeze({ instanceId, sequence, eventType, payload: Object.freeze({ ...payload }), truncated, createdAt: at });
    });
  }

  readEvents(instanceId: string, ownerPrincipalFingerprint: string, targetHost: string, after: number, maximum: number): { events: QuirtProviderEventRecord[]; nextSequence: number; truncated: boolean } {
    this.getInstance(instanceId, ownerPrincipalFingerprint, targetHost);
    if (!Number.isSafeInteger(after) || after < -1 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1000) throw new QuirtError("invalid_request", "Power provider event page is invalid");
    const rows = this.database.prepare("SELECT * FROM quirt_provider_events WHERE instance_id=? AND sequence>? ORDER BY sequence LIMIT ?").all(instanceId,after,maximum+1) as unknown as Array<{ instance_id: string; sequence: number; event_type: string; payload_json: string; truncated: number; created_at: string }>;
    const truncated = rows.length > maximum;
    const events = rows.slice(0,maximum).map(row => Object.freeze({ instanceId: row.instance_id, sequence: row.sequence, eventType: row.event_type, payload: parseObject(row.payload_json,"provider event"), truncated: row.truncated===1, createdAt: row.created_at }));
    return { events, nextSequence: events.at(-1)?.sequence ?? after, truncated };
  }

  reserveRequest(input: { ownerPrincipalFingerprint: string; operation: string; idempotencyKey: string; requestHash: string; instanceId?: string }): { replay: boolean; result: Readonly<Record<string, unknown>> | null } {
    const existing = this.database.prepare("SELECT request_hash,state,result_json FROM quirt_provider_requests WHERE owner_principal_fingerprint=? AND operation=? AND idempotency_key=?").get(input.ownerPrincipalFingerprint,input.operation,input.idempotencyKey) as { request_hash: string; state: string; result_json: string | null } | undefined;
    if (existing !== undefined) {
      if (existing.request_hash !== input.requestHash) throw new QuirtError("idempotency_conflict", "Power provider idempotency key conflicts with a different request");
      if (existing.state === "completed" && existing.result_json !== null) return { replay: true, result: parseObject(existing.result_json,"provider result") };
      throw new QuirtError("duplicate_request", "Power provider request is already in progress", true);
    }
    this.database.prepare("INSERT INTO quirt_provider_requests(owner_principal_fingerprint,operation,idempotency_key,request_hash,instance_id,state,created_at) VALUES(?,?,?,?,?,'reserved',?)").run(input.ownerPrincipalFingerprint,input.operation,input.idempotencyKey,input.requestHash,input.instanceId??null,this.now().toISOString());
    return { replay: false, result: null };
  }

  completeRequest(input: { ownerPrincipalFingerprint: string; operation: string; idempotencyKey: string; result: Readonly<Record<string, unknown>>; instanceId?: string }): void {
    const result = this.database.prepare("UPDATE quirt_provider_requests SET state='completed',result_json=?,instance_id=COALESCE(?,instance_id),completed_at=? WHERE owner_principal_fingerprint=? AND operation=? AND idempotency_key=? AND state='reserved'").run(JSON.stringify(input.result),input.instanceId??null,this.now().toISOString(),input.ownerPrincipalFingerprint,input.operation,input.idempotencyKey);
    if (Number(result.changes)!==1) throw new QuirtError("internal_error","Power provider request completion was not durable");
  }

  failRequest(input: { ownerPrincipalFingerprint: string; operation: string; idempotencyKey: string; errorCode: string }): void {
    this.database.prepare("UPDATE quirt_provider_requests SET state='failed',error_code=?,completed_at=? WHERE owner_principal_fingerprint=? AND operation=? AND idempotency_key=? AND state='reserved'").run(input.errorCode,this.now().toISOString(),input.ownerPrincipalFingerprint,input.operation,input.idempotencyKey);
  }

  recordProcess(instanceId: string, identity: Readonly<Record<string, unknown>>, state = "running"): void {
    const pid=identity.pid,start=identity.startTimeTicks,boot=identity.bootId,path=identity.executablePath;
    if(typeof pid!=="number"||typeof start!=="number"||typeof boot!=="string"||typeof path!=="string") throw new QuirtError("internal_error","Provider process identity is incomplete");
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_provider_processes(process_record_id,instance_id,pid,start_time_ticks,boot_id,executable_path,executable_device,executable_inode,state,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").run(randomUUID(),instanceId,pid,start,boot,path,typeof identity.executableDevice==="number"?identity.executableDevice:null,typeof identity.executableInode==="number"?identity.executableInode:null,state,JSON.stringify(identity),at,at);
  }

  recordPort(instanceId: string, input: { protocol: string; bindAddress: string; port: number; listenerIdentity?: Readonly<Record<string, unknown>>; state?: string }): void {
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_provider_ports(port_record_id,instance_id,protocol,bind_address,port,listener_identity_json,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)").run(randomUUID(),instanceId,input.protocol,input.bindAddress,input.port,JSON.stringify(input.listenerIdentity??{}),input.state??"reserved",at,at);
  }

  recordCredentialReferences(instanceId: string, references: Readonly<Record<string,string>>): void {
    const at=this.now().toISOString();
    for(const [name,value] of Object.entries(references)) this.database.prepare("INSERT INTO quirt_provider_credentials(instance_id,reference_name,reference_value,created_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,reference_name) DO UPDATE SET reference_value=excluded.reference_value").run(instanceId,name,value,at);
  }

  credentialReferences(instanceId: string): Record<string,string> {
    const rows=this.database.prepare("SELECT reference_name,reference_value FROM quirt_provider_credentials WHERE instance_id=? ORDER BY reference_name").all(instanceId) as unknown as Array<{reference_name:string;reference_value:string}>;
    return Object.fromEntries(rows.map(row=>[row.reference_name,row.reference_value]));
  }

  recoverCandidates(): QuirtProviderInstanceRecord[] {
    const rows=this.database.prepare("SELECT * FROM quirt_provider_instances WHERE lifecycle_state IN ('creating','starting','ready','degraded','stopping') ORDER BY created_at,instance_id").all() as unknown as InstanceRow[];
    return rows.map(instance);
  }

  recordRecovery(instanceId: string, classification: string, details: Readonly<Record<string,unknown>>): void {
    this.database.prepare("INSERT INTO quirt_provider_recovery(recovery_id,instance_id,classification,details_json,created_at) VALUES(?,?,?,?,?)").run(randomUUID(),instanceId,classification,JSON.stringify(details),this.now().toISOString());
  }

  cleanupExpired(maximum=100): number {
    if(!Number.isSafeInteger(maximum)||maximum<1||maximum>1000) throw new QuirtError("invalid_request","Provider cleanup bound is invalid");
    return transaction(this.database,()=>{
      const rows=this.database.prepare("SELECT instance_id FROM quirt_provider_instances WHERE expires_at IS NOT NULL AND expires_at<=? AND lifecycle_state IN ('stopped','failed','lost','unavailable') ORDER BY expires_at,instance_id LIMIT ?").all(this.now().toISOString(),maximum) as unknown as Array<{instance_id:string}>;
      for(const row of rows){this.database.prepare("DELETE FROM quirt_provider_instances WHERE instance_id=?").run(row.instance_id);this.database.prepare("INSERT INTO quirt_provider_cleanup(cleanup_id,instance_id,classification,details_json,created_at) VALUES(?,?,?,?,?)").run(randomUUID(),row.instance_id,"expired","{}",this.now().toISOString());}
      return rows.length;
    });
  }

  recordPaneTopology(instanceId: string, input: { sessionId?: string | null; windowId?: string | null; paneId?: string | null; topology: Readonly<Record<string, unknown>> }): void {
    this.database.prepare("INSERT INTO quirt_pane_topology(instance_id,session_id,window_id,pane_id,topology_json,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET session_id=excluded.session_id,window_id=excluded.window_id,pane_id=excluded.pane_id,topology_json=excluded.topology_json,updated_at=excluded.updated_at").run(instanceId,input.sessionId??null,input.windowId??null,input.paneId??null,JSON.stringify(input.topology),this.now().toISOString());
  }

  recordIde(instanceId: string, input: { workspacePath: string; repositoryPath?: string | null; route: Readonly<Record<string, unknown>> }): void {
    this.database.prepare("INSERT INTO quirt_ide_instances(instance_id,workspace_path,repository_path,route_json,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET workspace_path=excluded.workspace_path,repository_path=excluded.repository_path,route_json=excluded.route_json,updated_at=excluded.updated_at").run(instanceId,input.workspacePath,input.repositoryPath??null,JSON.stringify(input.route),this.now().toISOString());
  }

  recordPreview(instanceId: string, input: { kind: string; readiness: Readonly<Record<string, unknown>>; route: Readonly<Record<string, unknown>> }): void {
    this.database.prepare("INSERT INTO quirt_previews(instance_id,preview_kind,readiness_json,route_json,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET preview_kind=excluded.preview_kind,readiness_json=excluded.readiness_json,route_json=excluded.route_json,updated_at=excluded.updated_at").run(instanceId,input.kind,JSON.stringify(input.readiness),JSON.stringify(input.route),this.now().toISOString());
  }

  recordBrowser(instanceId: string, input: { engine: string; userDataPath: string; state: Readonly<Record<string, unknown>> }): void {
    this.database.prepare("INSERT INTO quirt_browsers(instance_id,engine,user_data_path,state_json,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET engine=excluded.engine,user_data_path=excluded.user_data_path,state_json=excluded.state_json,updated_at=excluded.updated_at").run(instanceId,input.engine,input.userDataPath,JSON.stringify(input.state),this.now().toISOString());
  }

  recordBrowserContext(contextId: string, instanceId: string, data: Readonly<Record<string, unknown>>): void {
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_browser_contexts(context_id,instance_id,data_json,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(context_id) DO UPDATE SET data_json=excluded.data_json,updated_at=excluded.updated_at").run(contextId,instanceId,JSON.stringify(data),at,at);
  }

  recordBrowserPage(pageId: string, contextId: string, data: Readonly<Record<string, unknown>>): void {
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_browser_pages(page_id,context_id,data_json,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(page_id) DO UPDATE SET data_json=excluded.data_json,updated_at=excluded.updated_at").run(pageId,contextId,JSON.stringify(data),at,at);
  }

  removeBrowserPage(pageId: string): void { this.database.prepare("DELETE FROM quirt_browser_pages WHERE page_id=?").run(pageId); }

  appendBrowserEvent(instanceId: string, eventType: string, pageId: string | null, payload: Readonly<Record<string, unknown>>): number {
    const sequence=Number((this.database.prepare("SELECT COALESCE(MAX(sequence),-1)+1 AS sequence FROM quirt_browser_events WHERE instance_id=?").get(instanceId) as {sequence:number}).sequence);
    this.database.prepare("INSERT INTO quirt_browser_events(instance_id,sequence,event_type,page_id,payload_json,created_at) VALUES(?,?,?,?,?,?)").run(instanceId,sequence,eventType,pageId,JSON.stringify(payload),this.now().toISOString());
    this.appendEvent(instanceId,"browser."+eventType,{ pageId, ...payload });
    return sequence;
  }

  recordSyncFolder(instanceId: string, input: { folderPath: string; identity: Readonly<Record<string, unknown>>; state: Readonly<Record<string, unknown>> }): void {
    this.database.prepare("INSERT INTO quirt_sync_folders(instance_id,folder_path,folder_identity_json,state_json,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET folder_path=excluded.folder_path,folder_identity_json=excluded.folder_identity_json,state_json=excluded.state_json,updated_at=excluded.updated_at").run(instanceId,input.folderPath,JSON.stringify(input.identity),JSON.stringify(input.state),this.now().toISOString());
  }

  appendSyncEvent(instanceId: string, eventType: string, payload: Readonly<Record<string, unknown>>): number {
    const sequence=Number((this.database.prepare("SELECT COALESCE(MAX(sequence),-1)+1 AS sequence FROM quirt_sync_events WHERE instance_id=?").get(instanceId) as {sequence:number}).sequence);
    this.database.prepare("INSERT INTO quirt_sync_events(instance_id,sequence,event_type,payload_json,created_at) VALUES(?,?,?,?,?)").run(instanceId,sequence,eventType,JSON.stringify(payload),this.now().toISOString());
    this.appendEvent(instanceId,"sync."+eventType,payload);
    return sequence;
  }

  recordSyncConflict(instanceId: string, path: string, details: Readonly<Record<string, unknown>>, state="unresolved"): string {
    const conflictId=randomUUID(),at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_sync_conflicts(conflict_id,instance_id,path,details_json,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?)").run(conflictId,instanceId,path,JSON.stringify(details),state,at,at);
    this.appendSyncEvent(instanceId,"conflict",{ conflictId,path,state });
    return conflictId;
  }

  recordRemoteOperation(instanceId: string | null, operation: string, state: string, data: Readonly<Record<string, unknown>>, operationId: string=randomUUID()): string {
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_remote_operations(operation_id,instance_id,operation,state,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(operation_id) DO UPDATE SET state=excluded.state,data_json=excluded.data_json,updated_at=excluded.updated_at").run(operationId,instanceId,operation,state,JSON.stringify(data),at,at);
    return operationId;
  }

  recordRemoteMount(instanceId: string, localPath: string, remote: Readonly<Record<string, unknown>>, state: string): void {
    this.database.prepare("INSERT INTO quirt_remote_mounts(instance_id,local_path,remote_json,state,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET local_path=excluded.local_path,remote_json=excluded.remote_json,state=excluded.state,updated_at=excluded.updated_at").run(instanceId,localPath,JSON.stringify(remote),state,this.now().toISOString());
  }

  recordSnapshotRepository(instanceId: string, repository: Readonly<Record<string, unknown>>, state: string): void {
    this.database.prepare("INSERT INTO quirt_snapshot_repositories(instance_id,repository_json,state,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET repository_json=excluded.repository_json,state=excluded.state,updated_at=excluded.updated_at").run(instanceId,JSON.stringify(repository),state,this.now().toISOString());
  }

  recordSnapshot(instanceId: string, immutableIdentity: string, manifest: Readonly<Record<string, unknown>>, snapshotId=immutableIdentity): string {
    this.database.prepare("INSERT INTO quirt_snapshots(snapshot_id,instance_id,immutable_identity,manifest_json,created_at) VALUES(?,?,?,?,?) ON CONFLICT(snapshot_id) DO UPDATE SET manifest_json=excluded.manifest_json").run(snapshotId,instanceId,immutableIdentity,JSON.stringify(manifest),this.now().toISOString());
    return snapshotId;
  }

  snapshots(ownerPrincipalFingerprint: string, repositoryInstanceId?: string): Array<{ snapshotId: string; instanceId: string; immutableIdentity: string; manifest: Readonly<Record<string, unknown>>; createdAt: string }> {
    const rows=this.database.prepare(`SELECT s.* FROM quirt_snapshots s JOIN quirt_provider_instances i ON i.instance_id=s.instance_id WHERE i.owner_principal_fingerprint=?${repositoryInstanceId===undefined?"":" AND s.instance_id=?"} ORDER BY s.created_at,s.snapshot_id`).all(...(repositoryInstanceId===undefined?[ownerPrincipalFingerprint]:[ownerPrincipalFingerprint,repositoryInstanceId])) as unknown as Array<{snapshot_id:string;instance_id:string;immutable_identity:string;manifest_json:string;created_at:string}>;
    return rows.map(row=>({snapshotId:row.snapshot_id,instanceId:row.instance_id,immutableIdentity:row.immutable_identity,manifest:parseObject(row.manifest_json,"snapshot manifest"),createdAt:row.created_at}));
  }

  snapshot(snapshotId: string, ownerPrincipalFingerprint: string): { snapshotId: string; instanceId: string; immutableIdentity: string; manifest: Readonly<Record<string, unknown>>; createdAt: string } {
    const row=this.database.prepare("SELECT s.* FROM quirt_snapshots s JOIN quirt_provider_instances i ON i.instance_id=s.instance_id WHERE s.snapshot_id=? AND i.owner_principal_fingerprint=?").get(snapshotId,ownerPrincipalFingerprint) as {snapshot_id:string;instance_id:string;immutable_identity:string;manifest_json:string;created_at:string}|undefined;
    if(row===undefined) throw new QuirtError("not_found","Snapshot was not found");
    return {snapshotId:row.snapshot_id,instanceId:row.instance_id,immutableIdentity:row.immutable_identity,manifest:parseObject(row.manifest_json,"snapshot manifest"),createdAt:row.created_at};
  }

  removeSnapshot(snapshotId: string, ownerPrincipalFingerprint: string): void {
    this.snapshot(snapshotId,ownerPrincipalFingerprint);
    this.database.prepare("DELETE FROM quirt_snapshots WHERE snapshot_id=?").run(snapshotId);
  }

  recordRestore(instanceId: string, snapshotId: string, destination: string, conflictPolicy: string, state: string, data: Readonly<Record<string, unknown>>, restoreId: string=randomUUID()): string {
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_restore_operations(restore_id,instance_id,snapshot_id,destination,conflict_policy,state,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(restore_id) DO UPDATE SET state=excluded.state,data_json=excluded.data_json,updated_at=excluded.updated_at").run(restoreId,instanceId,snapshotId,destination,conflictPolicy,state,JSON.stringify(data),at,at);
    return restoreId;
  }

  recordTunnel(instanceId: string, input: { tunnelType: string; localEndpoint: Readonly<Record<string, unknown>>; remoteEndpoint: Readonly<Record<string, unknown>>; state: string }): void {
    this.database.prepare("INSERT INTO quirt_tunnels(instance_id,tunnel_type,local_endpoint_json,remote_endpoint_json,state,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET local_endpoint_json=excluded.local_endpoint_json,remote_endpoint_json=excluded.remote_endpoint_json,state=excluded.state,updated_at=excluded.updated_at").run(instanceId,input.tunnelType,JSON.stringify(input.localEndpoint),JSON.stringify(input.remoteEndpoint),input.state,this.now().toISOString());
  }

  recordTrace(instanceId: string, traceType: string, targetIdentity: Readonly<Record<string, unknown>>, state: string): void {
    this.database.prepare("INSERT INTO quirt_trace_sessions(instance_id,trace_type,target_identity_json,state,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET target_identity_json=excluded.target_identity_json,state=excluded.state,updated_at=excluded.updated_at").run(instanceId,traceType,JSON.stringify(targetIdentity),state,this.now().toISOString());
  }

  appendTraceEvent(instanceId: string, payload: Buffer, metadata: Readonly<Record<string, unknown>>): number {
    const sequence=Number((this.database.prepare("SELECT COALESCE(MAX(sequence),-1)+1 AS sequence FROM quirt_trace_events WHERE instance_id=?").get(instanceId) as {sequence:number}).sequence);
    this.database.prepare("INSERT INTO quirt_trace_events(instance_id,sequence,payload,metadata_json,created_at) VALUES(?,?,?,?,?)").run(instanceId,sequence,payload,JSON.stringify(metadata),this.now().toISOString());
    return sequence;
  }

  recordTraceExport(instanceId: string, path: string, sha256: string, sizeBytes: number, exportId: string=randomUUID()): string {
    this.database.prepare("INSERT INTO quirt_trace_exports(export_id,instance_id,path,sha256,size_bytes,created_at) VALUES(?,?,?,?,?,?)").run(exportId,instanceId,path,sha256,sizeBytes,this.now().toISOString());
    return exportId;
  }

  recordCheckpoint(instanceId: string, input: { processIdentity: Readonly<Record<string, unknown>>; namespaces: Readonly<Record<string, unknown>>; cgroup: Readonly<Record<string, unknown>>; manifest: Readonly<Record<string, unknown>>; integritySha256: string; state: string; checkpointId?: string }): string {
    const checkpointId=input.checkpointId??randomUUID(),at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_checkpoint_manifests(checkpoint_id,instance_id,process_identity_json,namespace_json,cgroup_json,manifest_json,integrity_sha256,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(checkpoint_id) DO UPDATE SET state=excluded.state,manifest_json=excluded.manifest_json,integrity_sha256=excluded.integrity_sha256,updated_at=excluded.updated_at").run(checkpointId,instanceId,JSON.stringify(input.processIdentity),JSON.stringify(input.namespaces),JSON.stringify(input.cgroup),JSON.stringify(input.manifest),input.integritySha256,input.state,at,at);
    return checkpointId;
  }

  recordDesktop(instanceId: string, displayIdentity: string, listener: Readonly<Record<string, unknown>>, resourceLimits: Readonly<Record<string, unknown>>, state: string): void {
    this.database.prepare("INSERT INTO quirt_desktop_sessions(instance_id,display_identity,listener_json,resource_limits_json,state,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET listener_json=excluded.listener_json,resource_limits_json=excluded.resource_limits_json,state=excluded.state,updated_at=excluded.updated_at").run(instanceId,displayIdentity,JSON.stringify(listener),JSON.stringify(resourceLimits),state,this.now().toISOString());
  }

  recordFleetInventory(instanceId: string, identity: string, targets: readonly Readonly<Record<string, unknown>>[]): void {
    this.database.prepare("INSERT INTO quirt_fleet_inventories(instance_id,inventory_identity,targets_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET targets_json=excluded.targets_json,updated_at=excluded.updated_at").run(instanceId,identity,JSON.stringify(targets),this.now().toISOString());
  }

  recordFleetRun(instanceId: string, operation: string, state: string, data: Readonly<Record<string, unknown>>, runId: string=randomUUID()): string {
    const at=this.now().toISOString();
    this.database.prepare("INSERT INTO quirt_fleet_runs(run_id,instance_id,operation,state,data_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET state=excluded.state,data_json=excluded.data_json,updated_at=excluded.updated_at").run(runId,instanceId,operation,state,JSON.stringify(data),at,at);
    return runId;
  }

  recordFleetOutcome(runId: string, targetIdentity: string, outcome: string, output: Readonly<Record<string, unknown>>): void {
    this.database.prepare("INSERT INTO quirt_fleet_outcomes(run_id,target_identity,outcome,output_json,created_at) VALUES(?,?,?,?,?) ON CONFLICT(run_id,target_identity) DO UPDATE SET outcome=excluded.outcome,output_json=excluded.output_json").run(runId,targetIdentity,outcome,JSON.stringify(output),this.now().toISOString());
  }

  recordNetworkDiagnostic(ownerPrincipalFingerprint: string, operation: string, result: Readonly<Record<string, unknown>>, operationId: string=randomUUID()): string {
    this.database.prepare("INSERT INTO quirt_network_diagnostics(operation_id,owner_principal_fingerprint,operation,result_json,created_at) VALUES(?,?,?,?,?)").run(operationId,ownerPrincipalFingerprint,operation,JSON.stringify(result),this.now().toISOString());
    return operationId;
  }

  foreignKeyCheck(): void {
    const rows=this.database.prepare("PRAGMA foreign_key_check").all();
    if(rows.length>0) throw new QuirtError("internal_error","Power provider foreign-key integrity check failed");
  }
}
