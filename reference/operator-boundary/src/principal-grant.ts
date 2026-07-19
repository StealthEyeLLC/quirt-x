import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { canonicalJson, sha256Hex, type Json } from "./canonical.js";
import { OperatorError } from "./errors.js";

export const JAMIE_CURRIER_GRANT_ID = "jamie-currier-v1" as const;
export const JAMIE_CURRIER_GRANT_VERSION = 1 as const;
export const JAMIE_CURRIER_OAUTH_SUBJECT = "stealtheye-owner" as const;
export const JAMIE_CURRIER_DISPLAY_NAME = "Jamie Currier" as const;
export const HORSEY_AUTHORITY_MODE = "allow-all" as const;
export const HORSEY_CONFIRMATION_MODE = "never-ask" as const;
export const HORSEY_CAPABILITY_SCOPE = "all-registered" as const;

export const HORSEY_AUTHORITY_TOOL_META = Object.freeze({
  "horsey/authorityMode": HORSEY_AUTHORITY_MODE,
  "horsey/confirmationMode": HORSEY_CONFIRMATION_MODE,
  "horsey/principalGrantVersion": JAMIE_CURRIER_GRANT_VERSION
});

export type HorseyPrincipalType = "user" | "service" | "admin";
export type HorseyGrantStatus = "active" | "revoked";
export type HorseyAuthorityDenial =
  | "global_paused"
  | "grant_not_found"
  | "grant_revoked"
  | "identity_mismatch"
  | "system_binding_mismatch"
  | "capability_not_registered";

export interface HorseySystemBinding {
  hostId: string;
  machineIdFingerprint: string;
  brokerIdentityFingerprint: string;
  brokerPolicyDigest: string;
  hostPolicyId: string;
  hostPolicyRequestHash: string;
}

export interface HorseyPrincipalIdentityInput {
  issuer: string;
  resource: string;
  subject: string;
  principalType?: HorseyPrincipalType;
  workspaceId?: string | null;
}

export interface HorseyPrincipalIdentity {
  principalType: HorseyPrincipalType;
  issuer: string;
  resource: string;
  principalFingerprint: string;
  subjectFingerprint: string;
  workspaceFingerprint: string | null;
}

export interface HorseyPrincipalGrant {
  grantId: typeof JAMIE_CURRIER_GRANT_ID;
  version: typeof JAMIE_CURRIER_GRANT_VERSION;
  displayName: typeof JAMIE_CURRIER_DISPLAY_NAME;
  principalType: HorseyPrincipalType;
  issuer: string;
  resource: string;
  principalFingerprint: string;
  subjectFingerprint: string;
  authorityMode: typeof HORSEY_AUTHORITY_MODE;
  confirmationMode: typeof HORSEY_CONFIRMATION_MODE;
  capabilityScope: typeof HORSEY_CAPABILITY_SCOPE;
  systemBinding: HorseySystemBinding;
  systemBindingDigest: string;
  status: HorseyGrantStatus;
  createdAt: string;
  updatedAt: string;
  revokedAt: string | null;
  requestHash: string;
}

export interface HorseyAuthorityResolution {
  allowed: boolean;
  denialReason: HorseyAuthorityDenial | null;
  grant: HorseyPrincipalGrant | null;
  principalFingerprint: string;
  capabilityId: string | null;
  confirmationMode: typeof HORSEY_CONFIRMATION_MODE | null;
}

export interface HorseyAuthorityStatus {
  grant: HorseyPrincipalGrant;
  globalPaused: boolean;
  globalRevision: number;
  effective: "active" | "paused" | "revoked" | "system-mismatch";
  registeredCapabilityCount: number;
  registeredCapabilityDigest: string;
}

export interface HorseyAuthorityEvent {
  eventId: string;
  grantId: string | null;
  eventType: string;
  principalFingerprint: string | null;
  capabilityId: string | null;
  allowed: boolean | null;
  reasonCode: string | null;
  systemBindingDigest: string | null;
  actorId: string | null;
  details: Json;
  occurredAt: string;
}

interface GrantRow {
  grant_id: string;
  version: number;
  display_name: string;
  principal_type: string;
  issuer: string;
  resource: string;
  principal_fingerprint: string;
  subject_fingerprint: string;
  authority_mode: string;
  confirmation_mode: string;
  capability_scope: string;
  system_binding_json: string;
  system_binding_digest: string;
  status: string;
  created_at: string;
  updated_at: string;
  revoked_at: string | null;
  request_hash: string;
}

interface EventRow {
  event_id: string;
  grant_id: string | null;
  event_type: string;
  principal_fingerprint: string | null;
  capability_id: string | null;
  allowed: number | null;
  reason_code: string | null;
  system_binding_digest: string | null;
  actor_id: string | null;
  details_json: string;
  occurred_at: string;
}

const SHA256 = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u;

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function bounded(value: string, label: string, maximum: number): string {
  if (value.length < 1 || Buffer.byteLength(value, "utf8") > maximum || /[\0\r\n]/u.test(value)) {
    throw new OperatorError("INVALID_ARGUMENT", `${label} is invalid`);
  }
  return value;
}

function exactHttps(value: string, label: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new OperatorError("INVALID_ARGUMENT", `${label} is invalid`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new OperatorError("INVALID_ARGUMENT", `${label} is invalid`);
  }
  return value;
}

function validateBinding(value: HorseySystemBinding): HorseySystemBinding {
  if (!IDENTIFIER.test(value.hostId) || !IDENTIFIER.test(value.hostPolicyId)) {
    throw new OperatorError("INVALID_ARGUMENT", "Horsey system identity is invalid");
  }
  for (const fingerprint of [value.machineIdFingerprint, value.brokerIdentityFingerprint, value.brokerPolicyDigest, value.hostPolicyRequestHash]) {
    if (!SHA256.test(fingerprint) || fingerprint === "0".repeat(64)) {
      throw new OperatorError("INVALID_ARGUMENT", "Horsey system fingerprint is invalid");
    }
  }
  return Object.freeze({ ...value });
}

function bindingJson(value: HorseySystemBinding): Json {
  return {
    brokerIdentityFingerprint: value.brokerIdentityFingerprint,
    brokerPolicyDigest: value.brokerPolicyDigest,
    hostId: value.hostId,
    hostPolicyId: value.hostPolicyId,
    hostPolicyRequestHash: value.hostPolicyRequestHash,
    machineIdFingerprint: value.machineIdFingerprint
  };
}

export function horseySystemBindingDigest(value: HorseySystemBinding): string {
  return sha256Hex(canonicalJson(bindingJson(validateBinding(value))));
}

export function horseyPrincipalIdentity(input: HorseyPrincipalIdentityInput): HorseyPrincipalIdentity {
  const principalType = input.principalType ?? "user";
  if (principalType !== "user" && principalType !== "service" && principalType !== "admin") {
    throw new OperatorError("AUTHENTICATION_FAILED", "OAuth principal type is invalid");
  }
  const issuer = exactHttps(bounded(input.issuer, "OAuth issuer", 2048), "OAuth issuer");
  const resource = exactHttps(bounded(input.resource, "OAuth resource", 2048), "OAuth resource");
  const subject = bounded(input.subject, "OAuth subject", 256);
  const workspaceId = input.workspaceId ?? null;
  if (workspaceId !== null) bounded(workspaceId, "OAuth workspace", 256);
  return Object.freeze({
    principalType,
    issuer,
    resource,
    principalFingerprint: digest(`${principalType}\u0000${issuer}\u0000${subject}\u0000${workspaceId ?? ""}`),
    subjectFingerprint: digest(`${issuer}\u0000${subject}`),
    workspaceFingerprint: workspaceId === null ? null : digest(`${issuer}\u0000${workspaceId}`)
  });
}

function capabilityRegistry(values: readonly string[]): { values: string[]; digest: string } {
  const normalized = [...new Set(values)].sort();
  if (normalized.length < 1 || normalized.some(value => !/^[a-z][a-z0-9.-]{2,127}$/u.test(value))) {
    throw new OperatorError("CONFIGURATION_ERROR", "Horsey capability registry is invalid");
  }
  return { values: normalized, digest: sha256Hex(canonicalJson(normalized)) };
}

function grantFromRow(row: GrantRow): HorseyPrincipalGrant {
  let binding: HorseySystemBinding;
  try { binding = validateBinding(JSON.parse(row.system_binding_json) as HorseySystemBinding); }
  catch { throw new OperatorError("CONFIGURATION_ERROR", "Stored Horsey authority is invalid"); }
  const value: HorseyPrincipalGrant = {
    grantId: row.grant_id as typeof JAMIE_CURRIER_GRANT_ID,
    version: row.version as typeof JAMIE_CURRIER_GRANT_VERSION,
    displayName: row.display_name as typeof JAMIE_CURRIER_DISPLAY_NAME,
    principalType: row.principal_type as HorseyPrincipalType,
    issuer: row.issuer,
    resource: row.resource,
    principalFingerprint: row.principal_fingerprint,
    subjectFingerprint: row.subject_fingerprint,
    authorityMode: row.authority_mode as typeof HORSEY_AUTHORITY_MODE,
    confirmationMode: row.confirmation_mode as typeof HORSEY_CONFIRMATION_MODE,
    capabilityScope: row.capability_scope as typeof HORSEY_CAPABILITY_SCOPE,
    systemBinding: binding,
    systemBindingDigest: row.system_binding_digest,
    status: row.status as HorseyGrantStatus,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    revokedAt: row.revoked_at,
    requestHash: row.request_hash
  };
  const valid = value.grantId === JAMIE_CURRIER_GRANT_ID
    && value.version === JAMIE_CURRIER_GRANT_VERSION
    && value.displayName === JAMIE_CURRIER_DISPLAY_NAME
    && value.principalType === "user"
    && value.authorityMode === HORSEY_AUTHORITY_MODE
    && value.confirmationMode === HORSEY_CONFIRMATION_MODE
    && value.capabilityScope === HORSEY_CAPABILITY_SCOPE
    && (value.status === "active" || value.status === "revoked")
    && SHA256.test(value.principalFingerprint)
    && SHA256.test(value.subjectFingerprint)
    && SHA256.test(value.systemBindingDigest)
    && value.systemBindingDigest === horseySystemBindingDigest(binding);
  if (!valid) throw new OperatorError("CONFIGURATION_ERROR", "Stored Horsey authority is invalid");
  return Object.freeze(value);
}

export class HorseyPrincipalGrantStore {
  readonly #db: DatabaseSync;
  readonly #now: () => Date;
  readonly #id: () => string;

  constructor(path: string, options: { now?: () => Date; id?: () => string } = {}) {
    this.#db = new DatabaseSync(path);
    this.#now = options.now ?? (() => new Date());
    this.#id = options.id ?? randomUUID;
    this.#migrate();
  }

  #migrate(): void {
    this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS horsey_principal_grants(
        grant_id TEXT PRIMARY KEY, version INTEGER NOT NULL, display_name TEXT NOT NULL,
        principal_type TEXT NOT NULL CHECK(principal_type IN ('user','service','admin')),
        issuer TEXT NOT NULL, resource TEXT NOT NULL, principal_fingerprint TEXT NOT NULL UNIQUE,
        subject_fingerprint TEXT NOT NULL, authority_mode TEXT NOT NULL CHECK(authority_mode='allow-all'),
        confirmation_mode TEXT NOT NULL CHECK(confirmation_mode='never-ask'),
        capability_scope TEXT NOT NULL CHECK(capability_scope='all-registered'),
        system_binding_json TEXT NOT NULL, system_binding_digest TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active','revoked')), created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL, revoked_at TEXT, request_hash TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS horsey_authority_control(
        control_id INTEGER PRIMARY KEY CHECK(control_id=1), paused INTEGER NOT NULL CHECK(paused IN (0,1)),
        revision INTEGER NOT NULL CHECK(revision>=1), updated_at TEXT NOT NULL, updated_by TEXT NOT NULL, reason TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS horsey_authority_events(
        event_id TEXT PRIMARY KEY, grant_id TEXT, event_type TEXT NOT NULL,
        principal_fingerprint TEXT, capability_id TEXT, allowed INTEGER CHECK(allowed IS NULL OR allowed IN (0,1)),
        reason_code TEXT, system_binding_digest TEXT, actor_id TEXT, details_json TEXT NOT NULL, occurred_at TEXT NOT NULL
      ) STRICT;
      CREATE INDEX IF NOT EXISTS horsey_authority_events_time_idx ON horsey_authority_events(occurred_at DESC,event_id);
      CREATE INDEX IF NOT EXISTS horsey_authority_events_principal_idx ON horsey_authority_events(principal_fingerprint,occurred_at DESC);`);
    this.#db.prepare(`INSERT OR IGNORE INTO horsey_authority_control(control_id,paused,revision,updated_at,updated_by,reason)
      VALUES(1,0,1,?,'standing-authority-v1','initial')`).run(this.#now().toISOString());
  }

  #transaction<T>(action: () => T): T {
    this.#db.exec("BEGIN IMMEDIATE");
    try { const value = action(); this.#db.exec("COMMIT"); return value; }
    catch (error) { try { this.#db.exec("ROLLBACK"); } catch {} throw error; }
  }

  #event(input: {
    grantId?: string | null;
    eventType: string;
    principalFingerprint?: string | null;
    capabilityId?: string | null;
    allowed?: boolean | null;
    reasonCode?: string | null;
    systemBindingDigest?: string | null;
    actorId?: string | null;
    details?: Json;
  }): void {
    this.#db.prepare(`INSERT INTO horsey_authority_events(
      event_id,grant_id,event_type,principal_fingerprint,capability_id,allowed,reason_code,system_binding_digest,actor_id,details_json,occurred_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(
      this.#id(), input.grantId ?? null, bounded(input.eventType, "Authority event type", 128),
      input.principalFingerprint ?? null, input.capabilityId ?? null,
      input.allowed === undefined || input.allowed === null ? null : input.allowed ? 1 : 0,
      input.reasonCode ?? null, input.systemBindingDigest ?? null, input.actorId === undefined || input.actorId === null ? null : bounded(input.actorId, "Authority actor", 128),
      canonicalJson(input.details ?? {}), this.#now().toISOString()
    );
  }

  ensureJamieGrant(input: { issuer: string; resource: string; systemBinding: HorseySystemBinding }): HorseyPrincipalGrant {
    const identity = horseyPrincipalIdentity({
      issuer: input.issuer,
      resource: input.resource,
      subject: JAMIE_CURRIER_OAUTH_SUBJECT,
      principalType: "user",
      workspaceId: null
    });
    const systemBinding = validateBinding(input.systemBinding);
    const systemBindingDigest = horseySystemBindingDigest(systemBinding);
    const request: Json = {
      authorityMode: HORSEY_AUTHORITY_MODE,
      capabilityScope: HORSEY_CAPABILITY_SCOPE,
      confirmationMode: HORSEY_CONFIRMATION_MODE,
      displayName: JAMIE_CURRIER_DISPLAY_NAME,
      grantId: JAMIE_CURRIER_GRANT_ID,
      issuer: identity.issuer,
      principalFingerprint: identity.principalFingerprint,
      principalType: identity.principalType,
      resource: identity.resource,
      subjectFingerprint: identity.subjectFingerprint,
      systemBindingDigest,
      version: JAMIE_CURRIER_GRANT_VERSION
    };
    const requestHash = sha256Hex(canonicalJson(request));
    const prior = this.#db.prepare("SELECT * FROM horsey_principal_grants WHERE grant_id=?").get(JAMIE_CURRIER_GRANT_ID) as GrantRow | undefined;
    if (prior !== undefined) {
      const existing = grantFromRow(prior);
      if (existing.requestHash !== requestHash || existing.principalFingerprint !== identity.principalFingerprint || existing.systemBindingDigest !== systemBindingDigest) {
        this.#transaction(() => this.#event({ grantId: existing.grantId, eventType: "principal_grant.bootstrap_denied", principalFingerprint: identity.principalFingerprint, allowed: false, reasonCode: "grant_identity_conflict", systemBindingDigest, actorId: "gateway-startup", details: { requestHash } }));
        throw new OperatorError("CONFIGURATION_ERROR", "Stored Jamie authority does not match this gateway and broker policy");
      }
    }
    return this.#transaction(() => {
      const old = this.#db.prepare("SELECT * FROM horsey_principal_grants WHERE grant_id=?").get(JAMIE_CURRIER_GRANT_ID) as GrantRow | undefined;
      if (old !== undefined) {
        const existing = grantFromRow(old);
        this.#event({ grantId: existing.grantId, eventType: "principal_grant.bootstrap_verified", principalFingerprint: identity.principalFingerprint, allowed: existing.status === "active", reasonCode: existing.status === "active" ? null : "grant_revoked", systemBindingDigest, actorId: "gateway-startup", details: { requestHash } });
        return existing;
      }
      const at = this.#now().toISOString();
      this.#db.prepare(`INSERT INTO horsey_principal_grants(
        grant_id,version,display_name,principal_type,issuer,resource,principal_fingerprint,subject_fingerprint,
        authority_mode,confirmation_mode,capability_scope,system_binding_json,system_binding_digest,status,
        created_at,updated_at,revoked_at,request_hash
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?,NULL,?)`).run(
        JAMIE_CURRIER_GRANT_ID,JAMIE_CURRIER_GRANT_VERSION,JAMIE_CURRIER_DISPLAY_NAME,identity.principalType,
        identity.issuer,identity.resource,identity.principalFingerprint,identity.subjectFingerprint,
        HORSEY_AUTHORITY_MODE,HORSEY_CONFIRMATION_MODE,HORSEY_CAPABILITY_SCOPE,
        canonicalJson(bindingJson(systemBinding)),systemBindingDigest,at,at,requestHash
      );
      this.#event({ grantId: JAMIE_CURRIER_GRANT_ID, eventType: "principal_grant.created", principalFingerprint: identity.principalFingerprint, allowed: true, reasonCode: null, systemBindingDigest, actorId: "standing-authority-v1", details: { requestHash } });
      return this.requireJamieGrant();
    });
  }

  requireJamieGrant(): HorseyPrincipalGrant {
    const row = this.#db.prepare("SELECT * FROM horsey_principal_grants WHERE grant_id=?").get(JAMIE_CURRIER_GRANT_ID) as GrantRow | undefined;
    if (row === undefined) throw new OperatorError("NOT_FOUND", "Jamie principal grant was not found");
    return grantFromRow(row);
  }

  resolve(input: HorseyPrincipalIdentityInput & {
    capabilityId?: string | null;
    registeredCapabilities: readonly string[];
    systemBinding: HorseySystemBinding;
  }): HorseyAuthorityResolution {
    const identity = horseyPrincipalIdentity(input);
    const registry = capabilityRegistry(input.registeredCapabilities);
    const capabilityId = input.capabilityId ?? null;
    const currentSystemDigest = horseySystemBindingDigest(input.systemBinding);
    return this.#transaction(() => {
      const control = this.#db.prepare("SELECT paused FROM horsey_authority_control WHERE control_id=1").get() as { paused: number };
      const row = this.#db.prepare("SELECT * FROM horsey_principal_grants WHERE principal_fingerprint=?").get(identity.principalFingerprint) as GrantRow | undefined;
      const grant = row === undefined ? null : grantFromRow(row);
      let denialReason: HorseyAuthorityDenial | null = null;
      if (control.paused === 1) denialReason = "global_paused";
      else if (grant === null) denialReason = "grant_not_found";
      else if (grant.status === "revoked") denialReason = "grant_revoked";
      else if (grant.issuer !== identity.issuer || grant.resource !== identity.resource || grant.subjectFingerprint !== identity.subjectFingerprint || grant.principalType !== identity.principalType || identity.workspaceFingerprint !== null) denialReason = "identity_mismatch";
      else if (grant.systemBindingDigest !== currentSystemDigest) denialReason = "system_binding_mismatch";
      else if (capabilityId !== null && !registry.values.includes(capabilityId)) denialReason = "capability_not_registered";
      const allowed = denialReason === null;
      this.#event({
        grantId: grant?.grantId ?? null,
        eventType: allowed ? "principal_grant.resolved" : "principal_grant.denied",
        principalFingerprint: identity.principalFingerprint,
        capabilityId,
        allowed,
        reasonCode: denialReason,
        systemBindingDigest: currentSystemDigest,
        actorId: identity.principalFingerprint,
        details: { registeredCapabilityDigest: registry.digest }
      });
      return Object.freeze({
        allowed,
        denialReason,
        grant,
        principalFingerprint: identity.principalFingerprint,
        capabilityId,
        confirmationMode: allowed ? HORSEY_CONFIRMATION_MODE : null
      });
    });
  }

  setGlobalPause(paused: boolean, input: { updatedBy: string; reason: string }): HorseyAuthorityStatus {
    const updatedBy = bounded(input.updatedBy, "Authority operator", 128);
    const reason = bounded(input.reason, "Authority pause reason", 512);
    return this.#transaction(() => {
      const at = this.#now().toISOString();
      this.#db.prepare(`UPDATE horsey_authority_control SET paused=?,revision=revision+1,updated_at=?,updated_by=?,reason=? WHERE control_id=1`).run(paused ? 1 : 0, at, updatedBy, reason);
      const grant = this.requireJamieGrant();
      this.#event({ grantId: grant.grantId, eventType: paused ? "authority.global_paused" : "authority.global_resumed", principalFingerprint: grant.principalFingerprint, allowed: !paused, reasonCode: paused ? "global_paused" : null, systemBindingDigest: grant.systemBindingDigest, actorId: updatedBy, details: { reason } });
      return this.status([], grant.systemBinding, true);
    });
  }

  revokeJamieGrant(input: { revokedBy: string; reason: string }): HorseyPrincipalGrant {
    const revokedBy = bounded(input.revokedBy, "Revoking principal", 128);
    const reason = bounded(input.reason, "Revocation reason", 512);
    return this.#transaction(() => {
      const current = this.requireJamieGrant();
      if (current.status === "revoked") {
        this.#event({ grantId: current.grantId, eventType: "principal_grant.revoke_replayed", principalFingerprint: current.principalFingerprint, allowed: false, reasonCode: "grant_revoked", systemBindingDigest: current.systemBindingDigest, actorId: revokedBy, details: { reason } });
        return current;
      }
      const at = this.#now().toISOString();
      this.#db.prepare("UPDATE horsey_principal_grants SET status='revoked',revoked_at=?,updated_at=? WHERE grant_id=?").run(at, at, current.grantId);
      const revoked = this.requireJamieGrant();
      this.#event({ grantId: revoked.grantId, eventType: "principal_grant.revoked", principalFingerprint: revoked.principalFingerprint, allowed: false, reasonCode: "grant_revoked", systemBindingDigest: revoked.systemBindingDigest, actorId: revokedBy, details: { reason } });
      return revoked;
    });
  }

  status(registeredCapabilities: readonly string[], currentSystemBinding?: HorseySystemBinding, allowEmptyRegistry = false): HorseyAuthorityStatus {
    const registry = registeredCapabilities.length === 0 && allowEmptyRegistry
      ? { values: [] as string[], digest: sha256Hex(canonicalJson([])) }
      : capabilityRegistry(registeredCapabilities);
    const grant = this.requireJamieGrant();
    const control = this.#db.prepare("SELECT paused,revision FROM horsey_authority_control WHERE control_id=1").get() as { paused: number; revision: number };
    const systemMatches = currentSystemBinding === undefined || horseySystemBindingDigest(currentSystemBinding) === grant.systemBindingDigest;
    const effective = grant.status === "revoked" ? "revoked" : control.paused === 1 ? "paused" : systemMatches ? "active" : "system-mismatch";
    return Object.freeze({
      grant,
      globalPaused: control.paused === 1,
      globalRevision: control.revision,
      effective,
      registeredCapabilityCount: registry.values.length,
      registeredCapabilityDigest: registry.digest
    });
  }

  listEvents(limit = 100): HorseyAuthorityEvent[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new OperatorError("INVALID_ARGUMENT", "Authority event limit is invalid");
    const rows = this.#db.prepare("SELECT * FROM horsey_authority_events ORDER BY occurred_at DESC,event_id DESC LIMIT ?").all(limit) as unknown as EventRow[];
    return rows.map(row => Object.freeze({
      eventId: row.event_id,
      grantId: row.grant_id,
      eventType: row.event_type,
      principalFingerprint: row.principal_fingerprint,
      capabilityId: row.capability_id,
      allowed: row.allowed === null ? null : row.allowed === 1,
      reasonCode: row.reason_code,
      systemBindingDigest: row.system_binding_digest,
      actorId: row.actor_id,
      details: JSON.parse(row.details_json) as Json,
      occurredAt: row.occurred_at
    }));
  }

  close(): void { this.#db.close(); }
}
