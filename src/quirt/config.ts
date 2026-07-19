import { isAbsolute, normalize, relative, resolve } from "node:path";
import { QuirtError } from "./error.js";
import { DEFAULT_MAX_FRAME_BYTES } from "./protocol.js";

export const QUIRT_DEFAULT_SOCKET = "/run/horsey/quirt.sock" as const;
export const QUIRT_DEFAULT_STATE_ROOT = "/var/lib/stealtheye-quirt" as const;
export const QUIRT_DEFAULT_CONFIG_ROOT = "/etc/stealtheye-quirt" as const;
export const QUIRT_DEFAULT_RELEASE_ROOT = "/opt/stealtheye-quirt" as const;

export interface QuirtConfig {
  mode: "production" | "test";
  socketPath: string;
  stateRoot: string;
  databasePath: string;
  tmuxPath: string;
  shellPath: string;
  pythonPath: string;
  authoritySecretPath: string;
  gatewaySigningPrivateKeyPath: string;
  gatewayVerificationKeyRingPath: string;
  supervisorSigningPrivateKeyPath: string;
  supervisorVerificationKeyRingPath: string;
  legacyHmacEnabled: boolean;
  supportedAuthorityAlgorithms: readonly ("ed25519" | "hmac-sha256")[];
  supportedCompressionAlgorithms: readonly ("none")[];
  previousKeyGraceMs: number;
  maxReconnectAttempts: number;
  reconnectBackoffMinMs: number;
  reconnectBackoffMaxMs: number;
  gatewayId: string;
  supervisorId: string;
  targetHost: string;
  expectedPrincipal: {
    principalType: "user";
    issuer: string;
    subject: string;
    workspaceId: null;
    principalFingerprint: string;
  };
  gatewayUid: number;
  socketGroup: string;
  socketMode: number;
  maxFrameBytes: number;
  maxBufferedBytes: number;
  maxWriteQueueBytes: number;
  outputChunkBytes: number;
  outputRetentionBytes: number;
  connectionTimeoutMs: number;
  requestTimeoutMs: number;
  livenessIntervalMs: number;
  requestMaxAgeMs: number;
  replayRetentionMs: number;
  logging: "error" | "warn" | "info" | "debug";
}

function integer(env: NodeJS.ProcessEnv, name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new QuirtError("configuration_error", `${name} is invalid`);
  return value;
}

function absolute(env: NodeJS.ProcessEnv, name: string, fallback: string): string {
  const value = env[name] ?? fallback;
  if (!isAbsolute(value) || normalize(value) !== value || value.includes("\0")) throw new QuirtError("configuration_error", `${name} must be a normalized absolute path`);
  return value;
}

function identifier(env: NodeJS.ProcessEnv, name: string, fallback?: string): string {
  const value = env[name] ?? fallback;
  if (value === undefined || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u.test(value)) throw new QuirtError("configuration_error", `${name} is invalid`);
  return value;
}

function httpsUrl(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined) throw new QuirtError("configuration_error", `${name} is required`);
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new QuirtError("configuration_error", `${name} is invalid`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new QuirtError("configuration_error", `${name} is invalid`);
  return value;
}

function childPath(path: string, root: string, name: string): string {
  const child = relative(root, path);
  if (child.length > 0 && child !== ".." && !child.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) && !isAbsolute(child)) return path;
  throw new QuirtError("configuration_error", `${name} must be beneath the Quirt state root`);
}

function configChildPath(path: string, root: string, name: string): string {
  const child = relative(root, path);
  if (child.length > 0 && child !== ".." && !child.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) && !isAbsolute(child)) return path;
  throw new QuirtError("configuration_error", `${name} must be beneath the Quirt configuration root`);
}

function algorithmList(env: NodeJS.ProcessEnv, name: string, fallback: readonly ("ed25519" | "hmac-sha256")[]): readonly ("ed25519" | "hmac-sha256")[] {
  const raw = env[name];
  if (raw === undefined) return fallback;
  const values = raw.split(",").map(item => item.trim()).filter(Boolean);
  if (values.length < 1) throw new QuirtError("configuration_error", `${name} is invalid`);
  const parsed: ("ed25519" | "hmac-sha256")[] = [];
  for (const value of values) {
    if (value !== "ed25519" && value !== "hmac-sha256") throw new QuirtError("configuration_error", `${name} is invalid`);
    if (parsed.includes(value)) throw new QuirtError("configuration_error", `${name} contains duplicates`);
    parsed.push(value);
  }
  return Object.freeze(parsed);
}

export function loadQuirtConfig(env: NodeJS.ProcessEnv): QuirtConfig {
  const mode = env.QUIRT_MODE === "test" ? "test" : "production";
  const stateRoot = absolute(env, "QUIRT_STATE_ROOT", QUIRT_DEFAULT_STATE_ROOT);
  const configRoot = absolute(env, "QUIRT_CONFIG_ROOT", QUIRT_DEFAULT_CONFIG_ROOT);
  if (stateRoot === `${QUIRT_DEFAULT_RELEASE_ROOT}/releases` || stateRoot.startsWith(`${QUIRT_DEFAULT_RELEASE_ROOT}/releases/`)) throw new QuirtError("configuration_error", "Quirt state root must not be inside immutable releases");
  const databasePath = childPath(absolute(env, "QUIRT_DATABASE_PATH", resolve(stateRoot, "state.sqlite")), stateRoot, "QUIRT_DATABASE_PATH");
  const socketMode = integer(env, "QUIRT_SOCKET_MODE", 0o660, 0, 0o777);
  if (mode === "production" && socketMode !== 0o660) throw new QuirtError("configuration_error", "Production Quirt socket mode must be 0660");
  const issuer = httpsUrl(env, "QUIRT_EXPECTED_ISSUER");
  const principalFingerprint = env.QUIRT_EXPECTED_PRINCIPAL_FINGERPRINT;
  if (principalFingerprint === undefined || !/^[a-f0-9]{64}$/u.test(principalFingerprint) || principalFingerprint === "0".repeat(64)) throw new QuirtError("configuration_error", "QUIRT_EXPECTED_PRINCIPAL_FINGERPRINT is invalid");
  if (env.QUIRT_EXPECTED_WORKSPACE !== undefined && env.QUIRT_EXPECTED_WORKSPACE !== "") throw new QuirtError("configuration_error", "Quirt does not permit inherited workspace authority");
  const maxFrameBytes = integer(env, "QUIRT_MAX_FRAME_BYTES", DEFAULT_MAX_FRAME_BYTES, 65_536, 64 * 1024 * 1024);
  const outputChunkBytes = integer(env, "QUIRT_OUTPUT_CHUNK_BYTES", 64 * 1024, 1024, Math.min(maxFrameBytes - 4096, 1024 * 1024));
  const legacyHmacEnabled = env.QUIRT_LEGACY_HMAC_ENABLED === "true" || (mode === "test" && env.QUIRT_LEGACY_HMAC_ENABLED !== "false");
  const supportedAuthorityAlgorithms = algorithmList(env, "QUIRT_SUPPORTED_AUTHORITY_ALGORITHMS", mode === "test" ? ["ed25519", "hmac-sha256"] : ["ed25519"]);
  if (!supportedAuthorityAlgorithms.includes("ed25519") && mode === "production") throw new QuirtError("configuration_error", "Production Quirt must support Ed25519");
  const supportedCompressionAlgorithms = Object.freeze(["none"] as const);
  const previousKeyGraceMs = integer(env, "QUIRT_PREVIOUS_KEY_GRACE_MS", 7 * 24 * 60 * 60 * 1000, 60_000, 90 * 24 * 60 * 60 * 1000);
  const maxReconnectAttempts = integer(env, "QUIRT_MAX_RECONNECT_ATTEMPTS", 5, 1, 32);
  const reconnectBackoffMinMs = integer(env, "QUIRT_RECONNECT_BACKOFF_MIN_MS", 100, 10, 60_000);
  const reconnectBackoffMaxMs = integer(env, "QUIRT_RECONNECT_BACKOFF_MAX_MS", 2_000, reconnectBackoffMinMs, 60_000);
  if (legacyHmacEnabled && !supportedAuthorityAlgorithms.includes("hmac-sha256")) throw new QuirtError("configuration_error", "Legacy HMAC cannot be enabled without algorithm support");
  return Object.freeze({
    mode,
    socketPath: absolute(env, "QUIRT_SOCKET_PATH", QUIRT_DEFAULT_SOCKET),
    stateRoot,
    databasePath,
    tmuxPath: absolute(env, "QUIRT_TMUX_PATH", "/usr/bin/tmux"),
    shellPath: absolute(env, "QUIRT_SHELL", "/bin/bash"),
    pythonPath: absolute(env, "QUIRT_PYTHON_PATH", "/usr/bin/python3"),
    authoritySecretPath: configChildPath(absolute(env, "QUIRT_AUTHORITY_SECRET_PATH", resolve(configRoot, "authority.key")), configRoot, "QUIRT_AUTHORITY_SECRET_PATH"),
    gatewaySigningPrivateKeyPath: configChildPath(absolute(env, "QUIRT_GATEWAY_SIGNING_PRIVATE_KEY_PATH", resolve(configRoot, "gateway-signing.key")), configRoot, "QUIRT_GATEWAY_SIGNING_PRIVATE_KEY_PATH"),
    gatewayVerificationKeyRingPath: configChildPath(absolute(env, "QUIRT_GATEWAY_VERIFICATION_KEY_RING_PATH", resolve(configRoot, "gateway-verification-keys.json")), configRoot, "QUIRT_GATEWAY_VERIFICATION_KEY_RING_PATH"),
    supervisorSigningPrivateKeyPath: configChildPath(absolute(env, "QUIRT_SUPERVISOR_SIGNING_PRIVATE_KEY_PATH", resolve(configRoot, "supervisor-signing.key")), configRoot, "QUIRT_SUPERVISOR_SIGNING_PRIVATE_KEY_PATH"),
    supervisorVerificationKeyRingPath: configChildPath(absolute(env, "QUIRT_SUPERVISOR_VERIFICATION_KEY_RING_PATH", resolve(configRoot, "supervisor-verification-keys.json")), configRoot, "QUIRT_SUPERVISOR_VERIFICATION_KEY_RING_PATH"),
    legacyHmacEnabled,
    supportedAuthorityAlgorithms,
    supportedCompressionAlgorithms,
    previousKeyGraceMs,
    maxReconnectAttempts,
    reconnectBackoffMinMs,
    reconnectBackoffMaxMs,
    gatewayId: identifier(env, "QUIRT_GATEWAY_ID", "stealtheye-horsey-gateway"),
    supervisorId: identifier(env, "QUIRT_SUPERVISOR_ID", "stealtheye-quirt-supervisor"),
    targetHost: identifier(env, "QUIRT_TARGET_HOST"),
    expectedPrincipal: Object.freeze({
      principalType: "user" as const,
      issuer,
      subject: identifier(env, "QUIRT_EXPECTED_SUBJECT", "stealtheye-owner"),
      workspaceId: null,
      principalFingerprint
    }),
    gatewayUid: integer(env, "QUIRT_GATEWAY_UID", 997, mode === "test" ? 0 : 1, 0x7fffffff),
    socketGroup: identifier(env, "QUIRT_SOCKET_GROUP", "horsey"),
    socketMode,
    maxFrameBytes,
    maxBufferedBytes: integer(env, "QUIRT_MAX_BUFFERED_BYTES", maxFrameBytes * 2, maxFrameBytes, 128 * 1024 * 1024),
    maxWriteQueueBytes: integer(env, "QUIRT_MAX_WRITE_QUEUE_BYTES", 8 * 1024 * 1024, 65_536, 128 * 1024 * 1024),
    outputChunkBytes,
    outputRetentionBytes: integer(env, "QUIRT_OUTPUT_RETENTION_BYTES", 256 * 1024 * 1024, outputChunkBytes, 16 * 1024 * 1024 * 1024),
    connectionTimeoutMs: integer(env, "QUIRT_CONNECTION_TIMEOUT_MS", 5_000, 100, 60_000),
    requestTimeoutMs: integer(env, "QUIRT_REQUEST_TIMEOUT_MS", 30_000, 100, 10 * 60_000),
    livenessIntervalMs: integer(env, "QUIRT_LIVENESS_INTERVAL_MS", 15_000, 1000, 5 * 60_000),
    requestMaxAgeMs: integer(env, "QUIRT_REQUEST_MAX_AGE_MS", 30_000, 1000, 5 * 60_000),
    replayRetentionMs: integer(env, "QUIRT_REPLAY_RETENTION_MS", 24 * 60 * 60 * 1000, 60_000, 30 * 24 * 60 * 60 * 1000),
    logging: env.QUIRT_LOG_LEVEL === "error" || env.QUIRT_LOG_LEVEL === "warn" || env.QUIRT_LOG_LEVEL === "debug" ? env.QUIRT_LOG_LEVEL : "info"
  });
}
