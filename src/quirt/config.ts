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

export function loadQuirtConfig(env: NodeJS.ProcessEnv): QuirtConfig {
  const mode = env.QUIRT_MODE === "test" ? "test" : "production";
  const stateRoot = absolute(env, "QUIRT_STATE_ROOT", QUIRT_DEFAULT_STATE_ROOT);
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
  return Object.freeze({
    mode,
    socketPath: absolute(env, "QUIRT_SOCKET_PATH", QUIRT_DEFAULT_SOCKET),
    stateRoot,
    databasePath,
    tmuxPath: absolute(env, "QUIRT_TMUX_PATH", "/usr/bin/tmux"),
    shellPath: absolute(env, "QUIRT_SHELL", "/bin/bash"),
    pythonPath: absolute(env, "QUIRT_PYTHON_PATH", "/usr/bin/python3"),
    authoritySecretPath: absolute(env, "QUIRT_AUTHORITY_SECRET_PATH", `${QUIRT_DEFAULT_CONFIG_ROOT}/authority.key`),
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
