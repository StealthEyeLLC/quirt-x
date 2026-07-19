import { randomBytes, randomUUID } from "node:crypto";
import { QuirtError } from "./error.js";

export const QUIRT_PROTOCOL_VERSION = 1 as const;
export const QUIRT_PROTOCOL_MAGIC = Buffer.from("QRT1", "ascii");
export const QUIRT_FRAME_HEADER_BYTES = 16 as const;
export const DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_BUFFERED_BYTES = DEFAULT_MAX_FRAME_BYTES * 2;

export type QuirtFrameKind = "hello" | "welcome" | "request" | "response" | "error" | "event" | "cancel" | "ping" | "pong";

const FRAME_KIND_CODES: Readonly<Record<QuirtFrameKind, number>> = Object.freeze({
  hello: 1,
  welcome: 2,
  request: 3,
  response: 4,
  error: 5,
  event: 6,
  cancel: 7,
  ping: 8,
  pong: 9
});
const CODE_FRAME_KINDS = new Map<number, QuirtFrameKind>(Object.entries(FRAME_KIND_CODES).map(([kind, code]) => [code, kind as QuirtFrameKind]));

export interface QuirtPrincipalEnvelope {
  principalType: "user" | "service" | "admin";
  issuer: string;
  subject: string;
  workspaceId: string | null;
  principalFingerprint: string;
  grantId: string;
  grantVersion: number;
}

export interface QuirtEd25519AuthorityEnvelope {
  gatewayId: string;
  nonce: string;
  algorithm: "ed25519";
  keyId: string;
  signature: string;
}

export interface QuirtHmacAuthorityEnvelope {
  gatewayId: string;
  nonce: string;
  algorithm: "hmac-sha256";
  signature: string;
}

export type QuirtAuthorityEnvelope = QuirtEd25519AuthorityEnvelope | QuirtHmacAuthorityEnvelope;

export interface QuirtRequestEnvelope {
  kind: "request";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  requestId: string;
  operation: string;
  principal: QuirtPrincipalEnvelope;
  authority: QuirtAuthorityEnvelope;
  targetHost: string;
  timestamp: string;
  payload: Record<string, unknown>;
  binaryLength: number;
}

export interface QuirtResponseEnvelope {
  kind: "response";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  requestId: string;
  timestamp: string;
  payload: Record<string, unknown>;
  binaryLength: number;
  replayed?: boolean;
}

export interface QuirtErrorEnvelope {
  kind: "error";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  requestId: string | null;
  timestamp: string;
  error: { code: string; message: string; retryable: boolean; details?: Record<string, unknown> };
  binaryLength: 0;
}

export interface QuirtEventEnvelope {
  kind: "event";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  eventId: string;
  streamId: string | null;
  sequence: number;
  event: string;
  timestamp: string;
  payload: Record<string, unknown>;
  binaryLength: number;
}

export interface QuirtHelloEnvelope {
  kind: "hello";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  connectionId: string;
  gatewayId: string;
  challenge: string;
  capabilities: readonly string[];
  timestamp: string;
  binaryLength: 0;
}

export interface QuirtWelcomeEnvelope {
  kind: "welcome";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  connectionId: string;
  supervisorId: string;
  challengeResponse: string;
  capabilities: readonly string[];
  selectedAuthorityAlgorithm: "ed25519" | "hmac-sha256";
  selectedCompression: "none";
  supervisorKeyId?: string;
  timestamp: string;
  binaryLength: 0;
}

export interface QuirtCancelEnvelope {
  kind: "cancel";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  requestId: string;
  timestamp: string;
  binaryLength: 0;
}

export interface QuirtLivenessEnvelope {
  kind: "ping" | "pong";
  protocolVersion: typeof QUIRT_PROTOCOL_VERSION;
  nonce: string;
  timestamp: string;
  binaryLength: 0;
}

export type QuirtEnvelope =
  | QuirtHelloEnvelope
  | QuirtWelcomeEnvelope
  | QuirtRequestEnvelope
  | QuirtResponseEnvelope
  | QuirtErrorEnvelope
  | QuirtEventEnvelope
  | QuirtCancelEnvelope
  | QuirtLivenessEnvelope;

export interface QuirtFrame<T extends QuirtEnvelope = QuirtEnvelope> {
  envelope: T;
  binary: Buffer;
}

export interface QuirtFrameLimits {
  maxFrameBytes?: number;
  maxBufferedBytes?: number;
  maxMetadataBytes?: number;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function integer(value: unknown, minimum = 0): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= maximum && !/[\0\r\n]/u.test(value);
}

function validateCommon(value: Record<string, unknown>, expectedKind: QuirtFrameKind, binaryLength: number): void {
  if (value.kind !== expectedKind) throw new QuirtError("invalid_frame", "Frame kind does not match its header");
  if (value.protocolVersion !== QUIRT_PROTOCOL_VERSION) throw new QuirtError("protocol_mismatch", "Quirt protocol version is unsupported");
  if (!integer(value.binaryLength) || value.binaryLength !== binaryLength) throw new QuirtError("invalid_frame", "Frame binary length is inconsistent");
}

export function validateEnvelope(value: unknown, expectedKind: QuirtFrameKind, binaryLength: number): QuirtEnvelope {
  if (!record(value)) throw new QuirtError("invalid_frame", "Frame metadata must be an object");
  validateCommon(value, expectedKind, binaryLength);
  if (expectedKind === "request") {
    if (!boundedString(value.requestId, 128) || !boundedString(value.operation, 128) || !boundedString(value.targetHost, 256) || !boundedString(value.timestamp, 64) || !record(value.payload) || !record(value.principal) || !record(value.authority)) throw new QuirtError("invalid_request", "Quirt request envelope is invalid");
    const authority = value.authority as Record<string, unknown>;
    if (!boundedString(authority.gatewayId, 128) || !boundedString(authority.nonce, 128) || typeof authority.algorithm !== "string" || !boundedString(authority.signature, 256)) throw new QuirtError("invalid_request", "Quirt authority envelope is invalid");
    if (authority.algorithm === "ed25519") {
      if (!boundedString(authority.keyId, 64) || !/^[a-f0-9]{64}$/u.test(String(authority.keyId))) throw new QuirtError("invalid_request", "Quirt authority envelope is invalid");
    } else if (authority.algorithm !== "hmac-sha256" || "keyId" in authority) throw new QuirtError("invalid_request", "Quirt authority envelope is invalid");
  } else if (expectedKind === "response") {
    if (!boundedString(value.requestId, 128) || !boundedString(value.timestamp, 64) || !record(value.payload)) throw new QuirtError("invalid_frame", "Quirt response envelope is invalid");
  } else if (expectedKind === "error") {
    if (!(value.requestId === null || boundedString(value.requestId, 128)) || !boundedString(value.timestamp, 64) || !record(value.error) || value.binaryLength !== 0) throw new QuirtError("invalid_frame", "Quirt error envelope is invalid");
  } else if (expectedKind === "event") {
    if (!boundedString(value.eventId, 128) || !(value.streamId === null || boundedString(value.streamId, 128)) || !integer(value.sequence) || !boundedString(value.event, 128) || !boundedString(value.timestamp, 64) || !record(value.payload)) throw new QuirtError("invalid_frame", "Quirt event envelope is invalid");
  } else if (expectedKind === "hello") {
    if (!boundedString(value.connectionId, 128) || !boundedString(value.gatewayId, 128) || !boundedString(value.challenge, 256) || !Array.isArray(value.capabilities) || !boundedString(value.timestamp, 64) || value.binaryLength !== 0) throw new QuirtError("invalid_frame", "Quirt hello envelope is invalid");
  } else if (expectedKind === "welcome") {
    if (!boundedString(value.connectionId, 128) || !boundedString(value.supervisorId, 128) || !boundedString(value.challengeResponse, 512) || !Array.isArray(value.capabilities) || !boundedString(value.timestamp, 64) || value.binaryLength !== 0) throw new QuirtError("invalid_frame", "Quirt welcome envelope is invalid");
    if (value.selectedAuthorityAlgorithm !== "ed25519" && value.selectedAuthorityAlgorithm !== "hmac-sha256") throw new QuirtError("invalid_frame", "Quirt welcome envelope is invalid");
    if (value.selectedCompression !== "none") throw new QuirtError("invalid_frame", "Quirt welcome envelope is invalid");
    if (value.selectedAuthorityAlgorithm === "ed25519" && !boundedString(value.supervisorKeyId, 64)) throw new QuirtError("invalid_frame", "Quirt welcome envelope is invalid");
  } else if (expectedKind === "cancel") {
    if (!boundedString(value.requestId, 128) || !boundedString(value.timestamp, 64) || value.binaryLength !== 0) throw new QuirtError("invalid_frame", "Quirt cancellation envelope is invalid");
  } else if (expectedKind === "ping" || expectedKind === "pong") {
    if (!boundedString(value.nonce, 128) || !boundedString(value.timestamp, 64) || value.binaryLength !== 0) throw new QuirtError("invalid_frame", "Quirt liveness envelope is invalid");
  }
  return value as unknown as QuirtEnvelope;
}

export function encodeFrame(frame: QuirtFrame, limits: QuirtFrameLimits = {}): Buffer {
  const maxFrameBytes = limits.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  const maxMetadataBytes = limits.maxMetadataBytes ?? Math.min(1024 * 1024, maxFrameBytes - QUIRT_FRAME_HEADER_BYTES);
  const kindCode = FRAME_KIND_CODES[frame.envelope.kind];
  const binary = Buffer.from(frame.binary);
  const envelope = { ...frame.envelope, binaryLength: binary.length } as QuirtEnvelope;
  const metadata = Buffer.from(JSON.stringify(envelope), "utf8");
  if (metadata.length > maxMetadataBytes) throw new QuirtError("frame_too_large", "Quirt frame metadata exceeds its limit");
  const total = QUIRT_FRAME_HEADER_BYTES + metadata.length + binary.length;
  if (total > maxFrameBytes) throw new QuirtError("frame_too_large", "Quirt frame exceeds its limit");
  const header = Buffer.alloc(QUIRT_FRAME_HEADER_BYTES);
  QUIRT_PROTOCOL_MAGIC.copy(header, 0);
  header.writeUInt8(QUIRT_PROTOCOL_VERSION, 4);
  header.writeUInt8(kindCode, 5);
  header.writeUInt16BE(0, 6);
  header.writeUInt32BE(metadata.length, 8);
  header.writeUInt32BE(binary.length, 12);
  return Buffer.concat([header, metadata, binary], total);
}

export class QuirtFrameDecoder {
  readonly #maxFrameBytes: number;
  readonly #maxBufferedBytes: number;
  readonly #maxMetadataBytes: number;
  #buffer = Buffer.alloc(0);

  constructor(limits: QuirtFrameLimits = {}) {
    this.#maxFrameBytes = limits.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
    this.#maxBufferedBytes = limits.maxBufferedBytes ?? Math.max(this.#maxFrameBytes, DEFAULT_MAX_BUFFERED_BYTES);
    this.#maxMetadataBytes = limits.maxMetadataBytes ?? Math.min(1024 * 1024, this.#maxFrameBytes - QUIRT_FRAME_HEADER_BYTES);
    if (!Number.isSafeInteger(this.#maxFrameBytes) || this.#maxFrameBytes <= QUIRT_FRAME_HEADER_BYTES || this.#maxBufferedBytes < this.#maxFrameBytes || this.#maxMetadataBytes < 2) throw new QuirtError("configuration_error", "Quirt frame limits are invalid");
  }

  get bufferedBytes(): number { return this.#buffer.length; }

  push(chunk: Buffer | Uint8Array): QuirtFrame[] {
    const incoming = Buffer.from(chunk);
    if (this.#buffer.length + incoming.length > this.#maxBufferedBytes) {
      this.#buffer = Buffer.alloc(0);
      throw new QuirtError("queue_overflow", "Quirt frame buffer exceeded its limit");
    }
    this.#buffer = this.#buffer.length === 0 ? incoming : Buffer.concat([this.#buffer, incoming]);
    const frames: QuirtFrame[] = [];
    while (this.#buffer.length >= QUIRT_FRAME_HEADER_BYTES) {
      if (!this.#buffer.subarray(0, 4).equals(QUIRT_PROTOCOL_MAGIC)) throw new QuirtError("invalid_frame", "Quirt frame magic is invalid");
      const version = this.#buffer.readUInt8(4);
      if (version !== QUIRT_PROTOCOL_VERSION) throw new QuirtError("protocol_mismatch", "Quirt protocol version is unsupported");
      const kind = CODE_FRAME_KINDS.get(this.#buffer.readUInt8(5));
      if (kind === undefined || this.#buffer.readUInt16BE(6) !== 0) throw new QuirtError("invalid_frame", "Quirt frame header is invalid");
      const metadataLength = this.#buffer.readUInt32BE(8);
      const binaryLength = this.#buffer.readUInt32BE(12);
      const frameLength = QUIRT_FRAME_HEADER_BYTES + metadataLength + binaryLength;
      if (metadataLength < 2 || metadataLength > this.#maxMetadataBytes || frameLength > this.#maxFrameBytes) throw new QuirtError("frame_too_large", "Quirt frame length is invalid");
      if (this.#buffer.length < frameLength) break;
      const metadataBytes = this.#buffer.subarray(QUIRT_FRAME_HEADER_BYTES, QUIRT_FRAME_HEADER_BYTES + metadataLength);
      let metadata: unknown;
      try { metadata = JSON.parse(metadataBytes.toString("utf8")); }
      catch { throw new QuirtError("invalid_frame", "Quirt frame metadata is malformed"); }
      const envelope = validateEnvelope(metadata, kind, binaryLength);
      const binary = Buffer.from(this.#buffer.subarray(QUIRT_FRAME_HEADER_BYTES + metadataLength, frameLength));
      frames.push({ envelope, binary });
      this.#buffer = this.#buffer.subarray(frameLength);
    }
    return frames;
  }

  end(): void {
    if (this.#buffer.length !== 0) throw new QuirtError("invalid_frame", "Quirt connection ended with an incomplete frame");
  }
}

export function requestId(): string { return randomUUID(); }
export function protocolTimestamp(now = new Date()): string { return now.toISOString(); }
export function quirtHandshakeChallenge(): string { return randomBytes(32).toString("base64url"); }

export function errorFrame(requestIdValue: string | null, error: QuirtError, now = new Date()): QuirtFrame<QuirtErrorEnvelope> {
  return {
    envelope: {
      kind: "error",
      protocolVersion: QUIRT_PROTOCOL_VERSION,
      requestId: requestIdValue,
      timestamp: now.toISOString(),
      error: { code: error.code, message: error.message, retryable: error.retryable, details: { ...error.details } },
      binaryLength: 0
    },
    binary: Buffer.alloc(0)
  };
}
