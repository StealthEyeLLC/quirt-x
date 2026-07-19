import { createHash } from "node:crypto";
import { canonicalJson, type Json } from "../canonical.js";
import { QuirtError } from "./error.js";
import type { QuirtAuthorityAlgorithm } from "./authority-key.js";
import type { QuirtPrincipalEnvelope } from "./protocol.js";

export const QUIRT_REQUEST_SIGNING_DOCUMENT_VERSION = 1 as const;
export const QUIRT_HANDSHAKE_SIGNING_DOCUMENT_VERSION = 1 as const;

export interface QuirtUnsignedRequest {
  protocolVersion: 1;
  requestId: string;
  operation: string;
  principal: QuirtPrincipalEnvelope;
  targetHost: string;
  timestamp: string;
  payload: Record<string, unknown>;
  binaryLength: number;
}

function json(value: unknown): Json {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) return value.map(json);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, json(item)]));
  throw new QuirtError("invalid_request", "Quirt request contains a non-JSON value");
}

export function buildRequestSigningDocument(input: {
  request: QuirtUnsignedRequest;
  gatewayId: string;
  algorithm: QuirtAuthorityAlgorithm;
  keyId: string | null;
  nonce: string;
  binary: Buffer;
}): Json {
  return {
    signingDocumentVersion: QUIRT_REQUEST_SIGNING_DOCUMENT_VERSION,
    protocolVersion: input.request.protocolVersion,
    algorithm: input.algorithm,
    gatewayId: input.gatewayId,
    ...(input.keyId === null ? {} : { keyId: input.keyId }),
    nonce: input.nonce,
    requestId: input.request.requestId,
    operation: input.request.operation,
    principal: json(input.request.principal),
    targetHost: input.request.targetHost,
    timestamp: input.request.timestamp,
    payload: json(input.request.payload),
    binaryLength: input.binary.length,
    binarySha256: createHash("sha256").update(input.binary).digest("hex")
  };
}

export function canonicalRequestSigningBytes(document: Json): Buffer {
  return Buffer.from(canonicalJson(document), "utf8");
}

/** Semantic replay hash excludes only intentionally non-semantic replay fields. */
export function semanticRequestHash(document: Json): string {
  const signed = document as Record<string, Json>;
  const { nonce: _nonce, timestamp: _timestamp, ...semanticRequest } = signed;
  return createHash("sha256").update(canonicalJson(semanticRequest), "utf8").digest("hex");
}

export function buildHandshakeSigningDocument(input: {
  protocolVersion: 1;
  connectionId: string;
  gatewayId: string;
  supervisorId: string;
  challenge: string;
  selectedAuthorityAlgorithm: QuirtAuthorityAlgorithm;
  selectedCompression: "none";
  selectedCapabilities: readonly string[];
  supervisorKeyId: string | null;
  timestamp: string;
}): Json {
  return {
    handshakeDocumentVersion: QUIRT_HANDSHAKE_SIGNING_DOCUMENT_VERSION,
    protocolVersion: input.protocolVersion,
    connectionId: input.connectionId,
    gatewayId: input.gatewayId,
    supervisorId: input.supervisorId,
    challenge: input.challenge,
    selectedAuthorityAlgorithm: input.selectedAuthorityAlgorithm,
    selectedCompression: input.selectedCompression,
    selectedCapabilities: [...input.selectedCapabilities],
    ...(input.supervisorKeyId === null ? {} : { supervisorKeyId: input.supervisorKeyId }),
    timestamp: input.timestamp
  };
}

export function canonicalHandshakeSigningBytes(document: Json): Buffer {
  return Buffer.from(canonicalJson(document), "utf8");
}
