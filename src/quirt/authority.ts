import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { canonicalJson, type Json } from "../canonical.js";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtAuthorityEnvelope, QuirtPrincipalEnvelope, QuirtRequestEnvelope } from "./protocol.js";

const HEX_64 = /^[a-f0-9]{64}$/u;
const NONCE = /^[A-Za-z0-9_-]{22,128}$/u;

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

export interface QuirtRequestReservation {
  reserveRequest(requestId: string, operation: string, requestHash: string, nonce: string, expiresAt: string): "new" | "replayed";
}

function secret(value: Buffer): Buffer {
  if (value.length < 32 || value.length > 4096) throw new QuirtError("configuration_error", "Quirt authority secret length is invalid");
  return Buffer.from(value);
}

export function loadAuthoritySecret(path: string, expectedOwnerUid = 0, expectedMode = 0o440): Buffer {
  let stat;
  try { stat = lstatSync(path); } catch { throw new QuirtError("configuration_error", "Quirt authority secret is unavailable"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== expectedOwnerUid || (stat.mode & 0o777) !== expectedMode) throw new QuirtError("configuration_error", "Quirt authority secret permissions are unsafe");
  try { return secret(readFileSync(path)); } catch (cause) { if (cause instanceof QuirtError) throw cause; throw new QuirtError("configuration_error", "Quirt authority secret is unavailable"); }
}

function json(value: unknown): Json {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) return value.map(json);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, json(item)]));
  throw new QuirtError("invalid_request", "Quirt request contains a non-JSON value");
}

function signingDocument(request: QuirtUnsignedRequest, gatewayId: string, nonce: string, binary: Buffer): Json {
  return {
    binarySha256: createHash("sha256").update(binary).digest("hex"),
    gatewayId,
    nonce,
    operation: request.operation,
    payload: json(request.payload),
    principal: json(request.principal),
    protocolVersion: request.protocolVersion,
    requestId: request.requestId,
    targetHost: request.targetHost,
    timestamp: request.timestamp
  };
}

function digestDocument(request: QuirtUnsignedRequest, gatewayId: string, nonce: string, binary: Buffer): string {
  const signed = signingDocument(request, gatewayId, nonce, binary) as Record<string, Json>;
  const { nonce: _nonce, timestamp: _timestamp, ...semanticRequest } = signed;
  return createHash("sha256").update(canonicalJson(semanticRequest), "utf8").digest("hex");
}

function signature(request: QuirtUnsignedRequest, gatewayId: string, nonce: string, binary: Buffer, key: Buffer): string {
  return createHmac("sha256", key).update(canonicalJson(signingDocument(request, gatewayId, nonce, binary)), "utf8").digest("base64url");
}

export class QuirtGatewaySigner {
  readonly #secret: Buffer;
  constructor(private readonly gatewayId: string, secretValue: Buffer) { this.#secret = secret(secretValue); }

  sign(request: QuirtUnsignedRequest, binary: Buffer = Buffer.alloc(0), nonce = randomBytes(24).toString("base64url")): QuirtRequestEnvelope {
    if (!NONCE.test(nonce)) throw new QuirtError("invalid_request", "Quirt request nonce is invalid");
    return {
      kind: "request",
      ...request,
      binaryLength: binary.length,
      authority: {
        gatewayId: this.gatewayId,
        nonce,
        algorithm: "hmac-sha256",
        signature: signature({ ...request, binaryLength: binary.length }, this.gatewayId, nonce, binary, this.#secret)
      }
    };
  }

  challengeResponse(connectionId: string, challenge: string): string {
    return createHmac("sha256", this.#secret).update(`quirt-supervisor\0${connectionId}\0${challenge}`, "utf8").digest("base64url");
  }

  verifyChallengeResponse(connectionId: string, challenge: string, response: string): void {
    const expected = Buffer.from(this.challengeResponse(connectionId, challenge), "utf8");
    const actual = Buffer.from(response, "utf8");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
  }
}

export class QuirtSupervisorAuthority {
  readonly #secret: Buffer;
  constructor(private readonly config: QuirtConfig, secretValue: Buffer, private readonly reservations: QuirtRequestReservation, private readonly now: () => Date = () => new Date()) {
    this.#secret = secret(secretValue);
  }

  verify(request: QuirtRequestEnvelope, binary: Buffer = Buffer.alloc(0)): { requestHash: string; replayed: boolean } {
    const expected = this.config.expectedPrincipal;
    const actual = request.principal;
    if (request.authority.gatewayId !== this.config.gatewayId || request.authority.algorithm !== "hmac-sha256") throw new QuirtError("authentication_failed", "Quirt Gateway authority is untrusted");
    if (!NONCE.test(request.authority.nonce)) throw new QuirtError("authentication_failed", "Quirt request nonce is invalid");
    if (actual.principalType !== expected.principalType || actual.issuer !== expected.issuer || actual.subject !== expected.subject || actual.workspaceId !== null || actual.principalFingerprint !== expected.principalFingerprint) throw new QuirtError("authorization_failed", "Quirt principal is not authorized");
    if (!HEX_64.test(actual.principalFingerprint) || request.targetHost !== this.config.targetHost) throw new QuirtError("authorization_failed", "Quirt target host is not authorized");
    const at = Date.parse(request.timestamp);
    if (!Number.isFinite(at) || Math.abs(this.now().getTime() - at) > this.config.requestMaxAgeMs) throw new QuirtError("stale_request", "Quirt request timestamp is outside the accepted window");
    if (request.binaryLength !== binary.length) throw new QuirtError("invalid_request", "Quirt binary payload length is inconsistent");
    const unsigned: QuirtUnsignedRequest = {
      protocolVersion: request.protocolVersion,
      requestId: request.requestId,
      operation: request.operation,
      principal: request.principal,
      targetHost: request.targetHost,
      timestamp: request.timestamp,
      payload: request.payload,
      binaryLength: binary.length
    };
    const expectedSignature = Buffer.from(signature(unsigned, request.authority.gatewayId, request.authority.nonce, binary, this.#secret), "utf8");
    const actualSignature = Buffer.from(request.authority.signature, "utf8");
    if (expectedSignature.length !== actualSignature.length || !timingSafeEqual(expectedSignature, actualSignature)) throw new QuirtError("authentication_failed", "Quirt request signature is invalid");
    const requestHash = digestDocument(unsigned, request.authority.gatewayId, request.authority.nonce, binary);
    const expiresAt = new Date(this.now().getTime() + this.config.replayRetentionMs).toISOString();
    const reservation = this.reservations.reserveRequest(request.requestId, request.operation, requestHash, request.authority.nonce, expiresAt);
    return { requestHash, replayed: reservation === "replayed" };
  }

  verifySupervisorChallenge(connectionId: string, challenge: string, response: string): void {
    const expected = Buffer.from(createHmac("sha256", this.#secret).update(`quirt-supervisor\0${connectionId}\0${challenge}`, "utf8").digest("base64url"), "utf8");
    const actual = Buffer.from(response, "utf8");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
  }

  challengeResponse(connectionId: string, challenge: string): string {
    return createHmac("sha256", this.#secret).update(`quirt-supervisor\0${connectionId}\0${challenge}`, "utf8").digest("base64url");
  }
}
