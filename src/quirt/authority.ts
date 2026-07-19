import { createHmac, randomBytes, sign, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { decodeStrictBase64Url, encodeStrictBase64Url } from "./authority-base64url.js";
import { assertRegularOwnedFile, boundedAuthorityAlgorithm, boundedGatewayId, boundedKeyId, boundedNonce, loadEd25519PrivateKey, QUIRT_ED25519_SIGNATURE_BYTES, QUIRT_KEY_FILE_MAX_BYTES, type QuirtAuthorityAlgorithm, type QuirtLoadedPrivateKey } from "./authority-key.js";
import type { QuirtVerificationKeyRing } from "./authority-keyring.js";
import type { QuirtNegotiatedConnectionContext } from "./authority-negotiation.js";
import { buildHandshakeSigningDocument, buildRequestSigningDocument, canonicalHandshakeSigningBytes, canonicalRequestSigningBytes, semanticRequestHash, type QuirtUnsignedRequest } from "./authority-signing-document.js";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtAuthorityEnvelope, QuirtRequestEnvelope } from "./protocol.js";

export type { QuirtUnsignedRequest } from "./authority-signing-document.js";

export interface QuirtAuthorityIdentity {
  readonly gatewayId: string;
  readonly algorithm: QuirtAuthorityAlgorithm;
  readonly keyId: string | null;
  readonly nonce: string;
}

export interface QuirtRequestReservation {
  reserveRequest(
    requestId: string,
    operation: string,
    requestHash: string,
    authorityIdentity: QuirtAuthorityIdentity,
    expiresAt: string
  ): "new" | "replayed";
}

function secret(value: Buffer): Buffer {
  if (value.length < 32 || value.length > 4096) throw new QuirtError("configuration_error", "Quirt authority secret length is invalid");
  return Buffer.from(value);
}

export function loadAuthoritySecret(path: string, expectedOwnerUid = 0, expectedMode = 0o440): Buffer {
  assertRegularOwnedFile(path, expectedOwnerUid, expectedMode);
  try { return secret(readFileSync(path)); } catch (cause) { if (cause instanceof QuirtError) throw cause; throw new QuirtError("configuration_error", "Quirt authority secret is unavailable"); }
}

function validateAuthorityEnvelope(authority: QuirtAuthorityEnvelope): QuirtAuthorityEnvelope {
  boundedGatewayId(authority.gatewayId);
  boundedNonce(authority.nonce);
  boundedAuthorityAlgorithm(authority.algorithm);
  if (authority.algorithm === "ed25519") {
    if (!("keyId" in authority) || typeof authority.keyId !== "string") throw new QuirtError("invalid_request", "Quirt authority envelope is invalid");
    boundedKeyId(authority.keyId);
    decodeStrictBase64Url(authority.signature, "Quirt request signature", QUIRT_ED25519_SIGNATURE_BYTES, QUIRT_ED25519_SIGNATURE_BYTES);
    return authority;
  }
  if ("keyId" in authority) throw new QuirtError("invalid_request", "Quirt authority envelope is invalid");
  if (authority.signature.length < 16 || authority.signature.length > 256 || !/^[A-Za-z0-9_-]+$/u.test(authority.signature)) throw new QuirtError("invalid_request", "Quirt request signature is invalid");
  return authority;
}

export class QuirtGatewaySigner {
  readonly #gatewayId: string;
  readonly #ed25519: QuirtLoadedPrivateKey | null;
  readonly #hmacSecret: Buffer | null;
  readonly #legacyHmacEnabled: boolean;

  constructor(input: {
    gatewayId: string;
    signingPrivateKey?: QuirtLoadedPrivateKey;
    legacyHmacSecret?: Buffer;
    legacyHmacEnabled?: boolean;
  }) {
    this.#gatewayId = input.gatewayId;
    this.#ed25519 = input.signingPrivateKey ?? null;
    this.#hmacSecret = input.legacyHmacSecret === undefined ? null : secret(input.legacyHmacSecret);
    this.#legacyHmacEnabled = input.legacyHmacEnabled === true;
    if (this.#ed25519 === null && !(this.#legacyHmacEnabled && this.#hmacSecret !== null)) {
      throw new QuirtError("configuration_error", "Quirt gateway signer has no signing identity");
    }
  }

  get gatewayId(): string { return this.#gatewayId; }
  get signingKeyId(): string | null { return this.#ed25519?.keyId ?? null; }

  sign(request: QuirtUnsignedRequest, binary: Buffer = Buffer.alloc(0), nonce = randomBytes(24).toString("base64url"), algorithm: QuirtAuthorityAlgorithm = "ed25519"): QuirtRequestEnvelope {
    boundedNonce(nonce);
    if (algorithm === "ed25519") {
      if (this.#ed25519 === null) throw new QuirtError("configuration_error", "Quirt Ed25519 signing key is unavailable");
      const document = buildRequestSigningDocument({ request: { ...request, binaryLength: binary.length }, gatewayId: this.#gatewayId, algorithm, keyId: this.#ed25519.keyId, nonce, binary });
      const signature = encodeStrictBase64Url(sign(null, canonicalRequestSigningBytes(document), this.#ed25519.keyObject));
      return {
        kind: "request",
        ...request,
        binaryLength: binary.length,
        authority: { gatewayId: this.#gatewayId, nonce, algorithm, keyId: this.#ed25519.keyId, signature }
      };
    }
    if (!this.#legacyHmacEnabled || this.#hmacSecret === null) throw new QuirtError("configuration_error", "Quirt legacy HMAC signing is disabled");
    const document = buildRequestSigningDocument({ request: { ...request, binaryLength: binary.length }, gatewayId: this.#gatewayId, algorithm, keyId: null, nonce, binary });
    const signature = createHmac("sha256", this.#hmacSecret).update(canonicalRequestSigningBytes(document)).digest("base64url");
    return { kind: "request", ...request, binaryLength: binary.length, authority: { gatewayId: this.#gatewayId, nonce, algorithm: "hmac-sha256", signature } };
  }

  verifySupervisorHandshake(input: {
    connectionId: string;
    gatewayId: string;
    supervisorId: string;
    challenge: string;
    challengeResponse: string;
    negotiated: QuirtNegotiatedConnectionContext;
    supervisorVerificationKeyRing?: QuirtVerificationKeyRing;
    timestamp: string;
    now: Date;
  }): void {
    const age = Math.abs(input.now.getTime() - Date.parse(input.timestamp));
    if (!Number.isFinite(age) || age > 30_000) throw new QuirtError("stale_request", "Quirt handshake timestamp is stale");
    const document = buildHandshakeSigningDocument({
      protocolVersion: 1,
      connectionId: input.connectionId,
      gatewayId: input.gatewayId,
      supervisorId: input.supervisorId,
      challenge: input.challenge,
      selectedAuthorityAlgorithm: input.negotiated.authorityAlgorithm,
      selectedCompression: input.negotiated.compression,
      selectedCapabilities: input.negotiated.capabilities,
      supervisorKeyId: input.negotiated.supervisorKeyId,
      timestamp: input.timestamp
    });
    const bytes = canonicalHandshakeSigningBytes(document);
    if (input.negotiated.authorityAlgorithm === "ed25519") {
      if (input.negotiated.supervisorKeyId === null) throw new QuirtError("authentication_failed", "Quirt supervisor key ID is missing");
      if (input.supervisorVerificationKeyRing === undefined) throw new QuirtError("configuration_error", "Quirt supervisor verification key ring is unavailable");
      const signature = decodeStrictBase64Url(input.challengeResponse, "Quirt supervisor handshake signature", QUIRT_ED25519_SIGNATURE_BYTES, QUIRT_ED25519_SIGNATURE_BYTES);
      input.supervisorVerificationKeyRing.verify(bytes, signature, input.negotiated.supervisorKeyId, input.now);
      return;
    }
    if (this.#hmacSecret === null) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
    const expected = Buffer.from(createHmac("sha256", this.#hmacSecret).update(bytes).digest("base64url"), "utf8");
    const actual = Buffer.from(input.challengeResponse, "utf8");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
  }

  /** @deprecated Legacy HMAC challenge verification for transitional compatibility tests. */
  verifyChallengeResponse(connectionId: string, challenge: string, response: string): void {
    if (this.#hmacSecret === null) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
    const expected = Buffer.from(createHmac("sha256", this.#hmacSecret).update(`quirt-supervisor\0${connectionId}\0${challenge}`, "utf8").digest("base64url"), "utf8");
    const actual = Buffer.from(response, "utf8");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
  }
}

export class QuirtSupervisorAuthority {
  readonly #config: QuirtConfig;
  readonly #reservations: QuirtRequestReservation;
  readonly #now: () => Date;
  readonly #gatewayVerificationKeyRing: QuirtVerificationKeyRing | null;
  readonly #supervisorSigningKey: QuirtLoadedPrivateKey | null;
  readonly #hmacSecret: Buffer | null;

  constructor(input: {
    config: QuirtConfig;
    reservations: QuirtRequestReservation;
    gatewayVerificationKeyRing?: QuirtVerificationKeyRing;
    supervisorSigningKey?: QuirtLoadedPrivateKey;
    legacyHmacSecret?: Buffer;
    now?: () => Date;
  }) {
    this.#config = input.config;
    this.#reservations = input.reservations;
    this.#now = input.now ?? (() => new Date());
    this.#gatewayVerificationKeyRing = input.gatewayVerificationKeyRing ?? null;
    this.#supervisorSigningKey = input.supervisorSigningKey ?? null;
    this.#hmacSecret = input.legacyHmacSecret === undefined ? null : secret(input.legacyHmacSecret);
  }

  get supervisorKeyId(): string | null { return this.#supervisorSigningKey?.keyId ?? null; }

  signHandshakeResponse(input: {
    connectionId: string;
    gatewayId: string;
    challenge: string;
    negotiated: QuirtNegotiatedConnectionContext;
    timestamp: string;
  }): string {
    const document = buildHandshakeSigningDocument({
      protocolVersion: 1,
      connectionId: input.connectionId,
      gatewayId: input.gatewayId,
      supervisorId: this.#config.supervisorId,
      challenge: input.challenge,
      selectedAuthorityAlgorithm: input.negotiated.authorityAlgorithm,
      selectedCompression: input.negotiated.compression,
      selectedCapabilities: input.negotiated.capabilities,
      supervisorKeyId: input.negotiated.authorityAlgorithm === "ed25519" ? this.#supervisorSigningKey?.keyId ?? null : null,
      timestamp: input.timestamp
    });
    const bytes = canonicalHandshakeSigningBytes(document);
    if (input.negotiated.authorityAlgorithm === "ed25519") {
      if (this.#supervisorSigningKey === null) throw new QuirtError("configuration_error", "Quirt supervisor signing key is unavailable");
      return encodeStrictBase64Url(sign(null, bytes, this.#supervisorSigningKey.keyObject));
    }
    if (!this.#config.legacyHmacEnabled || this.#hmacSecret === null) throw new QuirtError("configuration_error", "Quirt legacy HMAC handshake is disabled");
    return createHmac("sha256", this.#hmacSecret).update(bytes).digest("base64url");
  }

  verify(request: QuirtRequestEnvelope, binary: Buffer, negotiated: QuirtNegotiatedConnectionContext): { requestHash: string; replayed: boolean; acceptedKeyId: string | null; algorithm: QuirtAuthorityAlgorithm } {
    const authority = validateAuthorityEnvelope(request.authority);
    if (authority.gatewayId !== this.#config.gatewayId) throw new QuirtError("authentication_failed", "Quirt Gateway authority is untrusted");
    if (authority.algorithm !== negotiated.authorityAlgorithm) throw new QuirtError("authentication_failed", "Quirt request authority algorithm does not match negotiated connection");
    const expected = this.#config.expectedPrincipal;
    const actual = request.principal;
    if (actual.principalType !== expected.principalType || actual.issuer !== expected.issuer || actual.subject !== expected.subject || actual.workspaceId !== null || actual.principalFingerprint !== expected.principalFingerprint) throw new QuirtError("authorization_failed", "Quirt principal is not authorized");
    if (request.targetHost !== this.#config.targetHost) throw new QuirtError("authorization_failed", "Quirt target host is not authorized");
    const at = Date.parse(request.timestamp);
    if (!Number.isFinite(at) || Math.abs(this.#now().getTime() - at) > this.#config.requestMaxAgeMs) throw new QuirtError("stale_request", "Quirt request timestamp is outside the accepted window");
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
    const document = buildRequestSigningDocument({
      request: unsigned,
      gatewayId: authority.gatewayId,
      algorithm: authority.algorithm,
      keyId: authority.algorithm === "ed25519" ? authority.keyId : null,
      nonce: authority.nonce,
      binary
    });
    const bytes = canonicalRequestSigningBytes(document);
    let acceptedKeyId: string | null = null;
    if (authority.algorithm === "ed25519") {
      if (this.#gatewayVerificationKeyRing === null) throw new QuirtError("authentication_failed", "Quirt Ed25519 verification is unavailable");
      const signature = decodeStrictBase64Url(authority.signature, "Quirt request signature", QUIRT_ED25519_SIGNATURE_BYTES, QUIRT_ED25519_SIGNATURE_BYTES);
      const verified = this.#gatewayVerificationKeyRing.verify(bytes, signature, authority.keyId, this.#now());
      acceptedKeyId = verified.acceptedKeyId;
    } else {
      if (!this.#config.legacyHmacEnabled || this.#hmacSecret === null) throw new QuirtError("authentication_failed", "Quirt legacy HMAC verification is disabled");
      const expectedSignature = Buffer.from(createHmac("sha256", this.#hmacSecret).update(bytes).digest("base64url"), "utf8");
      const actualSignature = Buffer.from(authority.signature, "utf8");
      if (expectedSignature.length !== actualSignature.length || !timingSafeEqual(expectedSignature, actualSignature)) throw new QuirtError("authentication_failed", "Quirt request signature is invalid");
    }
    const requestHash = semanticRequestHash(document);
    const expiresAt = new Date(this.#now().getTime() + this.#config.replayRetentionMs).toISOString();
    const reservation = this.#reservations.reserveRequest(request.requestId, request.operation, requestHash, {
      gatewayId: authority.gatewayId,
      algorithm: authority.algorithm,
      keyId: acceptedKeyId,
      nonce: authority.nonce
    }, expiresAt);
    return { requestHash, replayed: reservation === "replayed", acceptedKeyId, algorithm: authority.algorithm };
  }

  /** @deprecated Legacy HMAC challenge for transitional tests. */
  challengeResponse(connectionId: string, challenge: string): string {
    if (this.#hmacSecret === null) throw new QuirtError("configuration_error", "Quirt legacy HMAC handshake is disabled");
    return createHmac("sha256", this.#hmacSecret).update(`quirt-supervisor\0${connectionId}\0${challenge}`, "utf8").digest("base64url");
  }

  verifySupervisorChallenge(connectionId: string, challenge: string, response: string): void {
    if (this.#hmacSecret === null) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
    const expected = Buffer.from(createHmac("sha256", this.#hmacSecret).update(`quirt-supervisor\0${connectionId}\0${challenge}`, "utf8").digest("base64url"), "utf8");
    const actual = Buffer.from(response, "utf8");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new QuirtError("authentication_failed", "Quirt supervisor identity is invalid");
  }
}

export function readBoundedTextFile(path: string, expectedOwnerUid = 0, expectedMode = 0o444): string {
  assertRegularOwnedFile(path, expectedOwnerUid, expectedMode);
  try {
    const raw = readFileSync(path, "utf8");
    if (Buffer.byteLength(raw, "utf8") > QUIRT_KEY_FILE_MAX_BYTES) throw new QuirtError("configuration_error", "Quirt configuration file is invalid");
    return raw;
  } catch (cause) {
    if (cause instanceof QuirtError) throw cause;
    throw new QuirtError("configuration_error", "Quirt configuration file is unavailable");
  }
}
