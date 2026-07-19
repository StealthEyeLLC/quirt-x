import { readFileSync } from "node:fs";
import { verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { QuirtError } from "./error.js";
import { assertRegularOwnedFile, boundedKeyId, deriveEd25519KeyId, loadEd25519PublicKeyPem, QUIRT_KEY_FILE_MAX_BYTES, type QuirtAuthorityAlgorithm, type QuirtLoadedPublicKey } from "./authority-key.js";

export const QUIRT_KEY_RING_VERSION = 1 as const;

export type QuirtKeyRingStatus = "current" | "previous";

export interface QuirtKeyRingEntry {
  readonly keyId: string;
  readonly publicKey: KeyObject;
  readonly status: QuirtKeyRingStatus;
  readonly graceExpiresAt: string | null;
}

export interface QuirtVerificationKeyRing {
  readonly algorithm: "ed25519";
  readonly keys: ReadonlyMap<string, QuirtKeyRingEntry>;
  readonly currentKeyId: string;
  verify(bytes: Buffer, signature: Buffer, keyId: string, now: Date): { acceptedKeyId: string; algorithm: QuirtAuthorityAlgorithm };
}

interface KeyRingJsonEntry {
  keyId: string;
  publicKeyPem: string;
  status: QuirtKeyRingStatus;
  graceExpiresAt?: string;
}

interface KeyRingJson {
  keyRingVersion: number;
  keys: KeyRingJsonEntry[];
}

function parseKeyRingJson(raw: string): KeyRingJson {
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new QuirtError("configuration_error", "Quirt key ring is invalid"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new QuirtError("configuration_error", "Quirt key ring is invalid");
  const value = parsed as Record<string, unknown>;
  if (value.keyRingVersion !== QUIRT_KEY_RING_VERSION || !Array.isArray(value.keys)) throw new QuirtError("configuration_error", "Quirt key ring version is invalid");
  return value as unknown as KeyRingJson;
}

export function loadVerificationKeyRing(path: string, expectedOwnerUid = 0, expectedMode = 0o444, now: () => Date = () => new Date()): QuirtVerificationKeyRing {
  assertRegularOwnedFile(path, expectedOwnerUid, expectedMode);
  let raw: string;
  try { raw = readFileSync(path, "utf8"); } catch { throw new QuirtError("configuration_error", "Quirt key ring is unavailable"); }
  if (Buffer.byteLength(raw, "utf8") > QUIRT_KEY_FILE_MAX_BYTES) throw new QuirtError("configuration_error", "Quirt key ring is invalid");
  const document = parseKeyRingJson(raw);
  if (document.keys.length < 1) throw new QuirtError("configuration_error", "Quirt key ring is empty");
  const keys = new Map<string, QuirtKeyRingEntry>();
  let currentKeyId: string | null = null;
  for (const entry of document.keys) {
    boundedKeyId(entry.keyId);
    if (keys.has(entry.keyId)) throw new QuirtError("configuration_error", "Quirt key ring contains duplicate key IDs");
    const loaded = loadEd25519PublicKeyPem(entry.publicKeyPem, entry.keyId);
    if (entry.status === "current") {
      if (currentKeyId !== null) throw new QuirtError("configuration_error", "Quirt key ring has multiple current keys");
      currentKeyId = entry.keyId;
      keys.set(entry.keyId, Object.freeze({ keyId: entry.keyId, publicKey: loaded.keyObject, status: "current", graceExpiresAt: null }));
      continue;
    }
    if (entry.status !== "previous") throw new QuirtError("configuration_error", "Quirt key ring status is invalid");
    if (typeof entry.graceExpiresAt !== "string" || !Number.isFinite(Date.parse(entry.graceExpiresAt))) throw new QuirtError("configuration_error", "Quirt previous key grace deadline is invalid");
    keys.set(entry.keyId, Object.freeze({ keyId: entry.keyId, publicKey: loaded.keyObject, status: "previous", graceExpiresAt: entry.graceExpiresAt }));
  }
  if (currentKeyId === null) throw new QuirtError("configuration_error", "Quirt key ring has no current key");
  const frozenKeys = Object.freeze(keys) as ReadonlyMap<string, QuirtKeyRingEntry>;
  return Object.freeze({
    algorithm: "ed25519",
    keys: frozenKeys,
    currentKeyId,
    verify(bytes: Buffer, signature: Buffer, keyId: string, at: Date): { acceptedKeyId: string; algorithm: QuirtAuthorityAlgorithm } {
      boundedKeyId(keyId);
      const entry = frozenKeys.get(keyId);
      if (entry === undefined) throw new QuirtError("authentication_failed", "Quirt request key ID is unknown");
      if (entry.status === "previous") {
        const grace = entry.graceExpiresAt === null ? NaN : Date.parse(entry.graceExpiresAt);
        if (!Number.isFinite(grace) || at.getTime() > grace) throw new QuirtError("authentication_failed", "Quirt request signing key has expired");
      }
      if (!verify(null, bytes, entry.publicKey, signature)) throw new QuirtError("authentication_failed", "Quirt request signature is invalid");
      return { acceptedKeyId: entry.keyId, algorithm: "ed25519" };
    }
  });
}

export function buildKeyRingJson(entries: Array<{ keyId: string; publicKeyPem: string; status: QuirtKeyRingStatus; graceExpiresAt?: string }>): string {
  return `${JSON.stringify({ keyRingVersion: QUIRT_KEY_RING_VERSION, keys: entries }, null, 2)}\n`;
}

export function publicKeyPemFromKeyObject(publicKey: KeyObject): { pem: string; keyId: string } {
  const keyId = deriveEd25519KeyId(publicKey);
  return { pem: publicKey.export({ format: "pem", type: "spki" }).toString(), keyId };
}

export function loadedPublicKey(entry: QuirtLoadedPublicKey): { publicKeyPem: string; keyId: string } {
  return { publicKeyPem: entry.keyObject.export({ format: "pem", type: "spki" }).toString(), keyId: entry.keyId };
}
