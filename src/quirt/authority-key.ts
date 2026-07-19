import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { QuirtError } from "./error.js";

export const QUIRT_KEY_ID_PATTERN = /^[a-f0-9]{64}$/u;
export const QUIRT_GATEWAY_ID_MAX = 128;
export const QUIRT_KEY_ID_MAX = 64;
export const QUIRT_NONCE_MIN = 22;
export const QUIRT_NONCE_MAX = 128;
export const QUIRT_SIGNATURE_MAX = 256;
export const QUIRT_ED25519_SIGNATURE_BYTES = 64;
export const QUIRT_KEY_FILE_MAX_BYTES = 16_384;

export type QuirtAuthorityAlgorithm = "ed25519" | "hmac-sha256";

export interface QuirtLoadedPrivateKey {
  readonly keyObject: KeyObject;
  readonly keyId: string;
  readonly algorithm: "ed25519";
}

export interface QuirtLoadedPublicKey {
  readonly keyObject: KeyObject;
  readonly keyId: string;
  readonly algorithm: "ed25519";
}

export function assertRegularOwnedFile(path: string, expectedOwnerUid: number, expectedMode: number): void {
  let stat;
  try { stat = lstatSync(path); } catch { throw new QuirtError("configuration_error", "Quirt key material is unavailable"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > QUIRT_KEY_FILE_MAX_BYTES) throw new QuirtError("configuration_error", "Quirt key material is invalid");
  if (stat.uid !== expectedOwnerUid || (stat.mode & 0o777) !== expectedMode) throw new QuirtError("configuration_error", "Quirt key material permissions are unsafe");
  if ((stat.mode & 0o022) !== 0) throw new QuirtError("configuration_error", "Quirt key material permissions are unsafe");
}

export function deriveEd25519KeyId(publicKey: KeyObject): string {
  const der = publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}

function parseEd25519PublicKey(pem: string): KeyObject {
  let key: KeyObject;
  try { key = createPublicKey(pem); } catch { throw new QuirtError("configuration_error", "Quirt public key material is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") throw new QuirtError("configuration_error", "Quirt public key type is invalid");
  return key;
}

function parseEd25519PrivateKey(pem: string): KeyObject {
  let key: KeyObject;
  try { key = createPrivateKey(pem); } catch { throw new QuirtError("configuration_error", "Quirt private key material is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") throw new QuirtError("configuration_error", "Quirt private key type is invalid");
  return key;
}

export function loadEd25519PrivateKey(path: string, expectedOwnerUid = 0, expectedMode = 0o400): QuirtLoadedPrivateKey {
  assertRegularOwnedFile(path, expectedOwnerUid, expectedMode);
  let pem: string;
  try { pem = readFileSync(path, "utf8"); } catch { throw new QuirtError("configuration_error", "Quirt private key material is unavailable"); }
  const keyObject = parseEd25519PrivateKey(pem);
  const keyId = deriveEd25519KeyId(createPublicKey(keyObject));
  return Object.freeze({ keyObject, keyId, algorithm: "ed25519" });
}

export function loadEd25519PublicKey(path: string, expectedOwnerUid = 0, expectedMode = 0o444): QuirtLoadedPublicKey {
  assertRegularOwnedFile(path, expectedOwnerUid, expectedMode);
  let pem: string;
  try { pem = readFileSync(path, "utf8"); } catch { throw new QuirtError("configuration_error", "Quirt public key material is unavailable"); }
  const keyObject = parseEd25519PublicKey(pem);
  const keyId = deriveEd25519KeyId(keyObject);
  return Object.freeze({ keyObject, keyId, algorithm: "ed25519" });
}

export function loadEd25519PublicKeyPem(pem: string, expectedKeyId?: string): QuirtLoadedPublicKey {
  const keyObject = parseEd25519PublicKey(pem);
  const keyId = deriveEd25519KeyId(keyObject);
  if (expectedKeyId !== undefined && expectedKeyId !== keyId) throw new QuirtError("configuration_error", "Quirt public key ID does not match key material");
  return Object.freeze({ keyObject, keyId, algorithm: "ed25519" });
}

export function generateEd25519KeyPair(): { privateKeyPem: string; publicKeyPem: string; keyId: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  return { privateKeyPem, publicKeyPem, keyId: deriveEd25519KeyId(publicKey) };
}

export function boundedGatewayId(value: string): void {
  if (value.length < 3 || value.length > QUIRT_GATEWAY_ID_MAX || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)) throw new QuirtError("invalid_request", "Quirt gateway ID is invalid");
}

export function boundedKeyId(value: string): void {
  if (!QUIRT_KEY_ID_PATTERN.test(value) || value.length > QUIRT_KEY_ID_MAX) throw new QuirtError("invalid_request", "Quirt key ID is invalid");
}

export function boundedNonce(value: string): void {
  if (value.length < QUIRT_NONCE_MIN || value.length > QUIRT_NONCE_MAX || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new QuirtError("invalid_request", "Quirt request nonce is invalid");
}

export function boundedAuthorityAlgorithm(value: string): QuirtAuthorityAlgorithm {
  if (value === "ed25519" || value === "hmac-sha256") return value;
  throw new QuirtError("invalid_request", "Quirt authority algorithm is invalid");
}
