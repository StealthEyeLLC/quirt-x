import { QuirtError } from "./error.js";

const BASE64URL = /^[A-Za-z0-9_-]+$/u;

export function decodeStrictBase64Url(value: string, label: string, minimumBytes: number, maximumBytes: number): Buffer {
  if (!BASE64URL.test(value) || value.length < 4) throw new QuirtError("invalid_request", `${label} is invalid`);
  let bytes: Buffer;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    throw new QuirtError("invalid_request", `${label} is invalid`);
  }
  if (bytes.length < minimumBytes || bytes.length > maximumBytes) throw new QuirtError("invalid_request", `${label} is invalid`);
  if (bytes.toString("base64url") !== value) throw new QuirtError("invalid_request", `${label} is invalid`);
  return bytes;
}

export function encodeStrictBase64Url(bytes: Buffer): string {
  return bytes.toString("base64url");
}
