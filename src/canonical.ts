import { createHash } from "node:crypto";
import { OperatorError } from "./errors.js";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function canonicalJson(value: Json): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) throw new OperatorError("INVALID_ARGUMENT", "Canonical JSON number is invalid");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalJson(value[key]!)}`).join(",")}}`;
}

export function sha256Hex(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

export function machineIdFingerprint(value: string | Buffer): string {
  const normalized=value.toString().trim();
  if(!/^[a-f0-9]{32}$/.test(normalized))throw new OperatorError("MACHINE_ID_MISMATCH","Machine identity format is invalid");
  return sha256Hex(normalized);
}
