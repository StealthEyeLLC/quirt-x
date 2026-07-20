import { createHash } from "node:crypto";
import { quirtEnvironment } from "./environment.js";
import { QuirtError } from "./error.js";

const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;

export interface QuirtEnvironmentPolicy {
  environment?: Readonly<Record<string, string>>;
  unsetEnvironment?: readonly string[];
  replaceEnvironment?: boolean;
}

export interface QuirtResolvedEnvironment {
  values: Readonly<Record<string, string>>;
  keys: readonly string[];
  policyDigest: string;
  redactionStatus: "keys_only_persisted";
}

function validateName(name: string): void {
  if (!ENVIRONMENT_NAME.test(name)) throw new QuirtError("invalid_request", "Quirt environment name is invalid");
}

function canonicalPolicy(policy: QuirtEnvironmentPolicy): string {
  const environment = Object.entries(policy.environment ?? {}).sort(([left], [right]) => left.localeCompare(right));
  const unset = [...(policy.unsetEnvironment ?? [])].sort();
  const parts = [
    `replace:${policy.replaceEnvironment === true ? "1" : "0"}`,
    `unset:${unset.map(name => `n:${name}`).join(",")}`,
    ...environment.map(([name, value]) => `set:${name}:${Buffer.byteLength(value)}:${createHash("sha256").update(value).digest("hex")}`)
  ];
  return createHash("sha256").update(parts.join("\n")).digest("hex");
}

export function resolveEnvironment(shellPath: string, policy: QuirtEnvironmentPolicy = {}): QuirtResolvedEnvironment {
  const unset = new Set<string>();
  for (const name of policy.unsetEnvironment ?? []) {
    validateName(name);
    unset.add(name);
  }
  const base = policy.replaceEnvironment === true ? {} : { ...quirtEnvironment(shellPath) };
  for (const name of unset) delete base[name];
  for (const [name, value] of Object.entries(policy.environment ?? {})) {
    validateName(name);
    if (value.includes("\0") || Buffer.byteLength(value) > 64 * 1024) throw new QuirtError("invalid_request", "Quirt environment value is invalid");
    base[name] = value;
  }
  let totalBytes = 0;
  for (const [name, value] of Object.entries(base)) totalBytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 2;
  if (Object.keys(base).length > 512 || totalBytes > 256 * 1024) throw new QuirtError("invalid_request", "Quirt environment is too large");
  const keys = Object.freeze(Object.keys(base).sort());
  return Object.freeze({ values: Object.freeze(base), keys, policyDigest: canonicalPolicy(policy), redactionStatus: "keys_only_persisted" });
}

export function environmentKeysOnly(record: Readonly<Record<string, string>>): readonly string[] {
  return Object.freeze(Object.keys(record).sort());
}
