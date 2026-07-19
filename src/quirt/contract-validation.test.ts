import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { buildQuirtContractBundle } from "./contract-catalog.js";
import {
  assertQuirtContractSemantics,
  deterministicContractBundleJson,
  validateQuirtContractSemantics
} from "./contract-validation.js";

function mutate<T extends Record<string, unknown>>(value: T, path: string, replacement: unknown): T {
  const clone = structuredClone(value);
  const segments = path.split(".");
  let current: Record<string, unknown> = clone;
  for (let index = 0; index < segments.length - 1; index += 1) {
    current = current[segments[index]!] as Record<string, unknown>;
  }
  current[segments.at(-1)!] = replacement;
  return clone;
}

describe("Quirt contract semantic validation", () => {
  it("passes for the canonical bundle", () => {
    assert.doesNotThrow(() => assertQuirtContractSemantics());
  });

  it("matches the committed JSON bundle", () => {
    const generated = deterministicContractBundleJson(buildQuirtContractBundle());
    const committed = readFileSync(join(process.cwd(), "contracts/quirt-x-contracts-v1.json"), "utf8");
    assert.equal(generated, committed);
  });

  it("rejects forbidden socket and authority mutations", () => {
    const bundle = buildQuirtContractBundle();
    const socketIssues = validateQuirtContractSemantics(mutate(bundle as never, "paths.socket.path", "/tmp/quirt.sock"));
    assert.ok(socketIssues.some((item) => item.path === "paths.socket.path"));
    const authorityIssues = validateQuirtContractSemantics(mutate(bundle as never, "authority.prohibitedAuthorization", []));
    assert.ok(authorityIssues.some((item) => item.path === "authority.prohibitedAuthorization"));
  });

  it("rejects invalid program status vocabulary", () => {
    const bundle = buildQuirtContractBundle();
    const issues = validateQuirtContractSemantics(mutate(bundle as never, "operations.0.implementationStatus", "complete"));
    assert.ok(issues.some((item) => item.message.includes("approved vocabulary")));
  });

  it("rejects falsely implemented Ed25519 conformance", () => {
    const bundle = buildQuirtContractBundle();
    const conformance = [...bundle.conformance];
    const index = conformance.findIndex((item) => item.area === "target_ed25519_signatures");
    conformance[index] = { ...conformance[index]!, implementationStatus: "validated" };
    const issues = validateQuirtContractSemantics({ ...bundle, conformance });
    assert.ok(issues.some((item) => item.path.includes("target_ed25519_signatures")));
  });
});
