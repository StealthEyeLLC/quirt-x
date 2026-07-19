import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { loadAuthoritySecret, type QuirtUnsignedRequest } from "./authority.js";
import { createTestAuthorityRuntime } from "./authority-runtime.js";
import type { QuirtNegotiatedConnectionContext } from "./authority-negotiation.js";
import { QuirtStateStore } from "./state.js";
import { QUIRT_PROTOCOL_VERSION, type QuirtPrincipalEnvelope } from "./protocol.js";
import { QuirtError } from "./error.js";
import { quirtTestConfig } from "./test-support.test.js";

const key = Buffer.alloc(32, 0x5a);
const principal: QuirtPrincipalEnvelope = {
  principalType: "user",
  issuer: "https://identity.stealtheye.io/",
  subject: "stealtheye-owner",
  workspaceId: null,
  principalFingerprint: "a".repeat(64),
  grantId: "jamie-currier-v1",
  grantVersion: 1
};
const now = new Date("2026-07-17T12:00:00.000Z");

function unsigned(overrides: Partial<QuirtUnsignedRequest> = {}): QuirtUnsignedRequest {
  return {
    protocolVersion: QUIRT_PROTOCOL_VERSION,
    requestId: "request-0001",
    operation: "quirt.status",
    principal,
    targetHost: "vps-test-01",
    timestamp: now.toISOString(),
    payload: {},
    binaryLength: 0,
    ...overrides
  };
}

function fixture(legacyOnly = false): { root: string; store: QuirtStateStore; runtime: ReturnType<typeof createTestAuthorityRuntime>; negotiated: QuirtNegotiatedConnectionContext } {
  const root = mkdtempSync(join(tmpdir(), "quirt-authority-"));
  const config = quirtTestConfig(root, {
    QUIRT_EXPECTED_ISSUER: principal.issuer,
    QUIRT_EXPECTED_SUBJECT: principal.subject,
    QUIRT_TARGET_HOST: "fix-host-production",
    ...(legacyOnly ? { QUIRT_SUPPORTED_AUTHORITY_ALGORITHMS: "hmac-sha256" } : {})
  });
  const store = new QuirtStateStore(":memory:", { now: () => now });
  const runtime = createTestAuthorityRuntime(config, store, root, () => now);
  const negotiated: QuirtNegotiatedConnectionContext = Object.freeze({
    connectionId: "connection-1",
    authorityAlgorithm: legacyOnly ? "hmac-sha256" : "ed25519",
    compression: "none",
    capabilities: [],
    supervisorKeyId: legacyOnly ? null : runtime.supervisorAuthority.supervisorKeyId
  });
  return { root, store, runtime, negotiated };
}

describe("Quirt principal authority", () => {
  it("loads only the exact non-symlink authority-key ownership and mode", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-authority-secret-"));
    try {
      const path = join(root, "authority.key");
      writeFileSync(path, key, { mode: 0o440 });
      assert.deepEqual(loadAuthoritySecret(path, process.getuid?.() ?? 0), key);
      chmodSync(path, 0o444);
      assert.throws(() => loadAuthoritySecret(path, process.getuid?.() ?? 0), /permissions|invalid/u);
      chmodSync(path, 0o440);
      const link = join(root, "authority-link");
      symlinkSync(path, link);
      assert.throws(() => loadAuthoritySecret(link, process.getuid?.() ?? 0), /permissions|invalid/u);
      assert.throws(() => loadAuthoritySecret(path, (process.getuid?.() ?? 0) + 1), /permissions|invalid/u);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("accepts the exact signed principal and exact binary payload", () => {
    const f = fixture();
    const binary = Buffer.from([0, 255, 1, 2]);
    const signed = f.runtime.gatewaySigner.sign(unsigned({ binaryLength: binary.length, targetHost: "fix-host-production" }), binary, "valid_nonce_1234567890123456");
    const result = f.runtime.supervisorAuthority.verify(signed, binary, f.negotiated);
    assert.match(result.requestHash, /^[a-f0-9]{64}$/u);
    assert.equal(result.replayed, false);
    assert.equal(result.algorithm, "ed25519");
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });

  it("returns an idempotent replay for the identical signed request", () => {
    const f = fixture();
    const signed = f.runtime.gatewaySigner.sign(unsigned({ targetHost: "fix-host-production" }), Buffer.alloc(0), "replay_nonce_12345678901234");
    const first = f.runtime.supervisorAuthority.verify(signed, Buffer.alloc(0), f.negotiated);
    const second = f.runtime.supervisorAuthority.verify(signed, Buffer.alloc(0), f.negotiated);
    assert.equal(first.requestHash, second.requestHash);
    assert.equal(second.replayed, true);
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });

  it("replays the same semantic request ID after a fresh Gateway signature", () => {
    const f = fixture();
    const first = f.runtime.gatewaySigner.sign(unsigned({ targetHost: "fix-host-production" }), Buffer.alloc(0), "semantic_nonce_1234567890123");
    const second = f.runtime.gatewaySigner.sign(unsigned({ targetHost: "fix-host-production" }), Buffer.alloc(0), "semantic_nonce_9876543210987");
    assert.equal(f.runtime.supervisorAuthority.verify(first, Buffer.alloc(0), f.negotiated).replayed, false);
    assert.equal(f.runtime.supervisorAuthority.verify(second, Buffer.alloc(0), f.negotiated).replayed, true);
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });

  it("rejects wrong issuer, subject, workspace, fingerprint, and target", () => {
    const identities = [
      { ...principal, issuer: "https://attacker.invalid/" },
      { ...principal, subject: "other" },
      { ...principal, workspaceId: "parent" },
      { ...principal, principalFingerprint: "b".repeat(64) }
    ];
    for (const [index, modified] of identities.entries()) {
      const f = fixture();
      const signed = f.runtime.gatewaySigner.sign(unsigned({ principal: modified, targetHost: "fix-host-production" }), Buffer.alloc(0), `identity_nonce_${index}_${"x".repeat(24)}`);
      assert.throws(() => f.runtime.supervisorAuthority.verify(signed, Buffer.alloc(0), f.negotiated), (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed");
      f.store.close(); rmSync(f.root, { recursive: true, force: true });
    }
    const f = fixture();
    const signed = f.runtime.gatewaySigner.sign(unsigned({ targetHost: "wrong-host" }), Buffer.alloc(0), "wrong_target_nonce_1234567890");
    assert.throws(() => f.runtime.supervisorAuthority.verify(signed, Buffer.alloc(0), f.negotiated), /target host/u);
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });

  it("rejects stale, altered, untrusted, and nonce-replayed requests", () => {
    const f = fixture();
    const stale = f.runtime.gatewaySigner.sign(unsigned({ timestamp: "2026-07-17T11:00:00.000Z", targetHost: "fix-host-production" }), Buffer.alloc(0), "stale_nonce_1234567890123456");
    assert.throws(() => f.runtime.supervisorAuthority.verify(stale, Buffer.alloc(0), f.negotiated), (error: unknown) => error instanceof QuirtError && error.code === "stale_request");
    const altered = f.runtime.gatewaySigner.sign(unsigned({ requestId: "altered", targetHost: "fix-host-production" }), Buffer.alloc(0), "altered_nonce_1234567890123"); altered.payload = { changed: true };
    assert.throws(() => f.runtime.supervisorAuthority.verify(altered, Buffer.alloc(0), f.negotiated), /signature/u);
    const untrusted = f.runtime.gatewaySigner.sign(unsigned({ requestId: "untrusted", targetHost: "fix-host-production" }), Buffer.alloc(0), "untrusted_nonce_12345678901"); untrusted.authority.gatewayId = "other-gateway";
    assert.throws(() => f.runtime.supervisorAuthority.verify(untrusted, Buffer.alloc(0), f.negotiated), /untrusted/u);
    const first = f.runtime.gatewaySigner.sign(unsigned({ requestId: "first", targetHost: "fix-host-production" }), Buffer.alloc(0), "shared_nonce_123456789012345"); f.runtime.supervisorAuthority.verify(first, Buffer.alloc(0), f.negotiated);
    const second = f.runtime.gatewaySigner.sign(unsigned({ requestId: "second", targetHost: "fix-host-production" }), Buffer.alloc(0), "shared_nonce_123456789012345");
    assert.throws(() => f.runtime.supervisorAuthority.verify(second, Buffer.alloc(0), f.negotiated), (error: unknown) => error instanceof QuirtError && error.code === "duplicate_request");
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });

  it("rejects algorithm mismatch with negotiated connection context", () => {
    const f = fixture();
    const signed = f.runtime.gatewaySigner.sign(unsigned({ targetHost: "fix-host-production" }), Buffer.alloc(0), "algo_mismatch_nonce_123456789");
    const hmacNegotiated: QuirtNegotiatedConnectionContext = Object.freeze({ ...f.negotiated, authorityAlgorithm: "hmac-sha256", supervisorKeyId: null });
    assert.throws(() => f.runtime.supervisorAuthority.verify(signed, Buffer.alloc(0), hmacNegotiated), /algorithm/u);
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });

  it("supports explicitly negotiated legacy HMAC compatibility", () => {
    const f = fixture(true);
    const signed = f.runtime.gatewaySigner.sign(unsigned({ targetHost: "fix-host-production" }), Buffer.alloc(0), "legacy_hmac_nonce_1234567890", "hmac-sha256");
    const result = f.runtime.supervisorAuthority.verify(signed, Buffer.alloc(0), f.negotiated);
    assert.equal(result.algorithm, "hmac-sha256");
    f.store.close(); rmSync(f.root, { recursive: true, force: true });
  });
});
