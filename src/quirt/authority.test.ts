import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { QuirtConfig } from "./config.js";
import { loadAuthoritySecret, QuirtGatewaySigner, QuirtSupervisorAuthority, type QuirtUnsignedRequest } from "./authority.js";
import { QuirtStateStore } from "./state.js";
import { QUIRT_PROTOCOL_VERSION, type QuirtPrincipalEnvelope } from "./protocol.js";
import { QuirtError } from "./error.js";

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
const baseConfig = {
  gatewayId: "stealtheye-horsey-gateway",
  supervisorId: "stealtheye-quirt-supervisor",
  targetHost: "fix-host-production",
  expectedPrincipal: principal,
  requestMaxAgeMs: 30_000,
  replayRetentionMs: 86_400_000
} as unknown as QuirtConfig;
const now = new Date("2026-07-17T12:00:00.000Z");

function unsigned(overrides: Partial<QuirtUnsignedRequest> = {}): QuirtUnsignedRequest {
  return {
    protocolVersion: QUIRT_PROTOCOL_VERSION,
    requestId: "request-0001",
    operation: "quirt.status",
    principal,
    targetHost: "fix-host-production",
    timestamp: now.toISOString(),
    payload: {},
    binaryLength: 0,
    ...overrides
  };
}

function fixture(): { store: QuirtStateStore; signer: QuirtGatewaySigner; authority: QuirtSupervisorAuthority } {
  const store = new QuirtStateStore(":memory:", { now: () => now });
  return { store, signer: new QuirtGatewaySigner(baseConfig.gatewayId, key), authority: new QuirtSupervisorAuthority(baseConfig, key, store, () => now) };
}

describe("Quirt principal authority", () => {
  it("loads only the exact non-symlink authority-key ownership and mode", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-authority-secret-"));
    try {
      const path = join(root, "authority.key");
      writeFileSync(path, key, { mode: 0o440 });
      assert.deepEqual(loadAuthoritySecret(path, process.getuid?.() ?? 0), key);
      chmodSync(path, 0o444);
      assert.throws(() => loadAuthoritySecret(path, process.getuid?.() ?? 0), /permissions/u);
      chmodSync(path, 0o440);
      const link = join(root, "authority-link");
      symlinkSync(path, link);
      assert.throws(() => loadAuthoritySecret(link, process.getuid?.() ?? 0), /permissions/u);
      assert.throws(() => loadAuthoritySecret(path, (process.getuid?.() ?? 0) + 1), /permissions/u);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("accepts the exact signed principal and exact binary payload", () => {
    const f = fixture();
    const binary = Buffer.from([0, 255, 1, 2]);
    const signed = f.signer.sign(unsigned({ binaryLength: binary.length }), binary, "valid_nonce_1234567890123456");
    const result = f.authority.verify(signed, binary);
    assert.match(result.requestHash, /^[a-f0-9]{64}$/u);
    assert.equal(result.replayed, false);
    f.store.close();
  });

  it("returns an idempotent replay for the identical signed request", () => {
    const f = fixture();
    const signed = f.signer.sign(unsigned(), Buffer.alloc(0), "replay_nonce_12345678901234");
    const first = f.authority.verify(signed);
    const second = f.authority.verify(signed);
    assert.equal(first.requestHash, second.requestHash);
    assert.equal(second.replayed, true);
    f.store.close();
  });

  it("replays the same semantic request ID after a fresh Gateway signature", () => {
    const f = fixture();
    const first = f.signer.sign(unsigned(), Buffer.alloc(0), "semantic_nonce_1234567890123");
    const second = f.signer.sign(unsigned(), Buffer.alloc(0), "semantic_nonce_9876543210987");
    assert.equal(f.authority.verify(first).replayed, false);
    assert.equal(f.authority.verify(second).replayed, true);
    f.store.close();
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
      const signed = f.signer.sign(unsigned({ principal: modified }), Buffer.alloc(0), `identity_nonce_${index}_${"x".repeat(24)}`);
      assert.throws(() => f.authority.verify(signed), (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed");
      f.store.close();
    }
    const f = fixture();
    const signed = f.signer.sign(unsigned({ targetHost: "wrong-host" }), Buffer.alloc(0), "wrong_target_nonce_1234567890");
    assert.throws(() => f.authority.verify(signed), /target host/u);
    f.store.close();
  });

  it("rejects stale, altered, untrusted, and nonce-replayed requests", () => {
    const f = fixture();
    const stale = f.signer.sign(unsigned({ timestamp: "2026-07-17T11:00:00.000Z" }), Buffer.alloc(0), "stale_nonce_1234567890123456");
    assert.throws(() => f.authority.verify(stale), (error: unknown) => error instanceof QuirtError && error.code === "stale_request");
    const altered = f.signer.sign(unsigned({ requestId: "altered" }), Buffer.alloc(0), "altered_nonce_1234567890123"); altered.payload = { changed: true };
    assert.throws(() => f.authority.verify(altered), /signature/u);
    const untrusted = f.signer.sign(unsigned({ requestId: "untrusted" }), Buffer.alloc(0), "untrusted_nonce_12345678901"); untrusted.authority.gatewayId = "other-gateway";
    assert.throws(() => f.authority.verify(untrusted), /untrusted/u);
    const first = f.signer.sign(unsigned({ requestId: "first" }), Buffer.alloc(0), "shared_nonce_123456789012345"); f.authority.verify(first);
    const second = f.signer.sign(unsigned({ requestId: "second" }), Buffer.alloc(0), "shared_nonce_123456789012345");
    assert.throws(() => f.authority.verify(second), (error: unknown) => error instanceof QuirtError && error.code === "duplicate_request");
    f.store.close();
  });

  it("authenticates the supervisor challenge without revealing the key", () => {
    const f = fixture();
    const response = f.signer.challengeResponse("connection-1", "challenge-1");
    f.authority.verifySupervisorChallenge("connection-1", "challenge-1", response);
    assert.throws(() => f.authority.verifySupervisorChallenge("connection-1", "challenge-1", "wrong"), /identity/u);
    assert.equal(JSON.stringify(f.authority).includes(key.toString("hex")), false);
    f.store.close();
  });
});
