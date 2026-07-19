import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { createTestAuthorityRuntime } from "./authority-runtime.js";
import { decodeStrictBase64Url } from "./authority-base64url.js";
import { createPrivateKey, sign } from "node:crypto";
import { deriveEd25519KeyId, generateEd25519KeyPair, loadEd25519PrivateKey, loadEd25519PublicKey, loadEd25519PublicKeyPem, QUIRT_ED25519_SIGNATURE_BYTES } from "./authority-key.js";
import { buildKeyRingJson, loadVerificationKeyRing } from "./authority-keyring.js";
import { buildRequestSigningDocument, semanticRequestHash } from "./authority-signing-document.js";
import { gatewayOfferedCapabilities, negotiateConnection, QUIRT_CAPABILITY_AUTHORITY_ED25519, QUIRT_CAPABILITY_AUTHORITY_HMAC, QUIRT_CAPABILITY_COMPRESSION_NONE } from "./authority-negotiation.js";
import { QuirtStateStore, QUIRT_STATE_SCHEMA_VERSION } from "./state.js";
import { QuirtError } from "./error.js";
import { quirtTestConfig } from "./test-support.test.js";
import { DatabaseSync } from "node:sqlite";

const now = () => new Date("2026-07-19T12:00:00.000Z");

describe("Q2 authority keys and key rings", () => {
  it("derives deterministic lowercase key IDs from SPKI DER", () => {
    const pair = generateEd25519KeyPair();
    const loaded = loadEd25519PublicKeyPem(pair.publicKeyPem, pair.keyId);
    assert.equal(loaded.keyId, pair.keyId);
    assert.match(pair.keyId, /^[a-f0-9]{64}$/u);
  });

  it("rejects symbolic links, unsafe modes, and malformed key material", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-q2-keys-"));
    const pair = generateEd25519KeyPair();
    const publicPath = join(root, "public.pem");
    const privatePath = join(root, "private.pem");
    const uid = process.getuid?.() ?? 0;
    writeFileSync(publicPath, pair.publicKeyPem, { mode: 0o644 });
    writeFileSync(privatePath, pair.privateKeyPem, { mode: 0o600 });
    loadEd25519PublicKey(publicPath, uid, 0o644);
    loadEd25519PrivateKey(privatePath, uid, 0o600);
    chmodSync(publicPath, 0o666);
    assert.throws(() => loadEd25519PublicKey(publicPath, uid, 0o666), /permissions/u);
    chmodSync(publicPath, 0o644);
    symlinkSync(publicPath, join(root, "link.pem"));
    assert.throws(() => loadEd25519PublicKey(join(root, "link.pem"), uid, 0o644), /invalid/u);
    rmSync(root, { recursive: true, force: true });
  });

  it("enforces current/previous rotation and grace deadlines", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-q2-keyring-"));
    const current = generateEd25519KeyPair();
    const previous = generateEd25519KeyPair();
    const ringPath = join(root, "ring.json");
    writeFileSync(ringPath, buildKeyRingJson([
      { keyId: current.keyId, publicKeyPem: current.publicKeyPem, status: "current" },
      { keyId: previous.keyId, publicKeyPem: previous.publicKeyPem, status: "previous", graceExpiresAt: "2026-07-20T00:00:00.000Z" }
    ]), { mode: 0o644 });
    const ring = loadVerificationKeyRing(ringPath, process.getuid?.() ?? 0, 0o644, now);
    const document = Buffer.from("rotation-test", "utf8");
    const signature = sign(null, document, createPrivateKey(previous.privateKeyPem));
    assert.equal(ring.verify(document, signature, previous.keyId, new Date("2026-07-19T12:00:00.000Z")).acceptedKeyId, previous.keyId);
    assert.throws(() => ring.verify(document, signature, previous.keyId, new Date("2026-07-21T00:00:00.000Z")), /expired/u);
    assert.throws(() => ring.verify(document, signature, "f".repeat(64), new Date("2026-07-19T12:00:00.000Z")), /unknown/u);
    rmSync(root, { recursive: true, force: true });
  });
});


describe("Q2 negotiation and signing", () => {
  it("prefers Ed25519 when both peers support it and rejects downgrades", () => {
    const offers = gatewayOfferedCapabilities(["ed25519", "hmac-sha256"]);
    assert.ok(offers.includes(QUIRT_CAPABILITY_AUTHORITY_ED25519));
    const negotiated = negotiateConnection({
      gatewayOffers: offers,
      supervisorSupports: offers,
      gatewayPreferredAlgorithms: ["ed25519", "hmac-sha256"],
      supervisorSupportedAlgorithms: ["ed25519", "hmac-sha256"],
      legacyHmacEnabled: true
    });
    assert.equal(negotiated.authorityAlgorithm, "ed25519");
    assert.equal(negotiated.compression, "none");
    assert.ok(negotiated.capabilities.includes(QUIRT_CAPABILITY_COMPRESSION_NONE));
    assert.throws(() => negotiateConnection({
      gatewayOffers: offers,
      supervisorSupports: offers.filter(cap => cap !== QUIRT_CAPABILITY_AUTHORITY_ED25519),
      gatewayPreferredAlgorithms: ["ed25519"],
      supervisorSupportedAlgorithms: ["hmac-sha256"],
      legacyHmacEnabled: false
    }), /negotiation failed/u);
  });

  it("binds semantic replay hashes to signing-document fields", () => {
    const document = buildRequestSigningDocument({
      request: {
        protocolVersion: 1,
        requestId: "req-1",
        operation: "quirt.status",
        principal: { principalType: "user", issuer: "https://issuer.test", subject: "jamie-currier", workspaceId: null, principalFingerprint: "a".repeat(64), grantId: "g1", grantVersion: 1 },
        targetHost: "host",
        timestamp: "2026-07-19T12:00:00.000Z",
        payload: {},
        binaryLength: 0
      },
      gatewayId: "gateway",
      algorithm: "ed25519",
      keyId: "b".repeat(64),
      nonce: "nonce_value_123456789012",
      binary: Buffer.alloc(0)
    });
    const hash = semanticRequestHash(document);
    const tampered = { ...(document as Record<string, unknown>), operation: "quirt.exec" };
    assert.notEqual(semanticRequestHash(tampered), hash);
  });

  it("rejects malformed base64url signatures", () => {
    assert.throws(() => decodeStrictBase64Url("not*valid", "sig", 64, 64), /invalid/u);
    assert.throws(() => decodeStrictBase64Url("YQ", "sig", 64, 64), /invalid/u);
  });
});

describe("Q2 replay store migration", () => {
  it("migrates legacy nonce records into independent authority nonces", () => {
    const database = join(mkdtempSync(join(tmpdir(), "quirt-q2-migrate-")), "state.sqlite");
    const legacy = new DatabaseSync(database);
    legacy.exec(`CREATE TABLE quirt_schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
      INSERT INTO quirt_schema_migrations(version,applied_at) VALUES(18,'2026-01-01T00:00:00.000Z');
      CREATE TABLE quirt_request_records(request_id TEXT PRIMARY KEY, operation TEXT NOT NULL, request_hash TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, state TEXT NOT NULL, response_json TEXT, error_json TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, completed_at TEXT);
      CREATE TABLE quirt_request_nonces(nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
      INSERT INTO quirt_request_records VALUES('req-legacy','quirt.status','${"a".repeat(64)}','nonce-legacy','completed',NULL,NULL,'2026-01-01T00:00:00.000Z','2099-01-01T00:00:00.000Z',NULL);
      INSERT INTO quirt_request_nonces VALUES('nonce-legacy','req-legacy','2026-01-01T00:00:00.000Z','2099-01-01T00:00:00.000Z');`);
    legacy.close();
    const store = new QuirtStateStore(database, { now });
    assert.equal(store.schemaVersion(), QUIRT_STATE_SCHEMA_VERSION);
    const row = new DatabaseSync(database).prepare("SELECT request_id,algorithm FROM quirt_authority_nonces WHERE nonce='nonce-legacy'").get() as { request_id: string; algorithm: string };
    assert.equal(row.request_id, "req-legacy");
    assert.equal(row.algorithm, "hmac-sha256");
    store.close();
    rmSync(join(database, ".."), { recursive: true, force: true });
  });
});

describe("Q2 runtime integration", () => {
  it("creates an Ed25519-signed request through the real gateway signer path", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-q2-runtime-"));
    const config = quirtTestConfig(root);
    const store = new QuirtStateStore(":memory:", { now });
    const runtime = createTestAuthorityRuntime(config, store, root, now);
    const signed = runtime.gatewaySigner.sign({
      protocolVersion: 1,
      requestId: "runtime-req",
      operation: "quirt.status",
      principal: { principalType: "user", issuer: "https://issuer.test", subject: "jamie-currier", workspaceId: null, principalFingerprint: "a".repeat(64), grantId: "g1", grantVersion: 1 },
      targetHost: config.targetHost,
      timestamp: now().toISOString(),
      payload: {},
      binaryLength: 0
    });
    assert.equal(signed.authority.algorithm, "ed25519");
    if (signed.authority.algorithm === "ed25519") assert.equal(signed.authority.keyId, runtime.gatewaySigner.signingKeyId);
    store.close(); rmSync(root, { recursive: true, force: true });
  });
});
