import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { QuirtGatewayClient, QuirtClientResponse } from "./client.js";
import { QuirtError } from "./error.js";
import { QuirtGatewayAuditStore } from "./gateway-audit.js";
import { QuirtGatewayService, type QuirtGatewayAuthContext } from "./gateway-service.js";
import { quirtTestConfig } from "./test-support.test.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

const auth: QuirtGatewayAuthContext = { principalType: "user", issuer: "https://issuer.test", subject: "jamie-currier", workspaceId: null, principalFingerprint: "a".repeat(64), principalGrantId: "grant-1", principalGrantVersion: 1 };

describe("Quirt Gateway translation and audit", () => {
  it("forwards the exact principal and raw bytes while auditing metadata only", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-gateway-")); roots.push(root); const config = quirtTestConfig(root); const audit = new QuirtGatewayAuditStore(":memory:"); const calls: Array<Record<string, unknown>> = [];
    const client = { request: async (input: Record<string, unknown>): Promise<QuirtClientResponse> => { calls.push(input); return { payload: { ok: true, environmentKeys: ["TOP_SECRET"] }, binary: Buffer.from([0, 255]), replayed: false }; } } as unknown as QuirtGatewayClient;
    const service = new QuirtGatewayService(config, client, audit); const response = await service.invoke({ operation: "quirt.exec", payload: { command: "printf secret", environment: { TOP_SECRET: "never-audit-this" }, timeoutMs: 100 }, binary: Buffer.from([1, 2, 3]), requestId: "request-audit" }, auth);
    assert.equal((calls[0]?.principal as { subject: string }).subject, "jamie-currier"); assert.deepEqual(calls[0]?.binary, Buffer.from([1, 2, 3])); assert.equal(response.contentBase64, Buffer.from([0, 255]).toString("base64")); assert.equal(response.requestId, "request-audit");
    const receipt = audit.receipt(response.correlationId); assert.equal(receipt?.request_id, "request-audit"); assert.equal(receipt?.input_bytes, 3); assert.equal(receipt?.output_bytes, 2); assert.equal(receipt?.outcome, "succeeded"); assert.equal(JSON.stringify(receipt).includes("never-audit-this"), false); assert.equal(JSON.stringify(receipt).includes("printf secret"), false); audit.close();
  });

  it("fails closed on principal drift and records only a stable error code", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-gateway-error-")); roots.push(root); const config = quirtTestConfig(root); const audit = new QuirtGatewayAuditStore(":memory:"); const client = { request: async () => { throw new QuirtError("supervisor_unavailable", "private detail", true); } } as unknown as QuirtGatewayClient; const service = new QuirtGatewayService(config, client, audit);
    await assert.rejects(service.invoke({ operation: "quirt.status", payload: {}, binary: Buffer.alloc(0), requestId: "request-failed" }, auth), /private detail/u);
    const receipt = audit.latestForRequest("request-failed"); assert.equal(receipt?.outcome, "failed"); assert.equal(receipt?.safe_error_code, "supervisor_unavailable"); assert.equal(JSON.stringify(receipt).includes("private detail"), false);
    await assert.rejects(service.invoke({ operation: "quirt.status", payload: {}, binary: Buffer.alloc(0) }, { ...auth, workspaceId: "inherited" }), /not authorized/u);
    audit.close();
  });

  it("keeps recording bytes, file contents, and credentials out of metadata-only Gateway audit", async () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-gateway-recording-")); roots.push(root); const config = quirtTestConfig(root); const audit = new QuirtGatewayAuditStore(":memory:"); const secret = Buffer.from("recording-secret-and-file-content");
    const client = { request: async (): Promise<QuirtClientResponse> => ({ payload: { recordingId: "recording-1", credentialReference: "secret/reference" }, binary: secret, replayed: false }) } as unknown as QuirtGatewayClient; const service = new QuirtGatewayService(config, client, audit);
    const response = await service.invoke({ operation: "quirt.record.replay", payload: { recordingId: "recording-1" }, binary: Buffer.alloc(0), requestId: "recording-audit" }, auth); assert.equal(response.contentBase64, secret.toString("base64")); const receipt = audit.latestForRequest("recording-audit"); assert.equal(receipt?.output_bytes, secret.length); assert.equal(JSON.stringify(receipt).includes("recording-secret"), false); assert.equal(JSON.stringify(receipt).includes("secret/reference"), false); assert.equal(JSON.stringify(receipt).includes("recording-1"), false); audit.close();
  });
});
