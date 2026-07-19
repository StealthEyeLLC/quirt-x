import { randomUUID } from "node:crypto";
import type { QuirtGatewayClient } from "./client.js";
import type { QuirtConfig } from "./config.js";
import { QuirtError, safeQuirtError } from "./error.js";
import type { QuirtGatewayAuditStore } from "./gateway-audit.js";
import type { QuirtCoreOperation } from "./operations.js";
import type { QuirtPrincipalEnvelope } from "./protocol.js";

export interface QuirtGatewayAuthContext {
  principalType: "user" | "service" | "admin";
  issuer: string;
  subject: string;
  workspaceId: string | null;
  principalFingerprint: string;
  principalGrantId: string;
  principalGrantVersion: number;
}

export interface QuirtGatewayResult extends Record<string, unknown> {
  requestId: string;
  correlationId: string;
  replayed: boolean;
  contentBase64?: string;
}

export class QuirtGatewayService {
  constructor(private readonly config: QuirtConfig, private readonly client: QuirtGatewayClient, private readonly audit: QuirtGatewayAuditStore) {}

  async invoke(input: { operation: QuirtCoreOperation; payload: Record<string, unknown>; binary: Buffer; requestId?: string; signal?: AbortSignal }, auth: QuirtGatewayAuthContext): Promise<QuirtGatewayResult> {
    if (auth.workspaceId !== null || auth.principalType !== "user" || auth.principalFingerprint !== this.config.expectedPrincipal.principalFingerprint || auth.issuer !== this.config.expectedPrincipal.issuer || auth.subject !== this.config.expectedPrincipal.subject) throw new QuirtError("authorization_failed", "Quirt Gateway principal is not authorized");
    const requestId = input.requestId ?? randomUUID();
    const principal: QuirtPrincipalEnvelope = {
      principalType: auth.principalType,
      issuer: auth.issuer,
      subject: auth.subject,
      workspaceId: auth.workspaceId,
      principalFingerprint: auth.principalFingerprint,
      grantId: auth.principalGrantId,
      grantVersion: auth.principalGrantVersion
    };
    const correlationId = this.audit.begin({ requestId, operation: input.operation, principalFingerprint: auth.principalFingerprint, targetHost: this.config.targetHost, inputBytes: input.binary.length });
    try {
      const attachedExecTimeout = input.operation === "quirt.exec" && input.payload.detach !== true && typeof input.payload.timeoutMs === "number" ? Math.min(30_000, input.payload.timeoutMs + 2_000) : this.config.requestTimeoutMs;
      const response = await this.client.request({ operation: input.operation, payload: input.payload, binary: input.binary, principal, requestId, timeoutMs: attachedExecTimeout, signal: input.signal });
      this.audit.finish(correlationId, { outcome: "succeeded", outputBytes: response.binary.length, replayed: response.replayed });
      return {
        ...response.payload,
        requestId,
        correlationId,
        replayed: response.replayed,
        ...(response.binary.length > 0 ? { contentBase64: response.binary.toString("base64") } : {})
      };
    } catch (cause) {
      const error = safeQuirtError(cause);
      this.audit.finish(correlationId, { outcome: "failed", safeErrorCode: error.code });
      throw error;
    }
  }
}
