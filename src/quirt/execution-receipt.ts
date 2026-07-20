import { createHash, randomUUID } from "node:crypto";
import { canonicalJson, type Json } from "../canonical.js";
import type { QuirtCoreDumpState } from "./core-dump.js";
import type { QuirtLaunchForm } from "./launch-document.js";
import type { QuirtCgroupIdentity, QuirtNamespaceIdentities, QuirtProcessIdentity } from "./process-identity.js";
import type { QuirtResourceEvidence } from "./resource-accounting.js";
import type { QuirtTerminationEvidence } from "./execution-termination.js";
import type { QuirtJobStatus } from "./state.js";

export const QUIRT_EXECUTION_RECEIPT_SCHEMA_VERSION = "1.0.0" as const;

export interface QuirtExecutionReceiptInput {
  receiptId?: string;
  jobId: string;
  requestId: string;
  operationId: string;
  operationVersion: string;
  authenticatedSubject: string;
  authorityClass: string;
  principalFingerprint: string;
  targetHost: string;
  createdAt: string;
  startedAt: string | null;
  terminalAt: string;
  finalClassification: QuirtJobStatus;
  launchForm: QuirtLaunchForm;
  launchDocumentDigest: string;
  executableRequestedPath: string | null;
  executableObservedPath: string | null;
  executableSha256: string | null;
  interpreterIdentity: string | null;
  commandOrScriptDigest: string | null;
  workingDirectoryRequested: string;
  workingDirectoryObserved: string | null;
  environmentKeys: readonly string[];
  environmentPolicyDigest: string;
  processIdentity: QuirtProcessIdentity | null;
  cgroupIdentity: QuirtCgroupIdentity | null;
  namespaceIdentities: QuirtNamespaceIdentities | null;
  exitCode: number | null;
  exitSignal: string | null;
  timedOut: boolean;
  termination: QuirtTerminationEvidence | null;
  cancellation: QuirtTerminationEvidence | null;
  coreDump: QuirtCoreDumpState;
  stdoutStreamId: string;
  stdoutByteCount: number;
  stdoutDigest: string | null;
  stdoutDigestComplete: boolean;
  stderrStreamId: string;
  stderrByteCount: number;
  stderrDigest: string | null;
  stderrDigestComplete: boolean;
  stdinByteCount: number;
  stdinDigest: string | null;
  resourceEvidence: QuirtResourceEvidence | null;
  outputGap: boolean;
  ptyStreamModel: "combined" | "separate";
}

export interface QuirtExecutionReceipt extends QuirtExecutionReceiptInput {
  receiptSchemaVersion: typeof QUIRT_EXECUTION_RECEIPT_SCHEMA_VERSION;
  receiptId: string;
  receiptDigest: string;
}

function publicReceiptBody(input: QuirtExecutionReceiptInput): Json {
  return {
    receiptSchemaVersion: QUIRT_EXECUTION_RECEIPT_SCHEMA_VERSION,
    receiptId: input.receiptId ?? randomUUID(),
    jobId: input.jobId,
    requestId: input.requestId,
    operationId: input.operationId,
    operationVersion: input.operationVersion,
    authenticatedSubject: input.authenticatedSubject,
    authorityClass: input.authorityClass,
    principalFingerprint: input.principalFingerprint,
    targetHost: input.targetHost,
    createdAt: input.createdAt,
    startedAt: input.startedAt,
    terminalAt: input.terminalAt,
    finalClassification: input.finalClassification,
    launchForm: input.launchForm.kind,
    launchDocumentDigest: input.launchDocumentDigest,
    executableRequestedPath: input.executableRequestedPath,
    executableObservedPath: input.executableObservedPath,
    executableSha256: input.executableSha256,
    interpreterIdentity: input.interpreterIdentity,
    commandOrScriptDigest: input.commandOrScriptDigest,
    workingDirectoryRequested: input.workingDirectoryRequested,
    workingDirectoryObserved: input.workingDirectoryObserved,
    environmentKeys: [...input.environmentKeys],
    environmentPolicyDigest: input.environmentPolicyDigest,
    processIdentity: input.processIdentity as Json,
    cgroupIdentity: input.cgroupIdentity as Json,
    namespaceIdentities: input.namespaceIdentities as Json,
    exitCode: input.exitCode,
    exitSignal: input.exitSignal,
    timedOut: input.timedOut,
    termination: input.termination as Json,
    cancellation: input.cancellation as Json,
    coreDump: input.coreDump as Json,
    stdoutStreamId: input.stdoutStreamId,
    stdoutByteCount: input.stdoutByteCount,
    stdoutDigest: input.stdoutDigest,
    stdoutDigestComplete: input.stdoutDigestComplete,
    stderrStreamId: input.stderrStreamId,
    stderrByteCount: input.stderrByteCount,
    stderrDigest: input.stderrDigest,
    stderrDigestComplete: input.stderrDigestComplete,
    stdinByteCount: input.stdinByteCount,
    stdinDigest: input.stdinDigest,
    resourceEvidence: input.resourceEvidence as Json,
    outputGap: input.outputGap,
    ptyStreamModel: input.ptyStreamModel
  };
}

export function buildExecutionReceipt(input: QuirtExecutionReceiptInput): QuirtExecutionReceipt {
  const receiptId = input.receiptId ?? randomUUID();
  const body = publicReceiptBody({ ...input, receiptId });
  const receiptDigest = createHash("sha256").update(canonicalJson(body)).digest("hex");
  return Object.freeze({ ...input, receiptSchemaVersion: QUIRT_EXECUTION_RECEIPT_SCHEMA_VERSION, receiptId, receiptDigest });
}

export function receiptContainsSecret(receipt: QuirtExecutionReceipt, sentinel: string): boolean {
  return canonicalJson(receipt as unknown as Json).includes(sentinel);
}
