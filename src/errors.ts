export type ErrorCode =
  | "AUTHENTICATION_FAILED" | "CONFIGURATION_ERROR" | "HOST_KEY_MISMATCH"
  | "MACHINE_ID_MISMATCH" | "INVALID_ARGUMENT" | "NOT_ALLOWED"
  | "NOT_FOUND" | "OUTPUT_LIMIT" | "SSH_FAILURE" | "SYMLINK_REJECTED"
  | "TIMEOUT" | "DIGEST_MISMATCH" | "IDEMPOTENCY_CONFLICT" | "INTERNAL"
  | "UPSTREAM_UNAVAILABLE" | "UPSTREAM_RESPONSE_INVALID";

export class OperatorError extends Error {
  constructor(public readonly code: ErrorCode, message: string, public readonly retryable = false) {
    super(message);
    this.name = "OperatorError";
  }
}

export function normalizeError(value: unknown): OperatorError {
  if (value instanceof OperatorError) return value;
  const message = value instanceof Error ? value.message : "Unknown connector failure";
  const safe = message.replace(/(?:password|token|private[_ -]?key|authorization)\s*[:=]\s*\S+/gi, "$1=[REDACTED]").slice(0, 512);
  if (/authentication|permission denied/i.test(message)) return new OperatorError("AUTHENTICATION_FAILED", "SSH authentication failed");
  if (/timed? ?out/i.test(message)) return new OperatorError("TIMEOUT", "SSH operation timed out", true);
  return new OperatorError("SSH_FAILURE", safe || "SSH operation failed", true);
}
