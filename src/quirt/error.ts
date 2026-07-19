export type QuirtErrorCode =
  | "already_exists"
  | "authentication_failed"
  | "authentication_unavailable"
  | "authorization_failed"
  | "changed_during_operation"
  | "configuration_error"
  | "conflict"
  | "credentials_unavailable"
  | "digest_mismatch"
  | "duplicate_request"
  | "frame_too_large"
  | "idempotency_conflict"
  | "internal_error"
  | "invalid_frame"
  | "invalid_offset"
  | "invalid_request"
  | "journal_cursor_invalidated"
  | "not_found"
  | "object_missing"
  | "output_gap"
  | "pid_reused"
  | "process_exited"
  | "protocol_mismatch"
  | "provider_unavailable"
  | "queue_overflow"
  | "range_gap"
  | "repository_corrupt"
  | "request_canceled"
  | "result_truncated"
  | "signature_unverifiable"
  | "source_changed"
  | "stale_request"
  | "supervisor_unavailable"
  | "symlink_conflict"
  | "timeout"
  | "transfer_canceled"
  | "transfer_incomplete"
  | "unsupported_host_capability"
  | "watch_overflow"
  | "unknown_operation"
  | "executable_missing"
  | "executable_version_unsupported"
  | "host_feature_unavailable"
  | "configuration_missing"
  | "credentials_rejected"
  | "port_unavailable"
  | "unsafe_listener"
  | "readiness_timeout"
  | "process_identity_changed"
  | "provider_degraded"
  | "provider_lost"
  | "instance_not_found"
  | "instance_conflict"
  | "stale_instance"
  | "backend_unsupported"
  | "mount_unavailable"
  | "browser_crashed"
  | "page_gone"
  | "synchronization_conflict"
  | "snapshot_corrupt"
  | "restore_conflict"
  | "tunnel_handshake_failure"
  | "host_key_mismatch"
  | "trace_permission_denied"
  | "kernel_feature_unavailable"
  | "checkpoint_incompatible"
  | "desktop_unavailable"
  | "fleet_host_unavailable"
  | "output_truncated"
  | "canceled"
  | "replay_conflict"
  | "wrong_principal"
  | "wrong_target_host";

const QUIRT_ERROR_CODES = new Set<QuirtErrorCode>([
  "already_exists", "authentication_failed", "authentication_unavailable", "authorization_failed",
  "changed_during_operation", "configuration_error", "conflict", "credentials_unavailable", "digest_mismatch",
  "duplicate_request", "frame_too_large", "idempotency_conflict", "internal_error", "invalid_frame",
  "invalid_offset", "invalid_request", "journal_cursor_invalidated", "not_found", "object_missing", "output_gap",
  "pid_reused", "process_exited", "protocol_mismatch", "provider_unavailable", "queue_overflow", "range_gap",
  "repository_corrupt", "request_canceled", "result_truncated", "signature_unverifiable", "source_changed", "stale_request",
  "supervisor_unavailable", "symlink_conflict", "timeout", "transfer_canceled", "transfer_incomplete",
  "unsupported_host_capability", "watch_overflow", "unknown_operation",
  "executable_missing", "executable_version_unsupported", "host_feature_unavailable", "configuration_missing",
  "credentials_rejected", "port_unavailable", "unsafe_listener", "readiness_timeout", "process_identity_changed",
  "provider_degraded", "provider_lost", "instance_not_found", "instance_conflict", "stale_instance",
  "backend_unsupported", "mount_unavailable", "browser_crashed", "page_gone", "synchronization_conflict",
  "snapshot_corrupt", "restore_conflict", "tunnel_handshake_failure", "host_key_mismatch", "trace_permission_denied",
  "kernel_feature_unavailable", "checkpoint_incompatible", "desktop_unavailable", "fleet_host_unavailable",
  "output_truncated", "canceled", "replay_conflict", "wrong_principal", "wrong_target_host"
]);

export function quirtErrorCode(value: unknown): QuirtErrorCode {
  return typeof value === "string" && QUIRT_ERROR_CODES.has(value as QuirtErrorCode) ? value as QuirtErrorCode : "internal_error";
}

export class QuirtError extends Error {
  constructor(
    public readonly code: QuirtErrorCode,
    message: string,
    public readonly retryable = false,
    public readonly details: Readonly<Record<string, unknown>> = Object.freeze({})
  ) {
    super(message);
    this.name = "QuirtError";
  }
}

export function safeQuirtError(value: unknown): QuirtError {
  if (value instanceof QuirtError) return value;
  return new QuirtError("internal_error", "Quirt failed safely", false);
}

export function errorCode(value: unknown): QuirtErrorCode {
  if (value instanceof QuirtError) return value.code;
  if (typeof value === "object" && value !== null && "code" in value && typeof (value as QuirtError).code === "string") return quirtErrorCode((value as QuirtError).code);
  return "internal_error";
}
