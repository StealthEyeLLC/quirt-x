import { Duplex } from "node:stream";
import { join } from "node:path";
import type { QuirtConfig } from "./config.js";
import { loadQuirtConfig } from "./config.js";
import type { QuirtPrincipalEnvelope } from "./protocol.js";

class LinkedDuplex extends Duplex {
  peer: LinkedDuplex | null = null;
  override _read(): void {}
  override _write(chunk: Buffer | Uint8Array, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    const peer = this.peer;
    if (peer === null || peer.destroyed) { callback(new Error("memory peer is closed")); return; }
    peer.push(Buffer.from(chunk)); callback();
  }
  override _final(callback: (error?: Error | null) => void): void { this.peer?.push(null); callback(); }
  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void { this.peer?.push(null); callback(error); }
}

export function linkedDuplexPair(): [Duplex, Duplex] {
  const left = new LinkedDuplex(); const right = new LinkedDuplex(); left.peer = right; right.peer = left; return [left, right];
}

export function quirtTestConfig(root: string, overrides: NodeJS.ProcessEnv = {}): QuirtConfig {
  return loadQuirtConfig({
    QUIRT_MODE: "test",
    QUIRT_STATE_ROOT: root,
    QUIRT_DATABASE_PATH: join(root, "state.sqlite"),
    QUIRT_SOCKET_PATH: join(root, "quirt.sock"),
    QUIRT_AUTHORITY_SECRET_PATH: join(root, "authority.key"),
    QUIRT_TARGET_HOST: "vps-test-01",
    QUIRT_EXPECTED_ISSUER: "https://issuer.test",
    QUIRT_EXPECTED_SUBJECT: "jamie-currier",
    QUIRT_EXPECTED_PRINCIPAL_FINGERPRINT: "a".repeat(64),
    QUIRT_GATEWAY_UID: String(process.getuid?.() ?? 1000),
    QUIRT_CONNECTION_TIMEOUT_MS: "500",
    QUIRT_REQUEST_TIMEOUT_MS: "3000",
    QUIRT_LIVENESS_INTERVAL_MS: "1000",
    QUIRT_MAX_FRAME_BYTES: "1048576",
    QUIRT_MAX_BUFFERED_BYTES: "2097152",
    QUIRT_MAX_WRITE_QUEUE_BYTES: "1048576",
    QUIRT_OUTPUT_CHUNK_BYTES: "4096",
    QUIRT_OUTPUT_RETENTION_BYTES: "1048576",
    ...overrides
  });
}

export const TEST_PRINCIPAL: QuirtPrincipalEnvelope = Object.freeze({
  principalType: "user",
  issuer: "https://issuer.test",
  subject: "jamie-currier",
  workspaceId: null,
  principalFingerprint: "a".repeat(64),
  grantId: "grant-test-1",
  grantVersion: 1
});

export async function waitFor(predicate: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}
