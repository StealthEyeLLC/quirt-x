import { posix } from "node:path";
import * as tar from "tar";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtStateStore } from "./state.js";
import { QuirtTransferService as CoreTransferService, type QuirtTransferEvent } from "./transfer-service-core.js";

export type { QuirtTransferEvent };

const MAX_ARCHIVE_ENTRIES = 100_000;
const MAX_ARCHIVE_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_DEPTH = 64;

interface TarEntryLike {
  path: string;
  type?: string;
  size?: number;
  resume?: () => void;
}

function safeArchivePath(entry: TarEntryLike, seen: Set<string>): string | null {
  let raw = entry.path.replace(/^\.\//u, "");
  if (entry.type === "Directory" && raw.endsWith("/")) raw = raw.slice(0, -1);
  if ((raw === "" || raw === ".") && entry.type === "Directory") return null;
  if (raw.length === 0 || raw.length > 4096 || raw.startsWith("/") || raw.includes("\\") || raw.includes("\0")) throw new QuirtError("invalid_request", "Quirt archive path is unsafe");
  const segments = raw.split("/");
  if (segments.length > MAX_ARCHIVE_DEPTH || segments.some((segment) => segment.length === 0 || segment === "." || segment === ".." || /[\u0000-\u001f\u007f]/u.test(segment)) || posix.normalize(raw) !== raw) throw new QuirtError("invalid_request", "Quirt archive path is unsafe");
  const folded = raw.toLocaleLowerCase("en-US").normalize("NFC");
  if (seen.has(folded)) throw new QuirtError("conflict", "Quirt archive contains a duplicate or colliding path");
  seen.add(folded);
  return raw;
}

async function validateTarArchive(path: string): Promise<void> {
  const seen = new Set<string>();
  let count = 0;
  let expanded = 0;
  let failure: unknown = null;
  await tar.t({
    file: path,
    strict: true,
    onReadEntry: (entry: TarEntryLike) => {
      if (failure !== null) { entry.resume?.(); return; }
      try {
        const normalized = safeArchivePath(entry, seen);
        if (entry.type !== "File" && entry.type !== "Directory") throw new QuirtError("invalid_request", "Quirt archive contains a link or special file");
        const size = entry.size ?? 0;
        if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ARCHIVE_EXPANDED_BYTES) throw new QuirtError("invalid_request", "Quirt archive entry size is invalid");
        if (normalized !== null) { count += 1; expanded += size; }
        if (count > MAX_ARCHIVE_ENTRIES || expanded > MAX_ARCHIVE_EXPANDED_BYTES) throw new QuirtError("result_truncated", "Quirt archive exceeds extraction bounds");
      } catch (cause) { failure = cause; }
      entry.resume?.();
    }
  });
  if (failure !== null) throw failure;
}

/**
 * Active transfer service boundary. The extracted core preserves the audited
 * durable transfer state machine; this wrapper serializes mutation and applies
 * a fail-closed archive policy before the core can extract an uploaded tar.
 */
export class QuirtTransferService extends CoreTransferService {
  readonly #state: QuirtStateStore;
  readonly #locks = new Map<string, Promise<void>>();

  constructor(config: QuirtConfig, state: QuirtStateStore) {
    super(config, state);
    this.#state = state;
  }

  override async write(input: { transferId: string; offset: number; content: Buffer; chunkDigest?: string }, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    return await this.#exclusive(input.transferId, async () => await super.write(input, ownerPrincipalFingerprint));
  }

  override async complete(transferId: string, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    return await this.#exclusive(transferId, async () => {
      const record = this.#state.native.getTransfer(transferId, ownerPrincipalFingerprint);
      if (record.direction === "upload" && record.status === "active" && record.archiveFormat === "tar") {
        if (record.temporaryPath === null) throw new QuirtError("transfer_incomplete", "Quirt archive temporary object is unavailable");
        await validateTarArchive(record.temporaryPath);
      }
      return await super.complete(transferId, ownerPrincipalFingerprint);
    });
  }

  override async cancel(transferId: string, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    return await this.#exclusive(transferId, async () => await super.cancel(transferId, ownerPrincipalFingerprint));
  }

  async #exclusive<T>(transferId: string, action: () => Promise<T>): Promise<T> {
    const prior = this.#locks.get(transferId) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const tail = prior.then(() => gate);
    this.#locks.set(transferId, tail);
    await prior;
    try { return await action(); }
    finally {
      release();
      if (this.#locks.get(transferId) === tail) this.#locks.delete(transferId);
    }
  }
}
