import { randomUUID } from "node:crypto";
import { watch, type FSWatcher } from "node:fs";
import { chmod, chown, lstat, mkdir, opendir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { QuirtError } from "./error.js";
import { quirtPath, type QuirtFileType } from "./file-service.js";
import type { QuirtStateStore } from "./state.js";

interface DirectoryToken {
  path: string;
  device: number;
  inode: number;
  mtimeMs: number;
  afterName: string;
}

interface WatchSnapshotEntry { device: number; inode: number; type: QuirtFileType; mtimeMs: number; ctimeMs: number; size: number; mode: number; uid: number; gid: number; }
interface WatchHandle { watcher: FSWatcher; snapshot: Map<string, WatchSnapshotEntry>; scanning: boolean; }
const MAX_WATCH_EVENTS = 100_000;
const MAX_DIRECTORY_SCAN_BYTES = 64 * 1024 * 1024;

function type(value: Awaited<ReturnType<typeof lstat>>): QuirtFileType {
  if (value.isFile()) return "file"; if (value.isDirectory()) return "directory"; if (value.isSymbolicLink()) return "symlink";
  if (value.isSocket()) return "socket"; if (value.isFIFO()) return "fifo"; if (value.isBlockDevice()) return "block-device"; if (value.isCharacterDevice()) return "character-device"; return "unknown";
}

function encodeToken(value: DirectoryToken): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }
function decodeToken(value: string): DirectoryToken {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("object required");
    const token = parsed as Record<string, unknown>;
    if (typeof token.path !== "string" || typeof token.device !== "number" || typeof token.inode !== "number" || typeof token.mtimeMs !== "number" || typeof token.afterName !== "string") throw new Error("invalid token");
    return token as unknown as DirectoryToken;
  } catch { throw new QuirtError("invalid_request", "Quirt directory continuation token is invalid"); }
}

async function snapshot(root: string, recursive: boolean, maximumEntries = 100_000): Promise<Map<string, WatchSnapshotEntry>> {
  const output = new Map<string, WatchSnapshotEntry>(); const queue = [root]; let pathBytes = Buffer.byteLength(root);
  while (queue.length > 0) {
    const directoryPath = queue.shift()!; const directory = await opendir(directoryPath);
    try {
      for await (const entry of directory) {
        const path = join(directoryPath, entry.name); const raw = await lstat(path).catch(() => null); if (raw === null) continue;
        pathBytes += Buffer.byteLength(path); if (pathBytes > MAX_DIRECTORY_SCAN_BYTES) throw new QuirtError("result_truncated", "Quirt recursive watch exceeds the bounded path-byte count"); output.set(path, { device: raw.dev, inode: raw.ino, type: type(raw), mtimeMs: raw.mtimeMs, ctimeMs: raw.ctimeMs, size: raw.size, mode: raw.mode & 0o7777, uid: raw.uid, gid: raw.gid });
        if (recursive && raw.isDirectory() && !raw.isSymbolicLink()) queue.push(path);
        if (output.size > maximumEntries) throw new QuirtError("result_truncated", "Quirt recursive watch exceeds the bounded entry count");
      }
    } finally { await directory.close().catch(() => undefined); }
  }
  return output;
}

export class QuirtDirectoryService {
  readonly #watches = new Map<string, WatchHandle>();
  constructor(private readonly state: QuirtStateStore) {}

  async list(input: { path: string; workingDirectory?: string; followSymlinks?: boolean; maximumEntries?: number; continuationToken?: string }): Promise<Record<string, unknown>> {
    const path = quirtPath(input.path, input.workingDirectory); const maximum = input.maximumEntries ?? 256;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4096) throw new QuirtError("invalid_request", "Quirt directory page size is invalid");
    const before = input.followSymlinks === true ? await stat(path) : await lstat(path);
    if (!before.isDirectory()) throw new QuirtError("invalid_request", "Quirt directory list target is not a directory");
    let afterName = "";
    if (input.continuationToken !== undefined) {
      const token = decodeToken(input.continuationToken);
      if (token.path !== path || token.device !== before.dev || token.inode !== before.ino || token.mtimeMs !== before.mtimeMs) throw new QuirtError("source_changed", "Quirt directory changed between pages");
      afterName = token.afterName;
    }
    const names: string[] = []; const directory = await opendir(path); let truncatedScan = false; let nameBytes = 0;
    try {
      for await (const entry of directory) {
        nameBytes += Buffer.byteLength(entry.name); names.push(entry.name);
        if (names.length > 100_000 || nameBytes > MAX_DIRECTORY_SCAN_BYTES) { truncatedScan = true; break; }
      }
    } finally { await directory.close().catch(() => undefined); }
    if (truncatedScan) throw new QuirtError("result_truncated", "Quirt directory exceeds the bounded listing scan size");
    names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    const afterBytes = Buffer.from(afterName); const selected = names.filter(name => Buffer.from(name).compare(afterBytes) > 0).slice(0, maximum);
    const entries = [];
    for (const name of selected) {
      const entryPath = join(path, name); const raw = input.followSymlinks === true ? await stat(entryPath) : await lstat(entryPath);
      entries.push({ name, path: entryPath, type: type(raw), size: raw.size, device: raw.dev, inode: raw.ino, mode: raw.mode & 0o7777, uid: raw.uid, gid: raw.gid, mtime: raw.mtime.toISOString(), hidden: name.startsWith(".") });
    }
    const after = input.followSymlinks === true ? await stat(path) : await lstat(path);
    if (before.dev !== after.dev || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs) throw new QuirtError("changed_during_operation", "Quirt directory changed during listing", true);
    const lastBytes = selected.length === 0 ? null : Buffer.from(selected[selected.length - 1]!); const hasMore = lastBytes !== null && names.some(name => Buffer.from(name).compare(lastBytes) > 0);
    return {
      path, entries, entryCount: entries.length, hiddenIncluded: true, stableOrdering: "raw-name-bytes", changedDuringRead: false,
      continuationToken: hasMore ? encodeToken({ path, device: before.dev, inode: before.ino, mtimeMs: before.mtimeMs, afterName: selected[selected.length - 1]! }) : null
    };
  }

  async create(input: { path: string; workingDirectory?: string; recursive?: boolean; mode?: number; uid?: number; gid?: number; noClobber?: boolean }): Promise<Record<string, unknown>> {
    const path = quirtPath(input.path, input.workingDirectory); const mode = input.mode ?? 0o755;
    if (!Number.isSafeInteger(mode) || mode < 0 || mode > 0o7777 || input.uid !== undefined && (!Number.isSafeInteger(input.uid) || input.uid < 0 || input.uid > 0x7fffffff) || input.gid !== undefined && (!Number.isSafeInteger(input.gid) || input.gid < 0 || input.gid > 0x7fffffff)) throw new QuirtError("invalid_request", "Quirt directory mode or ownership is invalid");
    let existed = false; try { const existing = await lstat(path); if (!existing.isDirectory()) throw new QuirtError("already_exists", "Quirt directory path exists and is not a directory"); existed = true; } catch (cause) { if (cause instanceof QuirtError) throw cause; if (!(cause instanceof Error && "code" in cause && cause.code === "ENOENT")) throw cause; }
    if (existed && input.noClobber === true) throw new QuirtError("already_exists", "Quirt directory already exists");
    await mkdir(path, { recursive: input.recursive === true, mode });
    await chmod(path, mode);
    if (input.uid !== undefined || input.gid !== undefined) await chown(path, input.uid ?? -1, input.gid ?? -1);
    const result = await lstat(path);
    return { path, created: !existed, recursive: input.recursive === true, metadata: { device: result.dev, inode: result.ino, mode: result.mode & 0o7777, uid: result.uid, gid: result.gid, mtime: result.mtime.toISOString() } };
  }

  async watch(input: { action?: "start" | "read" | "cancel"; watchId?: string; path?: string; workingDirectory?: string; recursive?: boolean; after?: number; maximumEvents?: number }, ownerPrincipalFingerprint: string): Promise<Record<string, unknown>> {
    const action = input.action ?? "start";
    if (!["start", "read", "cancel"].includes(action)) throw new QuirtError("invalid_request", "Quirt watch action is invalid");
    if (action === "start") {
      if (input.path === undefined) throw new QuirtError("invalid_request", "Quirt watch path is required");
      const path = quirtPath(input.path, input.workingDirectory); const raw = await lstat(path); if (!raw.isDirectory()) throw new QuirtError("invalid_request", "Quirt watch target is not a directory");
      const watchId = input.watchId ?? randomUUID(); const recursive = input.recursive === true; const initial = await snapshot(path, recursive);
      const record = this.state.native.createWatch({ watchId, ownerPrincipalFingerprint, path, recursive });
      try {
        const watcher = watch(path, { recursive, persistent: false }, () => { void this.#rescan(watchId); });
        watcher.on("error", () => { try { if (this.state.native.watchEventCount(watchId) < MAX_WATCH_EVENTS) this.state.native.appendWatchEvent(watchId, "overflow", path, { reason: "kernel-watch-error" }); } catch {} this.state.native.updateWatch(watchId, { status: "lost", lost: true, rescanRequired: true }); this.#watches.get(watchId)?.watcher.close(); this.#watches.delete(watchId); });
        this.#watches.set(watchId, { watcher, snapshot: initial, scanning: false });
      } catch {
        this.state.native.updateWatch(watchId, { status: "failed", lost: true, rescanRequired: true });
        throw new QuirtError("unsupported_host_capability", "Quirt directory watching is unavailable on this host");
      }
      return { watch: record, eventDelivery: "at-least-once-kernel-derived", reconnectable: true, exactlyOnce: false };
    }
    if (input.watchId === undefined) throw new QuirtError("invalid_request", "Quirt watch ID is required");
    const record = this.state.native.getWatch(input.watchId, ownerPrincipalFingerprint);
    if (action === "cancel") {
      this.#watches.get(record.watchId)?.watcher.close(); this.#watches.delete(record.watchId);
      return { watch: this.state.native.updateWatch(record.watchId, { status: "canceled" }) };
    }
    const after = input.after ?? -1; const maximum = input.maximumEvents ?? 256;
    const events = this.state.native.readWatchEvents(record.watchId, after, maximum);
    return { watch: this.state.native.getWatch(record.watchId), events, nextSequence: events.length === 0 ? after : events[events.length - 1]!.sequence, truncated: events.length === maximum };
  }

  recover(): { lost: number } {
    for (const handle of this.#watches.values()) handle.watcher.close(); this.#watches.clear();
    return { lost: this.state.native.recoverWatches() };
  }

  shutdown(): void { for (const handle of this.#watches.values()) handle.watcher.close(); this.#watches.clear(); }

  async #rescan(watchId: string): Promise<void> {
    const handle = this.#watches.get(watchId); if (handle === undefined || handle.scanning) return; handle.scanning = true;
    try {
      const record = this.state.native.getWatch(watchId); const current = await snapshot(record.path, record.recursive);
      const removed = [...handle.snapshot.entries()].filter(([path]) => !current.has(path));
      const added = [...current.entries()].filter(([path]) => !handle.snapshot.has(path));
      const consumedAdded = new Set<string>(); const consumedRemoved = new Set<string>();
      for (const [oldPath, oldEntry] of removed) {
        const moved = added.find(([newPath, value]) => !consumedAdded.has(newPath) && value.device === oldEntry.device && value.inode === oldEntry.inode);
        if (moved !== undefined) { this.#append(watchId, "move", oldPath, { destination: moved[0], identity: { device: oldEntry.device, inode: oldEntry.inode } }); consumedRemoved.add(oldPath); consumedAdded.add(moved[0]); }
      }
      for (const [path, value] of removed) if (!consumedRemoved.has(path)) this.#append(watchId, "delete", path, { identity: { device: value.device, inode: value.inode }, type: value.type });
      for (const [path, value] of added) if (!consumedAdded.has(path)) this.#append(watchId, "create", path, { identity: { device: value.device, inode: value.inode }, type: value.type });
      for (const [path, value] of current) {
        const previous = handle.snapshot.get(path);
        if (previous !== undefined) { const contentChanged = previous.mtimeMs !== value.mtimeMs || previous.size !== value.size; const metadataChanged = previous.ctimeMs !== value.ctimeMs || previous.mode !== value.mode || previous.uid !== value.uid || previous.gid !== value.gid; if (contentChanged) this.#append(watchId, "modify", path, { identity: { device: value.device, inode: value.inode }, metadataChanged }); else if (metadataChanged) this.#append(watchId, "metadata", path, { identity: { device: value.device, inode: value.inode }, mode: value.mode, uid: value.uid, gid: value.gid }); }
      }
      handle.snapshot = current;
    } catch {
      this.state.native.updateWatch(watchId, { status: "lost", lost: true, rescanRequired: true }); handle.watcher.close(); this.#watches.delete(watchId);
    } finally { const active = this.#watches.get(watchId); if (active !== undefined) active.scanning = false; }
  }

  #append(watchId: string, event: string, path: string, details: Readonly<Record<string, unknown>>): void {
    if (this.state.native.watchEventCount(watchId) >= MAX_WATCH_EVENTS - 1) { this.state.native.appendWatchEvent(watchId, "overflow", path, { reason: "bounded-event-buffer" }); this.state.native.updateWatch(watchId, { status: "lost", lost: true, rescanRequired: true }); this.#watches.get(watchId)?.watcher.close(); this.#watches.delete(watchId); throw new QuirtError("watch_overflow", "Quirt directory watch overflowed and requires a rescan", true); }
    this.state.native.appendWatchEvent(watchId, event, path, details);
  }
}
