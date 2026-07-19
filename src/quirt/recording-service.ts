import { createHash, randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtSessionManager, QuirtSessionOutputEvent } from "./session-manager.js";
import type { QuirtNativeObjectRecord } from "./native-state.js";
import type { QuirtStateStore } from "./state.js";

interface RecordingHandle { recordingId: string; sessionId: string; owner: string; decoder: StringDecoder; }

const RECORDING_SEARCH_SCAN_MAX = 32 * 1024 * 1024;
const RECORDING_REPLAY_MAX = 8 * 1024 * 1024;
const RECORDING_EVENT_PAGE = 8;
const RECORDING_INDEX_PAGE = 128;

class RecordingExportPage {
  readonly #hash = createHash("sha256");
  readonly #parts: Buffer[] = [];
  size = 0;
  constructor(private readonly offset: number, private readonly maximum: number) {}
  add(value: Buffer | string): void {
    const bytes = typeof value === "string" ? Buffer.from(value) : value;
    const start = this.size; const end = start + bytes.length; this.#hash.update(bytes); this.size = end;
    const overlapStart = Math.max(start, this.offset); const overlapEnd = Math.min(end, this.offset + this.maximum);
    if (overlapStart < overlapEnd) this.#parts.push(Buffer.from(bytes.subarray(overlapStart - start, overlapEnd - start)));
  }
  finish(): { binary: Buffer; sha256: string } { return { binary: Buffer.concat(this.#parts), sha256: this.#hash.digest("hex") }; }
}

function number(value: unknown, fallback = 0): number { return typeof value === "number" && Number.isSafeInteger(value) ? value : fallback; }
function string(value: unknown): string | null { return typeof value === "string" ? value : null; }
function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter(item => typeof item === "string") as string[] : []; }
function terminalText(value: string): string { return value.replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)/gu, "").replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, ""); }
function html(value: string): string { return value.replace(/&/gu, "&amp;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;").replace(/"/gu, "&quot;"); }
function recordingListToken(value: string): { afterCreatedAt: string; afterObjectId: string } {
  try { const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown; if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("object required"); const token = parsed as Record<string, unknown>; if (typeof token.createdAt !== "string" || !Number.isFinite(Date.parse(token.createdAt)) || typeof token.objectId !== "string" || token.objectId.length < 1 || Buffer.byteLength(token.objectId) > 128) throw new Error("invalid token"); return { afterCreatedAt: token.createdAt, afterObjectId: token.objectId }; }
  catch { throw new QuirtError("invalid_request", "Quirt recording continuation token is invalid"); }
}

export class QuirtRecordingService {
  readonly #active = new Map<string, RecordingHandle>(); readonly #bySession = new Map<string, Set<string>>(); readonly #unsubscribe: () => void;
  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore, private readonly sessions: QuirtSessionManager) { this.#unsubscribe = sessions.onEvent(event => this.#event(event)); }

  start(input: { sessionId?: string; name?: string; retentionUntil?: string; marker?: string; bookmark?: string; recordingId?: string }, owner: string): Record<string, unknown> {
    if (input.recordingId !== undefined && (input.marker !== undefined || input.bookmark !== undefined)) return this.marker(input.recordingId, input.marker, input.bookmark, owner);
    if (input.sessionId === undefined) throw new QuirtError("invalid_request", "Quirt recording session is required");
    const session = this.sessions.get(input.sessionId, owner); if ((this.#bySession.get(session.sessionId)?.size ?? 0) > 0) throw new QuirtError("conflict", "Quirt session already has an active recording");
    if (input.retentionUntil !== undefined && !Number.isFinite(Date.parse(input.retentionUntil))) throw new QuirtError("invalid_request", "Quirt recording retention timestamp is invalid");
    const recordingId = input.recordingId ?? randomUUID(); const startedAt = new Date().toISOString(); const data = { recordingId, sessionId: session.sessionId, name: input.name ?? `recording-${recordingId.slice(0, 8)}`, startedAt, stoppedAt: null, durationMilliseconds: null, nextSequence: 0, eventCount: 0, byteCount: 0, inputBytes: 0, outputBytes: 0, resizeCount: 0, signalCount: 0, markers: [], bookmarks: [], retentionUntil: input.retentionUntil ?? null, interrupted: false, lossIndicators: [], terminal: { columns: session.columns, rows: session.rows }, processId: session.ptyPid, formats: ["quirt-json-v1", "asciinema-v2", "html-transcript"] };
    const record = this.state.native.putObject("quirt_recordings", { objectId: recordingId, ownerPrincipalFingerprint: owner, status: "active", data }); this.#activate(recordingId, session.sessionId, owner);
    this.#append(recordingId, owner, "marker", Buffer.from("recording-start"), { marker: "recording-start" }); return this.#public(this.state.native.getObject("quirt_recordings", recordingId, owner));
  }

  marker(recordingId: string, marker: string | undefined, bookmark: string | undefined, owner: string): Record<string, unknown> {
    const record = this.state.native.getObject("quirt_recordings", recordingId, owner); if (record.status !== "active") throw new QuirtError("invalid_request", "Quirt recording is not active");
    if (marker === undefined && bookmark === undefined) throw new QuirtError("invalid_request", "Quirt recording marker or bookmark is required");
    if (marker !== undefined) this.#append(recordingId, owner, "marker", Buffer.from(marker), { marker }); if (bookmark !== undefined) this.#append(recordingId, owner, "bookmark", Buffer.from(bookmark), { bookmark });
    return this.#public(this.state.native.getObject("quirt_recordings", recordingId, owner));
  }

  stop(input: { recordingId: string; remove?: boolean }, owner: string): Record<string, unknown> {
    const current = this.state.native.getObject("quirt_recordings", input.recordingId, owner);
    if (input.remove === true) { if (current.status === "active") throw new QuirtError("conflict", "Active Quirt recording must be stopped before removal"); this.state.native.removeRecording(input.recordingId, owner); return { recordingId: input.recordingId, removed: true }; }
    if (current.status === "completed") return { recording: this.#public(current), duplicate: true };
    if (current.status !== "active" && current.status !== "interrupted") throw new QuirtError("invalid_request", "Quirt recording cannot be stopped in its current state");
    if (current.status === "active") this.#append(input.recordingId, owner, "marker", Buffer.from("recording-stop"), { marker: "recording-stop" }); this.#deactivate(input.recordingId);
    const latest = this.state.native.getObject("quirt_recordings", input.recordingId, owner); const stoppedAt = new Date().toISOString(); const data = { ...latest.data, stoppedAt, durationMilliseconds: Math.max(0, Date.parse(stoppedAt) - Date.parse(string(latest.data.startedAt) ?? latest.createdAt)) };
    const completed = this.state.native.putObject("quirt_recordings", { objectId: input.recordingId, ownerPrincipalFingerprint: owner, status: "completed", data }); return { recording: this.#public(completed), duplicate: false };
  }

  list(owner: string, input: { maximumRecordings?: number; continuationToken?: string } = {}): Record<string, unknown> {
    const maximum = input.maximumRecordings ?? 256; if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1000) throw new QuirtError("invalid_request", "Quirt recording list bound is invalid"); const cursor = input.continuationToken === undefined ? {} : recordingListToken(input.continuationToken); const page = this.state.native.listObjectsPage("quirt_recordings", owner, { maximum, ...cursor });
    return { recordings: page.records.map(record => this.#public(record)), truncated: page.truncated, continuationToken: page.next === null ? null : Buffer.from(JSON.stringify(page.next)).toString("base64url"), ordering: "created-at-recording-id" };
  }

  search(input: { recordingId: string; query: string; regularExpression?: boolean; caseSensitive?: boolean; maximumMatches?: number }, owner: string): Record<string, unknown> {
    this.state.native.getObject("quirt_recordings", input.recordingId, owner); const maximum = input.maximumMatches ?? 100; if (maximum < 1 || maximum > 1000) throw new QuirtError("invalid_request", "Quirt recording search bound is invalid");
    let expression: RegExp | null = null; try { if (input.regularExpression === true) expression = new RegExp(input.query, input.caseSensitive === true ? "u" : "iu"); } catch { throw new QuirtError("invalid_request", "Quirt recording search expression is invalid"); }
    const needle = input.caseSensitive === true ? input.query : input.query.toLocaleLowerCase(); const matches = []; let after = -1; let scannedBytes = 0; let scannedIndexes = 0; let truncated = false;
    scan: while (matches.length < maximum) {
      const indexes = this.state.native.recordingIndexes(input.recordingId, after, RECORDING_INDEX_PAGE); if (indexes.length === 0) break;
      for (const index of indexes) {
        const bytes = Buffer.byteLength(index.text); if (scannedBytes + bytes > RECORDING_SEARCH_SCAN_MAX) { truncated = true; break scan; } scannedBytes += bytes; scannedIndexes += 1; after = index.sequence;
        const value = input.caseSensitive === true ? index.text : index.text.toLocaleLowerCase(); const regexMatch = expression?.exec(index.text) ?? null; const literalIndex = expression === null ? value.indexOf(needle) : -1; const matchIndex = regexMatch?.index ?? literalIndex; if (matchIndex < 0) continue;
        const matchText = regexMatch?.[0] ?? input.query; const event = this.state.native.recordingEvent(input.recordingId, index.sequence); const textByteOffset = Buffer.byteLength(index.text.slice(0, matchIndex)); const rawText = event?.payload.toString("utf8") ?? ""; const rawOffsetExact = event !== null && terminalText(rawText) === rawText;
        matches.push({ sequence: index.sequence, eventStreamOffset: index.byteOffset, streamOffset: rawOffsetExact && index.byteOffset !== null ? index.byteOffset + textByteOffset : index.byteOffset, textByteOffset, rawOffsetExact, text: index.text.slice(0, 8192), matchIndex, match: matchText });
        if (matches.length >= maximum) { truncated = this.state.native.recordingIndexes(input.recordingId, after, 1).length > 0; break scan; }
      }
      if (indexes.length < RECORDING_INDEX_PAGE) break;
    }
    return { recordingId: input.recordingId, matches, truncated, ordering: "event-sequence", rawRecordingRetained: true, scannedBytes, scannedIndexes, nextSequence: after, maximumScannedBytes: RECORDING_SEARCH_SCAN_MAX };
  }

  replay(input: { recordingId: string; afterSequence?: number; maximumEvents?: number; speed?: number }, owner: string): { payload: Record<string, unknown>; binary: Buffer } {
    const record = this.state.native.getObject("quirt_recordings", input.recordingId, owner); const maximum = input.maximumEvents ?? 256; const speed = input.speed ?? 1;
    if (maximum < 1 || maximum > 1000 || !Number.isFinite(speed) || speed <= 0 || speed > 100) throw new QuirtError("invalid_request", "Quirt recording replay bounds are invalid");
    const maximumBytes = Math.max(1, Math.min(RECORDING_REPLAY_MAX, this.config.maxFrameBytes - 64 * 1024)); const events = []; let after = input.afterSequence ?? -1; let byteLimitReached = false;
    while (events.length < maximum) {
      const pageSize = Math.min(RECORDING_EVENT_PAGE, maximum - events.length); const page = this.state.native.recordingEvents(input.recordingId, after, pageSize); if (page.length === 0) break;
      const used = events.reduce((total, item) => total + item.payload.length, 0); let pageUsed = used; for (const event of page) { if (pageUsed + event.payload.length > maximumBytes) { if (events.length === 0) throw new QuirtError("result_truncated", "A Quirt recording event exceeds the bounded replay frame"); byteLimitReached = true; break; } events.push(event); pageUsed += event.payload.length; after = event.sequence; }
      if (byteLimitReached || page.length < pageSize) break;
    }
    const parts: Buffer[] = []; let offset = 0;
    const manifest = events.map(event => { const start = offset; parts.push(event.payload); offset += event.payload.length; return { sequence: event.sequence, eventType: event.eventType, streamOffset: event.streamOffset, timestampNs: event.timestampNs, payloadOffset: start, payloadLength: event.payload.length, sha256: event.sha256, metadata: event.metadata }; });
    const hasMore = this.state.native.recordingEvents(input.recordingId, after, 1).length > 0;
    return { payload: { recording: this.#public(record), events: manifest, nextSequence: after, truncated: byteLimitReached || hasMore, speed, timingScale: 1 / speed, byteCount: offset, maximumBytes }, binary: Buffer.concat(parts) };
  }

  export(input: { recordingId: string; format: "quirt-json-v1" | "asciinema-v2" | "html-transcript"; offset?: number; maximumBytes?: number }, owner: string): { payload: Record<string, unknown>; binary: Buffer } {
    const record = this.state.native.getObject("quirt_recordings", input.recordingId, owner); if (record.status === "active") throw new QuirtError("conflict", "Active Quirt recording must be stopped before export");
    const offset = input.offset ?? 0; const maximum = input.maximumBytes ?? 1024 * 1024; if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024 * 1024) throw new QuirtError("invalid_offset", "Quirt recording export page is invalid"); const output = new RecordingExportPage(offset, maximum);
    const eventCount = this.state.native.recordingEventCount(input.recordingId); const indexCount = this.state.native.recordingIndexCount(input.recordingId);
    if (input.format === "quirt-json-v1") {
      output.add(`${JSON.stringify({ kind: "quirt-recording-manifest", version: 1, recording: this.#public(record), eventCount, indexCount, rawByteFidelity: true })}\n`);
      for (let after = -1;;) { const events = this.state.native.recordingEvents(input.recordingId, after, RECORDING_EVENT_PAGE); if (events.length === 0) break; for (const event of events) output.add(`${JSON.stringify({ kind: "event", sequence: event.sequence, eventType: event.eventType, streamOffset: event.streamOffset, timestampNs: event.timestampNs, payloadBase64: event.payload.toString("base64"), sha256: event.sha256, metadata: event.metadata })}\n`); after = events.at(-1)!.sequence; }
      for (let after = -1;;) { const indexes = this.state.native.recordingIndexes(input.recordingId, after, RECORDING_INDEX_PAGE); if (indexes.length === 0) break; for (const index of indexes) output.add(`${JSON.stringify({ kind: "index", sequence: index.sequence, text: index.text, byteOffset: index.byteOffset })}\n`); after = indexes.at(-1)!.sequence; }
    } else if (input.format === "asciinema-v2") {
      const started = this.state.native.recordingEvents(input.recordingId, -1, 1)[0]?.timestampNs ?? 0; const terminal = record.data.terminal !== null && typeof record.data.terminal === "object" && !Array.isArray(record.data.terminal) ? record.data.terminal as Record<string, unknown> : {}; output.add(`${JSON.stringify({ version: 2, width: number(terminal.columns, 120), height: number(terminal.rows, 40), timestamp: Math.floor(Date.parse(string(record.data.startedAt) ?? record.createdAt) / 1000), env: { TERM: "xterm-256color", SHELL: this.config.shellPath } })}\n`);
      for (let after = -1;;) { const events = this.state.native.recordingEvents(input.recordingId, after, RECORDING_EVENT_PAGE); if (events.length === 0) break; for (const event of events) if (event.eventType === "terminal-output" || event.eventType === "terminal-input") output.add(`${JSON.stringify([(event.timestampNs - started) / 1_000_000_000, event.eventType === "terminal-output" ? "o" : "i", event.payload.toString("utf8")])}\n`); after = events.at(-1)!.sequence; }
    } else {
      output.add(`<!doctype html><meta charset="utf-8"><title>${html(string(record.data.name) ?? "Quirt recording")}</title><pre>`); for (let after = -1;;) { const events = this.state.native.recordingEvents(input.recordingId, after, RECORDING_EVENT_PAGE); if (events.length === 0) break; for (const event of events) if (event.eventType === "terminal-output") output.add(html(terminalText(event.payload.toString("utf8")))); after = events.at(-1)!.sequence; } output.add("</pre>\n");
    }
    const completed = output.finish(); if (offset > output.size) throw new QuirtError("invalid_offset", "Quirt recording export offset is beyond the export"); const exportId = createHash("sha256").update(`${input.recordingId}\0${input.format}\0${completed.sha256}`).digest("hex"); this.state.native.putObject("quirt_recording_exports", { objectId: exportId, ownerPrincipalFingerprint: owner, status: "ready", data: { exportId, recordingId: input.recordingId, format: input.format, size: output.size, sha256: completed.sha256 } });
    return { payload: { exportId, recordingId: input.recordingId, format: input.format, size: output.size, sha256: completed.sha256, offset, nextOffset: offset + completed.binary.length, eof: offset + completed.binary.length >= output.size, byteCount: completed.binary.length }, binary: completed.binary };
  }

  recover(owner: string): { resumed: number; interrupted: number } {
    let resumed = 0; let interrupted = 0; let cursor: { afterCreatedAt?: string; afterObjectId?: string } = {}; const recoverableSessions = new Set(this.sessions.list(owner).filter(session => ["running", "detached"].includes(session.status)).map(session => session.sessionId));
    while (true) {
      const page = this.state.native.listObjectsPage("quirt_recordings", owner, { maximum: 1000, ...cursor });
      for (const record of page.records) {
        if (record.status !== "active") continue; const sessionId = string(record.data.sessionId); if (sessionId !== null && recoverableSessions.has(sessionId)) {
          const data = { ...record.data, interrupted: true, lossIndicators: [...strings(record.data.lossIndicators), "supervisor-restart-gap"] }; this.state.native.putObject("quirt_recordings", { objectId: record.objectId, ownerPrincipalFingerprint: owner, status: "active", data }); this.#activate(record.objectId, sessionId, owner); this.#append(record.objectId, owner, "recovery", Buffer.alloc(0), { outputGapPossible: true }); resumed += 1;
        } else { const stoppedAt = new Date().toISOString(); this.state.native.putObject("quirt_recordings", { objectId: record.objectId, ownerPrincipalFingerprint: owner, status: "interrupted", data: { ...record.data, interrupted: true, stoppedAt, durationMilliseconds: Math.max(0, Date.parse(stoppedAt) - Date.parse(string(record.data.startedAt) ?? record.createdAt)), lossIndicators: [...strings(record.data.lossIndicators), "session-unavailable-after-restart"] } }); interrupted += 1; }
      }
      if (page.next === null) break; cursor = { afterCreatedAt: page.next.createdAt, afterObjectId: page.next.objectId };
    }
    return { resumed, interrupted };
  }

  shutdown(): void { this.#unsubscribe(); for (const id of [...this.#active.keys()]) this.#deactivate(id); }

  #activate(recordingId: string, sessionId: string, owner: string): void { const handle = { recordingId, sessionId, owner, decoder: new StringDecoder("utf8") }; this.#active.set(recordingId, handle); const set = this.#bySession.get(sessionId) ?? new Set<string>(); set.add(recordingId); this.#bySession.set(sessionId, set); }
  #deactivate(recordingId: string): void { const handle = this.#active.get(recordingId); if (handle === undefined) return; this.#active.delete(recordingId); const set = this.#bySession.get(handle.sessionId); set?.delete(recordingId); if (set?.size === 0) this.#bySession.delete(handle.sessionId); }

  #event(event: QuirtSessionOutputEvent): void {
    for (const recordingId of this.#bySession.get(event.sessionId) ?? []) {
      const handle = this.#active.get(recordingId); if (handle === undefined) continue;
      if (event.event === "session.output") this.#append(recordingId, handle.owner, "terminal-output", event.bytes ?? Buffer.alloc(0), { startOffset: event.startOffset, endOffset: event.endOffset }, event.startOffset, handle.decoder.write(event.bytes ?? Buffer.alloc(0)));
      else if (event.event === "session.input") this.#append(recordingId, handle.owner, "terminal-input", event.bytes ?? Buffer.alloc(0), {});
      else if (event.event === "session.resize") this.#append(recordingId, handle.owner, "terminal-resize", Buffer.alloc(0), { columns: event.columns, rows: event.rows });
      else if (event.event === "session.signal") this.#append(recordingId, handle.owner, "terminal-signal", Buffer.alloc(0), { signal: event.signal });
      else if (event.event === "session.exit") this.#append(recordingId, handle.owner, "session-exit", Buffer.alloc(0), { exitCode: event.exitCode, exitSignal: event.exitSignal });
      else if (event.event === "session.recovered") this.#append(recordingId, handle.owner, "recovery", Buffer.alloc(0), { outputGapPossible: true });
    }
  }

  #append(recordingId: string, owner: string, eventType: string, payload: Buffer, metadata: Readonly<Record<string, unknown>>, streamOffset?: number, transcript?: string): void {
    this.state.native.transaction(() => {
      const record = this.state.native.getObject("quirt_recordings", recordingId, owner); const sequence = number(record.data.nextSequence); const digest = createHash("sha256").update(payload).digest("hex"); const timestampNs = Number(process.hrtime.bigint()); const realtimeTimestamp = new Date().toISOString(); const eventMetadata = { ...metadata, realtimeTimestamp }; const text = transcript === undefined ? undefined : terminalText(transcript);
      this.state.native.appendRecordingEvent({ recordingId, sequence, eventType, streamOffset, timestampNs, payload, metadata: eventMetadata, sha256: digest, ...(text === undefined || text.length === 0 ? {} : { text }) });
      const markers = strings(record.data.markers); const bookmarks = strings(record.data.bookmarks); if (eventType === "marker" && typeof metadata.marker === "string") markers.push(metadata.marker); if (eventType === "bookmark" && typeof metadata.bookmark === "string") bookmarks.push(metadata.bookmark);
      const data = { ...record.data, nextSequence: sequence + 1, eventCount: number(record.data.eventCount) + 1, byteCount: number(record.data.byteCount) + payload.length, inputBytes: number(record.data.inputBytes) + (eventType === "terminal-input" ? payload.length : 0), outputBytes: number(record.data.outputBytes) + (eventType === "terminal-output" ? payload.length : 0), resizeCount: number(record.data.resizeCount) + (eventType === "terminal-resize" ? 1 : 0), signalCount: number(record.data.signalCount) + (eventType === "terminal-signal" ? 1 : 0), markers, bookmarks };
      this.state.native.putObject("quirt_recordings", { objectId: recordingId, ownerPrincipalFingerprint: owner, status: record.status, data });
    });
  }

  #public(record: QuirtNativeObjectRecord): Record<string, unknown> { return { recordingId: record.objectId, status: record.status, ...record.data, createdAt: record.createdAt, updatedAt: record.updatedAt, rawFidelity: true, storage: "principal-bound-private-state" }; }
}
