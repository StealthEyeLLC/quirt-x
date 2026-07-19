import { randomUUID } from "node:crypto";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import type { QuirtJobManager } from "./job-manager.js";
import type { QuirtRecordingService } from "./recording-service.js";
import type { QuirtSessionManager } from "./session-manager.js";
import type { QuirtStateStore } from "./state.js";
import { QuirtTerminalRenderer } from "./terminal-renderer.js";

const SNAPSHOT_REFERENCE_MAX = 1000;

export class QuirtSessionNativeService {
  readonly #renderer = new QuirtTerminalRenderer();
  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore, private readonly sessions: QuirtSessionManager, private readonly jobs: QuirtJobManager, private readonly recordings: QuirtRecordingService) {}

  snapshot(input: { sessionId: string; readerId?: string; after?: number; createHandoff?: boolean; expiresInSeconds?: number; clientMetadata?: Record<string, unknown> }, owner: string): Record<string, unknown> {
    const session = this.sessions.get(input.sessionId, owner); const stream = this.state.getStream(session.outputStreamId); let readerOffset = input.after ?? stream.nextOffset;
    if (input.readerId !== undefined) { const reader = this.state.getSessionReader(input.readerId); if (reader.sessionId !== session.sessionId || reader.ownerPrincipalFingerprint !== owner) throw new QuirtError("authorization_failed", "Quirt snapshot reader principal does not match"); readerOffset = input.after ?? reader.cursorOffset; }
    if (readerOffset < stream.retainedStartOffset || readerOffset > stream.nextOffset) throw new QuirtError("invalid_offset", "Quirt snapshot reader offset is invalid");
    const createHandoff = input.createHandoff === true; const expiresIn = input.expiresInSeconds ?? 24 * 60 * 60; const clientMetadata = input.clientMetadata ?? {};
    if (createHandoff && (!Number.isSafeInteger(expiresIn) || expiresIn < 60 || expiresIn > 7 * 24 * 60 * 60)) throw new QuirtError("invalid_request", "Quirt handoff expiry is invalid");
    if (createHandoff && "workspaceId" in clientMetadata && clientMetadata.workspaceId !== null) throw new QuirtError("authorization_failed", "Quirt handoff does not permit workspace inheritance");
    const allTransferRecords = this.state.native.listTransfers(owner, SNAPSHOT_REFERENCE_MAX + 1); const transferRecords = allTransferRecords.filter(record => record.status === "active"); const transfers = transferRecords.slice(0, SNAPSHOT_REFERENCE_MAX).map(record => ({ transferId: record.transferId, direction: record.direction, status: record.status, source: record.sourcePath, destination: record.destinationPath }));
    const allRecordingRecords = this.state.native.listObjects("quirt_recordings", owner, SNAPSHOT_REFERENCE_MAX + 1); const recordingRecords = allRecordingRecords.filter(record => record.data.sessionId === session.sessionId); const recordings = recordingRecords.slice(0, SNAPSHOT_REFERENCE_MAX).map(record => ({ recordingId: record.objectId, status: record.status }));
    const repositoryRecords = this.state.native.listObjects("quirt_materializations", owner, SNAPSHOT_REFERENCE_MAX + 1); const repositories = repositoryRecords.slice(0, SNAPSHOT_REFERENCE_MAX).map(record => ({ materializationId: record.objectId, destination: record.data.destination, commit: record.data.commit, tree: record.data.tree, branch: record.data.branch }));
    const worktreeRecords = this.state.native.listObjects("quirt_worktrees", owner, SNAPSHOT_REFERENCE_MAX + 1); const worktrees = worktreeRecords.slice(0, SNAPSHOT_REFERENCE_MAX).map(record => ({ worktreeId: record.objectId, destination: record.data.destination, commit: record.data.commit, branch: record.data.branch }));
    const jobRecords = this.jobs.list(owner).filter(record => ["starting", "running", "unknown"].includes(record.status)); const jobs = jobRecords.slice(0, SNAPSHOT_REFERENCE_MAX).map(record => ({ jobId: record.jobId, status: record.status, processId: record.processId, stdoutStreamId: record.stdoutStreamId, stderrStreamId: record.stderrStreamId }));
    const referenceTruncation = { limit: SNAPSHOT_REFERENCE_MAX, transfers: allTransferRecords.length > SNAPSHOT_REFERENCE_MAX, recordings: allRecordingRecords.length > SNAPSHOT_REFERENCE_MAX, repositories: repositoryRecords.length > SNAPSHOT_REFERENCE_MAX, worktrees: worktreeRecords.length > SNAPSHOT_REFERENCE_MAX, jobs: jobRecords.length > SNAPSHOT_REFERENCE_MAX };
    const rendered = session.rows * session.columns <= 100_000 ? this.render({ sessionId: session.sessionId, maximumBytes: 1024 * 1024, rows: session.rows, columns: session.columns }, owner).render as { rows: string[]; cursor: Record<string, unknown>; alternateScreen: boolean; lossIndicators: string[] } : { rows: [], cursor: { row: 0, column: 0, visible: true }, alternateScreen: false, lossIndicators: ["snapshot-render-dimension-limit"] }; const environmentSummary = { keys: Object.keys(session.environment).sort(), variableCount: Object.keys(session.environment).length, valuesIncluded: false }; const processReferences = session.ptyPid === null ? [] : [{ pid: session.ptyPid, role: "session-pty" }];
    const snapshotId = randomUUID(); const createdAt = new Date().toISOString(); const data = {
      snapshotId, sessionId: session.sessionId, sessionName: session.name, tmuxIdentity: session.tmuxName, paneIdentity: null, windowIdentity: null,
      terminal: { columns: session.columns, rows: session.rows, outputStreamId: session.outputStreamId, retainedStartOffset: stream.retainedStartOffset, nextOffset: stream.nextOffset, readerOffset, renderedState: { rows: rendered.rows, cursor: rendered.cursor, alternateScreen: rendered.alternateScreen, lossIndicators: rendered.lossIndicators } },
      workingDirectory: session.workingDirectory, shell: session.shell, process: { pid: session.ptyPid, status: session.status, exitCode: session.exitCode, exitSignal: session.exitSignal },
      environmentSummary, tmux: { session: session.tmuxName, windows: [], panes: [], controlModeInventory: "checkpoint-D-pane-provider-pending" }, foregroundProcesses: processReferences, activeJobs: jobs, activeTransfers: transfers, recordings, repositories, worktrees, referenceTruncation, activePreviews: [], activeTunnels: [], createdAt, principalFingerprint: owner, supervisorRevision: process.env.QUIRT_COMMIT_SHA ?? "source-build",
      checkpointType: "descriptive-reconnect-state", processCheckpoint: false, unfinishedWork: [], lastSuccessfulCommand: null, commandBoundaryReliable: false
    };
    this.state.native.putObject("quirt_session_snapshots", { objectId: snapshotId, ownerPrincipalFingerprint: owner, status: "ready", data });
    if (!createHandoff) return { snapshot: data, handoff: null };
    const handoffId = randomUUID(); const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
    const handoff = { handoffId, snapshotId, sessionId: session.sessionId, sessionName: session.name, workingDirectory: session.workingDirectory, environmentSummary, tmux: data.tmux, foregroundProcesses: processReferences, readerOffset, terminal: data.terminal, activeJobs: jobs, activeTransfers: transfers, recordings, repositories, worktrees, referenceTruncation, activePreviews: [], activeTunnels: [], unfinishedWork: [], lastSuccessfulCommand: null, commandBoundaryReliable: false, processReferences, createdAt, expiresAt, originatingClient: clientMetadata, principalFingerprint: owner, targetHost: this.config.targetHost, protocolVersion: 1, supervisorVersion: process.env.QUIRT_COMMIT_SHA ?? "source-build" };
    this.state.native.createHandoff({ handoffId, ownerPrincipalFingerprint: owner, status: "ready", targetHost: this.config.targetHost, expiresAt, data: handoff }); return { snapshot: data, handoff };
  }

  handoff(handoffId: string, owner: string): { sessionId: string; after: number; columns: number; rows: number; handoff: Record<string, unknown> } {
    const record = this.state.native.getHandoff(handoffId, owner, this.config.targetHost); const data = record.data; const sessionId = typeof data.sessionId === "string" ? data.sessionId : null; const after = typeof data.readerOffset === "number" ? data.readerOffset : null; const terminal = data.terminal;
    if (sessionId === null || after === null || terminal === null || typeof terminal !== "object" || Array.isArray(terminal)) throw new QuirtError("internal_error", "Stored Quirt handoff is invalid"); this.sessions.get(sessionId, owner); const dimensions = terminal as Record<string, unknown>;
    return { sessionId, after, columns: typeof dimensions.columns === "number" ? dimensions.columns : 120, rows: typeof dimensions.rows === "number" ? dimensions.rows : 40, handoff: { handoffId: record.objectId, ...data } };
  }

  search(input: { sessionId: string; query: string; regularExpression?: boolean; caseSensitive?: boolean; afterOffset?: number; maximumMatches?: number; maximumBytes?: number; includeRecordings?: boolean }, owner: string): Record<string, unknown> {
    const session = this.sessions.get(input.sessionId, owner); const stream = this.state.getStream(session.outputStreamId); const start = Math.max(input.afterOffset ?? stream.retainedStartOffset, stream.retainedStartOffset); const maximumBytes = input.maximumBytes ?? 32 * 1024 * 1024; const maximumMatches = input.maximumMatches ?? 100;
    if (start > stream.nextOffset || maximumBytes < 1 || maximumBytes > 32 * 1024 * 1024 || maximumMatches < 1 || maximumMatches > 1000) throw new QuirtError("invalid_request", "Quirt session search bounds are invalid");
    const chunks: Buffer[] = []; let cursor = start; let scannedBytes = 0; while (cursor < stream.nextOffset && scannedBytes < maximumBytes) { const page = this.state.readStream(stream.streamId, cursor, Math.min(1024 * 1024, maximumBytes - scannedBytes)); if (page.bytes.length === 0) break; chunks.push(page.bytes); scannedBytes += page.bytes.length; cursor = page.endOffset; }
    const bytes = Buffer.concat(chunks); const text = bytes.toString("utf8"); const matches: Record<string, unknown>[] = [];
    if (input.regularExpression === true) {
      let expression: RegExp; try { expression = new RegExp(input.query, `${input.caseSensitive === true ? "" : "i"}gu`); } catch { throw new QuirtError("invalid_request", "Quirt session search expression is invalid"); }
      for (const match of text.matchAll(expression)) { const index = match.index ?? 0; const byteOffset = start + Buffer.byteLength(text.slice(0, index)); matches.push({ streamId: stream.streamId, startOffset: byteOffset, endOffset: byteOffset + Buffer.byteLength(match[0]), text: match[0].slice(0, 8192), source: "session-stream" }); if (matches.length >= maximumMatches) break; }
    } else {
      const haystack = input.caseSensitive === true ? text : text.toLocaleLowerCase(); const needle = input.caseSensitive === true ? input.query : input.query.toLocaleLowerCase(); let index = 0; while ((index = haystack.indexOf(needle, index)) >= 0 && matches.length < maximumMatches) { const byteOffset = start + Buffer.byteLength(text.slice(0, index)); matches.push({ streamId: stream.streamId, startOffset: byteOffset, endOffset: byteOffset + Buffer.byteLength(text.slice(index, index + needle.length)), text: text.slice(index, index + needle.length), source: "session-stream" }); index += Math.max(1, needle.length); }
    }
    const recordingMatches: Record<string, unknown>[] = []; let recordingSearchTruncated = false;
    if (input.includeRecordings !== false && matches.length < maximumMatches) {
      const allCandidates = this.state.native.listObjects("quirt_recordings", owner, SNAPSHOT_REFERENCE_MAX + 1); const candidates = allCandidates.filter(record => record.data.sessionId === session.sessionId); recordingSearchTruncated = allCandidates.length > SNAPSHOT_REFERENCE_MAX;
      for (const record of candidates.slice(0, SNAPSHOT_REFERENCE_MAX)) { const remaining = maximumMatches - matches.length - recordingMatches.length; if (remaining <= 0) { recordingSearchTruncated = true; break; } const result = this.recordings.search({ recordingId: record.objectId, query: input.query, regularExpression: input.regularExpression, caseSensitive: input.caseSensitive, maximumMatches: remaining }, owner); for (const match of result.matches as unknown[]) recordingMatches.push({ recordingId: record.objectId, source: "recording", match }); if (result.truncated === true) recordingSearchTruncated = true; }
    }
    return { sessionId: session.sessionId, streamId: stream.streamId, startOffset: start, scannedEndOffset: cursor, matches, recordingMatches, truncated: cursor < stream.nextOffset || matches.length + recordingMatches.length >= maximumMatches || recordingSearchTruncated, recordingSearchTruncated, lossIndicators: stream.retainedStartOffset > 0 ? ["retained-output-gap"] : [] };
  }

  render(input: { sessionId: string; afterOffset?: number; maximumBytes?: number; rows?: number; columns?: number }, owner: string): Record<string, unknown> {
    const session = this.sessions.get(input.sessionId, owner); const stream = this.state.getStream(session.outputStreamId); const maximum = input.maximumBytes ?? 8 * 1024 * 1024; if (maximum < 1 || maximum > 8 * 1024 * 1024) throw new QuirtError("invalid_request", "Quirt render bound is invalid");
    const desiredStart = input.afterOffset ?? Math.max(stream.retainedStartOffset, stream.nextOffset - maximum); const start = Math.max(desiredStart, stream.retainedStartOffset); const chunks: Buffer[] = []; let cursor = start; let renderedBytes = 0;
    while (cursor < stream.nextOffset && renderedBytes < maximum) { const page = this.state.readStream(stream.streamId, cursor, Math.min(1024 * 1024, maximum - renderedBytes)); if (page.bytes.length === 0) break; chunks.push(page.bytes); renderedBytes += page.bytes.length; cursor = page.endOffset; }
    const losses = []; if (start > 0) losses.push("render-starts-after-stream-origin"); if (cursor < stream.nextOffset) losses.push("render-byte-limit"); const rows = input.rows ?? session.rows; const columns = input.columns ?? session.columns; if (rows < 1 || rows > 1000 || columns < 2 || columns > 1000) throw new QuirtError("invalid_request", "Quirt render dimensions are invalid");
    return { sessionId: session.sessionId, streamId: stream.streamId, startOffset: start, endOffset: cursor, rows, columns, render: this.#renderer.render(Buffer.concat(chunks), rows, columns, losses), fidelity: "deterministic-cell-model", pixelPerfect: false };
  }
}
