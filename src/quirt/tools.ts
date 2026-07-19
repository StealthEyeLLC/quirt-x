import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { CallToolResult, ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import { HORSEY_AUTHORITY_TOOL_META } from "../principal-grant.js";
import type { QuirtOperation as QuirtCoreOperation } from "./catalog.js";
import { QUIRT_POWER_FOUNDATION_TOOL_DEFINITIONS, QUIRT_POWER_FOUNDATION_TOOL_SCOPES, quirtPowerFoundationToolSchemas } from "./power-tools.js";

export type QuirtToolScope = "fix.read" | "fix.execute";

export const QUIRT_TOOL_SCOPES = Object.freeze({
  "quirt.status": "fix.read", "quirt.capabilities": "fix.read", "quirt.version": "fix.read", "quirt.exec": "fix.execute",
  "quirt.session.open": "fix.execute", "quirt.session.list": "fix.read", "quirt.session.get": "fix.read",
  "quirt.session.attach": "fix.execute", "quirt.session.read": "fix.read", "quirt.session.write": "fix.execute",
  "quirt.session.resize": "fix.execute", "quirt.session.signal": "fix.execute", "quirt.session.detach": "fix.execute", "quirt.session.close": "fix.execute",
  "quirt.job.list": "fix.read", "quirt.job.get": "fix.read", "quirt.job.read": "fix.read", "quirt.job.input": "fix.execute",
  "quirt.job.signal": "fix.execute", "quirt.job.cancel": "fix.execute", "quirt.job.attach": "fix.read",
  "quirt.file.read": "fix.read", "quirt.file.write": "fix.execute", "quirt.file.patch": "fix.execute", "quirt.file.stat": "fix.read",
  "quirt.file.search": "fix.read", "quirt.file.remove": "fix.execute", "quirt.file.move": "fix.execute", "quirt.file.copy": "fix.execute",
  "quirt.directory.list": "fix.read", "quirt.directory.create": "fix.execute", "quirt.directory.watch": "fix.execute",
  "quirt.transfer.begin": "fix.execute", "quirt.transfer.read": "fix.read", "quirt.transfer.write": "fix.execute",
  "quirt.transfer.status": "fix.read", "quirt.transfer.complete": "fix.execute", "quirt.transfer.cancel": "fix.execute",
  "quirt.session.snapshot": "fix.execute", "quirt.session.search": "fix.read", "quirt.session.render": "fix.read",
  "quirt.git.materialize": "fix.execute", "quirt.git.mirror": "fix.execute", "quirt.git.fetch": "fix.execute", "quirt.git.status": "fix.read",
  "quirt.git.worktree": "fix.execute", "quirt.git.verify": "fix.read", "quirt.git.push": "fix.execute",
  "quirt.record.start": "fix.execute", "quirt.record.stop": "fix.execute", "quirt.record.list": "fix.read", "quirt.record.search": "fix.read", "quirt.record.replay": "fix.read", "quirt.record.export": "fix.read",
  "quirt.process.list": "fix.read", "quirt.process.get": "fix.read", "quirt.process.signal": "fix.execute", "quirt.process.attach": "fix.execute", "quirt.process.tree": "fix.read", "quirt.process.namespaces": "fix.read",
  ...QUIRT_POWER_FOUNDATION_TOOL_SCOPES
} satisfies Readonly<Record<QuirtCoreOperation, QuirtToolScope>>);

export const QUIRT_TOOL_NAMES = Object.freeze(Object.keys(QUIRT_TOOL_SCOPES) as QuirtCoreOperation[]);

const id = z.string().min(1).max(128).regex(/^[^\0\r\n]+$/u);
const request = { requestId: id.optional() };
const absolutePath = z.string().min(1).max(4096).startsWith("/").refine(value => !value.includes("\0"));
const hostPath = z.string().min(1).max(4096).refine(value => !value.includes("\0"));
const argument = z.string().max(65_536).refine(value => !value.includes("\0"));
const args = z.array(argument).max(1024).optional();
const environmentName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/u);
const environmentValue = z.string().max(65_536).refine(value => !value.includes("\0"));
const environment = z.record(environmentName, environmentValue).refine(value => Object.keys(value).length <= 512).optional();
const columns = z.number().int().min(2).max(1000).optional(); const rows = z.number().int().min(1).max(1000).optional();
const offset = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const maximumBytes = z.number().int().min(1).max(1024 * 1024).optional();
const signal = z.enum(["SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS"]);
const base64 = z.string().max(1_398_104).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u);
const empty = z.strictObject({ ...request });
const session = { sessionId: id };
const job = { jobId: id };
const transfer = { transferId: id };
const workingDirectory = absolutePath.optional();
const mode = z.number().int().min(0).max(0o7777).optional();
const uid = z.number().int().min(0).max(0x7fffffff).optional();
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const objectId = z.string().regex(/^[a-f0-9]{40,64}$/u);
const gitRef = z.string().min(1).max(1024).refine(value => !value.startsWith("-") && !value.endsWith(".") && !value.endsWith("/") && !value.includes("..") && !value.includes("@{") && !/[\u0000-\u0020\u007f~^:?*\\[\\]/u.test(value));
const credentialReference = z.string().min(3).max(256).regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]+$/u).optional();
const processIdentity = z.strictObject({ pid: z.number().int().min(1).max(0x7fffffff), startTimeTicks: offset, bootId: z.string().uuid(), pidNamespace: z.string().nullable(), executableDevice: offset.nullable(), executableInode: offset.nullable() });
const journalFilters = z.strictObject({ unit: z.string().min(1).max(512).optional(), pid: z.number().int().min(1).max(0x7fffffff).optional(), uid: uid, priority: z.number().int().min(0).max(7).optional() });

const exec = z.strictObject({
  command: z.string().min(1).max(1024 * 1024).refine(value => !value.includes("\0")).optional(),
  script: z.string().min(1).max(1024 * 1024).refine(value => !value.includes("\0")).optional(),
  executable: absolutePath.optional(), arguments: args, shell: z.boolean().optional(), workingDirectory: absolutePath.optional(), environment,
  inputBase64: base64.optional(), timeoutMs: z.number().int().min(1).max(24 * 60 * 60 * 1000).optional(), pty: z.boolean().optional(), detach: z.boolean().optional(), columns, rows, ...request
}).superRefine((value, context) => {
  if (Number(value.command !== undefined) + Number(value.script !== undefined) + Number(value.executable !== undefined) !== 1) context.addIssue({ code: "custom", message: "Exactly one execution form is required" });
  if (value.detach !== true && (value.timeoutMs ?? 0) > 25_000) context.addIssue({ code: "custom", message: "Attached MCP execution is bounded to 25 seconds; use detach for longer work" });
});

export const quirtToolSchemas = Object.freeze({
  "quirt.status": empty,
  "quirt.capabilities": empty,
  "quirt.version": empty,
  "quirt.exec": exec,
  "quirt.session.open": z.strictObject({ name: z.string().min(1).max(256).optional(), mode: z.enum(["tmux", "direct"]).optional(), executable: absolutePath.optional(), arguments: args, workingDirectory: absolutePath.optional(), environment, columns, rows, loginShell: z.boolean().optional(), ...request }),
  "quirt.session.list": empty,
  "quirt.session.get": z.strictObject({ ...session, ...request }),
  "quirt.session.attach": z.strictObject({ sessionId: id.optional(), handoffId: id.optional(), readerId: id.optional(), after: offset.optional(), ...request }).superRefine((value, context) => { if (Number(value.sessionId !== undefined) + Number(value.handoffId !== undefined) !== 1) context.addIssue({ code: "custom", message: "Exactly one session or handoff ID is required" }); }),
  "quirt.session.read": z.strictObject({ ...session, readerId: id.optional(), after: offset.optional(), maximumBytes, ...request }),
  "quirt.session.write": z.strictObject({ ...session, contentBase64: base64, ...request }),
  "quirt.session.resize": z.strictObject({ ...session, columns: columns.unwrap(), rows: rows.unwrap(), ...request }),
  "quirt.session.signal": z.strictObject({ ...session, signal, ...request }),
  "quirt.session.detach": z.strictObject({ ...session, readerId: id.optional(), ...request }),
  "quirt.session.close": z.strictObject({ ...session, signal: signal.optional(), ...request }),
  "quirt.job.list": empty,
  "quirt.job.get": z.strictObject({ ...job, ...request }),
  "quirt.job.read": z.strictObject({ ...job, stream: z.enum(["stdout", "stderr"]), after: offset.optional(), maximumBytes, ...request }),
  "quirt.job.input": z.strictObject({ ...job, contentBase64: base64, close: z.boolean().optional(), ...request }),
  "quirt.job.signal": z.strictObject({ ...job, signal, ...request }),
  "quirt.job.cancel": z.strictObject({ ...job, force: z.boolean().optional(), ...request }),
  "quirt.job.attach": z.strictObject({ ...job, ...request }),
  "quirt.file.read": z.strictObject({ path: hostPath, workingDirectory, followSymlinks: z.boolean().optional(), offset: offset.optional(), maximumBytes, ...request }),
  "quirt.file.write": z.strictObject({ path: hostPath, workingDirectory, contentBase64: base64, create: z.boolean().optional(), replace: z.boolean().optional(), append: z.boolean().optional(), offset: offset.optional(), atomic: z.boolean().optional(), noClobber: z.boolean().optional(), createParents: z.boolean().optional(), followSymlinks: z.boolean().optional(), expectedDigest: digest.optional(), expectedDevice: offset.optional(), expectedInode: offset.optional(), mode, uid, gid: uid, atime: z.iso.datetime().optional(), mtime: z.iso.datetime().optional(), durable: z.boolean().optional(), ...request }),
  "quirt.file.patch": z.strictObject({ path: hostPath, workingDirectory, expectedDigest: digest, edits: z.array(z.strictObject({ start: offset, deleteBytes: offset, contentBase64: base64 })).min(1).max(10_000), mode, ...request }),
  "quirt.file.stat": z.strictObject({ path: hostPath, workingDirectory, followSymlinks: z.boolean().optional(), digest: z.boolean().optional(), ...request }),
  "quirt.file.search": z.strictObject({ path: hostPath, workingDirectory, name: z.string().min(1).max(4096).optional(), text: z.string().min(1).max(65_536).optional(), regularExpression: z.boolean().optional(), caseSensitive: z.boolean().optional(), recursive: z.boolean().optional(), followSymlinks: z.boolean().optional(), maximumMatches: z.number().int().min(1).max(10_000).optional(), maximumBytes: z.number().int().min(1).max(512 * 1024 * 1024).optional(), ...request }).refine(value => value.name !== undefined || value.text !== undefined, "A filename or text search is required"),
  "quirt.file.remove": z.strictObject({ path: hostPath, workingDirectory, recursive: z.boolean().optional(), expectedDevice: offset.optional(), expectedInode: offset.optional(), ...request }),
  "quirt.file.move": z.strictObject({ source: hostPath, destination: hostPath, workingDirectory, overwrite: z.boolean().optional(), preserveMetadata: z.boolean().optional(), ...request }),
  "quirt.file.copy": z.strictObject({ source: hostPath, destination: hostPath, workingDirectory, recursive: z.boolean().optional(), overwrite: z.boolean().optional(), preserveMetadata: z.boolean().optional(), followSymlinks: z.boolean().optional(), ...request }),
  "quirt.directory.list": z.strictObject({ path: hostPath, workingDirectory, followSymlinks: z.boolean().optional(), maximumEntries: z.number().int().min(1).max(4096).optional(), continuationToken: z.string().min(1).max(8192).optional(), ...request }),
  "quirt.directory.create": z.strictObject({ path: hostPath, workingDirectory, recursive: z.boolean().optional(), mode, uid, gid: uid, noClobber: z.boolean().optional(), ...request }),
  "quirt.directory.watch": z.strictObject({ action: z.enum(["start", "read", "cancel"]).optional(), watchId: id.optional(), path: hostPath.optional(), workingDirectory, recursive: z.boolean().optional(), after: z.number().int().min(-1).max(Number.MAX_SAFE_INTEGER).optional(), maximumEvents: z.number().int().min(1).max(1000).optional(), ...request }).superRefine((value, context) => { const action = value.action ?? "start"; if (action === "start" && value.path === undefined) context.addIssue({ code: "custom", message: "A watch path is required" }); if (action !== "start" && value.watchId === undefined) context.addIssue({ code: "custom", message: "A watch ID is required" }); }),
  "quirt.transfer.begin": z.strictObject({ direction: z.enum(["upload", "download"]), source: hostPath.optional(), destination: hostPath.optional(), workingDirectory, expectedSize: offset.optional(), expectedDigest: digest.optional(), chunkSize: z.number().int().min(4096).max(1024 * 1024).optional(), compression: z.enum(["none", "gzip"]).optional(), archiveFormat: z.enum(["none", "tar"]).optional(), objectType: z.enum(["file", "directory", "symlink"]).optional(), overwrite: z.boolean().optional(), noClobber: z.boolean().optional(), mode, uid, gid: uid, atime: z.iso.datetime().optional(), mtime: z.iso.datetime().optional(), ...request }).superRefine((value, context) => { if (value.direction === "upload" && value.destination === undefined) context.addIssue({ code: "custom", message: "An upload destination is required" }); if (value.direction === "download" && value.source === undefined) context.addIssue({ code: "custom", message: "A download source is required" }); if (value.objectType === "directory" && value.archiveFormat !== "tar" || value.objectType !== undefined && value.objectType !== "directory" && value.archiveFormat === "tar") context.addIssue({ code: "custom", message: "Object type and archive format conflict" }); }),
  "quirt.transfer.read": z.strictObject({ ...transfer, offset: offset.optional(), maximumBytes, ...request }),
  "quirt.transfer.write": z.strictObject({ ...transfer, offset, contentBase64: base64, chunkDigest: digest.optional(), ...request }),
  "quirt.transfer.status": z.strictObject({ ...transfer, afterOffset: z.number().int().min(-1).max(Number.MAX_SAFE_INTEGER).optional(), maximumRanges: z.number().int().min(1).max(1000).optional(), ...request }),
  "quirt.transfer.complete": z.strictObject({ ...transfer, ...request }),
  "quirt.transfer.cancel": z.strictObject({ ...transfer, ...request }),
  "quirt.session.snapshot": z.strictObject({ ...session, readerId: id.optional(), after: offset.optional(), createHandoff: z.boolean().optional(), expiresInSeconds: z.number().int().min(60).max(7 * 24 * 60 * 60).optional(), clientMetadata: z.record(z.string().min(1).max(128), z.union([z.string().max(4096), z.number(), z.boolean(), z.null()])).refine(value => Object.keys(value).length <= 32 && (value.workspaceId === undefined || value.workspaceId === null)).optional(), ...request }),
  "quirt.session.search": z.strictObject({ ...session, query: z.string().min(1).max(65_536), regularExpression: z.boolean().optional(), caseSensitive: z.boolean().optional(), afterOffset: offset.optional(), maximumMatches: z.number().int().min(1).max(1000).optional(), maximumBytes: z.number().int().min(1).max(32 * 1024 * 1024).optional(), includeRecordings: z.boolean().optional(), ...request }),
  "quirt.session.render": z.strictObject({ ...session, afterOffset: offset.optional(), maximumBytes: z.number().int().min(1).max(8 * 1024 * 1024).optional(), rows, columns, ...request }),
  "quirt.git.materialize": z.strictObject({ remote: argument.min(1), destination: hostPath, ref: gitRef.optional(), exactCommit: objectId.optional(), expectedTree: objectId.optional(), branch: gitRef.optional(), depth: z.number().int().min(1).max(1_000_000).optional(), submodules: z.boolean().optional(), lfs: z.boolean().optional(), credentialReference, existing: z.enum(["reject", "reuse", "replace"]).optional(), ...request }),
  "quirt.git.mirror": z.strictObject({ remote: argument.min(1), credentialReference, fetch: z.boolean().optional(), prune: z.boolean().optional(), rebuild: z.boolean().optional(), ...request }),
  "quirt.git.fetch": z.strictObject({ repository: hostPath, remote: gitRef.optional(), prune: z.boolean().optional(), tags: z.boolean().optional(), credentialReference, ...request }),
  "quirt.git.status": z.strictObject({ repository: hostPath, includeIgnored: z.boolean().optional(), ...request }),
  "quirt.git.worktree": z.strictObject({ repository: hostPath, destination: hostPath.optional(), commit: objectId.optional(), branch: gitRef.optional(), action: z.enum(["create", "list", "remove"]).optional(), force: z.boolean().optional(), ...request }).superRefine((value, context) => { if ((value.action ?? "create") !== "list" && value.destination === undefined) context.addIssue({ code: "custom", message: "A worktree destination is required" }); }),
  "quirt.git.verify": z.strictObject({ repository: hostPath, commit: objectId.optional(), tree: objectId.optional(), tag: gitRef.optional(), signature: z.enum(["none", "report", "require"]).optional(), fsck: z.boolean().optional(), ...request }),
  "quirt.git.push": z.strictObject({ repository: hostPath, remote: gitRef.optional(), source: gitRef, destination: gitRef, force: z.boolean().optional(), lease: objectId.optional(), tags: z.boolean().optional(), signed: z.boolean().optional(), credentialReference, ...request }).superRefine((value, context) => { if (value.force === true && value.lease === undefined) context.addIssue({ code: "custom", message: "An exact force-with-lease object is required" }); }),
  "quirt.record.start": z.strictObject({ sessionId: id.optional(), recordingId: id.optional(), name: z.string().min(1).max(256).optional(), retentionUntil: z.iso.datetime().optional(), marker: z.string().min(1).max(4096).optional(), bookmark: z.string().min(1).max(4096).optional(), ...request }).superRefine((value, context) => { const annotation = value.marker !== undefined || value.bookmark !== undefined; if (annotation && value.recordingId === undefined || !annotation && value.sessionId === undefined) context.addIssue({ code: "custom", message: annotation ? "A recording ID is required for an annotation" : "A session ID is required to start recording" }); }),
  "quirt.record.stop": z.strictObject({ recordingId: id, remove: z.boolean().optional(), ...request }),
  "quirt.record.list": z.strictObject({ maximumRecordings: z.number().int().min(1).max(1000).optional(), continuationToken: z.string().min(1).max(8192).optional(), ...request }),
  "quirt.record.search": z.strictObject({ recordingId: id, query: z.string().min(1).max(65_536), regularExpression: z.boolean().optional(), caseSensitive: z.boolean().optional(), maximumMatches: z.number().int().min(1).max(1000).optional(), ...request }),
  "quirt.record.replay": z.strictObject({ recordingId: id, afterSequence: z.number().int().min(-1).max(Number.MAX_SAFE_INTEGER).optional(), maximumEvents: z.number().int().min(1).max(1000).optional(), speed: z.number().positive().max(100).optional(), ...request }),
  "quirt.record.export": z.strictObject({ recordingId: id, format: z.enum(["quirt-json-v1", "asciinema-v2", "html-transcript"]), offset: offset.optional(), maximumBytes, ...request }),
  "quirt.process.list": z.strictObject({ afterPid: z.number().int().min(0).max(0x7fffffff).optional(), maximumProcesses: z.number().int().min(1).max(4096).optional(), uid, state: z.string().min(1).max(16).optional(), ...request }),
  "quirt.process.get": z.strictObject({ pid: z.number().int().min(1).max(0x7fffffff), ...request }),
  "quirt.process.signal": z.strictObject({ identity: processIdentity, signal, ...request }),
  "quirt.process.attach": z.strictObject({ source: z.enum(["process", "journal"]).optional(), identity: processIdentity.optional(), action: z.enum(["open", "read", "cancel"]).optional(), attachmentId: id.optional(), filters: journalFilters.optional(), afterCursor: z.string().min(1).max(8192).optional(), maximumEntries: z.number().int().min(1).max(1000).optional(), ...request }).superRefine((value, context) => { if (value.source !== "journal" && value.identity === undefined) context.addIssue({ code: "custom", message: "An exact process identity is required" }); if (value.source === "journal" && (value.action === "read" || value.action === "cancel") && value.attachmentId === undefined) context.addIssue({ code: "custom", message: "A journal attachment ID is required" }); }),
  "quirt.process.tree": z.strictObject({ pid: z.number().int().min(1).max(0x7fffffff).optional(), maximumDepth: z.number().int().min(0).max(128).optional(), maximumProcesses: z.number().int().min(1).max(10_000).optional(), ...request }),
  "quirt.process.namespaces": z.strictObject({ pid: z.number().int().min(1).max(0x7fffffff), ...request }),
  ...quirtPowerFoundationToolSchemas
} satisfies Readonly<Record<QuirtCoreOperation, z.ZodType>>);

interface QuirtToolDefinition { name: QuirtCoreOperation; title: string; description: string; }
const DEFINITIONS: readonly QuirtToolDefinition[] = [
  { name: "quirt.status", title: "Inspect Quirt readiness", description: "Read the private Quirt supervisor, protocol, state, tmux, session, job, and UID readiness summary." },
  { name: "quirt.capabilities", title: "List Core Quirt capabilities", description: "List the genuinely implemented Core Quirt protocol operations and terminal fidelity features." },
  { name: "quirt.version", title: "Read Quirt version", description: "Read the exact Quirt source revision, protocol version, and state schema." },
  { name: "quirt.exec", title: "Execute immediately through Quirt", description: "Run an unrestricted command, script, or executable immediately as Quirt's privileged authority, optionally as a PTY or detached job." },
  { name: "quirt.session.open", title: "Open a persistent Quirt terminal", description: "Open a persistent root login shell or executable in a tmux-owned or direct real PTY." },
  { name: "quirt.session.list", title: "List Quirt terminals", description: "List the exact principal's durable Quirt terminal sessions." },
  { name: "quirt.session.get", title: "Inspect a Quirt terminal", description: "Inspect one durable Quirt terminal without exposing stored environment values." },
  { name: "quirt.session.attach", title: "Attach to a Quirt terminal", description: "Create or resume a durable reader cursor for a persistent Quirt terminal." },
  { name: "quirt.session.read", title: "Read Quirt terminal bytes", description: "Poll a bounded raw terminal byte page after an exact monotonic byte offset." },
  { name: "quirt.session.write", title: "Write Quirt terminal bytes", description: "Write exact base64-encoded raw input bytes, including control characters, to a persistent Quirt PTY." },
  { name: "quirt.session.resize", title: "Resize a Quirt terminal", description: "Resize the real PTY and tmux window for a persistent Quirt session." },
  { name: "quirt.session.signal", title: "Signal a Quirt terminal", description: "Deliver an explicit signal to the terminal foreground process group." },
  { name: "quirt.session.detach", title: "Detach from a Quirt terminal", description: "Detach a durable reader while leaving the supervisor-owned terminal running." },
  { name: "quirt.session.close", title: "Close a Quirt terminal", description: "Explicitly close and finalize a persistent Quirt terminal session." },
  { name: "quirt.job.list", title: "List Quirt jobs", description: "List durable immediate and detached jobs owned by the exact Quirt principal." },
  { name: "quirt.job.get", title: "Inspect a Quirt job", description: "Inspect one durable Quirt job and terminal outcome." },
  { name: "quirt.job.read", title: "Read Quirt job bytes", description: "Poll a bounded stdout or stderr byte page after an exact monotonic offset." },
  { name: "quirt.job.input", title: "Write Quirt job input", description: "Write exact base64-encoded bytes to a running Quirt job and optionally close stdin." },
  { name: "quirt.job.signal", title: "Signal a Quirt job", description: "Deliver an explicit signal to a running Quirt job process group." },
  { name: "quirt.job.cancel", title: "Cancel a Quirt job", description: "Cancel a running Quirt job with SIGTERM or an explicit forced SIGKILL." },
  { name: "quirt.job.attach", title: "Attach to a Quirt job", description: "Inspect live input availability and exact durable output streams for a Quirt job." },
  { name: "quirt.file.read", title: "Read a host file", description: "Read a bounded binary-safe page from an arbitrary authorized host path with exact identity and digest metadata." },
  { name: "quirt.file.write", title: "Write a host file", description: "Create, replace, append, or positionally write exact bytes with explicit atomicity, durability, and identity preconditions." },
  { name: "quirt.file.patch", title: "Patch a host file", description: "Apply deterministic non-overlapping byte edits against an exact base digest using atomic replacement." },
  { name: "quirt.file.stat", title: "Inspect a host path", description: "Read explicit stat or lstat metadata and an optional content digest for an arbitrary host path." },
  { name: "quirt.file.search", title: "Search host files", description: "Run a bounded cancellable filename or text search across arbitrary authorized paths." },
  { name: "quirt.file.remove", title: "Remove a host path", description: "Remove a file, symlink, or explicitly recursive directory with optional identity preconditions." },
  { name: "quirt.file.move", title: "Move a host path", description: "Move a host object atomically where possible, with verified cross-device copy fallback." },
  { name: "quirt.file.copy", title: "Copy a host path", description: "Copy files, symlinks, or explicitly recursive directories with explicit overwrite and metadata policy." },
  { name: "quirt.directory.list", title: "List a host directory", description: "List a stable bounded directory page with metadata and change-detecting continuation tokens." },
  { name: "quirt.directory.create", title: "Create a host directory", description: "Create one or more directories with explicit mode, ownership, and no-clobber behavior." },
  { name: "quirt.directory.watch", title: "Watch a host directory", description: "Start, poll, reconnect to, or cancel a durable kernel-backed directory watch with loss classification." },
  { name: "quirt.transfer.begin", title: "Begin a binary transfer", description: "Create a durable resumable upload or download manifest for files or tar archives." },
  { name: "quirt.transfer.read", title: "Read a transfer chunk", description: "Read a bounded integrity-labelled download chunk at an exact resumable offset." },
  { name: "quirt.transfer.write", title: "Write a transfer chunk", description: "Place an integrity-labelled upload chunk idempotently at an exact sparse-capable offset." },
  { name: "quirt.transfer.status", title: "Inspect a transfer", description: "Inspect durable transfer metadata, covered ranges, missing ranges, and completion state." },
  { name: "quirt.transfer.complete", title: "Complete a transfer", description: "Verify ranges, size, and digest before durably and atomically placing the final object." },
  { name: "quirt.transfer.cancel", title: "Cancel a transfer", description: "Cancel a durable transfer and remove its private partial object without exposing it." },
  { name: "quirt.session.snapshot", title: "Snapshot a Quirt session", description: "Persist descriptive reconnect state and an optional principal-bound cross-conversation handoff without process checkpointing." },
  { name: "quirt.session.search", title: "Search a Quirt session", description: "Search bounded retained terminal history and associated recording indexes with exact raw stream offsets." },
  { name: "quirt.session.render", title: "Render a Quirt terminal", description: "Deterministically render bounded raw terminal history into rows, cells, attributes, cursor state, and explicit loss indicators." },
  { name: "quirt.git.materialize", title: "Materialize a Git repository", description: "Materialize a real repository from a reusable mirror at an exact verified commit and tree." },
  { name: "quirt.git.mirror", title: "Manage a Git mirror", description: "Create, reuse, fetch, prune, integrity-check, or explicitly rebuild a credential-safe bare mirror." },
  { name: "quirt.git.fetch", title: "Fetch a Git repository", description: "Fetch a real repository with explicit remote, tag, prune, and credential-reference policy." },
  { name: "quirt.git.status", title: "Inspect Git state", description: "Read exact HEAD/tree, branch, remotes, ahead/behind, porcelain changes, submodules, LFS, and operation state." },
  { name: "quirt.git.worktree", title: "Manage Git worktrees", description: "Create, list, verify, or explicitly remove real Git worktrees with concurrent safety." },
  { name: "quirt.git.verify", title: "Verify Git identity", description: "Verify exact commit, tree, tag, working repository integrity, and requested signature trust status." },
  { name: "quirt.git.push", title: "Push Git refs", description: "Push exact branches or tags without force by default and require an exact lease for authorized force." },
  { name: "quirt.record.start", title: "Start or annotate recording", description: "Start a durable raw-byte terminal recording or append a marker/bookmark to an active recording." },
  { name: "quirt.record.stop", title: "Stop or remove recording", description: "Durably stop a recording, or deliberately remove a previously stopped principal-owned recording." },
  { name: "quirt.record.list", title: "List recordings", description: "List durable active, completed, and interrupted recordings for the exact principal." },
  { name: "quirt.record.search", title: "Search a recording", description: "Search indexed transcript text while retaining exact references to immutable raw recording events." },
  { name: "quirt.record.replay", title: "Replay a recording", description: "Read bounded ordered raw recording events with original timing and variable-speed metadata." },
  { name: "quirt.record.export", title: "Export a recording", description: "Produce deterministic paged Quirt JSON, asciinema-v2, or HTML transcript exports with checksums." },
  { name: "quirt.process.list", title: "List host processes", description: "List bounded Linux processes with exact PID/start/boot/namespace identity and Quirt correlation." },
  { name: "quirt.process.get", title: "Inspect a host process", description: "Inspect one process identity, credentials, arguments, CPU, memory, cgroup, namespaces, unit, and Quirt correlation." },
  { name: "quirt.process.signal", title: "Signal a host process", description: "Send an unrestricted authorized signal only after exact process identity and PID-reuse verification." },
  { name: "quirt.process.attach", title: "Attach to a process or journal", description: "Attach to Quirt-owned process streams, or open/read/cancel a durable machine-readable journald cursor poll." },
  { name: "quirt.process.tree", title: "Inspect a process tree", description: "Read bounded race-aware parent and child relationships with exact process identities." },
  { name: "quirt.process.namespaces", title: "Inspect process namespaces", description: "Read exact Linux mount, PID, network, user, IPC, UTS, cgroup, and time namespace identities." },
  ...QUIRT_POWER_FOUNDATION_TOOL_DEFINITIONS
];

export interface QuirtToolInvocation { operation: QuirtCoreOperation; payload: Record<string, unknown>; binary: Buffer; requestId?: string; signal?: AbortSignal; }
export interface QuirtToolHandlers { invoke(input: QuirtToolInvocation): Promise<CallToolResult> | CallToolResult; }

function decodeBase64(value: unknown): Buffer {
  if (typeof value !== "string") return Buffer.alloc(0);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error("Quirt binary input is not canonical base64");
  return bytes;
}

function invocation(operation: QuirtCoreOperation, raw: Record<string, unknown>): QuirtToolInvocation {
  const payload = { ...raw }; const requestId = typeof payload.requestId === "string" ? payload.requestId : undefined; delete payload.requestId;
  const binaryField = operation === "quirt.exec" ? "inputBase64" : operation === "quirt.session.write" || operation === "quirt.job.input" || operation === "quirt.file.write" || operation === "quirt.transfer.write" || operation === "quirt.pane.broadcast" || operation === "quirt.browser.upload" ? "contentBase64" : null;
  const binary = binaryField === null ? Buffer.alloc(0) : decodeBase64(payload[binaryField]); if (binaryField !== null) delete payload[binaryField];
  return { operation, payload, binary, requestId };
}

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
const mutation = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true } as const;

export function registerQuirtTools(server: McpServer, handlers: QuirtToolHandlers): void {
  for (const definition of DEFINITIONS) {
    const scope = QUIRT_TOOL_SCOPES[definition.name]; const meta = { ...HORSEY_AUTHORITY_TOOL_META, securitySchemes: [{ type: "oauth2", scopes: [scope] }] };
    server.registerTool(definition.name, { title: definition.title, description: definition.description, inputSchema: quirtToolSchemas[definition.name], annotations: scope === "fix.read" ? readOnly : mutation, _meta: meta }, (input: Record<string, unknown>, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => { const value = invocation(definition.name, input); return handlers.invoke(extra.signal === undefined ? value : { ...value, signal: extra.signal }); });
  }
}
