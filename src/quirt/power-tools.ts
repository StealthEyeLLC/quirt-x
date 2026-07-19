import * as z from "zod/v4";
import { QUIRT_POWER_OPERATION_MATRIX, QUIRT_POWER_OPERATIONS, type QuirtPowerOperation } from "./power-catalog.js";

const requestId = z.string().min(1).max(128).regex(/^[^\0\r\n]+$/u).optional();
const id = z.string().min(1).max(128).regex(/^[^\0\r\n]+$/u);
const text = z.string().min(1).max(65_536).refine((value) => !value.includes("\0"));
const path = z.string().min(1).max(32_768).startsWith("/").refine((value) => !value.includes("\0"));
const argument = z.string().max(65_536).refine((value) => !value.includes("\0"));
const argumentsList = z.array(argument).max(1024);
const contentBase64 = z.string().max(11_184_812).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u);
const references = z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9._-]{0,63}$/u), path).refine((value) => Object.keys(value).length <= 32);
const ideReferences = z.strictObject({ authentication: path });
const rcloneReferences = z.strictObject({ config: path });
const resticReferences = z.strictObject({ passwordFile: path });
const sshReferences = z.strictObject({ identityFile: path, knownHostsFile: path });
const desktopReferences = z.strictObject({ passwordFile: path });
const environment = z.record(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/u), argument)
  .refine((value) => Object.keys(value).length <= 512 && Object.keys(value).every((name) => !/password|secret|token|private.?key|credential/iu.test(name)));
const cursor = {
  maximum: z.number().int().min(1).max(1000).optional(),
  afterCreatedAt: z.iso.datetime().optional(),
  afterInstanceId: id.optional()
};
const events = {
  includeEvents: z.boolean().optional(),
  after: z.number().int().min(-1).max(Number.MAX_SAFE_INTEGER).optional(),
  maximumEvents: z.number().int().min(1).max(1000).optional()
};
const endpoint = z.union([z.strictObject({ host: z.string().min(1).max(1024), port: z.number().int().min(1).max(65_535) }), z.strictObject({ socketPath: path })]);
const instance = { instanceId: id };
const processIdentity = z.strictObject({
  pid: z.number().int().min(1).max(0x7fffffff),
  startTime: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  bootId: z.string().uuid()
});
function strict(shape: Record<string, z.ZodType>): z.ZodType {
  return z.strictObject({ requestId, ...shape });
}

const READ_OPERATIONS = new Set<QuirtPowerOperation>([
  "quirt.pane.list",
  "quirt.ide.list", "quirt.ide.repository", "quirt.ide.port",
  "quirt.browser.list", "quirt.browser.video", "quirt.browser.download", "quirt.browser.show",
  "quirt.preview.list", "quirt.preview.get", "quirt.preview.logs",
  "quirt.sync.list", "quirt.sync.status",
  "quirt.remote.list",
  "quirt.snapshot.list", "quirt.snapshot.get", "quirt.snapshot.diff",
  "quirt.network.interfaces", "quirt.network.routes", "quirt.network.connections", "quirt.network.listeners", "quirt.network.firewall",
  "quirt.tunnel.list", "quirt.tunnel.get",
  "quirt.trace.list", "quirt.trace.follow", "quirt.trace.report", "quirt.trace.flamegraph",
  "quirt.checkpoint.list", "quirt.checkpoint.get",
  "quirt.desktop.list",
  "quirt.host.list", "quirt.host.get", "quirt.fleet.status"
]);

export const QUIRT_POWER_FOUNDATION_TOOL_SCOPES = Object.freeze(Object.fromEntries(
  QUIRT_POWER_OPERATIONS.map((operation) => [operation, READ_OPERATIONS.has(operation) ? "fix.read" : "fix.execute"])
)) as Readonly<Record<QuirtPowerOperation, "fix.read" | "fix.execute">>;

export type QuirtPowerFoundationOperation = QuirtPowerOperation;

export const quirtPowerFoundationToolSchemas = Object.freeze({
  "quirt.pane.open": strict({ sessionId: id, name: text.max(256).optional(), executable: text.optional(), arguments: argumentsList.optional(), jobId: id.optional(), correlation: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).optional() }),
  "quirt.pane.list": strict({ sessionId: id }),
  "quirt.pane.split": strict({ sessionId: id, paneId: z.string().regex(/^%[0-9]+$/u), direction: z.enum(["horizontal", "vertical"]).optional(), size: z.number().int().min(1).max(10_000).optional(), executable: text.optional(), arguments: argumentsList.optional(), jobId: id.optional(), correlation: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).optional() }),
  "quirt.pane.focus": strict({ sessionId: id, paneId: z.string().regex(/^%[0-9]+$/u) }),
  "quirt.pane.resize": strict({ sessionId: id, paneId: z.string().regex(/^%[0-9]+$/u), width: z.number().int().min(1).max(10_000).optional(), height: z.number().int().min(1).max(10_000).optional() }),
  "quirt.pane.move": strict({ sessionId: id, sourcePaneId: z.string().regex(/^%[0-9]+$/u), destinationPaneId: z.string().regex(/^%[0-9]+$/u), action: z.enum(["swap", "move"]).optional() }),
  "quirt.pane.broadcast": strict({ sessionId: id, windowId: z.string().regex(/^@[0-9]+$/u).optional(), paneId: z.string().regex(/^%[0-9]+$/u).optional(), enabled: z.boolean().optional(), text: z.string().max(1_048_576).optional(), contentBase64: contentBase64.optional() }),
  "quirt.pane.close": strict({ sessionId: id, paneId: z.string().regex(/^%[0-9]+$/u).optional(), windowId: z.string().regex(/^@[0-9]+$/u).optional(), instanceId: id.optional() }),

  "quirt.ide.open": strict({ workspacePath: path, repositoryPath: path.optional(), executablePath: path.optional(), bindAddress: z.enum(["127.0.0.1", "::1", "localhost"]).optional(), port: z.number().int().min(0).max(65_535).optional(), credentialReferences: ideReferences, sessionId: id.optional(), handoffId: id.optional(), readinessTimeoutMs: z.number().int().min(100).max(300_000).optional(), expiresInSeconds: z.number().int().min(60).max(604_800).optional() }),
  "quirt.ide.list": strict(cursor),
  "quirt.ide.repository": strict({ ...instance, repositoryPath: path }),
  "quirt.ide.port": strict(instance),
  "quirt.ide.close": strict({ ...instance, force: z.boolean().optional() }),

  "quirt.browser.open": strict({ engine: z.enum(["chromium", "firefox", "webkit"]).optional(), executablePath: path.optional(), userDataPath: path.optional(), headless: z.boolean().optional(), viewport: z.strictObject({ width: z.number().int().min(200).max(7680), height: z.number().int().min(200).max(4320) }).optional(), recordVideo: z.boolean().optional() }),
  "quirt.browser.list": strict(cursor),
  "quirt.browser.command": strict({ ...instance, pageId: id.optional(), action: z.enum(["page.new", "page.select", "page.close", "navigate", "wait", "click", "type", "keyboard", "mouse", "evaluate", "content", "accessibility", "cookies", "storageState", "viewport", "pdf", "events"]), url: z.string().url().max(32_768).optional(), waitUntil: z.enum(["load", "domcontentloaded", "networkidle", "commit"]).optional(), selector: text.max(16_384).optional(), state: z.enum(["attached", "detached", "hidden", "visible"]).optional(), timeoutMs: z.number().int().min(0).max(300_000).optional(), text: z.string().max(1_048_576).optional(), key: text.max(256).optional(), mouseAction: z.enum(["move", "click"]).optional(), x: z.number().int().min(0).max(100_000).optional(), y: z.number().int().min(0).max(100_000).optional(), button: z.enum(["left", "middle", "right"]).optional(), expression: text.max(1_048_576).optional(), maximumBytes: z.number().int().min(1).max(1_048_576).optional(), path: path.optional(), width: z.number().int().min(200).max(7680).optional(), height: z.number().int().min(200).max(4320).optional(), printBackground: z.boolean().optional(), after: z.number().int().min(-1).optional(), maximumEvents: z.number().int().min(1).max(1000).optional() }),
  "quirt.browser.screenshot": strict({ ...instance, pageId: id.optional(), path: path.optional(), fullPage: z.boolean().optional(), type: z.enum(["png", "jpeg"]).optional(), quality: z.number().int().min(1).max(100).optional(), maximumBytes: z.number().int().min(1).max(8 * 1024 * 1024).optional() }),
  "quirt.browser.video": strict({ ...instance, pageId: id.optional() }),
  "quirt.browser.download": strict({ ...instance, downloadId: id }),
  "quirt.browser.upload": strict({ ...instance, pageId: id.optional(), selector: text.max(16_384), path: path.optional(), contentBase64: contentBase64.optional() }),
  "quirt.browser.show": strict(instance),
  "quirt.browser.close": strict(instance),

  "quirt.preview.open": strict({ kind: z.enum(["managed", "existing"]).optional(), executable: text.optional(), script: z.string().min(1).max(1_048_576).optional(), arguments: argumentsList.optional(), workingDirectory: path.optional(), environment: environment.optional(), bindAddress: z.enum(["127.0.0.1", "::1", "localhost", "0.0.0.0", "::", "*"]).optional(), allowPublicBinding: z.boolean().optional(), port: z.number().int().min(1).max(65_535).optional(), readiness: z.enum(["none", "tcp", "http"]).optional(), readinessPath: z.string().min(1).max(2048).startsWith("/").optional(), readinessTimeoutMs: z.number().int().min(100).max(300_000).optional(), lifetimeTimeoutMs: z.number().int().min(1000).max(604_800_000).optional(), expiresInSeconds: z.number().int().min(60).max(604_800).optional(), sessionId: id.optional(), jobId: id.optional() }),
  "quirt.preview.list": strict(cursor),
  "quirt.preview.get": strict({ ...instance, ...events }),
  "quirt.preview.logs": strict({ ...instance, jobId: id.optional(), stream: z.enum(["stdout", "stderr"]).optional(), after: z.number().int().min(0).optional(), maximumBytes: z.number().int().min(1).max(1_048_576).optional() }),
  "quirt.preview.close": strict({ ...instance, force: z.boolean().optional() }),

  "quirt.sync.create": strict({ folderPath: path, deviceIds: z.array(id).min(1).max(256), homePath: path.optional() }),
  "quirt.sync.list": strict(cursor),
  "quirt.sync.status": strict({ ...instance, after: z.number().int().min(-1).optional(), maximumEvents: z.number().int().min(1).max(1000).optional() }),
  "quirt.sync.pause": strict(instance),
  "quirt.sync.resume": strict(instance),
  "quirt.sync.remove": strict({ ...instance, force: z.boolean().optional() }),

  "quirt.remote.add": strict({ backend: text.max(128), remoteName: text.max(128).optional(), credentialReferences: rcloneReferences.optional() }),
  "quirt.remote.list": strict(cursor),
  "quirt.remote.mount": strict({ ...instance, remotePath: text.max(32_768), localPath: path }),
  "quirt.remote.copy": strict({ ...instance, remotePath: text.max(32_768), localPath: path, direction: z.enum(["upload", "download"]).optional(), timeoutMs: z.number().int().min(1000).max(604_800_000).optional() }),
  "quirt.remote.sync": strict({ ...instance, remotePath: text.max(32_768), localPath: path, direction: z.enum(["upload", "download"]).optional(), timeoutMs: z.number().int().min(1000).max(604_800_000).optional() }),
  "quirt.remote.serve": strict({ ...instance, remotePath: text.max(32_768), bindAddress: z.enum(["127.0.0.1", "::1"]).optional(), port: z.number().int().min(0).max(65_535).optional() }),
  "quirt.remote.unmount": strict({ ...instance, force: z.boolean().optional() }),

  "quirt.snapshot.create": strict({ repository: text.max(32_768), sourcePaths: z.array(path).min(1).max(256), includes: z.array(text.max(4096)).max(1024).optional(), excludes: z.array(text.max(4096)).max(1024).optional(), credentialReferences: resticReferences, initialize: z.boolean().optional(), timeoutMs: z.number().int().min(1000).max(604_800_000).optional() }),
  "quirt.snapshot.list": strict({ instanceId: id.optional(), maximum: z.number().int().min(1).max(1000).optional(), afterSnapshotId: id.optional() }),
  "quirt.snapshot.get": strict({ snapshotId: id }),
  "quirt.snapshot.diff": strict({ ...instance, leftSnapshotId: id, rightSnapshotId: id }),
  "quirt.snapshot.mount": strict({ ...instance, mountPath: path }),
  "quirt.snapshot.restore": strict({ snapshotId: id, destination: path, conflictPolicy: z.enum(["fail", "skip", "overwrite"]).optional(), preview: z.boolean().optional(), timeoutMs: z.number().int().min(1000).max(604_800_000).optional() }),
  "quirt.snapshot.unmount": strict({ ...instance, force: z.boolean().optional() }),
  "quirt.snapshot.remove": strict({ snapshotId: id, prune: z.boolean().optional() }),

  "quirt.network.interfaces": strict({}),
  "quirt.network.routes": strict({}),
  "quirt.network.connections": strict({}),
  "quirt.network.listeners": strict({}),
  "quirt.network.firewall": strict({}),
  "quirt.network.capture": strict({ interface: text.max(128).optional(), outputPath: path.optional(), packetLimit: z.number().int().min(1).max(10_000_000).optional(), filterArguments: argumentsList.optional() }),

  "quirt.tunnel.open": strict({ kind: z.enum(["local", "remote", "reverse", "tcp", "unix"]).optional(), sshHost: text.max(1024), sshUser: text.max(256), localEndpoint: endpoint, remoteEndpoint: endpoint, credentialReferences: sshReferences, allowPublicBinding: z.boolean().optional() }),
  "quirt.tunnel.list": strict(cursor),
  "quirt.tunnel.get": strict({ ...instance, ...events }),
  "quirt.tunnel.pause": strict(instance),
  "quirt.tunnel.resume": strict(instance),
  "quirt.tunnel.close": strict({ ...instance, force: z.boolean().optional() }),

  "quirt.trace.start": strict({ type: z.enum(["strace", "perf", "gdb", "bpftrace", "tcpdump"]), pid: z.number().int().min(0).max(0x7fffffff).optional(), processIdentity: processIdentity.optional(), outputPath: path.optional(), scriptPath: path.optional(), durationSeconds: z.number().int().min(1).max(86400).optional(), packetLimit: z.number().int().min(1).max(10_000_000).optional() }),
  "quirt.trace.list": strict(cursor),
  "quirt.trace.follow": strict({ ...instance, jobId: id.optional(), stream: z.enum(["stdout", "stderr"]).optional(), after: z.number().int().min(0).optional(), maximumBytes: z.number().int().min(1).max(1_048_576).optional() }),
  "quirt.trace.stop": strict({ ...instance, force: z.boolean().optional() }),
  "quirt.trace.report": strict({ ...instance, maximumBytes: z.number().int().min(1).max(4 * 1024 * 1024).optional(), exportPath: path.optional() }),
  "quirt.trace.flamegraph": strict(instance),

  "quirt.checkpoint.create": strict({ pid: z.number().int().min(1).max(0x7fffffff), processIdentity: processIdentity.optional(), checkpointPath: path.optional(), leaveRunning: z.boolean().optional(), timeoutMs: z.number().int().min(1000).max(3_600_000).optional() }),
  "quirt.checkpoint.list": strict(cursor),
  "quirt.checkpoint.get": strict({ ...instance, ...events }),
  "quirt.checkpoint.restore": strict({ ...instance, detach: z.boolean().optional(), timeoutMs: z.number().int().min(1000).max(3_600_000).optional() }),
  "quirt.checkpoint.remove": strict(instance),

  "quirt.desktop.open": strict({ credentialReferences: desktopReferences, display: z.number().int().min(1).max(999).optional(), port: z.number().int().min(1).max(65_535).optional(), width: z.number().int().min(320).max(7680).optional(), height: z.number().int().min(200).max(4320).optional(), depth: z.number().int().min(16).max(32).optional(), expiresInSeconds: z.number().int().min(60).max(604_800).optional() }),
  "quirt.desktop.list": strict(cursor),
  "quirt.desktop.capture": strict({ ...instance, outputPath: path.optional(), inline: z.boolean().optional() }),
  "quirt.desktop.input": strict({ ...instance, action: z.enum(["key", "type", "mousemove", "click"]), value: z.string().max(65_536).optional(), key: text.max(256).optional(), delayMs: z.number().int().min(0).max(10_000).optional(), x: z.number().int().min(0).max(100_000).optional(), y: z.number().int().min(0).max(100_000).optional(), button: z.number().int().min(1).max(32).optional() }),
  "quirt.desktop.resize": strict({ ...instance, width: z.number().int().min(320).max(7680), height: z.number().int().min(200).max(4320) }),
  "quirt.desktop.close": strict({ ...instance, force: z.boolean().optional() }),

  "quirt.host.add": strict({ host: text.max(1024), user: text.max(256), port: z.number().int().min(1).max(65_535).optional(), credentialReferences: sshReferences }),
  "quirt.host.list": strict(cursor),
  "quirt.host.get": strict({ ...instance, ...events }),
  "quirt.host.remove": strict({ ...instance, force: z.boolean().optional() }),
  "quirt.host.shell": strict({ ...instance, command: argumentsList }),
  "quirt.fleet.exec": strict({ instanceIds: z.array(id).min(1).max(256), command: argumentsList, maximumBytesPerHost: z.number().int().min(1).max(4 * 1024 * 1024).optional(), timeoutMs: z.number().int().min(1000).max(86_400_000).optional(), concurrency: z.number().int().min(1).max(32).optional() }),
  "quirt.fleet.copy": strict({ ...instance, localPath: path, remotePath: text.max(32_768), direction: z.enum(["upload", "download"]).optional(), timeoutMs: z.number().int().min(1000).max(604_800_000).optional() }),
  "quirt.fleet.playbook": strict({ instanceIds: z.array(id).min(1).max(256), inventoryPath: path, playbookPath: path, timeoutMs: z.number().int().min(1000).max(604_800_000).optional() }),
  "quirt.fleet.status": strict({ ...instance, runId: id.optional(), after: z.number().int().min(-1).optional(), maximumEvents: z.number().int().min(1).max(1000).optional() })
} satisfies Readonly<Record<QuirtPowerOperation, z.ZodType>>);

export interface QuirtPowerToolDefinition {
  name: QuirtPowerOperation;
  title: string;
  description: string;
}

export const QUIRT_POWER_FOUNDATION_TOOL_DEFINITIONS = Object.freeze(
  QUIRT_POWER_OPERATION_MATRIX.map((entry) => ({
    name: entry.operationId,
    title: entry.purpose,
    description: entry.purpose + " through the principal-bound durable Quirt power-provider framework."
  }))
) satisfies readonly QuirtPowerToolDefinition[];

export function isPowerFoundationOperation(value: QuirtPowerOperation): value is QuirtPowerFoundationOperation {
  return Object.hasOwn(QUIRT_POWER_FOUNDATION_TOOL_SCOPES, value);
}
