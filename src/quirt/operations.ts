import type { QuirtConfig } from "./config.js";
import { QUIRT_OPERATIONS, type QuirtOperation } from "./catalog.js";
import { isQuirtPowerOperation } from "./power-catalog.js";
import { QuirtPowerProviderRegistry, QuirtPowerProviderService } from "./power-provider.js";
import { TmuxPaneProvider } from "./providers/pane-provider.js";
import { PreviewProvider } from "./providers/preview-provider.js";
import { CodeServerProvider } from "./providers/ide-provider.js";
import { PlaywrightBrowserProvider } from "./providers/browser-provider.js";
import { RcloneProvider, ResticProvider, SyncthingProvider } from "./providers/storage-providers.js";
import { LinuxNetworkProvider, LinuxTraceProvider, OpenSshTunnelProvider } from "./providers/network-providers.js";
import { CriuCheckpointProvider, SshFleetProvider, VncDesktopProvider } from "./providers/conditional-providers.js";
import { QuirtDirectoryService } from "./directory-service.js";
import { QuirtError } from "./error.js";
import { QuirtFileService } from "./file-service.js";
import { QuirtGitService } from "./git-service.js";
import type { QuirtJobManager, QuirtExecInput } from "./job-manager.js";
import type { QuirtEnvironmentPolicy } from "./execution-environment.js";
import { QuirtCapabilityService } from "./capability-service.js";
import { QuirtProcessService, type QuirtProcessIdentity } from "./process-service.js";
import { QUIRT_PROTOCOL_VERSION, type QuirtPrincipalEnvelope, type QuirtRequestEnvelope } from "./protocol.js";
import type { QuirtSessionManager, QuirtSessionOpenInput } from "./session-manager.js";
import { QuirtRecordingService } from "./recording-service.js";
import { QuirtSessionNativeService } from "./session-native-service.js";
import { QUIRT_STATE_SCHEMA_VERSION, type QuirtJobRecord, type QuirtSessionRecord, type QuirtStateStore } from "./state.js";
import type { QuirtTmuxController } from "./tmux.js";
import { QuirtTransferService } from "./transfer-service.js";

export { QUIRT_CORE_OPERATIONS, QUIRT_NATIVE_FOUNDATION_OPERATIONS, QUIRT_NATIVE_OPERATOR_OPERATIONS, QUIRT_POWER_FOUNDATION_OPERATIONS, QUIRT_OPERATIONS } from "./catalog.js";
export type QuirtCoreOperation = QuirtOperation;
export interface QuirtOperationResult { payload: Record<string, unknown>; binary: Buffer; }

function object(value: unknown, label = "Quirt payload"): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new QuirtError("invalid_request", `${label} is invalid`);
  return value as Record<string, unknown>;
}

function text(value: unknown, name: string, options: { optional?: boolean; maximum?: number } = {}): string | undefined {
  if (value === undefined && options.optional) return undefined;
  if (typeof value !== "string" || value.length < 1 || value.includes("\0") || Buffer.byteLength(value) > (options.maximum ?? 4096)) throw new QuirtError("invalid_request", `${name} is invalid`);
  return value;
}

function integer(value: unknown, name: string, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new QuirtError("invalid_request", `${name} is invalid`);
  return value;
}

function boolean(value: unknown, name: string, fallback = false): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new QuirtError("invalid_request", `${name} is invalid`);
  return value;
}

function stringArray(value: unknown, name: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 1024 || value.some(item => typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > 64 * 1024)) throw new QuirtError("invalid_request", `${name} is invalid`);
  return [...value] as string[];
}

function environment(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const source = object(value, "Quirt environment");
  if (Object.keys(source).length > 512) throw new QuirtError("invalid_request", "Quirt environment is too large");
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(source)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(key) || typeof item !== "string" || item.includes("\0") || Buffer.byteLength(item) > 64 * 1024) throw new QuirtError("invalid_request", "Quirt environment is invalid");
    output[key] = item;
  }
  return output;
}

function signal(value: unknown, fallback: NodeJS.Signals = "SIGTERM"): NodeJS.Signals {
  return (text(value ?? fallback, "Quirt signal", { maximum: 16 }) ?? fallback) as NodeJS.Signals;
}

function noBinary(binary: Buffer): void {
  if (binary.length !== 0) throw new QuirtError("invalid_request", "This Quirt operation does not accept binary input");
}

function publicSession(record: QuirtSessionRecord): Record<string, unknown> {
  const { environment: storedEnvironment, ownerPrincipalFingerprint: _owner, ...rest } = record;
  return { ...rest, environmentKeys: Object.keys(storedEnvironment).sort() };
}

function environmentPolicy(value: unknown): QuirtEnvironmentPolicy | undefined {
  if (value === undefined) return undefined;
  const source = object(value, "Quirt environment policy");
  const unset = source.unsetEnvironment;
  if (unset !== undefined && (!Array.isArray(unset) || unset.some(item => typeof item !== "string"))) throw new QuirtError("invalid_request", "Quirt environment unset list is invalid");
  return {
    environment: environment(source.environment),
    unsetEnvironment: unset as string[] | undefined,
    replaceEnvironment: source.replaceEnvironment === undefined ? undefined : boolean(source.replaceEnvironment, "Quirt environment replacement")
  };
}

function publicJob(record: QuirtJobRecord): Record<string, unknown> {
  const {
    environment: _environment,
    ownerPrincipalFingerprint: _owner,
    command,
    ...rest
  } = record;
  const safeCommand = { ...command };
  delete safeCommand.command;
  delete safeCommand.script;
  return {
    ...rest,
    command: safeCommand,
    environmentKeys: record.environmentKeys,
    processIdentitySummary: record.processIdentity === null ? null : {
      pid: record.processIdentity.pid,
      startTimeTicks: record.processIdentity.startTimeTicks,
      bootId: record.processIdentity.bootId,
      executablePath: record.processIdentity.executablePath ?? null
    }
  };
}

function ok(payload: Record<string, unknown>, binary: Buffer = Buffer.alloc(0)): QuirtOperationResult { return { payload, binary }; }

export class QuirtOperationDispatcher {
  readonly files: QuirtFileService;
  readonly directories: QuirtDirectoryService;
  readonly transfers: QuirtTransferService;
  readonly git: QuirtGitService;
  readonly recordings: QuirtRecordingService;
  readonly processService: QuirtProcessService;
  readonly sessionNative: QuirtSessionNativeService;
  readonly capabilities: QuirtCapabilityService;
  readonly power: QuirtPowerProviderService;

  constructor(
    private readonly config: QuirtConfig,
    private readonly state: QuirtStateStore,
    private readonly sessions: QuirtSessionManager,
    private readonly jobs: QuirtJobManager,
    private readonly tmux: QuirtTmuxController,
    private readonly revision = process.env.QUIRT_COMMIT_SHA ?? "source-build",
    services: { files?: QuirtFileService; directories?: QuirtDirectoryService; transfers?: QuirtTransferService; git?: QuirtGitService; recordings?: QuirtRecordingService; processService?: QuirtProcessService; sessionNative?: QuirtSessionNativeService; capabilities?: QuirtCapabilityService; power?: QuirtPowerProviderService } = {}
  ) {
    this.files = services.files ?? new QuirtFileService();
    this.directories = services.directories ?? new QuirtDirectoryService(state);
    this.transfers = services.transfers ?? new QuirtTransferService(config, state);
    this.git = services.git ?? new QuirtGitService(config, state);
    this.recordings = services.recordings ?? new QuirtRecordingService(config, state, sessions);
    this.processService = services.processService ?? new QuirtProcessService(config, state, sessions, jobs);
    this.sessionNative = services.sessionNative ?? new QuirtSessionNativeService(config, state, sessions, jobs, this.recordings);
    if (services.power !== undefined) this.power = services.power;
    else {
      const registry = new QuirtPowerProviderRegistry(state);
      registry.register(new TmuxPaneProvider());
      registry.register(new CodeServerProvider());
      registry.register(new PlaywrightBrowserProvider());
      registry.register(new PreviewProvider());
      registry.register(new SyncthingProvider());
      registry.register(new RcloneProvider());
      registry.register(new ResticProvider());
      registry.register(new LinuxNetworkProvider());
      registry.register(new OpenSshTunnelProvider());
      registry.register(new LinuxTraceProvider());
      registry.register(new CriuCheckpointProvider());
      registry.register(new VncDesktopProvider());
      registry.register(new SshFleetProvider());
      this.power = new QuirtPowerProviderService(config, state, sessions, jobs, tmux, this.processService, registry);
    }
    this.capabilities = services.capabilities ?? new QuirtCapabilityService(config, state, tmux, this.git, this.processService, this.power);
  }

  async execute(request: QuirtRequestEnvelope, binary: Buffer, abortSignal?: AbortSignal): Promise<QuirtOperationResult> {
    if (!QUIRT_OPERATIONS.includes(request.operation as QuirtCoreOperation)) throw new QuirtError("unknown_operation", "Quirt operation is unknown");
    const principal = request.principal;
    const payload = object(request.payload);
    if (isQuirtPowerOperation(request.operation)) {
      const result = await this.power.execute({ operation: request.operation, payload, binary, requestId: request.requestId, ownerPrincipalFingerprint: principal.principalFingerprint, targetHost: request.targetHost, signal: abortSignal });
      return ok(result.payload, result.binary ?? Buffer.alloc(0));
    }
    switch (request.operation as QuirtCoreOperation) {
      case "quirt.status": {
        noBinary(binary);
        let tmux: string | null = null;
        try { tmux = await this.tmux.version(); } catch { tmux = null; }
        return ok({ ...await this.capabilities.status(principal.principalFingerprint), supervisorId: this.config.supervisorId, uid: process.getuid?.() ?? null, tmux, activeSessionCount: this.sessions.list(principal.principalFingerprint).filter(item => item.status === "running").length, activeJobCount: this.jobs.list(principal.principalFingerprint).filter(item => item.status === "running").length, activeTransferCount: this.state.native.listTransfers(principal.principalFingerprint).filter(item => item.status === "active").length, activeRecordingCount: this.state.native.listObjects("quirt_recordings", principal.principalFingerprint).filter(item => item.status === "active").length, transport: "unix-domain-socket", socketPath: this.config.socketPath, publicListener: false });
      }
      case "quirt.capabilities": {
        noBinary(binary);
        return ok(await this.capabilities.inventory(principal.principalFingerprint));
      }
      case "quirt.version":
        noBinary(binary);
        return ok({ product: "StealthEye Quirt", protocolVersion: QUIRT_PROTOCOL_VERSION, stateSchemaVersion: QUIRT_STATE_SCHEMA_VERSION, revision: this.revision, supervisorId: this.config.supervisorId, targetHost: this.config.targetHost, implementation: "native-unrestricted-root-supervisor", operationCount: QUIRT_OPERATIONS.length, operations: [...QUIRT_OPERATIONS], nodeVersion: process.version, gatewayCompatibility: { protocolVersions: [QUIRT_PROTOCOL_VERSION], exactPrincipalRequired: true, nullWorkspaceRequired: true } });
      case "quirt.exec":
        return await this.#exec(request, payload, binary, principal, abortSignal);
      case "quirt.session.open": {
        noBinary(binary);
        const input: QuirtSessionOpenInput = {
          name: text(payload.name, "Quirt session name", { optional: true, maximum: 256 }),
          mode: payload.mode === undefined ? undefined : payload.mode === "tmux" || payload.mode === "direct" ? payload.mode : (() => { throw new QuirtError("invalid_request", "Quirt session mode is invalid"); })(),
          executable: text(payload.executable, "Quirt session executable", { optional: true }),
          arguments: stringArray(payload.arguments, "Quirt session arguments"),
          workingDirectory: text(payload.workingDirectory, "Quirt session working directory", { optional: true }),
          environment: environment(payload.environment),
          columns: integer(payload.columns, "Quirt terminal columns", 120, 2, 1000),
          rows: integer(payload.rows, "Quirt terminal rows", 40, 1, 1000),
          loginShell: payload.loginShell === undefined ? undefined : boolean(payload.loginShell, "Quirt login shell")
        };
        return ok({ session: publicSession(await this.sessions.open(input, principal.principalFingerprint)) });
      }
      case "quirt.session.list":
        noBinary(binary);
        return ok({ sessions: this.sessions.list(principal.principalFingerprint).map(publicSession) });
      case "quirt.session.get":
        noBinary(binary);
        return ok({ session: publicSession(this.sessions.get(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint)) });
      case "quirt.session.attach": {
        noBinary(binary);
        const handoffId = text(payload.handoffId, "Quirt handoff ID", { optional: true, maximum: 128 }); const handoff = handoffId === undefined ? null : this.sessionNative.handoff(handoffId, principal.principalFingerprint); const sessionId = handoff?.sessionId ?? text(payload.sessionId, "Quirt session ID")!;
        const attached = await this.sessions.attach(sessionId, principal.principalFingerprint, { readerId: text(payload.readerId, "Quirt reader ID", { optional: true, maximum: 128 }), after: payload.after === undefined ? handoff?.after : integer(payload.after, "Quirt offset", 0, 0, Number.MAX_SAFE_INTEGER) });
        const record = object(attached.session, "Quirt session");
        return ok({ ...attached, session: publicSession(record as unknown as QuirtSessionRecord), handoff: handoff?.handoff ?? null, replacementShellOpened: false });
      }
      case "quirt.session.read": {
        noBinary(binary);
        const page = this.sessions.read(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint, { after: payload.after === undefined ? undefined : integer(payload.after, "Quirt offset", 0, 0, Number.MAX_SAFE_INTEGER), maximumBytes: integer(payload.maximumBytes, "Quirt maximum bytes", this.config.outputChunkBytes, 1, Math.min(this.config.maxFrameBytes - 4096, 8 * 1024 * 1024)), readerId: text(payload.readerId, "Quirt reader ID", { optional: true, maximum: 128 }) });
        return ok({ streamId: page.streamId, startOffset: page.startOffset, endOffset: page.endOffset, nextOffset: page.nextOffset, retainedStartOffset: page.retainedStartOffset, byteCount: page.bytes.length, eof: page.eof }, page.bytes);
      }
      case "quirt.session.write": {
        const value = await this.sessions.write(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint, binary);
        return ok(value);
      }
      case "quirt.session.resize":
        noBinary(binary);
        return ok({ session: publicSession(await this.sessions.resize(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint, integer(payload.columns, "Quirt terminal columns", 120, 2, 1000), integer(payload.rows, "Quirt terminal rows", 40, 1, 1000))) });
      case "quirt.session.signal":
        noBinary(binary);
        return ok({ session: publicSession(await this.sessions.signal(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint, signal(payload.signal))) });
      case "quirt.session.detach":
        noBinary(binary);
        return ok({ session: publicSession(this.sessions.detach(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint, text(payload.readerId, "Quirt reader ID", { optional: true, maximum: 128 }))) });
      case "quirt.session.close":
        noBinary(binary);
        return ok({ session: publicSession(await this.sessions.close(text(payload.sessionId, "Quirt session ID")!, principal.principalFingerprint, signal(payload.signal, "SIGHUP"))) });
      case "quirt.job.list": {
        noBinary(binary);
        const status = payload.status === undefined ? undefined : text(payload.status, "Quirt job status", { maximum: 32 }) as QuirtJobRecord["status"];
        const requestId = text(payload.requestId, "Quirt request ID", { optional: true, maximum: 128 });
        return ok({ jobs: this.jobs.list(principal.principalFingerprint, { ...(requestId === undefined ? {} : { requestId }), ...(status === undefined ? {} : { status }) }).map(publicJob) });
      }
      case "quirt.job.get": {
        noBinary(binary);
        const jobId = text(payload.jobId, "Quirt job ID", { optional: true });
        const requestId = text(payload.requestId, "Quirt request ID", { optional: true, maximum: 128 });
        if (jobId !== undefined && requestId !== undefined) throw new QuirtError("invalid_request", "Quirt job lookup must use job ID or request ID");
        const record = jobId !== undefined
          ? this.jobs.get(jobId, principal.principalFingerprint)
          : this.jobs.getByRequestId(requestId!, principal.principalFingerprint);
        return ok({ job: publicJob(record) });
      }
      case "quirt.job.read": {
        noBinary(binary);
        const stream = payload.stream === "stdout" || payload.stream === "stderr" ? payload.stream : (() => { throw new QuirtError("invalid_request", "Quirt job stream is invalid"); })();
        const page = this.jobs.read(text(payload.jobId, "Quirt job ID")!, principal.principalFingerprint, stream, integer(payload.after, "Quirt offset", 0, 0, Number.MAX_SAFE_INTEGER), integer(payload.maximumBytes, "Quirt maximum bytes", this.config.outputChunkBytes, 1, Math.min(this.config.maxFrameBytes - 4096, 8 * 1024 * 1024)));
        return ok({ streamId: page.streamId, stream, startOffset: page.startOffset, endOffset: page.endOffset, nextOffset: page.nextOffset, retainedStartOffset: page.retainedStartOffset, byteCount: page.bytes.length, eof: page.eof }, page.bytes);
      }
      case "quirt.job.input":
        return ok(this.jobs.input(text(payload.jobId, "Quirt job ID")!, principal.principalFingerprint, binary, boolean(payload.close, "Quirt job input close")));
      case "quirt.job.signal":
        noBinary(binary);
        return ok({ job: publicJob(await this.jobs.signal(text(payload.jobId, "Quirt job ID")!, principal.principalFingerprint, signal(payload.signal))) });
      case "quirt.job.cancel":
        noBinary(binary);
        return ok({ job: publicJob(await this.jobs.cancel(text(payload.jobId, "Quirt job ID")!, principal.principalFingerprint, boolean(payload.force, "Quirt force cancel"))) });
      case "quirt.job.attach":
        noBinary(binary);
        {
          const attached = this.jobs.attach(text(payload.jobId, "Quirt job ID")!, principal.principalFingerprint);
          return ok({ ...attached, job: publicJob(attached.job as QuirtJobRecord) });
        }
      case "quirt.receipt.get":
        noBinary(binary);
        return ok({ receipt: this.jobs.getReceipt(text(payload.receiptId, "Quirt receipt ID", { maximum: 128 })!, principal.principalFingerprint) });
      case "quirt.receipt.list":
        noBinary(binary);
        return ok({ receipts: this.jobs.listReceipts(principal.principalFingerprint, integer(payload.maximumReceipts, "Quirt maximum receipts", 256, 1, 1000)) });
      case "quirt.file.stat":
        noBinary(binary);
        return ok(await this.files.stat({ path: text(payload.path, "Quirt file path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), followSymlinks: boolean(payload.followSymlinks, "Quirt symlink following"), digest: boolean(payload.digest, "Quirt file digest") }));
      case "quirt.file.read": {
        noBinary(binary);
        const page = await this.files.read({ path: text(payload.path, "Quirt file path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), followSymlinks: boolean(payload.followSymlinks, "Quirt symlink following"), offset: integer(payload.offset, "Quirt file offset", 0, 0, Number.MAX_SAFE_INTEGER), maximumBytes: integer(payload.maximumBytes, "Quirt maximum bytes", this.config.outputChunkBytes, 1, Math.min(1024 * 1024, this.config.maxFrameBytes - 4096)) });
        const { content, ...details } = page; return ok(details, content);
      }
      case "quirt.file.write":
        return ok(await this.files.write({ path: text(payload.path, "Quirt file path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), content: binary, create: boolean(payload.create, "Quirt file creation"), replace: boolean(payload.replace, "Quirt file replacement"), append: boolean(payload.append, "Quirt file append"), offset: payload.offset === undefined ? undefined : integer(payload.offset, "Quirt file offset", 0, 0, Number.MAX_SAFE_INTEGER), atomic: payload.atomic === undefined ? undefined : boolean(payload.atomic, "Quirt atomic placement"), noClobber: boolean(payload.noClobber, "Quirt no-clobber"), createParents: boolean(payload.createParents, "Quirt parent creation"), followSymlinks: boolean(payload.followSymlinks, "Quirt symlink following"), expectedDigest: text(payload.expectedDigest, "Quirt expected digest", { optional: true, maximum: 64 }), expectedDevice: payload.expectedDevice === undefined ? undefined : integer(payload.expectedDevice, "Quirt expected device", 0, 0, Number.MAX_SAFE_INTEGER), expectedInode: payload.expectedInode === undefined ? undefined : integer(payload.expectedInode, "Quirt expected inode", 0, 0, Number.MAX_SAFE_INTEGER), mode: payload.mode === undefined ? undefined : integer(payload.mode, "Quirt file mode", 0, 0, 0o7777), uid: payload.uid === undefined ? undefined : integer(payload.uid, "Quirt file UID", 0, 0, 0x7fffffff), gid: payload.gid === undefined ? undefined : integer(payload.gid, "Quirt file GID", 0, 0, 0x7fffffff), atime: text(payload.atime, "Quirt atime", { optional: true, maximum: 64 }), mtime: text(payload.mtime, "Quirt mtime", { optional: true, maximum: 64 }), durable: payload.durable === undefined ? undefined : boolean(payload.durable, "Quirt file durability") }));
      case "quirt.file.patch": {
        noBinary(binary); const editsRaw = payload.edits;
        if (!Array.isArray(editsRaw)) throw new QuirtError("invalid_request", "Quirt patch edits are invalid");
        const edits = editsRaw.map(item => { const edit = object(item, "Quirt patch edit"); return { start: integer(edit.start, "Quirt patch start", 0, 0, Number.MAX_SAFE_INTEGER), deleteBytes: integer(edit.deleteBytes, "Quirt patch delete bytes", 0, 0, Number.MAX_SAFE_INTEGER), contentBase64: text(edit.contentBase64, "Quirt patch content", { maximum: 48 * 1024 * 1024 })! }; });
        return ok(await this.files.patch({ path: text(payload.path, "Quirt file path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), expectedDigest: text(payload.expectedDigest, "Quirt expected digest", { maximum: 64 })!, edits, mode: payload.mode === undefined ? undefined : integer(payload.mode, "Quirt file mode", 0, 0, 0o7777) }));
      }
      case "quirt.file.search":
        noBinary(binary);
        return ok(await this.files.search({ path: text(payload.path, "Quirt search path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), name: text(payload.name, "Quirt search name", { optional: true, maximum: 4096 }), text: text(payload.text, "Quirt search text", { optional: true, maximum: 64 * 1024 }), regularExpression: boolean(payload.regularExpression, "Quirt regular expression"), caseSensitive: payload.caseSensitive === undefined ? undefined : boolean(payload.caseSensitive, "Quirt case sensitivity"), recursive: payload.recursive === undefined ? undefined : boolean(payload.recursive, "Quirt recursive search"), followSymlinks: boolean(payload.followSymlinks, "Quirt symlink following"), maximumMatches: integer(payload.maximumMatches, "Quirt maximum matches", 1000, 1, 10_000), maximumBytes: integer(payload.maximumBytes, "Quirt maximum scan bytes", 512 * 1024 * 1024, 1, 512 * 1024 * 1024), signal: abortSignal }));
      case "quirt.file.remove":
        noBinary(binary); return ok(await this.files.remove({ path: text(payload.path, "Quirt file path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), recursive: boolean(payload.recursive, "Quirt recursive remove"), expectedDevice: payload.expectedDevice === undefined ? undefined : integer(payload.expectedDevice, "Quirt expected device", 0, 0, Number.MAX_SAFE_INTEGER), expectedInode: payload.expectedInode === undefined ? undefined : integer(payload.expectedInode, "Quirt expected inode", 0, 0, Number.MAX_SAFE_INTEGER) }));
      case "quirt.file.move":
        noBinary(binary); return ok(await this.files.move({ source: text(payload.source, "Quirt source path")!, destination: text(payload.destination, "Quirt destination path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), overwrite: boolean(payload.overwrite, "Quirt overwrite"), preserveMetadata: payload.preserveMetadata === undefined ? undefined : boolean(payload.preserveMetadata, "Quirt metadata preservation") }));
      case "quirt.file.copy":
        noBinary(binary); return ok(await this.files.copy({ source: text(payload.source, "Quirt source path")!, destination: text(payload.destination, "Quirt destination path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), recursive: boolean(payload.recursive, "Quirt recursive copy"), overwrite: boolean(payload.overwrite, "Quirt overwrite"), preserveMetadata: payload.preserveMetadata === undefined ? undefined : boolean(payload.preserveMetadata, "Quirt metadata preservation"), followSymlinks: boolean(payload.followSymlinks, "Quirt symlink following") }));
      case "quirt.directory.list":
        noBinary(binary); return ok(await this.directories.list({ path: text(payload.path, "Quirt directory path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), followSymlinks: boolean(payload.followSymlinks, "Quirt symlink following"), maximumEntries: integer(payload.maximumEntries, "Quirt maximum entries", 256, 1, 4096), continuationToken: text(payload.continuationToken, "Quirt continuation token", { optional: true, maximum: 8192 }) }));
      case "quirt.directory.create":
        noBinary(binary); return ok(await this.directories.create({ path: text(payload.path, "Quirt directory path")!, workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), recursive: boolean(payload.recursive, "Quirt recursive creation"), mode: payload.mode === undefined ? undefined : integer(payload.mode, "Quirt directory mode", 0, 0, 0o7777), uid: payload.uid === undefined ? undefined : integer(payload.uid, "Quirt directory UID", 0, 0, 0x7fffffff), gid: payload.gid === undefined ? undefined : integer(payload.gid, "Quirt directory GID", 0, 0, 0x7fffffff), noClobber: boolean(payload.noClobber, "Quirt no-clobber") }));
      case "quirt.directory.watch":
        noBinary(binary); return ok(await this.directories.watch({ action: payload.action === undefined ? undefined : payload.action === "start" || payload.action === "read" || payload.action === "cancel" ? payload.action : (() => { throw new QuirtError("invalid_request", "Quirt watch action is invalid"); })(), watchId: text(payload.watchId, "Quirt watch ID", { optional: true, maximum: 128 }), path: text(payload.path, "Quirt directory path", { optional: true }), workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), recursive: boolean(payload.recursive, "Quirt recursive watch"), after: payload.after === undefined ? undefined : integer(payload.after, "Quirt watch sequence", 0, -1, Number.MAX_SAFE_INTEGER), maximumEvents: integer(payload.maximumEvents, "Quirt maximum watch events", 256, 1, 1000) }, principal.principalFingerprint));
      case "quirt.transfer.begin": {
        noBinary(binary); const direction = payload.direction === "upload" || payload.direction === "download" ? payload.direction : (() => { throw new QuirtError("invalid_request", "Quirt transfer direction is invalid"); })();
        return ok(await this.transfers.begin({ direction, source: text(payload.source, "Quirt transfer source", { optional: true }), destination: text(payload.destination, "Quirt transfer destination", { optional: true }), workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }), expectedSize: payload.expectedSize === undefined ? undefined : integer(payload.expectedSize, "Quirt expected size", 0, 0, Number.MAX_SAFE_INTEGER), expectedDigest: text(payload.expectedDigest, "Quirt expected digest", { optional: true, maximum: 64 }), chunkSize: integer(payload.chunkSize, "Quirt chunk size", 256 * 1024, 4096, 1024 * 1024), compression: payload.compression === undefined ? undefined : payload.compression === "none" || payload.compression === "gzip" ? payload.compression : (() => { throw new QuirtError("invalid_request", "Quirt transfer compression is invalid"); })(), archiveFormat: payload.archiveFormat === undefined ? undefined : payload.archiveFormat === "none" || payload.archiveFormat === "tar" ? payload.archiveFormat : (() => { throw new QuirtError("invalid_request", "Quirt archive format is invalid"); })(), objectType: payload.objectType === undefined ? undefined : payload.objectType === "file" || payload.objectType === "directory" || payload.objectType === "symlink" ? payload.objectType : (() => { throw new QuirtError("invalid_request", "Quirt transfer object type is invalid"); })(), overwrite: boolean(payload.overwrite, "Quirt overwrite"), noClobber: payload.noClobber === undefined ? undefined : boolean(payload.noClobber, "Quirt no-clobber"), mode: payload.mode === undefined ? undefined : integer(payload.mode, "Quirt file mode", 0, 0, 0o7777), uid: payload.uid === undefined ? undefined : integer(payload.uid, "Quirt file UID", 0, 0, 0x7fffffff), gid: payload.gid === undefined ? undefined : integer(payload.gid, "Quirt file GID", 0, 0, 0x7fffffff), atime: text(payload.atime, "Quirt atime", { optional: true, maximum: 64 }), mtime: text(payload.mtime, "Quirt mtime", { optional: true, maximum: 64 }) }, principal.principalFingerprint));
      }
      case "quirt.transfer.write":
        return ok(await this.transfers.write({ transferId: text(payload.transferId, "Quirt transfer ID", { maximum: 128 })!, offset: integer(payload.offset, "Quirt transfer offset", 0, 0, Number.MAX_SAFE_INTEGER), content: binary, chunkDigest: text(payload.chunkDigest, "Quirt chunk digest", { optional: true, maximum: 64 }) }, principal.principalFingerprint));
      case "quirt.transfer.read": {
        noBinary(binary); const result = await this.transfers.read({ transferId: text(payload.transferId, "Quirt transfer ID", { maximum: 128 })!, offset: integer(payload.offset, "Quirt transfer offset", 0, 0, Number.MAX_SAFE_INTEGER), maximumBytes: integer(payload.maximumBytes, "Quirt maximum bytes", this.config.outputChunkBytes, 1, Math.min(1024 * 1024, this.config.maxFrameBytes - 4096)) }, principal.principalFingerprint); return ok(result.payload, result.binary);
      }
      case "quirt.transfer.status":
        noBinary(binary); return ok(this.transfers.status(text(payload.transferId, "Quirt transfer ID", { maximum: 128 })!, principal.principalFingerprint, { afterOffset: payload.afterOffset === undefined ? undefined : integer(payload.afterOffset, "Quirt transfer range cursor", -1, -1, Number.MAX_SAFE_INTEGER), maximumRanges: integer(payload.maximumRanges, "Quirt maximum transfer ranges", 256, 1, 1000) }));
      case "quirt.transfer.complete":
        noBinary(binary); return ok(await this.transfers.complete(text(payload.transferId, "Quirt transfer ID", { maximum: 128 })!, principal.principalFingerprint));
      case "quirt.transfer.cancel":
        noBinary(binary); return ok(await this.transfers.cancel(text(payload.transferId, "Quirt transfer ID", { maximum: 128 })!, principal.principalFingerprint));
      case "quirt.session.snapshot":
        noBinary(binary); return ok(this.sessionNative.snapshot({ sessionId: text(payload.sessionId, "Quirt session ID")!, readerId: text(payload.readerId, "Quirt reader ID", { optional: true, maximum: 128 }), after: payload.after === undefined ? undefined : integer(payload.after, "Quirt offset", 0, 0, Number.MAX_SAFE_INTEGER), createHandoff: payload.createHandoff === undefined ? undefined : boolean(payload.createHandoff, "Quirt handoff creation"), expiresInSeconds: payload.expiresInSeconds === undefined ? undefined : integer(payload.expiresInSeconds, "Quirt handoff expiry", 86400, 60, 7 * 86400), clientMetadata: payload.clientMetadata === undefined ? undefined : object(payload.clientMetadata, "Quirt client metadata") }, principal.principalFingerprint));
      case "quirt.session.search":
        noBinary(binary); return ok(this.sessionNative.search({ sessionId: text(payload.sessionId, "Quirt session ID")!, query: text(payload.query, "Quirt session search query", { maximum: 64 * 1024 })!, regularExpression: boolean(payload.regularExpression, "Quirt regular expression"), caseSensitive: boolean(payload.caseSensitive, "Quirt case sensitivity"), afterOffset: payload.afterOffset === undefined ? undefined : integer(payload.afterOffset, "Quirt search offset", 0, 0, Number.MAX_SAFE_INTEGER), maximumMatches: integer(payload.maximumMatches, "Quirt maximum matches", 100, 1, 1000), maximumBytes: integer(payload.maximumBytes, "Quirt maximum search bytes", 32 * 1024 * 1024, 1, 32 * 1024 * 1024), includeRecordings: payload.includeRecordings === undefined ? undefined : boolean(payload.includeRecordings, "Quirt recording search") }, principal.principalFingerprint));
      case "quirt.session.render":
        noBinary(binary); return ok(this.sessionNative.render({ sessionId: text(payload.sessionId, "Quirt session ID")!, afterOffset: payload.afterOffset === undefined ? undefined : integer(payload.afterOffset, "Quirt render offset", 0, 0, Number.MAX_SAFE_INTEGER), maximumBytes: integer(payload.maximumBytes, "Quirt maximum render bytes", 8 * 1024 * 1024, 1, 8 * 1024 * 1024), rows: payload.rows === undefined ? undefined : integer(payload.rows, "Quirt render rows", 40, 1, 1000), columns: payload.columns === undefined ? undefined : integer(payload.columns, "Quirt render columns", 120, 2, 1000) }, principal.principalFingerprint));
      case "quirt.git.mirror":
        noBinary(binary); return ok(await this.git.mirror({ remote: text(payload.remote, "Quirt Git remote")!, credentialReference: text(payload.credentialReference, "Quirt credential reference", { optional: true, maximum: 256 }), fetch: payload.fetch === undefined ? undefined : boolean(payload.fetch, "Quirt Git fetch"), prune: payload.prune === undefined ? undefined : boolean(payload.prune, "Quirt Git prune"), rebuild: boolean(payload.rebuild, "Quirt Git mirror rebuild") }, principal.principalFingerprint));
      case "quirt.git.fetch":
        noBinary(binary); return ok(await this.git.fetch({ repository: text(payload.repository, "Quirt Git repository")!, remote: text(payload.remote, "Quirt Git remote name", { optional: true, maximum: 256 }), prune: payload.prune === undefined ? undefined : boolean(payload.prune, "Quirt Git prune"), tags: payload.tags === undefined ? undefined : boolean(payload.tags, "Quirt Git tags"), credentialReference: text(payload.credentialReference, "Quirt credential reference", { optional: true, maximum: 256 }) }, principal.principalFingerprint));
      case "quirt.git.materialize":
        noBinary(binary); return ok(await this.git.materialize({ remote: text(payload.remote, "Quirt Git remote")!, destination: text(payload.destination, "Quirt Git destination")!, ref: text(payload.ref, "Quirt Git ref", { optional: true, maximum: 1024 }), exactCommit: text(payload.exactCommit, "Quirt exact commit", { optional: true, maximum: 64 }), expectedTree: text(payload.expectedTree, "Quirt expected tree", { optional: true, maximum: 64 }), branch: text(payload.branch, "Quirt Git branch", { optional: true, maximum: 1024 }), depth: payload.depth === undefined ? undefined : integer(payload.depth, "Quirt Git depth", 1, 1, 1_000_000), submodules: boolean(payload.submodules, "Quirt Git submodules"), lfs: boolean(payload.lfs, "Quirt Git LFS"), credentialReference: text(payload.credentialReference, "Quirt credential reference", { optional: true, maximum: 256 }), existing: payload.existing === undefined ? undefined : payload.existing === "reject" || payload.existing === "reuse" || payload.existing === "replace" ? payload.existing : (() => { throw new QuirtError("invalid_request", "Quirt Git existing destination policy is invalid"); })() }, principal.principalFingerprint));
      case "quirt.git.status":
        noBinary(binary); return ok(await this.git.status({ repository: text(payload.repository, "Quirt Git repository")!, includeIgnored: boolean(payload.includeIgnored, "Quirt Git ignored files") }, principal.principalFingerprint));
      case "quirt.git.worktree":
        noBinary(binary); return ok(await this.git.worktree({ repository: text(payload.repository, "Quirt Git repository")!, destination: text(payload.destination, "Quirt Git worktree destination", { optional: true }), commit: text(payload.commit, "Quirt Git commit", { optional: true, maximum: 64 }), branch: text(payload.branch, "Quirt Git branch", { optional: true, maximum: 1024 }), action: payload.action === undefined ? undefined : payload.action === "create" || payload.action === "list" || payload.action === "remove" ? payload.action : (() => { throw new QuirtError("invalid_request", "Quirt Git worktree action is invalid"); })(), force: boolean(payload.force, "Quirt Git force") }, principal.principalFingerprint));
      case "quirt.git.verify":
        noBinary(binary); return ok(await this.git.verify({ repository: text(payload.repository, "Quirt Git repository")!, commit: text(payload.commit, "Quirt Git commit", { optional: true, maximum: 64 }), tree: text(payload.tree, "Quirt Git tree", { optional: true, maximum: 64 }), tag: text(payload.tag, "Quirt Git tag", { optional: true, maximum: 1024 }), signature: payload.signature === undefined ? undefined : payload.signature === "none" || payload.signature === "report" || payload.signature === "require" ? payload.signature : (() => { throw new QuirtError("invalid_request", "Quirt Git signature policy is invalid"); })(), fsck: payload.fsck === undefined ? undefined : boolean(payload.fsck, "Quirt Git integrity verification") }, principal.principalFingerprint));
      case "quirt.git.push":
        noBinary(binary); return ok(await this.git.push({ repository: text(payload.repository, "Quirt Git repository")!, remote: text(payload.remote, "Quirt Git remote", { optional: true, maximum: 256 }), source: text(payload.source, "Quirt Git source ref", { maximum: 1024 })!, destination: text(payload.destination, "Quirt Git destination ref", { maximum: 1024 })!, force: boolean(payload.force, "Quirt Git force push"), lease: text(payload.lease, "Quirt Git force lease", { optional: true, maximum: 64 }), tags: boolean(payload.tags, "Quirt Git tags"), signed: boolean(payload.signed, "Quirt Git signed push"), credentialReference: text(payload.credentialReference, "Quirt credential reference", { optional: true, maximum: 256 }) }, principal.principalFingerprint));
      case "quirt.record.start":
        noBinary(binary); return ok(this.recordings.start({ sessionId: text(payload.sessionId, "Quirt session ID", { optional: true, maximum: 128 }), name: text(payload.name, "Quirt recording name", { optional: true, maximum: 256 }), retentionUntil: text(payload.retentionUntil, "Quirt recording retention", { optional: true, maximum: 64 }), marker: text(payload.marker, "Quirt recording marker", { optional: true, maximum: 4096 }), bookmark: text(payload.bookmark, "Quirt recording bookmark", { optional: true, maximum: 4096 }), recordingId: text(payload.recordingId, "Quirt recording ID", { optional: true, maximum: 128 }) }, principal.principalFingerprint));
      case "quirt.record.stop":
        noBinary(binary); return ok(this.recordings.stop({ recordingId: text(payload.recordingId, "Quirt recording ID", { maximum: 128 })!, remove: boolean(payload.remove, "Quirt recording removal") }, principal.principalFingerprint));
      case "quirt.record.list":
        noBinary(binary); return ok(this.recordings.list(principal.principalFingerprint, { maximumRecordings: integer(payload.maximumRecordings, "Quirt maximum recordings", 256, 1, 1000), continuationToken: text(payload.continuationToken, "Quirt recording continuation token", { optional: true, maximum: 8192 }) }));
      case "quirt.record.search":
        noBinary(binary); return ok(this.recordings.search({ recordingId: text(payload.recordingId, "Quirt recording ID", { maximum: 128 })!, query: text(payload.query, "Quirt recording query", { maximum: 64 * 1024 })!, regularExpression: boolean(payload.regularExpression, "Quirt regular expression"), caseSensitive: boolean(payload.caseSensitive, "Quirt case sensitivity"), maximumMatches: integer(payload.maximumMatches, "Quirt maximum matches", 100, 1, 1000) }, principal.principalFingerprint));
      case "quirt.record.replay": {
        noBinary(binary); const result = this.recordings.replay({ recordingId: text(payload.recordingId, "Quirt recording ID", { maximum: 128 })!, afterSequence: payload.afterSequence === undefined ? undefined : integer(payload.afterSequence, "Quirt recording sequence", -1, -1, Number.MAX_SAFE_INTEGER), maximumEvents: integer(payload.maximumEvents, "Quirt maximum recording events", 256, 1, 1000), speed: typeof payload.speed === "number" ? payload.speed : undefined }, principal.principalFingerprint); return ok(result.payload, result.binary);
      }
      case "quirt.record.export": {
        noBinary(binary); const format = payload.format === "quirt-json-v1" || payload.format === "asciinema-v2" || payload.format === "html-transcript" ? payload.format : (() => { throw new QuirtError("invalid_request", "Quirt recording export format is invalid"); })(); const result = this.recordings.export({ recordingId: text(payload.recordingId, "Quirt recording ID", { maximum: 128 })!, format, offset: integer(payload.offset, "Quirt export offset", 0, 0, Number.MAX_SAFE_INTEGER), maximumBytes: integer(payload.maximumBytes, "Quirt maximum export bytes", this.config.outputChunkBytes, 1, Math.min(1024 * 1024, this.config.maxFrameBytes - 4096)) }, principal.principalFingerprint); return ok(result.payload, result.binary);
      }
      case "quirt.process.list":
        noBinary(binary); return ok(await this.processService.list({ afterPid: payload.afterPid === undefined ? undefined : integer(payload.afterPid, "Quirt process cursor", 0, 0, 0x7fffffff), maximumProcesses: integer(payload.maximumProcesses, "Quirt maximum processes", 256, 1, 4096), uid: payload.uid === undefined ? undefined : integer(payload.uid, "Quirt process UID", 0, 0, 0x7fffffff), state: text(payload.state, "Quirt process state", { optional: true, maximum: 16 }) }, principal.principalFingerprint));
      case "quirt.process.get":
        noBinary(binary); return ok(await this.processService.get({ pid: integer(payload.pid, "Quirt process PID", 0, 1, 0x7fffffff) }, principal.principalFingerprint));
      case "quirt.process.signal": {
        noBinary(binary); const identity = object(payload.identity, "Quirt process identity") as unknown as QuirtProcessIdentity; return ok(await this.processService.signal({ identity, signal: signal(payload.signal) }, principal.principalFingerprint));
      }
      case "quirt.process.tree":
        noBinary(binary); return ok(await this.processService.tree({ pid: payload.pid === undefined ? undefined : integer(payload.pid, "Quirt process PID", 0, 1, 0x7fffffff), maximumDepth: integer(payload.maximumDepth, "Quirt process tree depth", 16, 0, 128), maximumProcesses: integer(payload.maximumProcesses, "Quirt maximum processes", 1024, 1, 10_000) }, principal.principalFingerprint));
      case "quirt.process.namespaces":
        noBinary(binary); return ok(await this.processService.namespaces({ pid: integer(payload.pid, "Quirt process PID", 0, 1, 0x7fffffff) }, principal.principalFingerprint));
      case "quirt.process.attach": {
        noBinary(binary); const result = await this.processService.attach(payload, principal.principalFingerprint); if ("payload" in result && "binary" in result) { const attached = result as { payload: Record<string, unknown>; binary: Buffer }; return ok(attached.payload, attached.binary); } return ok(result);
      }
    }
    throw new QuirtError("unknown_operation", "Quirt operation is unknown");
  }

  async #exec(request: QuirtRequestEnvelope, payload: Record<string, unknown>, binary: Buffer, principal: QuirtPrincipalEnvelope, abortSignal?: AbortSignal): Promise<QuirtOperationResult> {
    const policy = environmentPolicy(payload.environmentPolicy);
    const result = await this.jobs.exec(request.requestId, principal.principalFingerprint, {
      command: text(payload.command, "Quirt command", { optional: true, maximum: 1024 * 1024 }),
      script: text(payload.script, "Quirt script", { optional: true, maximum: 1024 * 1024 }),
      executable: text(payload.executable, "Quirt executable", { optional: true }),
      arguments: stringArray(payload.arguments, "Quirt arguments"),
      shell: boolean(payload.shell, "Quirt shell interpretation"),
      shellPath: text(payload.shellPath, "Quirt shell path", { optional: true }),
      workingDirectory: text(payload.workingDirectory, "Quirt working directory", { optional: true }),
      environment: environment(payload.environment),
      environmentPolicy: policy,
      input: binary.length === 0 ? undefined : binary,
      timeoutMs: payload.timeoutMs === undefined ? undefined : integer(payload.timeoutMs, "Quirt timeout", 1, 1, 24 * 60 * 60 * 1000),
      forceTimeout: boolean(payload.forceTimeout, "Quirt force timeout"),
      pty: boolean(payload.pty, "Quirt PTY"),
      detach: boolean(payload.detach, "Quirt detach"),
      columns: integer(payload.columns, "Quirt terminal columns", 120, 2, 1000),
      rows: integer(payload.rows, "Quirt terminal rows", 40, 1, 1000),
      gracefulSignal: payload.gracefulSignal === undefined ? undefined : signal(payload.gracefulSignal),
      graceIntervalMs: payload.graceIntervalMs === undefined ? undefined : integer(payload.graceIntervalMs, "Quirt grace interval", 5_000, 1, 3_600_000)
    } satisfies QuirtExecInput, abortSignal);
    return ok({
      job: publicJob(result.job),
      detached: result.detached,
      timedOut: result.timedOut,
      stdoutLength: result.stdout.length,
      stderrLength: result.stderr.length,
      stdoutStreamId: result.job.stdoutStreamId,
      stderrStreamId: result.job.stderrStreamId,
      receiptId: result.receiptId,
      byteCount: result.compatibilityCombinedOutput.length,
      compatibilityCombinedOutput: true
    }, result.compatibilityCombinedOutput);
  }
}
