import { randomUUID } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { dirname } from "node:path";
import type { Duplex } from "node:stream";
import type { QuirtSupervisorAuthority } from "./authority.js";
import { negotiateConnection, supervisorSupportedCapabilities, type QuirtNegotiatedConnectionContext } from "./authority-negotiation.js";
import type { QuirtConfig } from "./config.js";
import { QuirtFramedChannel } from "./connection.js";
import { QuirtError, quirtErrorCode, safeQuirtError } from "./error.js";
import type { QuirtJobManager, QuirtJobEvent } from "./job-manager.js";
import type { QuirtOperationDispatcher, QuirtOperationResult } from "./operations.js";
import { verifyQuirtGatewayPeer, type QuirtPeerCredentialSource, type QuirtPeerCredentials } from "./peer-credentials.js";
import { errorFrame, QUIRT_PROTOCOL_VERSION, type QuirtFrame, type QuirtHelloEnvelope, type QuirtRequestEnvelope } from "./protocol.js";
import type { QuirtSessionManager, QuirtSessionOutputEvent } from "./session-manager.js";
import type { QuirtStateStore } from "./state.js";

interface SupervisorConnection {
  channel: QuirtFramedChannel;
  handshaken: boolean;
  connectionId: string | null;
  negotiated: QuirtNegotiatedConnectionContext | null;
  peer: QuirtPeerCredentials;
  activeRequests: Map<string, AbortController>;
}

export interface QuirtSupervisorRecovery {
  sessions: { adopted: number; lost: number };
  jobs: { unknown: number; lost: number };
  transfers: { active: number; failed: number; completed: number };
  watches: { lost: number };
  recordings: { resumed: number; interrupted: number };
  providers: { checked: number; ready: number; degraded: number; lost: number };
  cleanup: { expiredHandoffs: number; expiredProviders: number };
}

function storedBinary(value: unknown): Buffer {
  if (typeof value !== "string" || value.length > 16 * 1024 * 1024) throw new QuirtError("internal_error", "Stored Quirt response is invalid");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new QuirtError("internal_error", "Stored Quirt response is invalid");
  return bytes;
}

export class QuirtSupervisorServer {
  readonly #server: Server;
  readonly #connections = new Set<SupervisorConnection>();
  readonly #unsubscribe: Array<() => void> = [];
  #eventSequence = 0;
  #started = false;

  constructor(
    private readonly config: QuirtConfig,
    private readonly state: QuirtStateStore,
    private readonly authority: QuirtSupervisorAuthority,
    private readonly dispatcher: QuirtOperationDispatcher,
    private readonly sessions: QuirtSessionManager,
    private readonly jobs: QuirtJobManager,
    private readonly peers: QuirtPeerCredentialSource
  ) {
    this.#server = createServer(socket => this.#acceptSocket(socket));
    this.#server.on("error", () => { /* start() observes listen errors; established clients are isolated */ });
    this.#unsubscribe.push(sessions.onEvent(event => this.#broadcastSession(event)), jobs.onEvent(event => this.#broadcastJob(event)), dispatcher.transfers.onEvent(event => this.#broadcast(event.event, null, { transferId: event.transferId, status: event.status, transferredBytes: event.transferredBytes, expectedSize: event.expectedSize }, Buffer.alloc(0))));
  }

  async start(): Promise<QuirtSupervisorRecovery> {
    if (this.#started) throw new QuirtError("invalid_request", "Quirt supervisor is already started");
    if (this.config.mode === "production" && process.getuid?.() !== 0) throw new QuirtError("configuration_error", "Quirt supervisor must run as UID 0");
    this.state.integrityCheck();
    this.state.purgeExpiredRequests();
    const sessions = await this.sessions.recover();
    const jobs = this.jobs.recover();
    const transfers = await this.dispatcher.transfers.recover();
    const watches = this.dispatcher.directories.recover();
    const recordings = this.dispatcher.recordings.recover(this.config.expectedPrincipal.principalFingerprint);
    const providerCandidates = this.state.power.recoverCandidates();
    await this.dispatcher.power.recover();
    const recoveredProviders = providerCandidates.map((record) => this.state.power.getInstance(record.instanceId));
    const providers = { checked: recoveredProviders.length, ready: recoveredProviders.filter((record) => record.state === "ready").length, degraded: recoveredProviders.filter((record) => record.state === "degraded").length, lost: recoveredProviders.filter((record) => record.state === "lost").length };
    const cleanup = { expiredHandoffs: this.state.native.cleanupExpiredHandoffs(), expiredProviders: this.dispatcher.power.cleanupExpired() };
    await this.#listen();
    this.#started = true;
    return { sessions, jobs, transfers, watches, recordings, providers, cleanup };
  }

  acceptAuthenticatedTestStream(stream: Duplex, peer: QuirtPeerCredentials): void {
    if (this.config.mode !== "test" || peer.uid !== this.config.gatewayUid) throw new QuirtError("authentication_failed", "Quirt test peer is not authorized");
    this.#accept(stream, peer);
  }

  async stop(): Promise<void> {
    if (!this.#started) return;
    this.#started = false;
    for (const connection of this.#connections) connection.channel.close(new QuirtError("supervisor_unavailable", "Quirt supervisor stopped", true));
    this.#connections.clear();
    await new Promise<void>(resolve => this.#server.close(() => resolve()));
    this.sessions.shutdown();
    this.jobs.shutdown();
    this.dispatcher.directories.shutdown();
    this.dispatcher.recordings.shutdown();
    for (const unsubscribe of this.#unsubscribe.splice(0)) unsubscribe();
  }

  #acceptSocket(socket: Socket): void {
    try { this.#accept(socket, verifyQuirtGatewayPeer(this.peers, socket, this.config)); }
    catch { socket.destroy(); }
  }

  #accept(stream: Duplex, peer: QuirtPeerCredentials): void {
    const channel = new QuirtFramedChannel(stream, { maxFrameBytes: this.config.maxFrameBytes, maxBufferedBytes: this.config.maxBufferedBytes, maxWriteQueueBytes: this.config.maxWriteQueueBytes });
    const connection: SupervisorConnection = { channel, handshaken: false, connectionId: null, negotiated: null, peer, activeRequests: new Map() };
    this.#connections.add(connection);
    channel.onFrame(frame => { void this.#frame(connection, frame); });
    channel.onDecodeError(cause => {
      const error = safeQuirtError(cause);
      void channel.send(errorFrame(null, error)).finally(() => channel.close(error));
    });
    channel.onClose(() => {
      for (const controller of connection.activeRequests.values()) controller.abort();
      connection.activeRequests.clear();
      this.#connections.delete(connection);
    });
  }

  async #frame(connection: SupervisorConnection, frame: QuirtFrame): Promise<void> {
    try {
      if (!connection.handshaken) {
        if (frame.envelope.kind !== "hello") throw new QuirtError("authentication_failed", "Quirt handshake is required");
        await this.#hello(connection, frame.envelope);
        return;
      }
      switch (frame.envelope.kind) {
        case "request": await this.#request(connection, frame.envelope, frame.binary); return;
        case "cancel": connection.activeRequests.get(frame.envelope.requestId)?.abort(); return;
        case "ping": await connection.channel.send({ envelope: { kind: "pong", protocolVersion: QUIRT_PROTOCOL_VERSION, nonce: frame.envelope.nonce, timestamp: new Date().toISOString(), binaryLength: 0 }, binary: Buffer.alloc(0) }); return;
        case "pong": return;
        default: throw new QuirtError("invalid_frame", "Quirt frame is not valid in this connection state");
      }
    } catch (cause) {
      const error = safeQuirtError(cause);
      const requestId = frame.envelope.kind === "request" || frame.envelope.kind === "cancel" ? frame.envelope.requestId : null;
      await connection.channel.send(errorFrame(requestId, error)).catch(() => undefined);
      if (error.code === "authentication_failed" || error.code === "protocol_mismatch" || error.code === "invalid_frame") connection.channel.close(error);
    }
  }

  async #hello(connection: SupervisorConnection, hello: QuirtHelloEnvelope): Promise<void> {
    if (hello.gatewayId !== this.config.gatewayId || hello.protocolVersion !== QUIRT_PROTOCOL_VERSION || hello.connectionId.length > 128 || hello.challenge.length > 256) throw new QuirtError("authentication_failed", "Quirt Gateway handshake is invalid");
    const age = Math.abs(Date.now() - Date.parse(hello.timestamp));
    if (!Number.isFinite(age) || age > this.config.requestMaxAgeMs) throw new QuirtError("stale_request", "Quirt handshake timestamp is stale");
    const negotiated = negotiateConnection({
      gatewayOffers: hello.capabilities,
      supervisorSupports: [...supervisorSupportedCapabilities(this.config.supportedAuthorityAlgorithms)],
      gatewayPreferredAlgorithms: this.config.supportedAuthorityAlgorithms.includes("ed25519") ? ["ed25519", "hmac-sha256"] : ["hmac-sha256"],
      supervisorSupportedAlgorithms: this.config.supportedAuthorityAlgorithms,
      legacyHmacEnabled: this.config.legacyHmacEnabled
    });
    const timestamp = new Date().toISOString();
    const negotiatedContext: QuirtNegotiatedConnectionContext = Object.freeze({
      connectionId: hello.connectionId,
      authorityAlgorithm: negotiated.authorityAlgorithm,
      compression: negotiated.compression,
      capabilities: negotiated.capabilities,
      supervisorKeyId: negotiated.authorityAlgorithm === "ed25519" ? this.authority.supervisorKeyId : null
    });
    const challengeResponse = this.authority.signHandshakeResponse({
      connectionId: hello.connectionId,
      gatewayId: hello.gatewayId,
      challenge: hello.challenge,
      negotiated: negotiatedContext,
      timestamp
    });
    connection.handshaken = true;
    connection.connectionId = hello.connectionId;
    connection.negotiated = negotiatedContext;
    await connection.channel.send({
      envelope: {
        kind: "welcome",
        protocolVersion: QUIRT_PROTOCOL_VERSION,
        connectionId: hello.connectionId,
        supervisorId: this.config.supervisorId,
        challengeResponse,
        capabilities: negotiated.capabilities,
        selectedAuthorityAlgorithm: negotiated.authorityAlgorithm,
        selectedCompression: negotiated.compression,
        ...(negotiated.authorityAlgorithm === "ed25519" ? { supervisorKeyId: this.authority.supervisorKeyId ?? undefined } : {}),
        timestamp,
        binaryLength: 0
      },
      binary: Buffer.alloc(0)
    });
  }

  async #request(connection: SupervisorConnection, request: QuirtRequestEnvelope, binary: Buffer): Promise<void> {
    if (connection.activeRequests.has(request.requestId)) throw new QuirtError("duplicate_request", "Quirt request is already in flight", true);
    const controller = new AbortController();
    connection.activeRequests.set(request.requestId, controller);
    let reserved = false;
    try {
      const verified = this.authority.verify(request, binary, connection.negotiated ?? (() => { throw new QuirtError("authentication_failed", "Quirt connection negotiation is missing"); })());
      reserved = !verified.replayed;
      if (verified.replayed) {
        const prior = this.state.requestResult(request.requestId);
        if (prior === null || prior.state === "reserved") throw new QuirtError("duplicate_request", "Quirt request is still in progress", true);
        if (prior.state === "failed") {
          const error = prior.error ?? {};
          throw new QuirtError(quirtErrorCode(error.code), typeof error.message === "string" ? error.message : "Quirt request failed", error.retryable === true);
        }
        const stored = prior.response ?? {};
        const payload = objectPayload(stored.payload);
        const responseBinary = storedBinary(stored.binaryBase64);
        connection.activeRequests.delete(request.requestId);
        await this.#respond(connection, request.requestId, { payload: { ...payload, replayed: true }, binary: responseBinary }, true);
        return;
      }
      const result = await this.dispatcher.execute(request, binary, controller.signal);
      this.state.completeRequest(request.requestId, { payload: result.payload, binaryBase64: result.binary.toString("base64") });
      connection.activeRequests.delete(request.requestId);
      if (!controller.signal.aborted && !connection.channel.closed) await this.#respond(connection, request.requestId, result, false).catch(() => undefined);
    } catch (cause) {
      const error = safeQuirtError(cause);
      if (reserved) {
        try { this.state.failRequest(request.requestId, { code: error.code, message: error.message, retryable: error.retryable }); } catch { /* preserve the original operation error */ }
      }
      connection.activeRequests.delete(request.requestId);
      await connection.channel.send(errorFrame(request.requestId, error)).catch(() => undefined);
    } finally { connection.activeRequests.delete(request.requestId); }
  }

  async #respond(connection: SupervisorConnection, requestId: string, result: QuirtOperationResult, replayed: boolean): Promise<void> {
    await connection.channel.send({
      envelope: { kind: "response", protocolVersion: QUIRT_PROTOCOL_VERSION, requestId, timestamp: new Date().toISOString(), payload: result.payload, binaryLength: result.binary.length, ...(replayed ? { replayed: true } : {}) },
      binary: result.binary
    });
  }

  #broadcastSession(event: QuirtSessionOutputEvent): void {
    this.#broadcast(event.event, event.streamId, { sessionId: event.sessionId, startOffset: event.startOffset, endOffset: event.endOffset, exitCode: event.exitCode, exitSignal: event.exitSignal, columns: event.columns, rows: event.rows, signal: event.signal }, event.bytes ?? Buffer.alloc(0));
  }

  #broadcastJob(event: QuirtJobEvent): void {
    this.#broadcast(event.event, event.streamId ?? null, { jobId: event.jobId, stream: event.stream, startOffset: event.startOffset, endOffset: event.endOffset, status: event.status }, event.bytes ?? Buffer.alloc(0));
  }

  #broadcast(event: string, streamId: string | null, payload: Record<string, unknown>, binary: Buffer): void {
    const sequence = this.#eventSequence++;
    for (const connection of this.#connections) {
      if (!connection.handshaken) continue;
      void connection.channel.send({ envelope: { kind: "event", protocolVersion: QUIRT_PROTOCOL_VERSION, eventId: randomUUID(), streamId, sequence, event, timestamp: new Date().toISOString(), payload, binaryLength: binary.length }, binary }).catch(() => connection.channel.close(new QuirtError("queue_overflow", "Quirt event consumer is too slow", true)));
    }
  }

  async #listen(): Promise<void> {
    const inherited = Number(process.env.LISTEN_FDS ?? 0) === 1 && Number(process.env.LISTEN_PID ?? 0) === process.pid;
    if (this.config.mode === "production" && !inherited) throw new QuirtError("configuration_error", "Production Quirt requires systemd socket activation");
    if (!inherited) {
      mkdirSync(dirname(this.config.socketPath), { recursive: true, mode: 0o750 });
      try {
        const stat = lstatSync(this.config.socketPath);
        if (!stat.isSocket() || stat.isSymbolicLink()) throw new QuirtError("configuration_error", "Existing Quirt socket path is unsafe");
        unlinkSync(this.config.socketPath);
      } catch (cause) {
        if (cause instanceof QuirtError) throw cause;
        if (!(cause instanceof Error && "code" in cause && cause.code === "ENOENT")) throw cause;
      }
    }
    await new Promise<void>((resolve, reject) => {
      const error = (cause: Error) => {
        this.#server.off("listening", ready);
        const code = "code" in cause && typeof cause.code === "string" ? cause.code : "unknown";
        reject(new QuirtError("configuration_error", `Quirt socket could not listen: ${code}`));
      };
      const ready = () => { this.#server.off("error", error); resolve(); };
      this.#server.once("error", error);
      this.#server.once("listening", ready);
      if (inherited) this.#server.listen({ fd: 3 }); else this.#server.listen(this.config.socketPath);
    });
    if (!inherited) chmodSync(this.config.socketPath, this.config.socketMode);
  }
}

function objectPayload(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new QuirtError("internal_error", "Stored Quirt response is invalid");
  return value as Record<string, unknown>;
}
