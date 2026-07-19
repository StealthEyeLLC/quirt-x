import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { createConnection } from "node:net";
import type { Duplex } from "node:stream";
import type { QuirtGatewaySigner } from "./authority.js";
import { assertWelcomeMatchesNegotiation, gatewayOfferedCapabilities, negotiateConnection, type QuirtNegotiatedConnectionContext } from "./authority-negotiation.js";
import type { QuirtVerificationKeyRing } from "./authority-keyring.js";
import type { QuirtConfig } from "./config.js";
import { QuirtFramedChannel } from "./connection.js";
import { QuirtError, quirtErrorCode } from "./error.js";
import { inspectQuirtSocket, resolveQuirtSocketGroupGid } from "./peer-credentials.js";
import { quirtHandshakeChallenge, QUIRT_PROTOCOL_VERSION, type QuirtEventEnvelope, type QuirtFrame, type QuirtPrincipalEnvelope, type QuirtRequestEnvelope, type QuirtResponseEnvelope, type QuirtWelcomeEnvelope } from "./protocol.js";

export interface QuirtSocketFactory { connect(): Promise<Duplex>; }

export class UnixQuirtSocketFactory implements QuirtSocketFactory {
  readonly #socketGroupGid: number;
  constructor(private readonly config: QuirtConfig) { this.#socketGroupGid = resolveQuirtSocketGroupGid(config.pythonPath, config.socketGroup); }
  async connect(): Promise<Duplex> {
    const before = inspectQuirtSocket(this.config.socketPath, this.config.socketMode, this.#socketGroupGid);
    const socket = createConnection({ path: this.config.socketPath });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { socket.destroy(); reject(new QuirtError("timeout", "Quirt socket connection timed out", true)); }, this.config.connectionTimeoutMs);
      timer.unref();
      socket.once("connect", () => { clearTimeout(timer); resolve(); });
      socket.once("error", () => { clearTimeout(timer); reject(new QuirtError("supervisor_unavailable", "Quirt supervisor socket is unavailable", true)); });
    });
    const after = inspectQuirtSocket(this.config.socketPath, this.config.socketMode, this.#socketGroupGid);
    if (before.device !== after.device || before.inode !== after.inode) { socket.destroy(); throw new QuirtError("authentication_failed", "Quirt socket changed during connection"); }
    return socket;
  }
}

export interface QuirtClientResponse { payload: Record<string, unknown>; binary: Buffer; replayed: boolean; }
export interface QuirtClientEvent { envelope: QuirtEventEnvelope; binary: Buffer; reconnectGap?: boolean; }

interface Pending {
  resolve: (response: QuirtClientResponse) => void;
  reject: (cause: unknown) => void;
  timer: NodeJS.Timeout;
  removeAbort?: () => void;
}

interface InFlightRequest {
  envelope: QuirtRequestEnvelope;
  binary: Buffer;
  timeoutMs: number;
  signal?: AbortSignal;
  startedAt: number;
  deadlineAt: number;
}

function aborted(signal: AbortSignal | undefined): boolean { return signal?.aborted === true; }

export class QuirtGatewayClient {
  readonly #events = new EventEmitter();
  readonly #pending = new Map<string, Pending>();
  readonly #supervisorVerificationKeyRing: QuirtVerificationKeyRing | null;
  #channel: QuirtFramedChannel | null = null;
  #connecting: Promise<QuirtFramedChannel> | null = null;
  #welcome: { resolve: (value: QuirtWelcomeEnvelope) => void; reject: (cause: unknown) => void } | null = null;
  #negotiated: QuirtNegotiatedConnectionContext | null = null;
  #connectionGeneration = 0;
  #lastAcceptedEventSequence: number | null = null;
  #liveness: NodeJS.Timeout | null = null;
  #lastPong = 0;
  #closed = false;

  constructor(
    private readonly config: QuirtConfig,
    private readonly signer: QuirtGatewaySigner,
    private readonly sockets: QuirtSocketFactory = new UnixQuirtSocketFactory(config),
    options: { supervisorVerificationKeyRing?: QuirtVerificationKeyRing } = {}
  ) {
    this.#supervisorVerificationKeyRing = options.supervisorVerificationKeyRing ?? null;
  }

  onEvent(listener: (event: QuirtClientEvent) => void): () => void {
    this.#events.on("event", listener);
    return () => this.#events.off("event", listener);
  }

  async probe(): Promise<void> { await this.#connect(); }

  async request(input: { operation: string; payload?: Record<string, unknown>; binary?: Buffer; principal: QuirtPrincipalEnvelope; requestId?: string; timeoutMs?: number; signal?: AbortSignal }): Promise<QuirtClientResponse> {
    if (this.#closed) throw new QuirtError("supervisor_unavailable", "Quirt Gateway client is closed", true);
    const binary = Buffer.from(input.binary ?? Buffer.alloc(0));
    const timeoutMs = input.timeoutMs ?? this.config.requestTimeoutMs;
    const startedAt = Date.now();
    const deadlineAt = startedAt + timeoutMs;
    const envelope = this.signer.sign({
      protocolVersion: QUIRT_PROTOCOL_VERSION,
      requestId: input.requestId ?? randomUUID(),
      operation: input.operation,
      principal: input.principal,
      targetHost: this.config.targetHost,
      timestamp: new Date(startedAt).toISOString(),
      payload: input.payload ?? {},
      binaryLength: binary.length
    }, binary);
    const inFlight: InFlightRequest = { envelope, binary, timeoutMs, signal: input.signal, startedAt, deadlineAt };
    let attempt = 0;
    let last: unknown;
    while (attempt < this.config.maxReconnectAttempts) {
      attempt += 1;
      if (aborted(input.signal)) throw new QuirtError("request_canceled", "Quirt request was canceled", false);
      const remaining = deadlineAt - Date.now();
      if (remaining < 100) throw new QuirtError("timeout", "Quirt request timed out", true);
      try {
        return await this.#send(inFlight, remaining, input.signal);
      } catch (cause) {
        last = cause;
        if (!(cause instanceof QuirtError) || !cause.retryable || cause.code === "request_canceled") throw cause;
        if (cause.code !== "supervisor_unavailable" && cause.code !== "timeout") throw cause;
        if (attempt >= this.config.maxReconnectAttempts) throw cause;
        this.#resetTransport(cause);
        const backoff = Math.min(this.config.reconnectBackoffMaxMs, this.config.reconnectBackoffMinMs * (2 ** (attempt - 1)));
        await this.#sleep(backoff, input.signal);
      }
    }
    throw last;
  }

  close(): void {
    this.#closed = true;
    if (this.#liveness !== null) clearInterval(this.#liveness);
    this.#liveness = null;
    this.#channel?.close(new QuirtError("supervisor_unavailable", "Quirt Gateway client closed", true));
    this.#channel = null;
  }

  async #send(inFlight: InFlightRequest, timeoutMs: number, signal?: AbortSignal): Promise<QuirtClientResponse> {
    const envelope = inFlight.envelope;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 24 * 60 * 60 * 1000) throw new QuirtError("invalid_request", "Quirt client timeout is invalid");
    if (aborted(signal)) throw new QuirtError("request_canceled", "Quirt request was canceled", false);
    if (this.#pending.has(envelope.requestId)) throw new QuirtError("duplicate_request", "Quirt request ID is already in flight", true);
    const channel = await this.#connect();
    if (this.#negotiated !== null && envelope.authority.algorithm !== this.#negotiated.authorityAlgorithm) {
      throw new QuirtError("authentication_failed", "Quirt signed request does not match negotiated authority algorithm", false);
    }
    if (aborted(signal)) throw new QuirtError("request_canceled", "Quirt request was canceled", false);
    return await new Promise<QuirtClientResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        const active = this.#pending.get(envelope.requestId); active?.removeAbort?.(); this.#pending.delete(envelope.requestId);
        reject(new QuirtError("timeout", "Quirt request timed out", true));
      }, timeoutMs);
      timer.unref();
      const pending: Pending = { resolve, reject, timer };
      if (signal !== undefined) {
        const abort = () => {
          const active = this.#pending.get(envelope.requestId); if (active === undefined) return;
          clearTimeout(active.timer); active.removeAbort?.(); this.#pending.delete(envelope.requestId);
          void channel.send({ envelope: { kind: "cancel", protocolVersion: QUIRT_PROTOCOL_VERSION, requestId: envelope.requestId, timestamp: new Date().toISOString(), binaryLength: 0 }, binary: Buffer.alloc(0) }).catch(() => undefined);
          active.reject(new QuirtError("request_canceled", "Quirt request was canceled", false));
        };
        signal.addEventListener("abort", abort, { once: true }); pending.removeAbort = () => signal.removeEventListener("abort", abort);
      }
      this.#pending.set(envelope.requestId, pending);
      if (aborted(signal)) { const active = this.#pending.get(envelope.requestId); if (active !== undefined) { clearTimeout(active.timer); active.removeAbort?.(); this.#pending.delete(envelope.requestId); active.reject(new QuirtError("request_canceled", "Quirt request was canceled", false)); } return; }
      void channel.send({ envelope, binary: inFlight.binary }).catch(cause => {
        const pending = this.#pending.get(envelope.requestId);
        if (pending === undefined) return;
        clearTimeout(pending.timer); pending.removeAbort?.();
        this.#pending.delete(envelope.requestId);
        pending.reject(new QuirtError("supervisor_unavailable", "Quirt request could not be sent", true, { cause: cause instanceof Error ? cause.name : "unknown" }));
      });
    });
  }

  async #connect(): Promise<QuirtFramedChannel> {
    if (this.#closed) throw new QuirtError("supervisor_unavailable", "Quirt Gateway client is closed", true);
    if (this.#channel !== null && !this.#channel.closed) return this.#channel;
    if (this.#connecting !== null) return await this.#connecting;
    this.#connecting = this.#establish();
    try { return await this.#connecting; }
    finally { this.#connecting = null; }
  }

  async #establish(): Promise<QuirtFramedChannel> {
    const stream = await this.sockets.connect();
    const channel = new QuirtFramedChannel(stream, { maxFrameBytes: this.config.maxFrameBytes, maxBufferedBytes: this.config.maxBufferedBytes, maxWriteQueueBytes: this.config.maxWriteQueueBytes });
    channel.onFrame(frame => this.#frame(channel, frame));
    channel.onDecodeError(cause => {
      const welcome = this.#welcome; this.#welcome = null; welcome?.reject(cause);
      channel.close(cause);
    });
    channel.onClose(cause => this.#disconnected(channel, cause));
    const connectionId = randomUUID();
    const challenge = quirtHandshakeChallenge();
    const welcome = new Promise<QuirtWelcomeEnvelope>((resolve, reject) => { this.#welcome = { resolve, reject }; });
    void welcome.catch(() => undefined);
    await channel.send({
      envelope: {
        kind: "hello",
        protocolVersion: QUIRT_PROTOCOL_VERSION,
        connectionId,
        gatewayId: this.config.gatewayId,
        challenge,
        capabilities: [...gatewayOfferedCapabilities(this.config.supportedAuthorityAlgorithms)],
        timestamp: new Date().toISOString(),
        binaryLength: 0
      },
      binary: Buffer.alloc(0)
    });
    const timer = setTimeout(() => this.#welcome?.reject(new QuirtError("timeout", "Quirt handshake timed out", true)), this.config.connectionTimeoutMs);
    timer.unref();
    let response: QuirtWelcomeEnvelope;
    try { response = await welcome; }
    catch (cause) { channel.close(cause); throw cause; }
    finally { clearTimeout(timer); this.#welcome = null; }
    if (response.connectionId !== connectionId || response.supervisorId !== this.config.supervisorId) { channel.close(); throw new QuirtError("authentication_failed", "Quirt supervisor handshake identity is invalid"); }
    const negotiated: QuirtNegotiatedConnectionContext = Object.freeze({
      connectionId,
      authorityAlgorithm: response.selectedAuthorityAlgorithm,
      compression: response.selectedCompression,
      capabilities: [...response.capabilities],
      supervisorKeyId: response.selectedAuthorityAlgorithm === "ed25519" ? response.supervisorKeyId ?? null : null
    });
    const expected = negotiateConnection({
      gatewayOffers: [...gatewayOfferedCapabilities(this.config.supportedAuthorityAlgorithms)],
      supervisorSupports: [...response.capabilities],
      gatewayPreferredAlgorithms: this.config.supportedAuthorityAlgorithms.includes("ed25519") ? ["ed25519", "hmac-sha256"] : ["hmac-sha256"],
      supervisorSupportedAlgorithms: this.config.supportedAuthorityAlgorithms,
      legacyHmacEnabled: this.config.legacyHmacEnabled
    });
    assertWelcomeMatchesNegotiation({
      welcomeCapabilities: response.capabilities,
      selectedAuthorityAlgorithm: response.selectedAuthorityAlgorithm,
      selectedCompression: response.selectedCompression,
      negotiated: expected
    });
    this.signer.verifySupervisorHandshake({
      connectionId,
      gatewayId: this.config.gatewayId,
      supervisorId: response.supervisorId,
      challenge,
      challengeResponse: response.challengeResponse,
      negotiated,
      supervisorVerificationKeyRing: this.#supervisorVerificationKeyRing ?? undefined,
      timestamp: response.timestamp,
      now: new Date()
    });
    this.#negotiated = negotiated;
    this.#connectionGeneration += 1;
    this.#channel = channel;
    this.#lastPong = Date.now();
    this.#startLiveness();
    return channel;
  }

  #frame(channel: QuirtFramedChannel, frame: QuirtFrame): void {
    const envelope = frame.envelope;
    if (envelope.kind === "welcome") { this.#welcome?.resolve(envelope); return; }
    if (envelope.kind === "response") { this.#resolve(envelope, frame.binary); return; }
    if (envelope.kind === "error") {
      const error = new QuirtError(quirtErrorCode(envelope.error.code), envelope.error.message, envelope.error.retryable, envelope.error.details ?? {});
      if (envelope.requestId === null) this.#welcome?.reject(error); else this.#reject(envelope.requestId, error);
      return;
    }
    if (envelope.kind === "event") {
      let reconnectGap = false;
      if (this.#lastAcceptedEventSequence !== null && envelope.sequence !== this.#lastAcceptedEventSequence + 1) reconnectGap = true;
      this.#lastAcceptedEventSequence = envelope.sequence;
      this.#events.emit("event", { envelope, binary: frame.binary, reconnectGap } satisfies QuirtClientEvent);
      return;
    }
    if (envelope.kind === "ping") { void channel.send({ envelope: { kind: "pong", protocolVersion: QUIRT_PROTOCOL_VERSION, nonce: envelope.nonce, timestamp: new Date().toISOString(), binaryLength: 0 }, binary: Buffer.alloc(0) }); return; }
    if (envelope.kind === "pong") this.#lastPong = Date.now();
  }

  #resolve(envelope: QuirtResponseEnvelope, binary: Buffer): void {
    const pending = this.#pending.get(envelope.requestId);
    if (pending === undefined) return;
    clearTimeout(pending.timer); pending.removeAbort?.();
    this.#pending.delete(envelope.requestId);
    pending.resolve({ payload: envelope.payload, binary, replayed: envelope.replayed === true });
  }

  #reject(requestId: string, cause: unknown): void {
    const pending = this.#pending.get(requestId);
    if (pending === undefined) return;
    clearTimeout(pending.timer); pending.removeAbort?.();
    this.#pending.delete(requestId);
    pending.reject(cause);
  }

  #disconnected(channel: QuirtFramedChannel, cause: unknown): void {
    if (this.#channel === channel) {
      this.#channel = null;
      this.#negotiated = null;
    }
    const welcome = this.#welcome; this.#welcome = null;
    welcome?.reject(new QuirtError("supervisor_unavailable", "Quirt supervisor disconnected during handshake", true));
    for (const requestId of [...this.#pending.keys()]) this.#reject(requestId, cause instanceof QuirtError ? cause : new QuirtError("supervisor_unavailable", "Quirt supervisor disconnected", true));
  }

  #resetTransport(cause: unknown): void {
    this.#channel?.close(cause);
    this.#channel = null;
    this.#negotiated = null;
  }

  async #sleep(ms: number, signal?: AbortSignal): Promise<void> {
    if (ms <= 0) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); resolve(); }, ms);
      const onAbort = () => { cleanup(); reject(new QuirtError("request_canceled", "Quirt request was canceled", false)); };
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener("abort", onAbort); };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  #startLiveness(): void {
    if (this.#liveness !== null) clearInterval(this.#liveness);
    this.#liveness = setInterval(() => {
      const channel = this.#channel;
      if (channel === null) return;
      if (Date.now() - this.#lastPong > this.config.livenessIntervalMs * 3) { channel.close(new QuirtError("timeout", "Quirt liveness check failed", true)); return; }
      void channel.send({ envelope: { kind: "ping", protocolVersion: QUIRT_PROTOCOL_VERSION, nonce: randomUUID(), timestamp: new Date().toISOString(), binaryLength: 0 }, binary: Buffer.alloc(0) }).catch(() => channel.close());
    }, this.config.livenessIntervalMs);
    this.#liveness.unref();
  }
}
