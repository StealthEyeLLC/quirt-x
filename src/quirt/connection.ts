import { EventEmitter } from "node:events";
import type { Duplex } from "node:stream";
import { QuirtError } from "./error.js";
import { encodeFrame, QuirtFrameDecoder, type QuirtFrame, type QuirtFrameLimits } from "./protocol.js";

interface QueuedFrame {
  bytes: Buffer;
  resolve: () => void;
  reject: (cause: unknown) => void;
}

export class QuirtFramedChannel {
  readonly #events = new EventEmitter();
  readonly #decoder: QuirtFrameDecoder;
  readonly #limits: QuirtFrameLimits;
  readonly #maximumQueueBytes: number;
  readonly #queue: QueuedFrame[] = [];
  #queuedBytes = 0;
  #writing = false;
  #closed = false;

  constructor(readonly stream: Duplex, options: QuirtFrameLimits & { maxWriteQueueBytes: number }) {
    this.#limits = options;
    this.#decoder = new QuirtFrameDecoder(options);
    this.#maximumQueueBytes = options.maxWriteQueueBytes;
    if (!Number.isSafeInteger(this.#maximumQueueBytes) || this.#maximumQueueBytes < 1024) throw new QuirtError("configuration_error", "Quirt write queue limit is invalid");
    stream.on("data", (chunk: Buffer | Uint8Array) => this.#data(chunk));
    stream.once("error", cause => this.#finish(cause));
    stream.once("end", () => {
      try { this.#decoder.end(); }
      catch (cause) { if (this.#events.listenerCount("decodeError") > 0) this.#events.emit("decodeError", cause); this.#finish(cause); return; }
      this.#finish(new QuirtError("supervisor_unavailable", "Quirt connection ended", true));
    });
    stream.once("close", () => this.#finish(new QuirtError("supervisor_unavailable", "Quirt connection closed", true)));
  }

  get closed(): boolean { return this.#closed; }
  get queuedBytes(): number { return this.#queuedBytes; }

  onFrame(listener: (frame: QuirtFrame) => void): () => void {
    this.#events.on("frame", listener);
    return () => this.#events.off("frame", listener);
  }

  onClose(listener: (cause: unknown) => void): () => void {
    this.#events.on("close", listener);
    return () => this.#events.off("close", listener);
  }

  onDecodeError(listener: (cause: unknown) => void): () => void {
    this.#events.on("decodeError", listener);
    return () => this.#events.off("decodeError", listener);
  }

  send(frame: QuirtFrame): Promise<void> {
    if (this.#closed) return Promise.reject(new QuirtError("supervisor_unavailable", "Quirt connection is closed", true));
    let bytes: Buffer;
    try { bytes = encodeFrame(frame, this.#limits); }
    catch (cause) { return Promise.reject(cause); }
    if (this.#queuedBytes + bytes.length > this.#maximumQueueBytes) {
      const error = new QuirtError("queue_overflow", "Quirt connection write queue exceeded its limit", true);
      this.close(error);
      return Promise.reject(error);
    }
    return new Promise<void>((resolve, reject) => {
      this.#queue.push({ bytes, resolve, reject });
      this.#queuedBytes += bytes.length;
      this.#flush();
    });
  }

  close(cause: unknown = new QuirtError("supervisor_unavailable", "Quirt connection closed", true)): void {
    if (this.#closed) return;
    this.stream.destroy();
    this.#finish(cause);
  }

  #data(chunk: Buffer | Uint8Array): void {
    if (this.#closed) return;
    try {
      for (const frame of this.#decoder.push(chunk)) this.#events.emit("frame", frame);
    } catch (cause) {
      if (this.#events.listenerCount("decodeError") > 0) this.#events.emit("decodeError", cause);
      else this.close(cause);
    }
  }

  #flush(): void {
    if (this.#closed || this.#writing) return;
    const current = this.#queue[0];
    if (current === undefined) return;
    this.#writing = true;
    try {
      this.stream.write(current.bytes, cause => {
        this.#writing = false;
        if (this.#queue[0] === current) this.#queue.shift();
        this.#queuedBytes -= current.bytes.length;
        if (cause) { current.reject(cause); this.close(cause); return; }
        current.resolve();
        this.#flush();
      });
    } catch (cause) {
      this.#writing = false;
      current.reject(cause);
      this.close(cause);
    }
  }

  #finish(cause: unknown): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const item of this.#queue.splice(0)) item.reject(cause);
    this.#queuedBytes = 0;
    this.#events.emit("close", cause);
    this.#events.removeAllListeners();
  }
}
