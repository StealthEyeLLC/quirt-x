import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { QuirtError } from "./error.js";
import {
  DEFAULT_MAX_FRAME_BYTES,
  QUIRT_FRAME_HEADER_BYTES,
  QUIRT_PROTOCOL_VERSION,
  QuirtFrameDecoder,
  encodeFrame,
  errorFrame,
  type QuirtEventEnvelope,
  type QuirtFrame,
  type QuirtResponseEnvelope
} from "./protocol.js";

function response(binary = Buffer.alloc(0)): QuirtFrame<QuirtResponseEnvelope> {
  return {
    envelope: {
      kind: "response",
      protocolVersion: QUIRT_PROTOCOL_VERSION,
      requestId: "request-123",
      timestamp: "2026-07-17T12:00:00.000Z",
      payload: { ok: true },
      binaryLength: binary.length
    },
    binary
  };
}

function event(sequence: number): QuirtFrame<QuirtEventEnvelope> {
  return {
    envelope: {
      kind: "event",
      protocolVersion: QUIRT_PROTOCOL_VERSION,
      eventId: `event-${sequence}`,
      streamId: "stream-1",
      sequence,
      event: "session.output",
      timestamp: "2026-07-17T12:00:00.000Z",
      payload: {},
      binaryLength: 1
    },
    binary: Buffer.from([sequence])
  };
}

describe("Quirt protocol framing", () => {
  it("round-trips complete and zero-length binary frames", () => {
    const decoder = new QuirtFrameDecoder();
    const [decoded] = decoder.push(encodeFrame(response()));
    assert.equal(decoded?.envelope.kind, "response");
    assert.equal(decoded?.binary.length, 0);
    assert.equal(decoder.bufferedBytes, 0);
    decoder.end();
  });

  it("preserves arbitrary raw binary bytes", () => {
    const binary = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
    const [decoded] = new QuirtFrameDecoder().push(encodeFrame(response(binary)));
    assert.deepEqual(decoded?.binary, binary);
  });

  it("decodes a frame fragmented at every byte boundary", () => {
    const encoded = encodeFrame(response(Buffer.from("fragmented")));
    const decoder = new QuirtFrameDecoder();
    const frames: QuirtFrame[] = [];
    for (const byte of encoded) frames.push(...decoder.push(Buffer.from([byte])));
    assert.equal(frames.length, 1);
    assert.equal(frames[0]?.binary.toString("utf8"), "fragmented");
  });

  it("decodes multiple coalesced frames in order", () => {
    const decoder = new QuirtFrameDecoder();
    const frames = decoder.push(Buffer.concat([encodeFrame(event(1)), encodeFrame(event(2)), encodeFrame(event(3))]));
    assert.deepEqual(frames.map(frame => frame.envelope.kind === "event" ? frame.envelope.sequence : -1), [1, 2, 3]);
    assert.deepEqual(frames.map(frame => frame.binary[0]), [1, 2, 3]);
  });

  it("accepts the maximum configured frame and rejects one byte more", () => {
    const validBinary = Buffer.alloc(100);
    const maximum = encodeFrame(response(validBinary)).length;
    const valid = encodeFrame(response(validBinary), { maxFrameBytes: maximum, maxMetadataBytes: maximum });
    assert.equal(valid.length, maximum);
    assert.throws(() => encodeFrame(response(Buffer.alloc(validBinary.length + 1)), { maxFrameBytes: maximum, maxMetadataBytes: maximum }), (error: unknown) => error instanceof QuirtError && error.code === "frame_too_large");
  });

  it("rejects oversized, malformed, and unsupported headers", () => {
    const oversized = Buffer.alloc(QUIRT_FRAME_HEADER_BYTES);
    Buffer.from("QRT1").copy(oversized);
    oversized.writeUInt8(1, 4); oversized.writeUInt8(4, 5); oversized.writeUInt32BE(DEFAULT_MAX_FRAME_BYTES, 8);
    assert.throws(() => new QuirtFrameDecoder().push(oversized), /length/u);
    const badMagic = encodeFrame(response()); badMagic[0] = 0;
    assert.throws(() => new QuirtFrameDecoder().push(badMagic), /magic/u);
    const badVersion = encodeFrame(response()); badVersion[4] = 99;
    assert.throws(() => new QuirtFrameDecoder().push(badVersion), (error: unknown) => error instanceof QuirtError && error.code === "protocol_mismatch");
    const malformed = encodeFrame(response()); malformed[QUIRT_FRAME_HEADER_BYTES] = 0xff;
    assert.throws(() => new QuirtFrameDecoder().push(malformed), /malformed/u);
  });

  it("rejects a request envelope with a missing authenticated principal", () => {
    const frame = {
      envelope: { kind: "request", protocolVersion: 1, requestId: "request-missing-principal", operation: "quirt.status", authority: {}, targetHost: "host", timestamp: new Date().toISOString(), payload: {}, binaryLength: 0 },
      binary: Buffer.alloc(0)
    } as unknown as QuirtFrame;
    assert.throws(() => new QuirtFrameDecoder().push(encodeFrame(frame)), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request");
  });

  it("bounds buffered partial data and rejects incomplete disconnects", () => {
    const decoder = new QuirtFrameDecoder({ maxFrameBytes: 1024, maxBufferedBytes: 1024, maxMetadataBytes: 512 });
    assert.throws(() => decoder.push(Buffer.alloc(1025)), (error: unknown) => error instanceof QuirtError && error.code === "queue_overflow");
    const partial = encodeFrame(response(Buffer.from("partial"))).subarray(0, 20);
    const second = new QuirtFrameDecoder(); second.push(partial);
    assert.throws(() => second.end(), /incomplete/u);
  });

  it("normalizes protocol errors without binary data", () => {
    const encoded = encodeFrame(errorFrame("request-1", new QuirtError("unknown_operation", "No such operation")));
    const [decoded] = new QuirtFrameDecoder().push(encoded);
    assert.equal(decoded?.envelope.kind, "error");
    assert.equal(decoded?.binary.length, 0);
  });
});
