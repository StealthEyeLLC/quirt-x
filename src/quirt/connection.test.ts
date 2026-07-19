import assert from "node:assert/strict";
import { Duplex } from "node:stream";
import { describe, it } from "node:test";
import { QuirtFramedChannel } from "./connection.js";
import { QuirtError } from "./error.js";
import { QUIRT_PROTOCOL_VERSION, type QuirtFrame } from "./protocol.js";
import { linkedDuplexPair, waitFor } from "./test-support.test.js";

function event(sequence: number, binary = Buffer.alloc(0)): QuirtFrame {
  return { envelope: { kind: "event", protocolVersion: QUIRT_PROTOCOL_VERSION, eventId: `event-${sequence}`, streamId: "stream-1", sequence, event: "test.output", timestamp: new Date().toISOString(), payload: { sequence }, binaryLength: binary.length }, binary };
}

const options = { maxFrameBytes: 4096, maxBufferedBytes: 8192, maxWriteQueueBytes: 4096 };

describe("Quirt framed connection", () => {
  it("delivers ordered binary frames and unsolicited events across a duplex stream", async () => {
    const [leftStream, rightStream] = linkedDuplexPair();
    const left = new QuirtFramedChannel(leftStream, options); const right = new QuirtFramedChannel(rightStream, options);
    const received: QuirtFrame[] = []; right.onFrame(frame => received.push(frame));
    await Promise.all([left.send(event(1, Buffer.from([0, 255]))), left.send(event(2)), left.send(event(3, Buffer.from("three")))]);
    await waitFor(() => received.length === 3);
    assert.deepEqual(received.map(frame => frame.envelope.kind === "event" ? frame.envelope.sequence : -1), [1, 2, 3]);
    assert.deepEqual(received[0]?.binary, Buffer.from([0, 255])); assert.equal(received[2]?.binary.toString(), "three");
    left.close(); right.close();
  });

  it("bounds a stalled write queue and deterministically closes it", async () => {
    class StalledDuplex extends Duplex {
      override _read(): void {}
      override _write(_chunk: Buffer, _encoding: BufferEncoding, _callback: (error?: Error | null) => void): void {}
    }
    const channel = new QuirtFramedChannel(new StalledDuplex(), { maxFrameBytes: 2048, maxBufferedBytes: 4096, maxWriteQueueBytes: 1024 });
    const pending = channel.send(event(1, Buffer.alloc(600))).catch(error => error as unknown);
    await assert.rejects(channel.send(event(2, Buffer.alloc(600))), (error: unknown) => error instanceof QuirtError && error.code === "queue_overflow");
    assert.ok(await pending instanceof QuirtError); assert.equal(channel.closed, true); assert.equal(channel.queuedBytes, 0);
  });

  it("reports malformed input and clean peer disconnects without hanging queued requests", async () => {
    const [leftStream, rightStream] = linkedDuplexPair();
    const left = new QuirtFramedChannel(leftStream, options); const right = new QuirtFramedChannel(rightStream, options);
    let decode: unknown; let closed: unknown; right.onDecodeError(error => { decode = error; right.close(error); }); right.onClose(error => { closed = error; });
    leftStream.write(Buffer.from("not-a-quirt-frame"));
    await waitFor(() => decode !== undefined && closed !== undefined);
    assert.ok(decode instanceof QuirtError); assert.equal((decode as QuirtError).code, "invalid_frame"); assert.equal(right.closed, true); left.close();
  });

  it("classifies a disconnect with a partial frame as malformed", async () => {
    const [leftStream, rightStream] = linkedDuplexPair(); const right = new QuirtFramedChannel(rightStream, options); let decode: unknown; right.onDecodeError(error => { decode = error; });
    leftStream.end(Buffer.from("QRT1")); await waitFor(() => decode !== undefined); assert.ok(decode instanceof QuirtError); assert.equal((decode as QuirtError).code, "invalid_frame"); assert.equal(right.closed, true);
  });
});
