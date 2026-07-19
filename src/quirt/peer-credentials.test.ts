import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtError } from "./error.js";
import { inspectQuirtSocket, LinuxQuirtPeerCredentialSource, resolveQuirtSocketGroupGid, verifyQuirtGatewayPeer } from "./peer-credentials.js";
import { quirtTestConfig } from "./test-support.test.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe("Quirt private socket identity", () => {
  it("accepts only the configured Gateway peer UID", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-peer-")); roots.push(root); const config = quirtTestConfig(root, { QUIRT_GATEWAY_UID: "1234" }); const socket = {} as Socket;
    assert.deepEqual(verifyQuirtGatewayPeer({ read: () => ({ pid: 22, uid: 1234, gid: 55 }) }, socket, config), { pid: 22, uid: 1234, gid: 55 });
    assert.throws(() => verifyQuirtGatewayPeer({ read: () => ({ pid: 22, uid: 1235, gid: 55 }) }, socket, config), (error: unknown) => error instanceof QuirtError && error.code === "authentication_failed");
  });

  it("rejects regular files, symlinks, and unsafe parent paths as supervisor sockets", () => {
    const root = mkdtempSync(join(tmpdir(), "quirt-socket-")); roots.push(root); const parent = join(root, "run"); mkdirSync(parent, { mode: 0o755 }); const path = join(parent, "quirt.sock"); writeFileSync(path, "not a socket", { mode: 0o660 });
    assert.throws(() => inspectQuirtSocket(path, 0o660, process.getgid?.() ?? 0), (error: unknown) => error instanceof QuirtError && error.code === "supervisor_unavailable");
    assert.equal(resolveQuirtSocketGroupGid("/usr/bin/python3", "root"), 0); assert.throws(() => resolveQuirtSocketGroupGid("/usr/bin/python3", "group-that-does-not-exist"), /unavailable/u);
  });

  it("reads Linux SO_PEERCRED from a real private Unix socket when the harness permits UDS listeners", async context => {
    const root = mkdtempSync(join(tmpdir(), "quirt-peer-real-")); roots.push(root); const path = join(root, "peer.sock"); const server = createServer();
    try {
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(path, resolve); });
    } catch (cause) {
      server.close();
      if (cause instanceof Error && "code" in cause && cause.code === "EPERM") { context.skip("sandbox denies Unix-domain socket listen"); return; }
      throw cause;
    }
    try {
      const accepted = new Promise<Socket>(resolve => server.once("connection", resolve)); const client = createConnection(path); await new Promise<void>((resolve, reject) => { client.once("connect", resolve); client.once("error", reject); }); const peer = await accepted;
      try { const credentials = new LinuxQuirtPeerCredentialSource("/usr/bin/python3").read(peer); assert.equal(credentials.uid, process.getuid?.()); assert.equal(credentials.pid, process.pid); }
      finally { peer.destroy(); client.destroy(); }
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  });
});
