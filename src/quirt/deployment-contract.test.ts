import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

function text(path: string): string { return readFileSync(path, "utf8"); }

describe("Quirt source deployment contract", () => {
  it("defines only a private root-owned systemd socket and an unrestricted UID-0 supervisor", () => {
    const socket = text("ops/systemd/stealtheye-quirt.socket"); const service = text("ops/systemd/stealtheye-quirt.service"); const config = text("ops/config/stealtheye-quirt.env.example");
    assert.match(socket, /^ListenStream=\/run\/horsey\/quirt\.sock$/mu); assert.match(socket, /^SocketUser=root$/mu); assert.match(socket, /^SocketGroup=horsey$/mu); assert.match(socket, /^SocketMode=0660$/mu); assert.doesNotMatch(socket, /ListenStream=.*:/u);
    assert.match(service, /^User=root$/mu); assert.match(service, /^Group=root$/mu); assert.match(service, /^ExecStart=.*dist\/quirt\/supervisor-main\.js$/mu); assert.match(service, /^StateDirectory=stealtheye-quirt$/mu); assert.match(service, /^KillMode=process$/mu);
    for (const incompatible of ["PrivateNetwork=true", "NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet="]) assert.equal(service.includes(incompatible), false, incompatible);
    for (const expected of ["QUIRT_SOCKET_PATH=/run/horsey/quirt.sock", "QUIRT_STATE_ROOT=/var/lib/stealtheye-quirt", "QUIRT_DATABASE_PATH=/var/lib/stealtheye-quirt/state.sqlite", "QUIRT_TMUX_PATH=/usr/bin/tmux", "QUIRT_AUTHORITY_SECRET_PATH=/etc/stealtheye-quirt/authority.key"]) assert.ok(config.includes(expected), expected);
  });

  it("keeps the public Gateway unprivileged and free of PTY, tmux, and session ownership", () => {
    const service = text("reference/operator-boundary/ops/systemd/stealtheye-fix-operator.service");
    const server = text("reference/operator-boundary/src/server.ts");
    assert.match(service, /^User=fix-mcp$/mu); assert.match(service, /^SupplementaryGroups=horsey$/mu); assert.match(service, /^EnvironmentFile=-\/etc\/stealtheye-quirt\/quirt\.env$/mu);
    for (const forbidden of ["NodePtyFactory", "QuirtSessionManager", "QuirtJobManager", "QuirtTmuxController", "node-pty"]) assert.equal(server.includes(forbidden), false, forbidden);
    assert.ok(server.includes("QuirtGatewayClient")); assert.ok(server.includes("registerQuirtTools"));
  });
});
