import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loadQuirtConfig, QUIRT_DEFAULT_SOCKET, QUIRT_DEFAULT_STATE_ROOT } from "./config.js";

function env(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    QUIRT_TARGET_HOST: "fix-host-production",
    QUIRT_EXPECTED_ISSUER: "https://identity.stealtheye.io/",
    QUIRT_EXPECTED_SUBJECT: "stealtheye-owner",
    QUIRT_EXPECTED_PRINCIPAL_FINGERPRINT: "a".repeat(64),
    ...overrides
  };
}

describe("Quirt configuration", () => {
  it("uses secure production path and protocol defaults", () => {
    const config = loadQuirtConfig(env());
    assert.equal(config.socketPath, QUIRT_DEFAULT_SOCKET);
    assert.equal(config.stateRoot, QUIRT_DEFAULT_STATE_ROOT);
    assert.equal(config.databasePath, `${QUIRT_DEFAULT_STATE_ROOT}/state.sqlite`);
    assert.equal(config.socketMode, 0o660);
    assert.equal(config.expectedPrincipal.workspaceId, null);
  });

  it("accepts explicit isolated test paths", () => {
    const config = loadQuirtConfig(env({ QUIRT_MODE: "test", QUIRT_STATE_ROOT: "/tmp/quirt-test", QUIRT_DATABASE_PATH: "/tmp/quirt-test/state.sqlite", QUIRT_SOCKET_PATH: "/tmp/quirt-test/quirt.sock" }));
    assert.equal(config.mode, "test");
    assert.equal(config.socketPath, "/tmp/quirt-test/quirt.sock");
  });

  it("rejects state inside releases and database outside state", () => {
    assert.throws(() => loadQuirtConfig(env({ QUIRT_STATE_ROOT: "/opt/stealtheye-quirt/releases/a/state" })), /state root/u);
    assert.throws(() => loadQuirtConfig(env({ QUIRT_DATABASE_PATH: "/tmp/state.sqlite" })), /beneath/u);
  });

  it("rejects workspace inheritance and unsafe limits", () => {
    assert.throws(() => loadQuirtConfig(env({ QUIRT_EXPECTED_WORKSPACE: "workspace-parent" })), /inherited/u);
    assert.throws(() => loadQuirtConfig(env({ QUIRT_MAX_FRAME_BYTES: "1" })), /invalid/u);
    assert.throws(() => loadQuirtConfig(env({ QUIRT_SOCKET_PATH: "relative.sock" })), /absolute/u);
  });
});
