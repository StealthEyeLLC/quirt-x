import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtCapabilityService } from "./capability-service.js";
import { QUIRT_OPERATIONS } from "./catalog.js";
import type { QuirtGitService } from "./git-service.js";
import type { QuirtProcessService } from "./process-service.js";
import { QUIRT_STATE_SCHEMA_VERSION, QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";
import type { QuirtTmuxController } from "./tmux.js";

const roots: string[] = []; const stores: QuirtStateStore[] = []; const owner = "a".repeat(64);
afterEach(() => { for (const store of stores.splice(0)) store.close(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture(options: { tmux?: string | null; git?: { available: boolean; version: string | null; lfsAvailable: boolean; lfsVersion: string | null }; bootId?: string | null } = {}) {
  const root = mkdtempSync(join(tmpdir(), "quirt-capability-")); roots.push(root); const config = quirtTestConfig(root); const state = new QuirtStateStore(config.databasePath); stores.push(state);
  const tmux = { version: async () => { if (options.tmux === null) throw new Error("missing"); return options.tmux ?? "tmux 3.4"; } } as unknown as QuirtTmuxController;
  const git = { version: async () => options.git ?? { available: true, version: "git version fixture", lfsAvailable: true, lfsVersion: "git-lfs fixture" } } as unknown as QuirtGitService;
  const processes = { bootId: async () => { if (options.bootId === null) throw new Error("missing"); return options.bootId ?? "11111111-1111-4111-8111-111111111111"; } } as unknown as QuirtProcessService;
  return { state, service: new QuirtCapabilityService(config, state, tmux, git, processes) };
}

describe("Quirt capability inventory", () => {
  it("reports the exact native catalog, host facts, validation boundaries, and durable current-host probe", async () => {
    const f = fixture(); const inventory = await f.service.inventory(owner);
    assert.equal(inventory.protocolVersion, 1); assert.equal(inventory.stateSchemaVersion, QUIRT_STATE_SCHEMA_VERSION); assert.equal(inventory.implementedOperationCount, 146); assert.deepEqual(inventory.operations, QUIRT_OPERATIONS);
    assert.equal((inventory.host as { bootId: string }).bootId, "11111111-1111-4111-8111-111111111111"); assert.equal((inventory.terminal as { nativePty: { locallyTested: boolean } }).nativePty.locallyTested, true);
    assert.deepEqual((inventory.recordings as { formats: string[] }).formats, ["quirt-json-v1", "asciinema-v2", "html-transcript"]); assert.deepEqual((inventory.transfers as { digestAlgorithms: string[] }).digestAlgorithms, ["sha256"]);
    assert.ok((inventory.privilegedValidationPending as string[]).includes("systemd-socket-activation-so-peercred")); const browser = (inventory.providers as Record<string, { sourceImplemented: boolean; classification: string; enabledOperations: readonly string[] }>)["browser.playwright"]!; assert.equal(browser.sourceImplemented, false); assert.equal(browser.classification, "dependency_absent"); assert.deepEqual(browser.enabledOperations, []);
    assert.ok(Array.isArray(inventory.packageManagers)); assert.ok(Array.isArray(inventory.containerRuntimes)); assert.ok(Array.isArray(inventory.debuggingTools)); assert.ok(Array.isArray(inventory.networkTools)); assert.equal((inventory.filesystem as { mountInspection: string }).mountInspection, "available");
    assert.deepEqual((inventory.git as { credentialMechanisms: string[] }).credentialMechanisms, ["controlled-askpass", "isolated-ssh-key"]); assert.deepEqual((inventory.transfers as { objectTypes: string[] }).objectTypes, ["file", "directory", "symlink"]);
    const record = f.state.native.getObject("quirt_capability_probes", "current-host", owner); assert.equal(record.data.implementedOperationCount, 146);
  });

  it("distinguishes unavailable host executables from implemented source without claiming provider support", async () => {
    const f = fixture({ tmux: null, git: { available: true, version: "git fixture", lfsAvailable: false, lfsVersion: null }, bootId: null }); const inventory = await f.service.inventory(owner);
    const degraded = inventory.degraded as Array<{ capability: string; state: string }>; assert.ok(degraded.some(item => item.capability === "persistent-tmux" && item.state === "unavailable")); assert.ok(degraded.some(item => item.capability === "git-lfs" && item.state === "unavailable"));
    assert.equal((inventory.git as { state: string }).state, "available"); assert.equal((inventory.git as { lfs: { state: string } }).lfs.state, "unsupported");
    assert.equal((inventory.host as { bootId: null }).bootId, null); const status = await f.service.status(owner); assert.equal(status.status, "degraded"); assert.equal((status.capabilitySummary as { operationCount: number }).operationCount, 146);
  });
});
