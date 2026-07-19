import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { buildQuirtContractBundle } from "./contract-catalog.js";
import { deterministicContractBundleJson } from "./contract-validation.js";
import {
  QUIRT_OWNER_AUTHORITY_CLASS,
  QUIRT_OWNER_SUBJECT,
  QUIRT_SOCKET_GROUP,
  QUIRT_SOCKET_MODE,
  QUIRT_SOCKET_OWNER,
  QUIRT_SOCKET_PATH
} from "./contract-types.js";

function text(path: string): string {
  return readFileSync(path, "utf8");
}

const FORBIDDEN_MARKERS = Object.freeze({
  mcpServer: ["Mcp", "Server"].join(""),
  registerTool: [".", "register", "Tool", "("].join(""),
  sdkImport: ["@", "modelcontextprotocol", "/", "sdk"].join("")
});

function walkSource(directory: string): string[] {
  const output: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...walkSource(path));
    else if (entry.isFile() && path.endsWith(".ts") && !path.endsWith(".test.ts")) output.push(path);
  }
  return output;
}

function walkActiveRuntimeSource(directory: string): string[] {
  return walkSource(directory).filter((path) => !path.endsWith("contract-validation.ts"));
}

describe("Quirt architecture contract invariants", () => {
  it("defines the exact private socket and unrestricted owner contract", () => {
    const bundle = buildQuirtContractBundle();
    assert.equal(bundle.paths.socket.path, QUIRT_SOCKET_PATH);
    assert.equal(bundle.paths.socket.owner, QUIRT_SOCKET_OWNER);
    assert.equal(bundle.paths.socket.group, QUIRT_SOCKET_GROUP);
    assert.equal(bundle.paths.socket.mode, QUIRT_SOCKET_MODE);
    assert.equal(bundle.paths.daemonUid, 0);
    assert.equal(bundle.authority.ownerSubject, QUIRT_OWNER_SUBJECT);
    assert.equal(bundle.authority.authorityClass, QUIRT_OWNER_AUTHORITY_CLASS);
    assert.equal(bundle.protocol.publicRootListener, false);
    assert.equal(bundle.protocol.activeMcpServer, false);
    assert.equal(bundle.protocol.activeOAuthServer, false);
  });

  it("forbids owner permission gates and preserves raw execution", () => {
    const bundle = buildQuirtContractBundle();
    for (const forbidden of [
      "command_allowlists",
      "executable_allowlists",
      "argument_allowlists",
      "path_allowlists",
      "provider_permission_gates",
      "mandatory_plan_apply",
      "routine_confirmations",
      "default_timeouts"
    ]) {
      assert.ok(bundle.authority.prohibitedAuthorization.includes(forbidden), forbidden);
    }
    assert.ok(bundle.authority.afterAuthentication.includes("arbitrary_executable_execution"));
    assert.equal(String(bundle.skills["powerInvariant"]).includes("does_not_remove_unrestricted_owner_execution"), true);
  });

  it("keeps active runtime free of public MCP server code and SDK dependencies", () => {
    const activeSources = walkActiveRuntimeSource("src");
    for (const path of activeSources) {
      const source = text(path);
      assert.equal(new RegExp(`\\b${FORBIDDEN_MARKERS.mcpServer}\\b`, "u").test(source), false, path);
      assert.equal(source.includes(FORBIDDEN_MARKERS.registerTool), false, path);
      assert.equal(source.includes(FORBIDDEN_MARKERS.sdkImport), false, path);
    }
    const packageJson = JSON.parse(text("package.json")) as { dependencies?: Record<string, string> };
    assert.equal(packageJson.dependencies?.[FORBIDDEN_MARKERS.sdkImport], undefined);
  });

  it("keeps systemd socket contract exact and rescue independent of gateway", () => {
    const socket = text("ops/systemd/stealtheye-quirt.socket");
    assert.match(socket, /^ListenStream=\/run\/horsey\/quirt\.sock$/mu);
    assert.match(socket, /^SocketUser=root$/mu);
    assert.match(socket, /^SocketGroup=horsey$/mu);
    assert.match(socket, /^SocketMode=0660$/mu);
    const rescueDeps = buildQuirtContractBundle().rescue["forbiddenDependencies"] as string[];
    assert.ok(rescueDeps.includes("horsey_gateway"));
    assert.ok(rescueDeps.includes("oauth"));
  });

  it("documents Ed25519 runtime and transitional HMAC compatibility without claiming production validation", () => {
    const bundle = buildQuirtContractBundle();
    assert.equal(bundle.protocol.currentRuntimeSignatureAlgorithm, "ed25519");
    assert.equal(bundle.protocol.targetSignatureAlgorithm, "ed25519");
    const ed25519 = bundle.conformance.find((item) => item.area === "target_ed25519_signatures");
    assert.equal(ed25519?.implementationStatus, "source complete");
    assert.equal(ed25519?.firstPlannedPhase, "Q2");
  });

  it("includes contract bundle and schema in release build script", () => {
    const releaseScript = text("scripts/build-quirt-release.sh");
    assert.ok(releaseScript.includes("contracts/quirt-x-contracts-v1.json"));
    assert.ok(releaseScript.includes("schemas/quirt-x-contracts-v1.schema.json"));
    assert.ok(!releaseScript.includes("reference/operator-boundary/"));
  });

  it("runs the contract validation script successfully", () => {
    execFileSync("npx", ["tsc", "-p", "tsconfig.json"], { encoding: "utf8", stdio: "ignore" });
    const output = execFileSync("node", ["scripts/validate-quirt-contracts.mjs"], { encoding: "utf8" });
    const summary = JSON.parse(output.trim()) as { contractBundleSha256: string; contractSchemaSha256: string };
    const bundleDigest = createHash("sha256").update(readFileSync("contracts/quirt-x-contracts-v1.json")).digest("hex");
    const schemaDigest = createHash("sha256").update(readFileSync("schemas/quirt-x-contracts-v1.schema.json")).digest("hex");
    assert.equal(summary.contractBundleSha256, bundleDigest);
    assert.equal(summary.contractSchemaSha256, schemaDigest);
    assert.equal(deterministicContractBundleJson(buildQuirtContractBundle()), readFileSync("contracts/quirt-x-contracts-v1.json", "utf8"));
  });
});
