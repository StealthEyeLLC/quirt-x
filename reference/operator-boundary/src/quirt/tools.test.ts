import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, it } from "node:test";
import * as z from "zod/v4";
import { QUIRT_TOOL_NAMES, QUIRT_TOOL_SCOPES, quirtToolSchemas, registerQuirtTools, type QuirtToolInvocation } from "./tools.js";

function result(value: Record<string, unknown>): CallToolResult { return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value }; }

describe("Core Quirt MCP tools", () => {
  it("registers exactly the implemented catalog with strict schemas, standing authority, and truthful scopes", async () => {
    const invocations: QuirtToolInvocation[] = []; const server = new McpServer({ name: "Horsey Quirt", version: "test" }); registerQuirtTools(server, { invoke: input => { invocations.push(input); return result({ ok: true }); } });
    const client = new Client({ name: "quirt-tools-test", version: "1" }); const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair(); await server.connect(serverTransport); await client.connect(clientTransport);
    try {
      const listed = await client.listTools(); assert.deepEqual(listed.tools.map(tool => tool.name).sort(), [...QUIRT_TOOL_NAMES].sort()); assert.equal(listed.tools.length, 148);
      for (const tool of listed.tools) {
        assert.equal(tool.inputSchema.additionalProperties, false, tool.name); assert.equal(tool._meta?.["horsey/authorityMode"], "allow-all", tool.name); assert.equal(tool._meta?.["horsey/confirmationMode"], "never-ask", tool.name);
        const scope = QUIRT_TOOL_SCOPES[tool.name as keyof typeof QUIRT_TOOL_SCOPES]; assert.equal(tool.annotations?.readOnlyHint, scope === "fix.read", tool.name); assert.equal(tool.annotations?.openWorldHint, true, tool.name);
      }
      const bytes = Buffer.from([0, 1, 2, 255]); await client.callTool({ name: "quirt.session.write", arguments: { sessionId: "session-1", contentBase64: bytes.toString("base64"), requestId: "request-1" } }); const { signal, ...invocation } = invocations[0]!; assert.deepEqual(invocation, { operation: "quirt.session.write", payload: { sessionId: "session-1" }, binary: bytes, requestId: "request-1" }); assert.ok(signal instanceof AbortSignal);
    } finally { await client.close(); await server.close(); }
  });

  it("rejects malformed input, unknown fields, noncanonical base64, and unbounded attached execution", () => {
    for (const schema of Object.values(quirtToolSchemas)) assert.equal((z.toJSONSchema(schema) as Record<string, unknown>)["additionalProperties"], false);
    assert.equal(quirtToolSchemas["quirt.session.write"].safeParse({ sessionId: "session", contentBase64: "***" }).success, false);
    assert.equal(quirtToolSchemas["quirt.session.read"].safeParse({ sessionId: "session", maximumBytes: 1024 * 1024 + 1 }).success, false);
    assert.equal(quirtToolSchemas["quirt.status"].safeParse({ unexpected: true }).success, false);
    assert.equal(quirtToolSchemas["quirt.exec"].safeParse({ command: "sleep 60", timeoutMs: 60_000 }).success, false);
    assert.equal(quirtToolSchemas["quirt.exec"].safeParse({ command: "sleep 60", timeoutMs: 60_000, detach: true }).success, true);
    assert.equal(quirtToolSchemas["quirt.exec"].safeParse({ command: "id", executable: "/usr/bin/id" }).success, false);
    assert.equal(quirtToolSchemas["quirt.session.attach"].safeParse({ sessionId: "session", handoffId: "handoff" }).success, false);
    assert.equal(quirtToolSchemas["quirt.session.snapshot"].safeParse({ sessionId: "session", createHandoff: true, clientMetadata: { workspaceId: "inherited" } }).success, false);
    assert.equal(quirtToolSchemas["quirt.git.push"].safeParse({ repository: "/tmp/repo", source: "--upload-pack=bad", destination: "refs/heads/main" }).success, false);
    assert.equal(quirtToolSchemas["quirt.git.push"].safeParse({ repository: "/tmp/repo", source: "HEAD", destination: "refs/heads/main", force: true }).success, false);
    assert.equal(quirtToolSchemas["quirt.process.attach"].safeParse({ source: "journal", action: "read" }).success, false);
  });

  it("accepts a concrete bounded schema example for every Checkpoint C native operator operation", () => {
    const identity = { pid: 123, startTimeTicks: 456, bootId: "11111111-1111-4111-8111-111111111111", pidNamespace: "pid:[1]", executableDevice: 1, executableInode: 2 }; const commit = "1".repeat(40);
    const examples: Record<string, Record<string, unknown>> = {
      "quirt.session.snapshot": { sessionId: "session", createHandoff: true, clientMetadata: { client: "test", workspaceId: null } }, "quirt.session.search": { sessionId: "session", query: "needle", maximumMatches: 10 }, "quirt.session.render": { sessionId: "session", maximumBytes: 1024, rows: 24, columns: 80 },
      "quirt.git.materialize": { remote: "https://example.invalid/repository.git", destination: "/tmp/repository", exactCommit: commit }, "quirt.git.mirror": { remote: "https://example.invalid/repository.git", fetch: true }, "quirt.git.fetch": { repository: "/tmp/repository", remote: "origin" }, "quirt.git.status": { repository: "/tmp/repository" }, "quirt.git.worktree": { repository: "/tmp/repository", action: "list" }, "quirt.git.verify": { repository: "/tmp/repository", commit }, "quirt.git.push": { repository: "/tmp/repository", source: "HEAD", destination: "refs/heads/main" },
      "quirt.record.start": { sessionId: "session", name: "recording" }, "quirt.record.stop": { recordingId: "recording" }, "quirt.record.list": {}, "quirt.record.search": { recordingId: "recording", query: "needle" }, "quirt.record.replay": { recordingId: "recording", maximumEvents: 10, speed: 2 }, "quirt.record.export": { recordingId: "recording", format: "quirt-json-v1", maximumBytes: 1024 },
      "quirt.process.list": { maximumProcesses: 10 }, "quirt.process.get": { pid: 123 }, "quirt.process.signal": { identity, signal: "SIGCONT" }, "quirt.process.attach": { source: "journal", action: "open", filters: { unit: "demo.service", priority: 4 }, maximumEntries: 10 }, "quirt.process.tree": { pid: 123, maximumDepth: 4 }, "quirt.process.namespaces": { pid: 123 }
    };
    assert.deepEqual(Object.keys(examples).sort(), QUIRT_TOOL_NAMES.filter(name => name.startsWith("quirt.session.snapshot") || name.startsWith("quirt.session.search") || name.startsWith("quirt.session.render") || name.startsWith("quirt.git.") || name.startsWith("quirt.record.") || name.startsWith("quirt.process.")).sort());
    for (const [name, value] of Object.entries(examples)) assert.equal(quirtToolSchemas[name as keyof typeof quirtToolSchemas].safeParse(value).success, true, name);
  });
});
