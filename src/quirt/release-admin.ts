#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { canonicalJson, type Json } from "../canonical.js";
import {
  QuirtReleaseError,
  QuirtReleaseManager,
  createQuirtArtifactDescriptor,
  finalizeQuirtReleaseDirectory,
  inspectQuirtReleaseArtifact
} from "./release.js";

function usage(): never {
  throw new QuirtReleaseError("invalid_arguments", "usage: quirt-release <finalize|descriptor|inspect|install|verify-installed|activate|rollback|recover|status|receipts> ...");
}

function exactArguments(args: readonly string[], count: number): void {
  if (args.length !== count || args.some(value => value.includes("\0"))) usage();
}

async function jsonFile(path: string): Promise<unknown> {
  const bytes = await readFile(path);
  if (bytes.length < 2 || bytes.length > 32 * 1024 * 1024) throw new QuirtReleaseError("metadata_invalid", "Quirt release metadata is outside its bound");
  try { return JSON.parse(bytes.toString("utf8")); }
  catch { throw new QuirtReleaseError("metadata_invalid", "Quirt release metadata is invalid JSON"); }
}

async function main(args: readonly string[]): Promise<Json> {
  const [command, ...rest] = args;
  if (command === "finalize") {
    exactArguments(rest, 4);
    const [root, commit, tree, epochText] = rest as [string, string, string, string];
    if (!/^[0-9]+$/u.test(epochText)) usage();
    return await finalizeQuirtReleaseDirectory(root, { commit, tree, epoch: Number(epochText) }) as unknown as Json;
  }
  if (command === "descriptor") {
    exactArguments(rest, 2);
    return await createQuirtArtifactDescriptor(rest[0]!, rest[1]!) as unknown as Json;
  }
  if (command === "inspect") {
    exactArguments(rest, 2);
    return await inspectQuirtReleaseArtifact(rest[0]!, await jsonFile(rest[1]!)) as unknown as Json;
  }
  const manager = new QuirtReleaseManager();
  if (command === "install") { exactArguments(rest, 2); return await manager.install(rest[0]!, await jsonFile(rest[1]!)) as unknown as Json; }
  if (command === "verify-installed") { exactArguments(rest, 1); return await manager.inspectInstalled(rest[0]!) as unknown as Json; }
  if (command === "activate") { exactArguments(rest, 1); return await manager.activate(rest[0]!); }
  if (command === "rollback") { exactArguments(rest, 0); return await manager.rollback(); }
  if (command === "recover") { exactArguments(rest, 0); return await manager.recover(); }
  if (command === "status") { exactArguments(rest, 0); return await manager.status(); }
  if (command === "receipts") { exactArguments(rest, 0); return await manager.listReceipts(); }
  return usage();
}

try { process.stdout.write(`${canonicalJson(await main(process.argv.slice(2)))}\n`); }
catch (cause) {
  const classification = cause instanceof QuirtReleaseError ? cause.classification : "release_admin_failed";
  const diagnostic = (cause instanceof Error ? cause.message : "Quirt release administration failed").replace(/[\r\n\0]+/gu, " ").slice(0, 384);
  process.stderr.write(`${canonicalJson({ classification, diagnostic, ok: false })}\n`);
  process.exitCode = 1;
}
