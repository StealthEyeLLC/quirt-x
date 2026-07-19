import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as tar from "tar";
import { QuirtError } from "./error.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";
import { QuirtTransferService } from "./transfer-service.js";

const owner = "a".repeat(64);
const digest = (value: Buffer): string => createHash("sha256").update(value).digest("hex");

test("uploaded directory archives reject links before extraction", { skip: process.platform !== "linux" }, async t => {
  const root = await mkdtemp(join(tmpdir(), "quirt-unsafe-tar-"));
  const config = quirtTestConfig(root);
  const state = new QuirtStateStore(":memory:");
  t.after(async () => { state.close(); await rm(root, { recursive: true, force: true }); });
  const source = join(root, "source");
  const archive = join(root, "unsafe.tar");
  const destination = join(root, "destination");
  await mkdir(source);
  await writeFile(join(source, "safe.txt"), "safe");
  await symlink("../outside", join(source, "escape"));
  await tar.c({ cwd: source, file: archive, portable: true, noMtime: true }, ["."]);
  const bytes = await readFile(archive);
  const service = new QuirtTransferService(config, state);
  const begun = await service.begin({ direction: "upload", destination, expectedSize: bytes.length, expectedDigest: digest(bytes), archiveFormat: "tar", chunkSize: 1024 * 1024 }, owner);
  const transferId = (begun.transfer as { transferId: string }).transferId;
  await service.write({ transferId, offset: 0, content: bytes }, owner);
  await assert.rejects(service.complete(transferId, owner), (cause: unknown) => cause instanceof QuirtError && cause.code === "invalid_request" && /link or special file/u.test(cause.message));
  assert.equal(existsSync(destination), false);
});
