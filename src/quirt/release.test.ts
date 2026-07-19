import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, readlink, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  QUIRT_RELEASE_ENTRYPOINT,
  QUIRT_RELEASE_FORMAT,
  QuirtReleaseError,
  QuirtReleaseManager,
  assertSafeArchiveEntry,
  createQuirtArtifactDescriptor,
  finalizeQuirtReleaseDirectory,
  inspectQuirtReleaseArtifact,
  normalizeReleasePath,
  parseQuirtArtifactDescriptor,
  parseQuirtReleaseManifest,
  verifyQuirtReleaseTree,
  type QuirtReleaseArtifactDescriptor,
  type QuirtReleaseLayout,
  type QuirtReleaseManifest
} from "./release.js";

const COMMIT_ONE = "1".repeat(40);
const TREE_ONE = "2".repeat(40);
const COMMIT_TWO = "3".repeat(40);
const TREE_TWO = "4".repeat(40);
const RUNTIME = { operatingSystem: "linux", architecture: "x64", nodeVersion: "24.18.0" };
const execute = promisify(execFile);

interface ArtifactFixture {
  root: string;
  archive: string;
  descriptor: QuirtReleaseArtifactDescriptor;
  manifest: QuirtReleaseManifest;
}

async function temporary(): Promise<string> { return await mkdtemp(join(tmpdir(), "quirt-release-test-")); }

async function normalizeSbom(input: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/normalize-quirt-sbom.mjs", COMMIT_ONE, TREE_ONE, "1700000001"], { stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code === 0 && signal === null) resolve(Buffer.concat(stdout).toString("utf8"));
      else reject(new Error(`SBOM normalizer failed (${code ?? signal}): ${Buffer.concat(stderr).toString("utf8")}`));
    });
    child.stdin.end(input);
  });
}

async function cleanup(path: string): Promise<void> {
  const details = await lstat(path).catch(() => null);
  if (details === null) return;
  if (details.isDirectory()) {
    await chmod(path, 0o755);
    for (const name of await readdir(path)) await cleanup(join(path, name));
  } else if (!details.isSymbolicLink()) await chmod(path, 0o644);
  if (path.includes("quirt-release-test-")) await rm(path, { recursive: true, force: true });
}

async function artifact(base: string, commit = COMMIT_ONE, tree = TREE_ONE, epoch = 1_700_000_001, body = "export const quirt = true;\n"): Promise<ArtifactFixture> {
  const root = join(base, `payload-${randomUUID()}`);
  await mkdir(join(root, "dist/quirt"), { recursive: true });
  await mkdir(join(root, "evidence"), { recursive: true });
  await writeFile(join(root, QUIRT_RELEASE_ENTRYPOINT), body);
  await writeFile(join(root, "package.json"), '{"name":"@stealtheye/quirt-release","private":true,"type":"module"}\n');
  await writeFile(join(root, "package-lock.json"), '{"lockfileVersion":3,"name":"@stealtheye/quirt-release","packages":{}}\n');
  await writeFile(join(root, "evidence/sbom.cdx.json"), `{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:${commit}","specVersion":"1.6"}\n`);
  const finalized = await finalizeQuirtReleaseDirectory(root, { commit, tree, epoch });
  const archive = join(base, `stealtheye-quirt-${finalized.manifest.releaseId}.tar.gz`);
  await execute("tar", ["--format=gnu", "--owner=0", "--group=0", "--numeric-owner", "-czf", archive, "-C", root, "."]);
  const descriptor = await createQuirtArtifactDescriptor(archive, join(root, "evidence/manifest.json"));
  return { root, archive, descriptor, manifest: finalized.manifest };
}

function layout(base: string): QuirtReleaseLayout {
  const root = join(base, "install-root");
  const ownerUid = process.getuid?.() ?? 0, groupGid = process.getgid?.() ?? 0;
  return {
    root,
    releasesRoot: join(root, "releases"),
    stagingRoot: join(root, ".staging"),
    currentLink: join(root, "current"),
    previousLink: join(root, "previous"),
    lockPath: join(root, ".release.lock"),
    transitionPath: join(root, ".transition.json"),
    receiptsRoot: join(base, "state/receipts"),
    ownerUid,
    groupGid
  };
}

function manager(value: QuirtReleaseLayout, fault: (phase: string) => void = () => undefined): QuirtReleaseManager {
  return new QuirtReleaseManager(value, RUNTIME, "fixture-principal", () => new Date("2026-07-18T12:00:00.000Z"), randomUUID, fault);
}

async function classification(action: () => Promise<unknown>, expected: string): Promise<void> {
  await assert.rejects(action, error => error instanceof QuirtReleaseError && error.classification === expected);
}

async function makeFileWritable(path: string): Promise<void> {
  await chmod(dirname(path), 0o755);
  await chmod(path, 0o644);
}

test("normalizes safe release paths and rejects traversal forms", () => {
  assert.equal(normalizeReleasePath("dist/quirt/main.js"), "dist/quirt/main.js");
  for (const value of ["", ".", "../escape", "a/../../escape", "/absolute", "a\\b", "a\0b", "a//b"]) {
    assert.throws(() => normalizeReleasePath(value), QuirtReleaseError);
  }
});

test("archive entry policy accepts exact immutable files and directories", () => {
  const seen = new Set<string>();
  assert.equal(assertSafeArchiveEntry({ path: "dist", type: "Directory", mode: 0o555, uid: 0, gid: 0, size: 0 }, seen), "dist");
  assert.equal(assertSafeArchiveEntry({ path: "dist/main.js", type: "File", mode: 0o444, uid: 0, gid: 0, size: 2 }, seen), "dist/main.js");
});

test("archive entry policy rejects links, special files, modes, owners, and collisions", () => {
  const base = { path: "bad", mode: 0o444, uid: 0, gid: 0, size: 1 };
  for (const type of ["SymbolicLink", "Link", "CharacterDevice", "BlockDevice", "FIFO", "Socket"]) {
    assert.throws(() => assertSafeArchiveEntry({ ...base, type }, new Set()), QuirtReleaseError);
  }
  for (const mode of [0o4755, 0o2755, 0o777, 0o644]) assert.throws(() => assertSafeArchiveEntry({ ...base, type: "File", mode }, new Set()), QuirtReleaseError);
  assert.throws(() => assertSafeArchiveEntry({ ...base, type: "File", uid: 1000 }, new Set()), QuirtReleaseError);
  const seen = new Set<string>();
  assertSafeArchiveEntry({ ...base, path: "Same", type: "File" }, seen);
  assert.throws(() => assertSafeArchiveEntry({ ...base, path: "same", type: "File" }, seen), QuirtReleaseError);
});

test("finalization is deterministic and produces a strict canonical identity", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const one = await artifact(base);
  const two = await artifact(base);
  assert.equal(one.manifest.releaseId, two.manifest.releaseId);
  assert.equal(await readFile(join(one.root, "evidence/manifest.json"), "utf8"), await readFile(join(two.root, "evidence/manifest.json"), "utf8"));
  assert.equal(one.manifest.releaseFormatVersion, QUIRT_RELEASE_FORMAT);
  assert.equal(one.manifest.source.commit, COMMIT_ONE);
  assert.equal(one.manifest.source.tree, TREE_ONE);
  assert.ok(one.manifest.files.some(file => file.path === QUIRT_RELEASE_ENTRYPOINT));
});

test("payload inventories use one canonical code-point path order", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const root = join(base, "mixed-order");
  await mkdir(join(root, "dist/quirt"), { recursive: true });
  await mkdir(join(root, "evidence"), { recursive: true });
  await mkdir(join(root, "node_modules/@scope"), { recursive: true });
  await writeFile(join(root, QUIRT_RELEASE_ENTRYPOINT), "ok\n");
  await writeFile(join(root, "package-lock.json"), "{}\n");
  await writeFile(join(root, "evidence/sbom.cdx.json"), "{}\n");
  for (const name of ["-dash", ".dot", "Zed", "_under", "alpha", "node_modules/@scope/value"]) await writeFile(join(root, name), "x\n");
  const { manifest } = await finalizeQuirtReleaseDirectory(root, { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 });
  const paths = manifest.files.map(file => file.path);
  assert.deepEqual(paths, [...paths].sort());
  assert.doesNotThrow(() => parseQuirtReleaseManifest(manifest));
});

test("SBOM normalization executes on the supported runtime and is byte deterministic", async () => {
  const input = `${JSON.stringify({ bomFormat: "CycloneDX", metadata: { component: { name: "fixture", type: "application" } }, specVersion: "1.6", version: 1 })}\n`;
  const one = await normalizeSbom(input), two = await normalizeSbom(input);
  assert.equal(one, two);
  const value = JSON.parse(one) as { metadata: { timestamp: string; component: { version: string } }; serialNumber: string };
  assert.equal(value.metadata.timestamp, "2023-11-14T22:13:21.000Z");
  assert.equal(value.metadata.component.version, COMMIT_ONE);
  assert.match(value.serialNumber, /^urn:uuid:[a-f0-9-]{36}$/u);
  assert.doesNotMatch(one, /\/workspace\/|\/home\//u);
});

test("manifest and descriptor schemas reject unknown or inconsistent identity", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base);
  assert.throws(() => parseQuirtReleaseManifest({ ...value.manifest, unexpected: true }));
  assert.throws(() => parseQuirtReleaseManifest({ ...value.manifest, releaseId: "0".repeat(64) }), QuirtReleaseError);
  assert.throws(() => parseQuirtReleaseManifest({ ...value.manifest, build: { ...value.manifest.build, payloadInventorySha256: "0".repeat(64) } }), QuirtReleaseError);
  assert.throws(() => parseQuirtArtifactDescriptor({ ...value.descriptor, unexpected: true }));
});

test("finalizer rejects missing entrypoints, secrets, host paths, and identity collisions", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const create = async (name: string): Promise<string> => {
    const root = join(base, name); await mkdir(join(root, "evidence"), { recursive: true });
    await writeFile(join(root, "package-lock.json"), "{}\n"); await writeFile(join(root, "evidence/sbom.cdx.json"), "{}\n"); return root;
  };
  await classification(async () => await finalizeQuirtReleaseDirectory(await create("missing"), { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 }), "entrypoint_missing");
  const secret = await create("secret"); await mkdir(join(secret, "dist/quirt"), { recursive: true }); await writeFile(join(secret, QUIRT_RELEASE_ENTRYPOINT), "ok\n"); await writeFile(join(secret, ".env"), "TOKEN=x\n");
  await classification(() => finalizeQuirtReleaseDirectory(secret, { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 }), "secret_detected");
  const host = await create("host"); await mkdir(join(host, "dist/quirt"), { recursive: true }); await writeFile(join(host, QUIRT_RELEASE_ENTRYPOINT), "const p='/workspace/leak';\n");
  await classification(() => finalizeQuirtReleaseDirectory(host, { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 }), "secret_detected");
  const parser = await create("parser"); await mkdir(join(parser, "dist/quirt"), { recursive: true }); await writeFile(join(parser, QUIRT_RELEASE_ENTRYPOINT), "const headers=['-----BEGIN PRIVATE KEY-----','-----END PRIVATE KEY-----'];\n");
  await finalizeQuirtReleaseDirectory(parser, { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 });
  const material = await create("key-material"); await mkdir(join(material, "dist/quirt"), { recursive: true }); await writeFile(join(material, QUIRT_RELEASE_ENTRYPOINT), "ok\n"); await writeFile(join(material, "payload.txt"), "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\n-----END PRIVATE KEY-----\n");
  await classification(() => finalizeQuirtReleaseDirectory(material, { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 }), "secret_detected");
  const complete = await artifact(base); await chmod(complete.root, 0o755);
  await classification(() => finalizeQuirtReleaseDirectory(complete.root, { commit: COMMIT_ONE, tree: TREE_ONE, epoch: 1 }), "identity_collision");
});

test("offline artifact inspection binds archive, manifest, SBOM, source, and runtime", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base);
  const result = await inspectQuirtReleaseArtifact(value.archive, value.descriptor, RUNTIME, base);
  assert.equal(result.verified, true);
  assert.equal(result.manifest.releaseId, value.manifest.releaseId);
  await classification(() => inspectQuirtReleaseArtifact(value.archive, { ...value.descriptor, archiveSha256: "0".repeat(64) }, RUNTIME, base), "artifact_mismatch");
  await classification(() => inspectQuirtReleaseArtifact(value.archive, { ...value.descriptor, manifestSha256: "0".repeat(64) }, RUNTIME, base), "identity_mismatch");
  await classification(() => inspectQuirtReleaseArtifact(value.archive, value.descriptor, { ...RUNTIME, nodeVersion: "22.22.0" }, base), "runtime_incompatible");
  await classification(() => inspectQuirtReleaseArtifact(value.archive, value.descriptor, { ...RUNTIME, architecture: "arm64" }, base), "runtime_incompatible");
});

test("corrupt compression streams fail closed even when their detached digest matches", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base); const corrupt = Buffer.from("not-a-tar-gzip");
  await writeFile(value.archive, corrupt);
  const descriptor = { ...value.descriptor, archiveSize: corrupt.length, archiveSha256: createHash("sha256").update(corrupt).digest("hex") };
  await assert.rejects(() => inspectQuirtReleaseArtifact(value.archive, descriptor, RUNTIME, base));
});

test("tree verification rejects altered, missing, extra, and writable payload files", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  for (const kind of ["altered", "missing", "extra", "mode"] as const) {
    const value = await artifact(base); const entry = join(value.root, QUIRT_RELEASE_ENTRYPOINT);
    await chmod(value.root, 0o755); await chmod(join(value.root, "dist"), 0o755); await chmod(join(value.root, "dist/quirt"), 0o755);
    if (kind === "altered") { await chmod(entry, 0o644); await writeFile(entry, "changed\n"); await chmod(entry, 0o444); }
    if (kind === "missing") await rm(entry);
    if (kind === "extra") { await writeFile(join(value.root, "extra"), "x"); await chmod(join(value.root, "extra"), 0o444); }
    if (kind === "mode") await chmod(entry, 0o644);
    await assert.rejects(() => verifyQuirtReleaseTree(value.root));
  }
});

test("inactive install verifies, promotes immutably, emits receipts, and is idempotent", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base), lane = manager(paths);
  const first = await lane.install(value.archive, value.descriptor);
  assert.equal(first.replayed, false); assert.equal((await lane.status()).current, null);
  const installed = join(paths.releasesRoot, value.manifest.releaseId), details = await lstat(installed);
  assert.equal(details.mode & 0o222, 0); assert.equal((await lane.inspectInstalled(value.manifest.releaseId)).verified, true);
  const replay = await lane.install(value.archive, value.descriptor); assert.equal(replay.replayed, true);
  const receipts = (await lane.listReceipts()).receipts as unknown[]; assert.equal(receipts.length, 2);
});

test("conflicting reuse of an installed release identity is rejected without overwrite", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base), lane = manager(paths); await lane.install(value.archive, value.descriptor);
  const entry = join(paths.releasesRoot, value.manifest.releaseId, QUIRT_RELEASE_ENTRYPOINT);
  await makeFileWritable(entry); await writeFile(entry, "conflict\n");
  await classification(() => lane.install(value.archive, value.descriptor), "release_identity_conflict");
  assert.equal(await readFile(entry, "utf8"), "conflict\n");
});

test("interrupted installs clean staging and never activate partial content", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base), lane = manager(paths, phase => { if (phase === "beforePromotion") throw new Error("fixture interruption"); });
  await assert.rejects(() => lane.install(value.archive, value.descriptor), /fixture interruption/u);
  assert.deepEqual((await lane.status()).staged, []); assert.equal((await lane.status()).current, null);
  assert.equal(await lstat(join(paths.releasesRoot, value.manifest.releaseId)).catch(() => null), null);
});

test("post-promotion interruption leaves a complete inactive release and retries exactly", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base);
  await assert.rejects(() => manager(paths, phase => { if (phase === "afterPromotion") throw new Error("fixture crash"); }).install(value.archive, value.descriptor));
  assert.equal((await manager(paths).inspectInstalled(value.manifest.releaseId)).verified, true);
  assert.equal((await manager(paths).install(value.archive, value.descriptor)).replayed, true);
  assert.equal((await manager(paths).status()).current, null);
});

test("activation preserves previous and explicit rollback restores it atomically", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const one = await artifact(base), two = await artifact(base, COMMIT_TWO, TREE_TWO, 1_700_000_002, "export const quirt = 2;\n");
  const paths = layout(base), lane = manager(paths); await lane.install(one.archive, one.descriptor); await lane.install(two.archive, two.descriptor);
  await lane.activate(one.manifest.releaseId); assert.deepEqual({ current: (await lane.status()).current, previous: (await lane.status()).previous }, { current: one.manifest.releaseId, previous: null });
  await lane.activate(two.manifest.releaseId); assert.deepEqual({ current: (await lane.status()).current, previous: (await lane.status()).previous }, { current: two.manifest.releaseId, previous: one.manifest.releaseId });
  await lane.rollback(); assert.deepEqual({ current: (await lane.status()).current, previous: (await lane.status()).previous }, { current: one.manifest.releaseId, previous: two.manifest.releaseId });
});

test("forward activation rejects downgrade while explicit rollback remains available", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const old = await artifact(base), fresh = await artifact(base, COMMIT_TWO, TREE_TWO, 1_700_000_002);
  const paths = layout(base), lane = manager(paths); await lane.install(old.archive, old.descriptor); await lane.install(fresh.archive, fresh.descriptor);
  await lane.activate(fresh.manifest.releaseId);
  await classification(() => lane.activate(old.manifest.releaseId), "downgrade_rejected");
  assert.equal((await lane.status()).current, fresh.manifest.releaseId);
});

test("rollback fails closed without a previous release or with a corrupt previous release", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const one = await artifact(base), two = await artifact(base, COMMIT_TWO, TREE_TWO, 1_700_000_002);
  const paths = layout(base), lane = manager(paths); await lane.install(one.archive, one.descriptor); await lane.activate(one.manifest.releaseId);
  await classification(() => lane.rollback(), "rollback_unavailable");
  await lane.install(two.archive, two.descriptor); await lane.activate(two.manifest.releaseId);
  const prior = join(paths.releasesRoot, one.manifest.releaseId, QUIRT_RELEASE_ENTRYPOINT); await makeFileWritable(prior); await writeFile(prior, "corrupt\n");
  await assert.rejects(() => lane.rollback()); assert.equal((await lane.status()).current, two.manifest.releaseId);
});

test("lock acquisition is fail-closed and concurrent activations cannot interleave", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const one = await artifact(base), two = await artifact(base, COMMIT_TWO, TREE_TWO, 1_700_000_002), paths = layout(base), lane = manager(paths);
  await lane.install(one.archive, one.descriptor); await lane.install(two.archive, two.descriptor); await lane.activate(one.manifest.releaseId);
  await writeFile(paths.lockPath, "held\n"); await classification(() => lane.activate(two.manifest.releaseId), "release_busy"); await rm(paths.lockPath);
  const results = await Promise.allSettled([lane.activate(two.manifest.releaseId), lane.activate(two.manifest.releaseId)]);
  assert.ok(results.some(result => result.status === "fulfilled")); assert.equal((await lane.status()).current, two.manifest.releaseId);
});

test("crash before current replacement restores the prior pointer through explicit recovery", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const one = await artifact(base), two = await artifact(base, COMMIT_TWO, TREE_TWO, 1_700_000_002), paths = layout(base), lane = manager(paths);
  await lane.install(one.archive, one.descriptor); await lane.install(two.archive, two.descriptor); await lane.activate(one.manifest.releaseId);
  await assert.rejects(() => manager(paths, phase => { if (phase === "afterPreviousPointer") throw new Error("crash"); }).activate(two.manifest.releaseId));
  assert.equal((await lane.status()).transitionPending, true); assert.equal((await lane.status()).current, one.manifest.releaseId);
  await lane.recover(); assert.deepEqual({ current: (await lane.status()).current, previous: (await lane.status()).previous }, { current: one.manifest.releaseId, previous: null });
});

test("crash after current replacement completes one durable transition on recovery", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const one = await artifact(base), two = await artifact(base, COMMIT_TWO, TREE_TWO, 1_700_000_002), paths = layout(base), lane = manager(paths);
  await lane.install(one.archive, one.descriptor); await lane.install(two.archive, two.descriptor); await lane.activate(one.manifest.releaseId);
  await assert.rejects(() => manager(paths, phase => { if (phase === "afterCurrentPointer") throw new Error("crash"); }).activate(two.manifest.releaseId));
  assert.equal((await lane.status()).current, two.manifest.releaseId); assert.equal((await lane.status()).transitionPending, true);
  await lane.recover(); assert.deepEqual({ current: (await lane.status()).current, previous: (await lane.status()).previous }, { current: two.manifest.releaseId, previous: one.manifest.releaseId });
});

test("first-activation crash recovery safely preserves an absent current pointer", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base), lane = manager(paths); await lane.install(value.archive, value.descriptor);
  await assert.rejects(() => manager(paths, phase => { if (phase === "afterPreviousPointer") throw new Error("crash"); }).activate(value.manifest.releaseId));
  await lane.recover(); assert.equal((await lane.status()).current, null); assert.equal((await lane.status()).transitionPending, false);
});

test("escaped and dangling pointers are rejected without repair", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base), lane = manager(paths); await lane.install(value.archive, value.descriptor);
  await symlink(base, paths.currentLink); await classification(() => lane.status(), "pointer_escape"); await rm(paths.currentLink);
  await symlink(join(paths.releasesRoot, "0".repeat(64)), paths.currentLink); await classification(() => lane.status(), "pointer_unsafe");
});

test("status is read-only for an absent fixture and receipts never claim production activation", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const paths = layout(base), lane = manager(paths);
  assert.equal((await lane.status()).current, null); assert.equal(await lstat(paths.root).catch(() => null), null);
  const value = await artifact(base); await lane.install(value.archive, value.descriptor); await lane.activate(value.manifest.releaseId);
  const listed = (await lane.listReceipts()).receipts as Array<{ receipt: { productionActivated: boolean; diagnostic: string } }>;
  assert.ok(listed.length >= 2); assert.ok(listed.every(value => value.receipt.productionActivated === false && value.receipt.diagnostic.length <= 384));
});

test("release marker and pointer targets remain exact release identities", async t => {
  const base = await temporary(); t.after(async () => await cleanup(base));
  const value = await artifact(base), paths = layout(base), lane = manager(paths); await lane.install(value.archive, value.descriptor); await lane.activate(value.manifest.releaseId);
  assert.equal((await readFile(join(paths.releasesRoot, value.manifest.releaseId, ".quirt-release-id"), "utf8")).trim(), value.manifest.releaseId);
  assert.equal(await readlink(paths.currentLink), join(paths.releasesRoot, value.manifest.releaseId));
  for (const name of await readdir(paths.stagingRoot)) assert.ok(!name.startsWith(".artifact-"));
});
