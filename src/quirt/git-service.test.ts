import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtError } from "./error.js";
import { QuirtGitService } from "./git-service.js";
import { QuirtStateStore } from "./state.js";
import { quirtTestConfig } from "./test-support.test.js";

const roots: string[] = []; const stores: QuirtStateStore[] = []; const owner = "a".repeat(64);
afterEach(() => { for (const store of stores.splice(0)) store.close(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function git(cwd: string, ...args: string[]): string { return execFileSync("/usr/bin/git", args, { cwd, encoding: "utf8", env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1" } }).trim(); }
function fixture(): { root: string; seed: string; remote: string; commit: string; tree: string; service: QuirtGitService; state: QuirtStateStore } {
  const root = mkdtempSync(join(tmpdir(), "quirt-git-")); roots.push(root); const seed = join(root, "seed"); const remote = join(root, "remote.git"); execFileSync("/usr/bin/git", ["init", "--initial-branch=main", seed]); git(seed, "config", "user.name", "Quirt Test"); git(seed, "config", "user.email", "quirt@example.invalid"); writeFileSync(join(seed, "README.md"), "first\n"); git(seed, "add", "README.md"); git(seed, "commit", "-m", "first"); git(seed, "tag", "v1"); execFileSync("/usr/bin/git", ["clone", "--bare", seed, remote]); git(seed, "remote", "add", "origin", remote);
  const config = quirtTestConfig(root); const state = new QuirtStateStore(config.databasePath); stores.push(state); return { root, seed, remote, commit: git(seed, "rev-parse", "HEAD"), tree: git(seed, "rev-parse", "HEAD^{tree}"), service: new QuirtGitService(config, state), state };
}

describe("Quirt native Git service", () => {
  it("creates and reuses verified mirrors and materializes exact commits and trees", async () => {
    const f = fixture(); const first = await f.service.mirror({ remote: f.remote }, owner); assert.equal(first.reused, false); assert.equal(first.verified, true); const second = await f.service.mirror({ remote: f.remote }, owner); assert.equal(second.reused, true); assert.equal(second.mirrorId, first.mirrorId);
    const destination = join(f.root, "materialized"); const materialized = await f.service.materialize({ remote: f.remote, destination, exactCommit: f.commit, expectedTree: f.tree }, owner); assert.equal(materialized.commit, f.commit); assert.equal(materialized.tree, f.tree); assert.equal(materialized.detached, true);
    const verified = await f.service.verify({ repository: destination, commit: f.commit, tree: f.tree, signature: "report" }, owner); assert.equal(verified.integrity, "verified"); assert.equal((verified.signature as { status: string }).status, "unverifiable");
    await assert.rejects(f.service.verify({ repository: destination, signature: "require" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "signature_unverifiable");
    const reused = await f.service.materialize({ remote: f.remote, destination, exactCommit: f.commit, expectedTree: f.tree, existing: "reuse" }, owner); assert.equal(reused.reused, true);
    const tagDestination = join(f.root, "tagged"); const tagged = await f.service.materialize({ remote: f.remote, destination: tagDestination, ref: "v1", exactCommit: f.commit, expectedTree: f.tree }, owner); assert.equal(tagged.detached, true); const tagVerified = await f.service.verify({ repository: tagDestination, tag: "v1" }, owner); assert.equal(tagVerified.tagIdentity, f.commit);
    writeFileSync(join(destination, "temporary.txt"), "replace me\n"); await assert.rejects(f.service.materialize({ remote: f.remote, destination, ref: "does-not-exist", existing: "replace" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "object_missing"); assert.equal(readFileSync(join(destination, "temporary.txt"), "utf8"), "replace me\n"); assert.equal(git(destination, "rev-parse", "HEAD"), f.commit); const replaced = await f.service.materialize({ remote: f.remote, destination, exactCommit: f.commit, existing: "replace" }, owner); assert.equal(replaced.commit, f.commit);
    await assert.rejects(f.service.materialize({ remote: f.remote, destination: join(f.root, "missing"), ref: "does-not-exist" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "object_missing");
  });

  it("reports dirty state, ahead/behind, submodules, LFS availability, and operation state", async () => {
    const f = fixture(); const destination = join(f.root, "working"); await f.service.materialize({ remote: f.remote, destination, branch: "main" }, owner); writeFileSync(join(destination, ".gitignore"), "ignored.txt\n"); writeFileSync(join(destination, "dirty.txt"), "dirty\n"); writeFileSync(join(destination, "ignored.txt"), "ignored\n"); const status = await f.service.status({ repository: destination, includeIgnored: true }, owner); assert.equal(status.branch, "main"); assert.equal(status.dirty, true); assert.ok((status.changes as Array<{ record: string }>).some(item => item.record === "?")); assert.ok((status.changes as Array<{ record: string }>).some(item => item.record === "!")); assert.equal(typeof (status.lfs as { available: boolean }).available, "boolean"); assert.deepEqual(status.operationState, { merge: false, rebase: false, cherryPick: false, bisect: false });
    const verified = await f.service.verify({ repository: destination }, owner); assert.equal(verified.workingTreeMatchesHead, false);
  });

  it("fetches new objects, creates worktrees, and verifies missing or mismatched objects precisely", async () => {
    const f = fixture(); const destination = join(f.root, "working"); await f.service.materialize({ remote: f.remote, destination, branch: "main" }, owner); writeFileSync(join(f.seed, "second.txt"), "second\n"); git(f.seed, "add", "second.txt"); git(f.seed, "commit", "-m", "second"); git(f.seed, "push", "origin", "main"); const second = git(f.seed, "rev-parse", "HEAD"); await f.service.fetch({ repository: destination }, owner); const worktree = join(f.root, "worktree"); const created = await f.service.worktree({ repository: destination, destination: worktree, commit: second }, owner); assert.equal(created.commit, second); const listed = await f.service.worktree({ repository: destination, action: "list" }, owner); assert.ok((listed.worktrees as unknown[]).length >= 2); const removed = await f.service.worktree({ repository: destination, destination: worktree, action: "remove" }, owner); assert.equal(removed.removed, true);
    await assert.rejects(f.service.verify({ repository: destination, commit: "0".repeat(40) }, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
    await assert.rejects(f.service.worktree({ repository: destination, destination: join(f.root, "unsafe"), branch: "--upload-pack=bad" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request");
  });

  it("pushes non-force refs, rejects unsafe force, and records exact remote results", async () => {
    const f = fixture(); const destination = join(f.root, "working"); await f.service.materialize({ remote: f.remote, destination, branch: "main" }, owner); writeFileSync(join(destination, "feature.txt"), "feature\n"); git(destination, "config", "user.name", "Quirt Test"); git(destination, "config", "user.email", "quirt@example.invalid"); git(destination, "add", "feature.txt"); git(destination, "commit", "-m", "feature"); const commit = git(destination, "rev-parse", "HEAD"); const pushed = await f.service.push({ repository: destination, source: commit, destination: "refs/heads/feature" }, owner); assert.equal(pushed.force, false); assert.equal(execFileSync("/usr/bin/git", ["--git-dir", f.remote, "rev-parse", "refs/heads/feature"], { encoding: "utf8" }).trim(), commit);
    await assert.rejects(f.service.push({ repository: destination, source: commit, destination: "refs/heads/main", force: true }, owner), (error: unknown) => error instanceof QuirtError && error.code === "invalid_request");
  });

  it("rejects non-fast-forward and stale leases and permits only an exact force-with-lease", async () => {
    const f = fixture(); const destination = join(f.root, "diverged"); await f.service.materialize({ remote: f.remote, destination, branch: "main" }, owner);
    writeFileSync(join(f.seed, "remote.txt"), "remote\n"); git(f.seed, "add", "remote.txt"); git(f.seed, "commit", "-m", "remote"); git(f.seed, "push", "origin", "main"); const remoteHead = git(f.seed, "rev-parse", "HEAD");
    writeFileSync(join(destination, "local.txt"), "local\n"); git(destination, "config", "user.name", "Quirt Test"); git(destination, "config", "user.email", "quirt@example.invalid"); git(destination, "add", "local.txt"); git(destination, "commit", "-m", "local"); const localHead = git(destination, "rev-parse", "HEAD"); await f.service.fetch({ repository: destination }, owner);
    const status = await f.service.status({ repository: destination }, owner); assert.equal(status.ahead, 1); assert.equal(status.behind, 1);
    await assert.rejects(f.service.push({ repository: destination, source: localHead, destination: "refs/heads/main" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
    await assert.rejects(f.service.push({ repository: destination, source: localHead, destination: "refs/heads/main", force: true, lease: f.commit }, owner), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
    const forced = await f.service.push({ repository: destination, source: localHead, destination: "refs/heads/main", force: true, lease: remoteHead }, owner); assert.equal(forced.force, true); assert.equal(execFileSync("/usr/bin/git", ["--git-dir", f.remote, "rev-parse", "refs/heads/main"], { encoding: "utf8" }).trim(), localHead);
  });

  it("serializes concurrent mirror creation and repairs an explicitly rebuilt corrupt mirror", async () => {
    const f = fixture(); const concurrent = await Promise.all([f.service.mirror({ remote: f.remote }, owner), f.service.mirror({ remote: f.remote }, owner), f.service.mirror({ remote: f.remote }, owner)]); assert.equal(concurrent.filter(item => item.reused === false).length, 1); assert.equal(new Set(concurrent.map(item => item.mirrorId)).size, 1);
    const mirrorPath = concurrent[0]!.path as string; writeFileSync(join(mirrorPath, "config"), "[broken\n"); await assert.rejects(f.service.mirror({ remote: f.remote }, owner), (error: unknown) => error instanceof QuirtError && error.code === "repository_corrupt"); const rebuilt = await f.service.mirror({ remote: f.remote, rebuild: true }, owner); assert.equal(rebuilt.reused, false); assert.equal(rebuilt.verified, true);
  });

  it("materializes real submodules and reports Git LFS host availability precisely", async () => {
    const f = fixture(); const sub = join(f.root, "sub"); execFileSync("/usr/bin/git", ["init", "--initial-branch=main", sub]); git(sub, "config", "user.name", "Quirt Test"); git(sub, "config", "user.email", "quirt@example.invalid"); writeFileSync(join(sub, "sub.txt"), "submodule\n"); git(sub, "add", "sub.txt"); git(sub, "commit", "-m", "submodule");
    git(f.seed, "-c", "protocol.file.allow=always", "submodule", "add", sub, "vendor/sub"); git(f.seed, "commit", "-m", "add submodule"); git(f.seed, "push", "origin", "main"); const commit = git(f.seed, "rev-parse", "HEAD"); const destination = join(f.root, "with-submodule"); const materialized = await f.service.materialize({ remote: f.remote, destination, exactCommit: commit, submodules: true }, owner); assert.equal(materialized.submodules, true); assert.equal(git(join(destination, "vendor/sub"), "rev-parse", "HEAD"), git(sub, "rev-parse", "HEAD"));
    const version = await f.service.version(); if (!version.lfsAvailable) await assert.rejects(f.service.materialize({ remote: f.remote, destination: join(f.root, "lfs"), exactCommit: commit, lfs: true }, owner), (error: unknown) => error instanceof QuirtError && error.code === "unsupported_host_capability");
  });

  it("uses credential references without returning or retaining raw credentials", async () => {
    const f = fixture(); const secret = "quirt-secret-password"; const service = new QuirtGitService(quirtTestConfig(f.root), f.state, { resolve: async () => ({ kind: "https", username: "quirt-user", password: secret }) }); const result = await service.mirror({ remote: f.remote, credentialReference: "secret/test" }, owner); assert.equal(JSON.stringify(result).includes(secret), false); const credentialRoot = join(f.root, "credentials"); assert.deepEqual(readdirSync(credentialRoot), []);
    await assert.rejects(f.service.mirror({ remote: f.remote, credentialReference: "secret/missing" }, owner), (error: unknown) => error instanceof QuirtError && error.code === "credentials_unavailable");
  });
});
