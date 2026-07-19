import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { QuirtError } from "./error.js";
import { QuirtFileService } from "./file-service.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function root(): string { const value = mkdtempSync(join(tmpdir(), "quirt-files-")); roots.push(value); return value; }
function digest(value: Buffer | string): string { return createHash("sha256").update(value).digest("hex"); }

describe("Quirt native file service", () => {
  it("creates, pages, replaces, appends, and positionally writes binary files", async () => {
    const directory = root(); const path = join(directory, "binary.dat"); const service = new QuirtFileService(); const bytes = Buffer.from([0, 1, 2, 255, 4, 5]);
    const created = await service.write({ path, content: bytes, create: true, atomic: true, noClobber: true, mode: 0o640 });
    assert.equal(created.sha256, digest(bytes)); assert.equal((created.metadata as { mode: number }).mode, 0o640);
    const page = await service.read({ path, offset: 2, maximumBytes: 3 }); assert.deepEqual(page.content, Buffer.from([2, 255, 4])); assert.equal(page.eof, false); assert.equal(page.nextOffset, 5);
    await service.write({ path, content: Buffer.from("XY"), offset: 1, replace: true, atomic: false }); assert.deepEqual(readFileSync(path), Buffer.from([0, 88, 89, 255, 4, 5]));
    await service.write({ path, content: Buffer.from("!"), append: true, replace: true, atomic: false }); assert.equal(readFileSync(path).at(-1), 33);
    await service.write({ path, content: Buffer.from("short"), replace: true, atomic: false }); assert.equal(readFileSync(path, "utf8"), "short");
    const before = digest(readFileSync(path)); await service.write({ path, content: Buffer.from("replaced"), replace: true, atomic: true, expectedDigest: before }); assert.equal(readFileSync(path, "utf8"), "replaced");
  });

  it("pages large content and reports regular, FIFO, and character-device metadata precisely", async () => {
    const directory = root(); const service = new QuirtFileService(); const path = join(directory, "large.bin"); const content = Buffer.alloc(2 * 1024 * 1024 + 17, 0x5a); writeFileSync(path, content); const first = await service.read({ path, maximumBytes: 1024 * 1024 }); const second = await service.read({ path, offset: first.nextOffset, maximumBytes: 1024 * 1024 }); const third = await service.read({ path, offset: second.nextOffset, maximumBytes: 1024 * 1024 }); assert.equal(first.eof, false); assert.equal(second.eof, false); assert.equal(third.eof, true); assert.deepEqual(Buffer.concat([first.content, second.content, third.content]), content);
    const fifo = join(directory, "events.fifo"); execFileSync("/usr/bin/mkfifo", [fifo]); assert.equal(((await service.stat({ path: fifo })).metadata as { type: string }).type, "fifo"); assert.equal(((await service.stat({ path: "/dev/null" })).metadata as { type: string }).type, "character-device");
  });

  it("enforces no-clobber, digest, inode, and explicit symlink policies", async () => {
    const directory = root(); const path = join(directory, "target"); const link = join(directory, "link"); const service = new QuirtFileService(); writeFileSync(path, "original"); symlinkSync(path, link);
    await assert.rejects(service.write({ path, content: Buffer.from("bad"), create: true, noClobber: true }), (error: unknown) => error instanceof QuirtError && error.code === "already_exists");
    await assert.rejects(service.write({ path, content: Buffer.from("bad"), replace: true, expectedDigest: "0".repeat(64) }), (error: unknown) => error instanceof QuirtError && error.code === "digest_mismatch");
    await assert.rejects(service.read({ path: link }), (error: unknown) => error instanceof QuirtError && error.code === "symlink_conflict");
    assert.equal((await service.read({ path: link, followSymlinks: true })).content.toString(), "original");
    const linkStat = await service.stat({ path: link }); assert.equal((linkStat.metadata as { type: string }).type, "symlink"); assert.equal((linkStat.metadata as { symlinkTarget: string }).symlinkTarget, path);
  });

  it("detects changed-during-read and symlink replacement races before mutation", async () => {
    const directory = root(); const readPath = join(directory, "changing"); writeFileSync(readPath, "before"); const changing = new QuirtFileService({ afterRead: async path => { writeFileSync(path, "after-change"); } }); await assert.rejects(changing.read({ path: readPath }), (error: unknown) => error instanceof QuirtError && error.code === "changed_during_operation");
    const denied = new QuirtFileService({ afterRead: async () => { throw Object.assign(new Error("denied"), { code: "EACCES" }); } }); await assert.rejects(denied.read({ path: readPath }), (error: unknown) => error instanceof QuirtError && error.code === "authorization_failed");
    const victim = join(directory, "victim"); const target = join(directory, "target"); writeFileSync(victim, "must-survive"); writeFileSync(target, "replace-me"); const guarded = new QuirtFileService({ beforeRemoveIsolation: async path => { unlinkSync(path); symlinkSync(victim, path); } }); await assert.rejects(guarded.remove({ path: target }), (error: unknown) => error instanceof QuirtError && error.code === "changed_during_operation"); assert.equal(readFileSync(victim, "utf8"), "must-survive"); assert.equal((await guarded.stat({ path: target })).metadata && ((await guarded.stat({ path: target })).metadata as { type: string }).type, "symlink");
  });

  it("applies deterministic digest-bound patches atomically and rejects conflicts", async () => {
    const directory = root(); const path = join(directory, "patch.txt"); const service = new QuirtFileService(); writeFileSync(path, "abcdef");
    const result = await service.patch({ path, expectedDigest: digest("abcdef"), edits: [{ start: 1, deleteBytes: 2, contentBase64: Buffer.from("XYZ").toString("base64") }, { start: 5, deleteBytes: 1, contentBase64: Buffer.from("!").toString("base64") }] });
    assert.equal(readFileSync(path, "utf8"), "aXYZde!"); assert.equal(result.sha256, digest("aXYZde!"));
    await assert.rejects(service.patch({ path, expectedDigest: digest("wrong"), edits: [{ start: 0, deleteBytes: 1, contentBase64: "QQ==" }] }), (error: unknown) => error instanceof QuirtError && error.code === "digest_mismatch");
    await assert.rejects(service.patch({ path, expectedDigest: digest("aXYZde!"), edits: [{ start: 0, deleteBytes: 3, contentBase64: "QQ==" }, { start: 2, deleteBytes: 1, contentBase64: "Qg==" }] }), (error: unknown) => error instanceof QuirtError && error.code === "conflict");
  });

  it("searches with explicit bounds and cancellation without loading directory trees eagerly", async () => {
    const directory = root(); const nested = join(directory, "nested"); const service = new QuirtFileService(); await service.write({ path: join(directory, "alpha.txt"), content: Buffer.from("needle one"), create: true }); await service.write({ path: join(nested, "beta.txt"), content: Buffer.from("needle two"), create: true, createParents: true }); writeFileSync(join(directory, "binary.bin"), Buffer.from([0, 1, 2, 3]));
    const result = await service.search({ path: directory, text: "needle", name: "beta", recursive: true, maximumMatches: 10 }); assert.equal(result.matchCount, 3); assert.equal(result.truncated, false); assert.equal(result.binaryFilesSkipped, 1);
    const bounded = await service.search({ path: directory, text: "needle", recursive: true, maximumMatches: 1 }); assert.equal(bounded.matchCount, 1); assert.equal(bounded.truncated, true);
    const controller = new AbortController(); controller.abort(); await assert.rejects(service.search({ path: directory, text: "needle", recursive: true, signal: controller.signal }), (error: unknown) => error instanceof QuirtError && error.code === "request_canceled");
    symlinkSync(directory, join(nested, "cycle")); const followed = await service.search({ path: directory, name: "alpha", recursive: true, followSymlinks: true, maximumMatches: 10 }); assert.equal(followed.matchCount, 1); assert.equal((followed.directoryCyclesSkipped as number) > 0, true); assert.equal(followed.truncated, false);
  });

  it("copies, moves, and removes files, directories, and symlinks without following replacement links", async () => {
    const directory = root(); const service = new QuirtFileService(); const tree = join(directory, "tree"); await service.write({ path: join(tree, "a"), content: Buffer.from("a"), create: true, createParents: true }); symlinkSync("a", join(tree, "link"));
    const copy = join(directory, "copy"); await service.copy({ source: tree, destination: copy, recursive: true, preserveMetadata: true }); assert.equal(readFileSync(join(copy, "a"), "utf8"), "a"); assert.equal((await service.stat({ path: join(copy, "link") })).metadata && (await service.stat({ path: join(copy, "link") })).metadata instanceof Object, true);
    const moved = join(directory, "moved"); await service.move({ source: copy, destination: moved }); assert.equal((await service.stat({ path: moved })).metadata && true, true);
    const identity = (await service.stat({ path: moved })).metadata as { device: number; inode: number }; await service.remove({ path: moved, recursive: true, expectedDevice: identity.device, expectedInode: identity.inode });
    await assert.rejects(service.stat({ path: moved }), (error: unknown) => error instanceof QuirtError && error.code === "not_found");
    const empty = join(directory, "empty"); mkdirSync(empty); await service.remove({ path: empty }); await assert.rejects(service.stat({ path: empty }), /not found/u); const nonempty = join(directory, "nonempty"); mkdirSync(nonempty); writeFileSync(join(nonempty, "child"), "child"); await assert.rejects(service.remove({ path: nonempty }), (error: unknown) => error instanceof QuirtError && error.code === "conflict"); assert.equal(readFileSync(join(nonempty, "child"), "utf8"), "child");
  });

  it("uses a verified copy-and-remove fallback for simulated cross-device moves", async () => {
    const directory = root(); const source = join(directory, "source"); const destination = join(directory, "destination"); writeFileSync(source, "cross-device"); const service = new QuirtFileService({ moveRename: async () => { throw Object.assign(new Error("cross device"), { code: "EXDEV" }); } }); const moved = await service.move({ source, destination, preserveMetadata: true }); assert.equal(moved.crossDevice, true); assert.equal(readFileSync(destination, "utf8"), "cross-device"); await assert.rejects(service.stat({ path: source }), (error: unknown) => error instanceof QuirtError && error.code === "not_found");
  });
});
