import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import type { QuirtConfig } from "./config.js";
import { QuirtError } from "./error.js";
import { quirtPath } from "./file-service.js";
import type { QuirtStateStore } from "./state.js";

const MAX_GIT_OUTPUT = 4 * 1024 * 1024;

export type QuirtGitCredential =
  | { kind: "https"; username: string; password: string }
  | { kind: "ssh"; privateKey: string; knownHostsPath?: string };

export interface QuirtGitCredentialProvider { resolve(reference: string): Promise<QuirtGitCredential | null>; }

interface GitResult { stdout: string; stderr: string; exitCode: number; }
interface CredentialEnvironment { env: NodeJS.ProcessEnv; cleanup(): Promise<void>; secrets: string[]; }

function canonicalRemote(value: string): string {
  if (value.includes("\0") || Buffer.byteLength(value) > 4096) throw new QuirtError("invalid_request", "Quirt Git remote is invalid");
  if (isAbsolute(value)) return value;
  if (/^[^@\s]+@[^:\s]+:.+$/u.test(value)) return value;
  try {
    const url = new URL(value); if (!["https:", "ssh:", "git:", "file:"].includes(url.protocol)) throw new Error("unsupported"); url.username = ""; url.password = ""; url.hash = ""; return url.toString();
  } catch { throw new QuirtError("invalid_request", "Quirt Git remote is invalid"); }
}

function redact(value: string, secrets: readonly string[]): string {
  let output = value.replace(/https?:\/\/[^/@\s]+@/giu, match => `${match.split(":")[0]}://[redacted]@`).replace(/(authorization|password|token|bearer)[=: ]+[^\s]+/giu, "$1=[redacted]");
  for (const secret of secrets) if (secret.length > 0) output = output.split(secret).join("[redacted]");
  return output.slice(0, MAX_GIT_OUTPUT);
}

function oid(value: string, label: string): string {
  if (!/^[a-f0-9]{40,64}$/u.test(value)) throw new QuirtError("invalid_request", `${label} is invalid`); return value;
}

function ref(value: string, label: string): string {
  if (Buffer.byteLength(value) > 1024 || value.length === 0 || value.startsWith("-") || value.endsWith(".") || value.endsWith("/") || value.includes("..") || value.includes("@{") || /[\u0000-\u0020\u007f~^:?*\\[\\]/u.test(value)) throw new QuirtError("invalid_request", `${label} is invalid`);
  return value;
}

async function pathExists(path: string): Promise<boolean> { try { await lstat(path); return true; } catch { return false; } }

export class QuirtGitService {
  readonly #root: string; readonly #mirrors: string; readonly #credentials: string;
  constructor(private readonly config: QuirtConfig, private readonly state: QuirtStateStore, private readonly credentialProvider?: QuirtGitCredentialProvider) {
    this.#root = join(config.stateRoot, "repositories"); this.#mirrors = join(this.#root, "mirrors"); this.#credentials = join(config.stateRoot, "credentials");
  }

  async mirror(input: { remote: string; credentialReference?: string; fetch?: boolean; prune?: boolean; rebuild?: boolean }, owner: string): Promise<Record<string, unknown>> {
    const remote = canonicalRemote(input.remote); const mirrorId = createHash("sha256").update(remote).digest("hex"); const path = join(this.#mirrors, `${mirrorId}.git`);
    await mkdir(this.#mirrors, { recursive: true, mode: 0o700 });
    return await this.#lock(mirrorId, async () => {
      const credentials = await this.#credentialEnvironment(input.credentialReference);
      try {
        const existing = await lstat(path).catch(() => null); const reused = existing !== null && input.rebuild !== true;
        if (!reused) {
          const temporary = `${path}.quirt-${randomUUID()}.tmp`; const clone = await this.#git(["clone", "--mirror", "--", remote, temporary], undefined, credentials);
          if (clone.exitCode !== 0) { await rm(temporary, { recursive: true, force: true }); throw new QuirtError(input.credentialReference === undefined ? "repository_corrupt" : "authentication_unavailable", `Quirt Git mirror creation failed: ${redact(clone.stderr, credentials.secrets)}`); }
          if (existing === null) await rename(temporary, path); else await this.#replacePreparedPath(temporary, path, { device: Number(existing.dev), inode: Number(existing.ino) });
        }
        if (input.fetch !== false || reused) {
          const args = ["remote", "update", ...(input.prune === false ? [] : ["--prune"])]; const fetched = await this.#git(args, path, credentials);
          if (fetched.exitCode !== 0) throw new QuirtError("repository_corrupt", `Quirt Git mirror fetch failed: ${redact(fetched.stderr, credentials.secrets)}`);
        }
        const verified = await this.#git(["fsck", "--no-dangling"], path, credentials); if (verified.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git mirror integrity check failed");
        const data = { mirrorId, path, remote, reused, verified: true, fetchedAt: new Date().toISOString() };
        this.state.native.putObject("quirt_repository_mirrors", { objectId: mirrorId, ownerPrincipalFingerprint: owner, status: "ready", data }); return data;
      } finally { await credentials.cleanup(); }
    });
  }

  async fetch(input: { repository: string; remote?: string; prune?: boolean; tags?: boolean; credentialReference?: string }, owner: string): Promise<Record<string, unknown>> {
    const repository = quirtPath(input.repository); await this.#assertRepository(repository); const remote = ref(input.remote ?? "origin", "Quirt Git remote name"); const credentials = await this.#credentialEnvironment(input.credentialReference);
    try {
      const args = ["fetch", ...(input.prune === false ? [] : ["--prune"]), ...(input.tags === false ? ["--no-tags"] : ["--tags"]), "--", remote];
      const result = await this.#git(args, repository, credentials); if (result.exitCode !== 0) throw new QuirtError(input.credentialReference === undefined ? "repository_corrupt" : "authentication_unavailable", `Quirt Git fetch failed: ${redact(result.stderr, credentials.secrets)}`);
      const operationId = randomUUID(); const data = { operationId, repository, remote, stdout: redact(result.stdout, credentials.secrets), stderr: redact(result.stderr, credentials.secrets), completedAt: new Date().toISOString() };
      this.state.native.putObject("quirt_git_operations", { objectId: operationId, ownerPrincipalFingerprint: owner, status: "completed", data }); return data;
    } finally { await credentials.cleanup(); }
  }

  async materialize(input: { remote: string; destination: string; ref?: string; exactCommit?: string; expectedTree?: string; branch?: string; depth?: number; submodules?: boolean; lfs?: boolean; credentialReference?: string; existing?: "reject" | "reuse" | "replace" }, owner: string): Promise<Record<string, unknown>> {
    const remote = canonicalRemote(input.remote); const destination = quirtPath(input.destination); const existing = input.existing ?? "reject";
    if (input.depth !== undefined && (!Number.isSafeInteger(input.depth) || input.depth < 1 || input.depth > 1_000_000)) throw new QuirtError("invalid_request", "Quirt Git depth is invalid");
    if (input.exactCommit !== undefined) oid(input.exactCommit, "Quirt Git exact commit"); if (input.expectedTree !== undefined) oid(input.expectedTree, "Quirt Git expected tree"); if (input.ref !== undefined) ref(input.ref, "Quirt Git ref"); if (input.branch !== undefined) ref(input.branch, "Quirt Git branch");
    const mirror = await this.mirror({ remote, credentialReference: input.credentialReference, fetch: true }, owner); const mirrorPath = mirror.path as string; const materializationId = randomUUID();
    let replacementIdentity: { device: number; inode: number } | null = null; const existingDestination = await lstat(destination).catch(() => null);
    if (existingDestination !== null) {
      if (existing === "reject") throw new QuirtError("already_exists", "Quirt Git materialization destination already exists");
      if (existing === "replace") replacementIdentity = { device: Number(existingDestination.dev), inode: Number(existingDestination.ino) };
      if (existing === "reuse") {
        await this.#assertRepository(destination); const verified = await this.verify({ repository: destination, commit: input.exactCommit, tree: input.expectedTree }, owner); return { ...verified, materializationId, reused: true };
      }
    }
    await mkdir(dirname(destination), { recursive: true, mode: 0o755 }); const temporary = `${destination}.quirt-${randomUUID()}.tmp`; const credentials = await this.#credentialEnvironment(input.credentialReference);
    try {
      const cloneArgs = ["clone", ...(input.depth === undefined ? [] : ["--depth", String(input.depth)]), ...(input.branch === undefined ? [] : ["--branch", input.branch]), "--no-checkout", "--", mirrorPath, temporary];
      const cloned = await this.#git(cloneArgs, undefined, credentials); if (cloned.exitCode !== 0) throw new QuirtError("repository_corrupt", `Quirt Git materialization failed: ${redact(cloned.stderr, credentials.secrets)}`);
      const origin = await this.#git(["remote", "set-url", "origin", remote], temporary, credentials); if (origin.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git remote configuration failed");
      const requested = input.exactCommit ?? input.ref ?? input.branch ?? "HEAD"; const resolved = await this.#git(["rev-parse", "--verify", `${requested}^{commit}`], temporary, credentials);
      if (resolved.exitCode !== 0) throw new QuirtError("object_missing", "Requested Quirt Git commit does not exist"); const commit = oid(resolved.stdout.trim(), "Resolved Quirt Git commit");
      if (input.exactCommit !== undefined && commit !== input.exactCommit) throw new QuirtError("conflict", "Resolved Quirt Git commit does not match the requested exact commit");
      const checked = await this.#git(["checkout", "--detach", commit], temporary, credentials); if (checked.exitCode !== 0) throw new QuirtError("repository_corrupt", `Quirt Git checkout failed: ${redact(checked.stderr, credentials.secrets)}`);
      if (input.branch !== undefined) { const branch = await this.#git(["switch", "-C", input.branch, commit], temporary, credentials); if (branch.exitCode !== 0) throw new QuirtError("conflict", "Quirt Git branch checkout failed"); }
      if (input.submodules === true) { const submodules = await this.#git(["submodule", "update", "--init", "--recursive"], temporary, credentials); if (submodules.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git submodule materialization failed"); }
      if (input.lfs === true) { const lfs = await this.#git(["lfs", "version"], temporary, credentials); if (lfs.exitCode !== 0) throw new QuirtError("unsupported_host_capability", "Git LFS is unavailable on this host"); const pull = await this.#git(["lfs", "pull"], temporary, credentials); if (pull.exitCode !== 0) throw new QuirtError("object_missing", "Quirt Git LFS objects are unavailable"); }
      const treeResult = await this.#git(["rev-parse", "HEAD^{tree}"], temporary, credentials); const tree = oid(treeResult.stdout.trim(), "Resolved Quirt Git tree"); if (input.expectedTree !== undefined && tree !== input.expectedTree) throw new QuirtError("conflict", "Materialized Quirt Git tree does not match the expected tree");
      if (replacementIdentity === null) await rename(temporary, destination); else await this.#replacePreparedPath(temporary, destination, replacementIdentity);
      const data = { materializationId, destination, remote, mirrorId: mirror.mirrorId, commit, tree, branch: input.branch ?? null, detached: input.branch === undefined, submodules: input.submodules === true, lfs: input.lfs === true, verified: true };
      this.state.native.putObject("quirt_materializations", { objectId: materializationId, ownerPrincipalFingerprint: owner, status: "ready", data }); return data;
    } catch (cause) { await rm(temporary, { recursive: true, force: true }); throw cause; } finally { await credentials.cleanup(); }
  }

  async status(input: { repository: string; includeIgnored?: boolean }, owner: string): Promise<Record<string, unknown>> {
    const repository = quirtPath(input.repository); await this.#assertRepository(repository); const credentials = await this.#credentialEnvironment(undefined);
    try {
      const [head, tree, branch, porcelain, remotes, upstream, submodules, lfs] = await Promise.all([
        this.#git(["rev-parse", "HEAD"], repository, credentials), this.#git(["rev-parse", "HEAD^{tree}"], repository, credentials), this.#git(["symbolic-ref", "--quiet", "--short", "HEAD"], repository, credentials),
        this.#git(["status", "--porcelain=v2", "-z", ...(input.includeIgnored === true ? ["--ignored"] : [])], repository, credentials), this.#git(["remote", "-v"], repository, credentials), this.#git(["rev-list", "--left-right", "--count", "HEAD...@{upstream}"], repository, credentials),
        this.#git(["submodule", "status", "--recursive"], repository, credentials), this.#git(["lfs", "version"], repository, credentials)
      ]);
      if (head.exitCode !== 0 || tree.exitCode !== 0 || porcelain.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git repository status failed");
      const changed = porcelain.stdout.split("\0").filter(Boolean).map(line => ({ record: line.slice(0, 1), value: line.slice(0, 4096) })); const counts = upstream.exitCode === 0 ? upstream.stdout.trim().split(/\s+/u).map(Number) : [null, null];
      return { repository, head: head.stdout.trim(), tree: tree.stdout.trim(), branch: branch.exitCode === 0 ? branch.stdout.trim() : null, detached: branch.exitCode !== 0, remotes: redact(remotes.stdout, []), ahead: counts[0], behind: counts[1], changes: changed, dirty: changed.length > 0, submodules: submodules.stdout.trim().split("\n").filter(Boolean), lfs: { available: lfs.exitCode === 0, version: lfs.exitCode === 0 ? lfs.stdout.trim() : null }, operationState: await this.#operationState(repository) };
    } finally { await credentials.cleanup(); }
  }

  async worktree(input: { repository: string; destination?: string; commit?: string; branch?: string; action?: "create" | "list" | "remove"; force?: boolean }, owner: string): Promise<Record<string, unknown>> {
    const repository = quirtPath(input.repository); await this.#assertRepository(repository); if (input.branch !== undefined) ref(input.branch, "Quirt Git worktree branch"); const action = input.action ?? "create"; const credentials = await this.#credentialEnvironment(undefined);
    try {
      if (action === "list") { const listed = await this.#git(["worktree", "list", "--porcelain"], repository, credentials); if (listed.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git worktree list failed"); return { repository, worktrees: listed.stdout.split("\n\n").filter(Boolean).map(item => Object.fromEntries(item.split("\n").map(line => { const [key, ...rest] = line.split(" "); return [key!, rest.join(" ") || true]; }))) }; }
      if (input.destination === undefined) throw new QuirtError("invalid_request", "Quirt Git worktree destination is required"); const destination = quirtPath(input.destination);
      if (action === "remove") { const removed = await this.#git(["worktree", "remove", ...(input.force === true ? ["--force"] : []), "--", destination], repository, credentials); if (removed.exitCode !== 0) throw new QuirtError("conflict", "Quirt Git worktree removal failed"); return { repository, destination, removed: true }; }
      const target = input.commit ?? "HEAD"; if (input.commit !== undefined) oid(input.commit, "Quirt Git worktree commit"); const args = ["worktree", "add", ...(input.branch === undefined ? ["--detach"] : ["-b", input.branch]), destination, target]; const created = await this.#git(args, repository, credentials); if (created.exitCode !== 0) throw new QuirtError("conflict", `Quirt Git worktree creation failed: ${redact(created.stderr, credentials.secrets)}`);
      const verified = await this.verify({ repository: destination, commit: input.commit }, owner); const worktreeId = randomUUID(); this.state.native.putObject("quirt_worktrees", { objectId: worktreeId, ownerPrincipalFingerprint: owner, status: "ready", data: { worktreeId, repository, destination, ...verified } }); return { worktreeId, repository, destination, ...verified };
    } finally { await credentials.cleanup(); }
  }

  async verify(input: { repository: string; commit?: string; tree?: string; tag?: string; signature?: "none" | "report" | "require"; fsck?: boolean }, _owner: string): Promise<Record<string, unknown>> {
    const repository = quirtPath(input.repository); await this.#assertRepository(repository); const credentials = await this.#credentialEnvironment(undefined);
    try {
      const [headResult, treeResult, porcelain, submodules, lfs] = await Promise.all([this.#git(["rev-parse", "HEAD"], repository, credentials), this.#git(["rev-parse", "HEAD^{tree}"], repository, credentials), this.#git(["status", "--porcelain=v2", "-z"], repository, credentials), this.#git(["submodule", "status", "--recursive"], repository, credentials), this.#git(["lfs", "version"], repository, credentials)]);
      if (headResult.exitCode !== 0 || treeResult.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git identities are unavailable"); const commit = oid(headResult.stdout.trim(), "Quirt Git commit"); const tree = oid(treeResult.stdout.trim(), "Quirt Git tree");
      if (input.commit !== undefined && commit !== input.commit) throw new QuirtError("conflict", "Quirt Git commit verification failed"); if (input.tree !== undefined && tree !== input.tree) throw new QuirtError("conflict", "Quirt Git tree verification failed");
      let tagIdentity: string | null = null; if (input.tag !== undefined) { ref(input.tag, "Quirt Git tag"); const tag = await this.#git(["rev-parse", "--verify", `${input.tag}^{}`], repository, credentials); if (tag.exitCode !== 0) throw new QuirtError("object_missing", "Quirt Git tag was not found"); tagIdentity = tag.stdout.trim(); }
      if (input.fsck !== false) { const fsck = await this.#git(["fsck", "--no-dangling"], repository, credentials); if (fsck.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git integrity verification failed"); }
      let signature: Record<string, unknown> = { requested: input.signature ?? "none", status: "not-requested" };
      if (input.signature === "report" || input.signature === "require") { const verify = await this.#git(input.tag === undefined ? ["verify-commit", commit] : ["verify-tag", input.tag], repository, credentials); signature = { requested: input.signature, target: input.tag === undefined ? commit : input.tag, status: verify.exitCode === 0 ? "verified" : "unverifiable", diagnostic: redact(verify.stderr, []) }; if (input.signature === "require" && verify.exitCode !== 0) throw new QuirtError("signature_unverifiable", "Quirt Git signature could not be verified"); }
      const submoduleLines = submodules.stdout.trim().split("\n").filter(Boolean); const lfsCheck = lfs.exitCode === 0 ? await this.#git(["lfs", "fsck"], repository, credentials) : null;
      return { repository, commit, tree, tagIdentity, signature, integrity: "verified", workingTreeMatchesHead: porcelain.exitCode === 0 && porcelain.stdout.length === 0, changes: porcelain.stdout.split("\0").filter(Boolean).map(value => value.slice(0, 4096)), submodules: { status: submoduleLines, matches: submodules.exitCode === 0 && submoduleLines.every(line => !/^[+\-U]/u.test(line)) }, lfs: { available: lfs.exitCode === 0, objectsVerified: lfsCheck?.exitCode === 0, diagnostic: lfsCheck === null ? null : redact(lfsCheck.stderr, []) } };
    } finally { await credentials.cleanup(); }
  }

  async push(input: { repository: string; remote?: string; source: string; destination: string; force?: boolean; lease?: string; tags?: boolean; signed?: boolean; credentialReference?: string }, owner: string): Promise<Record<string, unknown>> {
    const repository = quirtPath(input.repository); await this.#assertRepository(repository); ref(input.source, "Quirt Git push source"); ref(input.destination, "Quirt Git push destination"); const remote = ref(input.remote ?? "origin", "Quirt Git remote name");
    if (input.force === true && input.lease === undefined) throw new QuirtError("invalid_request", "Quirt Git force push requires an exact lease"); if (input.lease !== undefined) oid(input.lease, "Quirt Git push lease");
    const credentials = await this.#credentialEnvironment(input.credentialReference);
    try {
      const args = ["push", "--porcelain", ...(input.force === true ? [`--force-with-lease=${input.destination}:${input.lease!}`] : []), ...(input.signed === true ? ["--signed"] : []), ...(input.tags === true ? ["--tags"] : []), "--", remote, `${input.source}:${input.destination}`];
      const pushed = await this.#git(args, repository, credentials); if (pushed.exitCode !== 0) throw new QuirtError(input.credentialReference === undefined ? "conflict" : "authentication_unavailable", `Quirt Git push was rejected: ${redact(pushed.stderr, credentials.secrets)}`);
      const operationId = randomUUID(); const data = { operationId, repository, remote, source: input.source, destination: input.destination, force: input.force === true, lease: input.lease ?? null, signed: input.signed === true, result: redact(`${pushed.stdout}\n${pushed.stderr}`, credentials.secrets), completedAt: new Date().toISOString() };
      this.state.native.putObject("quirt_git_operations", { objectId: operationId, ownerPrincipalFingerprint: owner, status: "completed", data }); return data;
    } finally { await credentials.cleanup(); }
  }

  async version(): Promise<{ available: boolean; version: string | null; lfsAvailable: boolean; lfsVersion: string | null }> {
    const credentials = await this.#credentialEnvironment(undefined); try { const git = await this.#git(["--version"], undefined, credentials); const lfs = await this.#git(["lfs", "version"], undefined, credentials); return { available: git.exitCode === 0, version: git.exitCode === 0 ? git.stdout.trim() : null, lfsAvailable: lfs.exitCode === 0, lfsVersion: lfs.exitCode === 0 ? lfs.stdout.trim() : null }; } finally { await credentials.cleanup(); }
  }

  async #assertRepository(path: string): Promise<void> {
    const credentials = await this.#credentialEnvironment(undefined);
    try { const result = await this.#git(["rev-parse", "--git-dir"], path, credentials); if (result.exitCode !== 0) throw new QuirtError("repository_corrupt", "Quirt Git repository is invalid"); }
    finally { await credentials.cleanup(); }
  }

  async #git(args: readonly string[], cwd: string | undefined, credentials: CredentialEnvironment): Promise<GitResult> {
    return await new Promise((resolve, reject) => {
      const child = spawn("/usr/bin/git", [...args], { cwd, env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: "/nonexistent", LANG: "C.UTF-8", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ALLOW_PROTOCOL: "file:https:ssh:git", GIT_TERMINAL_PROMPT: "0", ...credentials.env }, stdio: ["ignore", "pipe", "pipe"] }); const stdout: Buffer[] = []; const stderr: Buffer[] = []; let bytes = 0; let settled = false;
      const timer = setTimeout(() => { if (!settled) child.kill("SIGKILL"); }, 120_000); timer.unref();
      const collect = (target: Buffer[]) => (chunk: Buffer) => { bytes += chunk.length; if (bytes <= MAX_GIT_OUTPUT) target.push(Buffer.from(chunk)); else child.kill("SIGKILL"); };
      child.stdout.on("data", collect(stdout)); child.stderr.on("data", collect(stderr)); child.once("error", cause => { settled = true; clearTimeout(timer); const code = "code" in cause && typeof cause.code === "string" ? cause.code : "unknown"; reject(new QuirtError("provider_unavailable", `Quirt Git executable is unavailable: ${code}`)); }); child.once("close", code => { settled = true; clearTimeout(timer); if (bytes > MAX_GIT_OUTPUT) { reject(new QuirtError("result_truncated", "Quirt Git output exceeded the bounded limit")); return; } resolve({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), exitCode: code ?? 1 }); });
    });
  }

  async #credentialEnvironment(reference?: string): Promise<CredentialEnvironment> {
    if (reference === undefined) return { env: {}, secrets: [], cleanup: async () => undefined };
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$/u.test(reference)) throw new QuirtError("invalid_request", "Quirt credential reference is invalid");
    const credential = await this.credentialProvider?.resolve(reference); if (credential === undefined || credential === null) throw new QuirtError("credentials_unavailable", "Referenced Quirt Git credentials are unavailable");
    await mkdir(this.#credentials, { recursive: true, mode: 0o700 }); const directory = await mkdtemp(join(this.#credentials, "git-")); await chmod(directory, 0o700);
    if (credential.kind === "https") {
      const askpass = join(directory, "askpass.sh"); await writeFile(askpass, "#!/bin/sh\ncase \"$1\" in *sername*) printf '%s\\n' \"$QUIRT_GIT_USERNAME\";; *) printf '%s\\n' \"$QUIRT_GIT_PASSWORD\";; esac\n", { mode: 0o700, flag: "wx" });
      return { env: { GIT_ASKPASS: askpass, QUIRT_GIT_USERNAME: credential.username, QUIRT_GIT_PASSWORD: credential.password }, secrets: [credential.username, credential.password], cleanup: async () => { await rm(directory, { recursive: true, force: true }); } };
    }
    const key = join(directory, "identity"); await writeFile(key, credential.privateKey, { mode: 0o600, flag: "wx" }); const known = credential.knownHostsPath === undefined ? join(directory, "known_hosts") : quirtPath(credential.knownHostsPath); const wrapper = join(directory, "ssh-wrapper.sh");
    await writeFile(wrapper, "#!/bin/sh\nexec /usr/bin/ssh -i \"$QUIRT_GIT_SSH_KEY\" -o IdentitiesOnly=yes -o \"StrictHostKeyChecking=$QUIRT_GIT_SSH_STRICT\" -o \"UserKnownHostsFile=$QUIRT_GIT_KNOWN_HOSTS\" \"$@\"\n", { mode: 0o700, flag: "wx" });
    return { env: { GIT_SSH: wrapper, QUIRT_GIT_SSH_KEY: key, QUIRT_GIT_SSH_STRICT: credential.knownHostsPath === undefined ? "accept-new" : "yes", QUIRT_GIT_KNOWN_HOSTS: known }, secrets: [credential.privateKey], cleanup: async () => { await rm(directory, { recursive: true, force: true }); } };
  }

  async #lock(id: string, action: () => Promise<Record<string, unknown>>): Promise<Record<string, unknown>> {
    const lock = join(this.#root, "locks", id); await mkdir(dirname(lock), { recursive: true, mode: 0o700 }); const deadline = Date.now() + 10_000;
    while (true) { try { await mkdir(lock, { mode: 0o700 }); break; } catch { if (Date.now() >= deadline) throw new QuirtError("timeout", "Quirt Git mirror lock timed out", true); await new Promise(resolve => setTimeout(resolve, 25)); } }
    try { return await action(); } finally { await rm(lock, { recursive: true, force: true }); }
  }

  async #replacePreparedPath(temporary: string, destination: string, expected: { device: number; inode: number }): Promise<void> {
    const current = await lstat(destination).catch(() => null); if (current === null || Number(current.dev) !== expected.device || Number(current.ino) !== expected.inode) throw new QuirtError("conflict", "Quirt Git replacement target changed before placement"); const backup = `${destination}.quirt-${randomUUID()}.backup`; await rename(destination, backup);
    try { await rename(temporary, destination); }
    catch (cause) { await rename(backup, destination).catch(() => undefined); throw cause; }
    await rm(backup, { recursive: true, force: true }).catch(() => undefined);
  }

  async #operationState(repository: string): Promise<Record<string, boolean>> {
    const credentials = await this.#credentialEnvironment(undefined);
    try { const gitDirResult = await this.#git(["rev-parse", "--git-dir"], repository, credentials); const gitDir = gitDirResult.stdout.trim(); const root = isAbsolute(gitDir) ? gitDir : join(repository, gitDir); return { merge: await pathExists(join(root, "MERGE_HEAD")), rebase: await pathExists(join(root, "rebase-merge")) || await pathExists(join(root, "rebase-apply")), cherryPick: await pathExists(join(root, "CHERRY_PICK_HEAD")), bisect: await pathExists(join(root, "BISECT_LOG")) }; }
    finally { await credentials.cleanup(); }
  }
}
