import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import {
  chmod,
  chown,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import * as tar from "tar";
import * as z from "zod/v4";
import { canonicalJson, type Json } from "../canonical.js";

export const QUIRT_RELEASE_COMPONENT = "stealtheye-quirt" as const;
export const QUIRT_RELEASE_FORMAT = "stealtheye-quirt-release/v1" as const;
export const QUIRT_RELEASE_MANIFEST_SCHEMA = 1 as const;
export const QUIRT_RELEASE_ENTRYPOINT = "dist/quirt/supervisor-main.js" as const;
export const QUIRT_RELEASE_SOCKET = "/run/horsey/quirt.sock" as const;
export const QUIRT_RELEASE_SERVICE = "stealtheye-quirt.service" as const;
export const QUIRT_RELEASE_NODE_MINIMUM = "24.18.0" as const;

const COMMIT = /^[a-f0-9]{40}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const RELEASE_ID = DIGEST;
const MANIFEST_PATH = "evidence/manifest.json";
const SBOM_PATH = "evidence/sbom.cdx.json";
const RELEASE_MARKER = ".quirt-release-id";
const COMMIT_MARKER = ".quirt-source-commit";
const TREE_MARKER = ".quirt-source-tree";
const MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_FILE_COUNT = 100_000;
const MAX_MANIFEST_BYTES = 32 * 1024 * 1024;

export interface QuirtReleaseLayout {
  root: string;
  releasesRoot: string;
  stagingRoot: string;
  currentLink: string;
  previousLink: string;
  lockPath: string;
  transitionPath: string;
  receiptsRoot: string;
  ownerUid: number;
  groupGid: number;
}

export const QUIRT_RELEASE_LAYOUT: Readonly<QuirtReleaseLayout> = Object.freeze({
  root: "/opt/stealtheye-quirt",
  releasesRoot: "/opt/stealtheye-quirt/releases",
  stagingRoot: "/opt/stealtheye-quirt/.staging",
  currentLink: "/opt/stealtheye-quirt/current",
  previousLink: "/opt/stealtheye-quirt/previous",
  lockPath: "/opt/stealtheye-quirt/.release.lock",
  transitionPath: "/opt/stealtheye-quirt/.transition.json",
  receiptsRoot: "/var/lib/stealtheye-quirt/evidence/releases",
  ownerUid: 0,
  groupGid: 0
});

const fileSchema = z.object({
  path: z.string().min(1).max(1024),
  type: z.literal("file"),
  mode: z.literal(0o444),
  ownerUid: z.literal(0),
  groupGid: z.literal(0),
  size: z.number().int().min(0).max(MAX_EXPANDED_BYTES),
  sha256: z.string().regex(DIGEST)
}).strict();

export type QuirtReleaseFile = z.infer<typeof fileSchema>;

function canonicalPathOrder(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }

const manifestSchema = z.object({
  manifestSchemaVersion: z.literal(QUIRT_RELEASE_MANIFEST_SCHEMA),
  releaseFormatVersion: z.literal(QUIRT_RELEASE_FORMAT),
  component: z.literal(QUIRT_RELEASE_COMPONENT),
  releaseId: z.string().regex(RELEASE_ID),
  source: z.object({
    commit: z.string().regex(COMMIT),
    tree: z.string().regex(COMMIT),
    epoch: z.number().int().positive()
  }).strict(),
  target: z.object({
    operatingSystem: z.literal("linux"),
    architecture: z.literal("x64"),
    nodeMajor: z.literal(24),
    nodeMinimum: z.literal(QUIRT_RELEASE_NODE_MINIMUM)
  }).strict(),
  runtime: z.object({
    entrypoint: z.literal(QUIRT_RELEASE_ENTRYPOINT),
    serviceIdentity: z.literal(QUIRT_RELEASE_SERVICE),
    privateSocketPath: z.literal(QUIRT_RELEASE_SOCKET),
    protocolVersion: z.literal(1)
  }).strict(),
  build: z.object({
    tool: z.literal("scripts/build-quirt-release.sh/v1"),
    packageLockSha256: z.string().regex(DIGEST),
    sbomSha256: z.string().regex(DIGEST),
    payloadInventorySha256: z.string().regex(DIGEST)
  }).strict(),
  ownership: z.object({ ownerUid: z.literal(0), groupGid: z.literal(0), directoryMode: z.literal(0o555), fileMode: z.literal(0o444) }).strict(),
  files: z.array(fileSchema).min(1).max(MAX_FILE_COUNT),
  secretsIncluded: z.literal(false)
}).strict().superRefine((value, context) => {
  const paths = value.files.map(file => file.path);
  if (new Set(paths).size !== paths.length) context.addIssue({ code: "custom", message: "Release file paths must be unique" });
  if ([...paths].sort(canonicalPathOrder).some((path, index) => path !== paths[index])) context.addIssue({ code: "custom", message: "Release file paths must be sorted" });
});

export type QuirtReleaseManifest = z.infer<typeof manifestSchema>;

const descriptorSchema = z.object({
  descriptorSchemaVersion: z.literal(1),
  component: z.literal(QUIRT_RELEASE_COMPONENT),
  releaseId: z.string().regex(RELEASE_ID),
  sourceCommit: z.string().regex(COMMIT),
  sourceTree: z.string().regex(COMMIT),
  sourceEpoch: z.number().int().positive(),
  archiveFile: z.string().regex(/^stealtheye-quirt-[a-f0-9]{64}\.tar\.gz$/u),
  archiveSize: z.number().int().positive().max(MAX_ARCHIVE_BYTES),
  archiveSha256: z.string().regex(DIGEST),
  manifestSha256: z.string().regex(DIGEST),
  sbomSha256: z.string().regex(DIGEST),
  payloadInventorySha256: z.string().regex(DIGEST)
}).strict();

export type QuirtReleaseArtifactDescriptor = z.infer<typeof descriptorSchema>;

export interface QuirtReleaseRuntimeIdentity {
  operatingSystem: string;
  architecture: string;
  nodeVersion: string;
}

export interface QuirtReleaseInspection {
  descriptor: QuirtReleaseArtifactDescriptor;
  manifest: QuirtReleaseManifest;
  archivePath: string;
  verified: true;
}

export interface QuirtReleaseReceipt {
  receiptSchemaVersion: 1;
  operation: "install" | "activate" | "rollback" | "recover";
  operationId: string;
  actorRef: string;
  component: typeof QUIRT_RELEASE_COMPONENT;
  releaseId: string;
  sourceCommit: string;
  sourceTree: string;
  artifactSha256: string | null;
  manifestSha256: string;
  sbomSha256: string;
  previousReleaseId: string | null;
  newReleaseId: string | null;
  targetRef: string;
  startedAt: string;
  completedAt: string;
  result: "succeeded" | "failed";
  classification: string;
  verification: "passed" | "failed";
  pointerTransition: { current: string | null; previous: string | null } | null;
  diagnostic: string;
  productionActivated: false;
}

interface TransitionRecord {
  version: 1;
  action: "activate" | "rollback";
  oldCurrent: string | null;
  oldPrevious: string | null;
  newCurrent: string;
  newPrevious: string | null;
}

export class QuirtReleaseError extends Error {
  constructor(readonly classification: string, message: string) { super(message); this.name = "QuirtReleaseError"; }
}

function fail(classification: string, message: string): never { throw new QuirtReleaseError(classification, message); }
function safeDiagnostic(value: unknown): string { return (value instanceof Error ? value.message : "Quirt release operation failed").replace(/[\r\n\0]+/gu, " ").slice(0, 384); }
function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const stream = createReadStream(path);
    stream.on("data", chunk => hash.update(chunk));
    stream.once("error", rejectPromise);
    stream.once("end", resolvePromise);
  });
  return hash.digest("hex");
}

function inside(root: string, target: string): boolean {
  const value = relative(root, target);
  return value === "" || (!isAbsolute(value) && value !== ".." && !value.startsWith(`..${sep}`));
}

export function normalizeReleasePath(value: string): string {
  if (value.includes("\0") || value.includes("\\") || value.startsWith("/") || isAbsolute(value)) fail("unsafe_path", "Release path is unsafe");
  const normalized = normalize(value).split(sep).join("/").replace(/^\.\//u, "");
  const segments = normalized.split("/");
  if (normalized !== value || normalized === "" || normalized === "." || normalized.length > 1024 || segments.some(segment => segment === "" || segment === "." || segment === ".." || /[\u0000-\u001f\u007f]/u.test(segment))) fail("unsafe_path", "Release path is unsafe");
  return normalized;
}

function releasePath(layout: QuirtReleaseLayout, releaseId: string): string {
  if (!RELEASE_ID.test(releaseId)) fail("invalid_identity", "Quirt release ID is invalid");
  const path = resolve(layout.releasesRoot, releaseId);
  if (!inside(layout.releasesRoot, path)) fail("unsafe_path", "Quirt release path escaped its root");
  return path;
}

async function safeDirectory(path: string, ownerUid: number, groupGid: number, create = false, mode = 0o750): Promise<void> {
  if (create) await mkdir(path, { recursive: true, mode });
  const value = await lstat(path).catch(() => null);
  if (value === null || value.isSymbolicLink() || !value.isDirectory() || value.uid !== ownerUid || value.gid !== groupGid || (value.mode & 0o022) !== 0) fail("unsafe_root", "Quirt release directory is unsafe");
  if (await realpath(path) !== resolve(path)) fail("unsafe_root", "Quirt release directory has an indirect path");
}

async function fsyncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try { await handle.sync(); } finally { await handle.close(); }
}

async function removeControlledTree(path: string, trustedParent: string): Promise<void> {
  const target = resolve(path);
  if (!inside(resolve(trustedParent), target) || target === resolve(trustedParent)) fail("unsafe_cleanup", "Quirt staging cleanup target is unsafe");
  const root = await lstat(target).catch(() => null);
  if (root === null) return;
  if (root.isSymbolicLink() || !root.isDirectory()) fail("unsafe_cleanup", "Quirt staging cleanup root is unsafe");
  const stack = [target];
  while (stack.length > 0) {
    const directory = stack.pop()!;
    await chmod(directory, 0o700);
    for (const name of await readdir(directory)) {
      const child = join(directory, name), details = await lstat(child);
      if (details.isDirectory() && !details.isSymbolicLink()) stack.push(child);
    }
  }
  await rm(target, { recursive: true, force: true });
}

async function treeFiles(root: string, directory = root): Promise<QuirtReleaseFile[]> {
  const output: QuirtReleaseFile[] = [];
  const casePaths = new Set<string>();
  let totalSize = 0;
  const visit = async (path: string): Promise<void> => {
    for (const entry of (await readdir(path, { withFileTypes: true })).sort((left, right) => canonicalPathOrder(left.name, right.name))) {
      const child = join(path, entry.name);
      const name = normalizeReleasePath(relative(root, child).split(sep).join("/"));
      const folded = name.toLocaleLowerCase("en-US").normalize("NFC");
      if (casePaths.has(folded)) fail("path_collision", "Release tree has a case or normalization collision");
      casePaths.add(folded);
      if (entry.isSymbolicLink()) fail("symlink_rejected", "Release tree contains a symbolic link");
      if (entry.isDirectory()) { await visit(child); continue; }
      if (!entry.isFile()) fail("special_file_rejected", "Release tree contains an unsupported file type");
      const details = await lstat(child);
      if ((details.mode & 0o6000) !== 0 || ((details.mode & 0o002) !== 0 && (details.mode & 0o111) !== 0)) fail("unsafe_mode", "Release file mode is unsafe");
      if ((details.mode & 0o777) !== 0o444) fail("immutability_mismatch", "Quirt release file mode differs from its contract");
      output.push({ path: name, type: "file", mode: 0o444, ownerUid: 0, groupGid: 0, size: details.size, sha256: await sha256File(child) });
      totalSize += details.size;
      if (output.length > MAX_FILE_COUNT || totalSize > MAX_EXPANDED_BYTES) fail("artifact_too_large", "Release tree exceeds its bounds");
    }
  };
  await visit(directory);
  return output.sort((left, right) => canonicalPathOrder(left.path, right.path));
}

async function normalizePayload(root: string, ownerUid: number, groupGid: number): Promise<void> {
  const directories: string[] = [];
  const visit = async (path: string): Promise<void> => {
    directories.push(path);
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isSymbolicLink()) fail("symlink_rejected", "Release tree contains a symbolic link");
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile()) {
        const details = await lstat(child);
        if (details.uid !== ownerUid || details.gid !== groupGid) await chown(child, ownerUid, groupGid);
        await chmod(child, 0o444);
      }
      else fail("special_file_rejected", "Release tree contains an unsupported file type");
    }
  };
  await visit(root);
  for (const directory of directories.reverse()) {
    const details = await lstat(directory);
    if (details.uid !== ownerUid || details.gid !== groupGid) await chown(directory, ownerUid, groupGid);
    await chmod(directory, 0o555);
  }
}

function identityBasis(manifest: Omit<QuirtReleaseManifest, "releaseId">): Json {
  return {
    manifestSchemaVersion: manifest.manifestSchemaVersion,
    releaseFormatVersion: manifest.releaseFormatVersion,
    component: manifest.component,
    source: manifest.source,
    target: manifest.target,
    runtime: manifest.runtime,
    build: manifest.build,
    ownership: manifest.ownership,
    secretsIncluded: manifest.secretsIncluded
  } as unknown as Json;
}

function expectedReleaseId(manifest: Omit<QuirtReleaseManifest, "releaseId">): string { return sha256(canonicalJson(identityBasis(manifest))); }
function inventoryDigest(files: readonly QuirtReleaseFile[]): string { return sha256(canonicalJson(files as unknown as Json)); }

async function assertNoSecrets(root: string, files: readonly QuirtReleaseFile[]): Promise<void> {
  for (const file of files) {
    if (/(^|\/)(\.git|\.npmrc|\.env(?:\.|$)|authority\.key|id_(?:rsa|ed25519)|[^/]+\.(?:pem|key))$/iu.test(file.path)) fail("secret_detected", "Release contains a prohibited secret-bearing path");
    if (file.size > 1_048_576) continue;
    const contents = await readFile(join(root, file.path));
    if (contents.includes(0)) continue;
    const text = contents.toString("utf8");
    if (/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----\r?\n(?:[A-Za-z0-9+/]{16,128}={0,2}\r?\n){1,4096}-----END \1-----|QUIRT_AUTHORITY_SECRET\s*=|\/workspace\/|\/home\/[A-Za-z0-9._-]+\//u.test(text)) fail("secret_detected", "Release contains secret or build-host material");
  }
}

export async function finalizeQuirtReleaseDirectory(root: string, input: { commit: string; tree: string; epoch: number }): Promise<{ manifest: QuirtReleaseManifest; manifestSha256: string }> {
  if (!COMMIT.test(input.commit) || !COMMIT.test(input.tree) || !Number.isSafeInteger(input.epoch) || input.epoch < 1) fail("invalid_identity", "Quirt source identity is invalid");
  const canonicalRoot = await realpath(root);
  if (canonicalRoot !== resolve(root)) fail("unsafe_root", "Quirt payload root is indirect");
  for (const reserved of [MANIFEST_PATH, RELEASE_MARKER, COMMIT_MARKER, TREE_MARKER]) if (await lstat(join(root, reserved)).catch(() => null) !== null) fail("identity_collision", "Release metadata already exists");
  const sbomPath = join(root, SBOM_PATH), sbomDetails = await lstat(sbomPath).catch(() => null);
  if (sbomDetails === null || sbomDetails.isSymbolicLink() || !sbomDetails.isFile() || sbomDetails.size < 2 || sbomDetails.size > MAX_MANIFEST_BYTES) fail("sbom_invalid", "Quirt SBOM is missing or unsafe");
  await normalizePayload(root, process.getuid?.() ?? 0, process.getgid?.() ?? 0);
  await chmod(root, 0o755);
  await chmod(join(root, "evidence"), 0o755);
  const files = await treeFiles(root);
  if (!files.some(file => file.path === QUIRT_RELEASE_ENTRYPOINT)) fail("entrypoint_missing", "Quirt release entrypoint is missing");
  const packageLock = files.find(file => file.path === "package-lock.json");
  const sbom = files.find(file => file.path === SBOM_PATH);
  if (packageLock === undefined || sbom === undefined) fail("payload_incomplete", "Quirt release package identity is incomplete");
  await assertNoSecrets(root, files);
  const build = { tool: "scripts/build-quirt-release.sh/v1" as const, packageLockSha256: packageLock.sha256, sbomSha256: sbom.sha256, payloadInventorySha256: inventoryDigest(files) };
  const withoutId: Omit<QuirtReleaseManifest, "releaseId"> = {
    manifestSchemaVersion: 1,
    releaseFormatVersion: QUIRT_RELEASE_FORMAT,
    component: QUIRT_RELEASE_COMPONENT,
    source: { commit: input.commit, tree: input.tree, epoch: input.epoch },
    target: { operatingSystem: "linux", architecture: "x64", nodeMajor: 24, nodeMinimum: QUIRT_RELEASE_NODE_MINIMUM },
    runtime: { entrypoint: QUIRT_RELEASE_ENTRYPOINT, serviceIdentity: QUIRT_RELEASE_SERVICE, privateSocketPath: QUIRT_RELEASE_SOCKET, protocolVersion: 1 },
    build,
    ownership: { ownerUid: 0, groupGid: 0, directoryMode: 0o555, fileMode: 0o444 },
    files,
    secretsIncluded: false
  };
  const manifest = manifestSchema.parse({ ...withoutId, releaseId: expectedReleaseId(withoutId) });
  const serialized = `${canonicalJson(manifest as unknown as Json)}\n`;
  await writeFile(join(root, MANIFEST_PATH), serialized, { flag: "wx", mode: 0o444 });
  await writeFile(join(root, RELEASE_MARKER), `${manifest.releaseId}\n`, { flag: "wx", mode: 0o444 });
  await writeFile(join(root, COMMIT_MARKER), `${input.commit}\n`, { flag: "wx", mode: 0o444 });
  await writeFile(join(root, TREE_MARKER), `${input.tree}\n`, { flag: "wx", mode: 0o444 });
  await normalizePayload(root, process.getuid?.() ?? 0, process.getgid?.() ?? 0);
  return { manifest, manifestSha256: sha256(serialized) };
}

export function parseQuirtReleaseManifest(value: unknown): QuirtReleaseManifest {
  const manifest = manifestSchema.parse(value);
  const { releaseId: _releaseId, ...withoutId } = manifest;
  if (manifest.releaseId !== expectedReleaseId(withoutId)) fail("release_id_mismatch", "Quirt release ID does not match its manifest");
  if (manifest.build.payloadInventorySha256 !== inventoryDigest(manifest.files)) fail("inventory_mismatch", "Quirt payload inventory identity is inconsistent");
  return manifest;
}

export function parseQuirtArtifactDescriptor(value: unknown): QuirtReleaseArtifactDescriptor { return descriptorSchema.parse(value); }

export async function createQuirtArtifactDescriptor(archivePath: string, manifestPath: string): Promise<QuirtReleaseArtifactDescriptor> {
  const manifestBytes = await readFile(manifestPath);
  const manifest = parseQuirtReleaseManifest(JSON.parse(manifestBytes.toString("utf8")));
  const details = await lstat(archivePath);
  if (!details.isFile() || details.isSymbolicLink() || details.size < 1 || details.size > MAX_ARCHIVE_BYTES) fail("artifact_invalid", "Quirt archive is unsafe");
  return descriptorSchema.parse({
    descriptorSchemaVersion: 1,
    component: QUIRT_RELEASE_COMPONENT,
    releaseId: manifest.releaseId,
    sourceCommit: manifest.source.commit,
    sourceTree: manifest.source.tree,
    sourceEpoch: manifest.source.epoch,
    archiveFile: basename(archivePath),
    archiveSize: details.size,
    archiveSha256: await sha256File(archivePath),
    manifestSha256: sha256(manifestBytes),
    sbomSha256: manifest.build.sbomSha256,
    payloadInventorySha256: manifest.build.payloadInventorySha256
  });
}

interface ArchiveEntryLike { path: string; type?: string; mode?: number; size?: number; uid?: number; gid?: number }

export function assertSafeArchiveEntry(entry: ArchiveEntryLike, seen: Set<string>): string | null {
  let raw = entry.path.replace(/^\.\//u, "");
  if ((raw === "" || raw === ".") && entry.type === "Directory") return null;
  if (entry.type === "Directory" && raw.endsWith("/")) raw = raw.slice(0, -1);
  const path = normalizeReleasePath(raw);
  const folded = path.toLocaleLowerCase("en-US").normalize("NFC");
  if (seen.has(folded)) fail("duplicate_path", "Quirt archive contains a duplicate or colliding path");
  seen.add(folded);
  if (entry.type !== "File" && entry.type !== "Directory") fail("special_file_rejected", "Quirt archive contains a link or special file");
  const mode = (entry.mode ?? 0) & 0o7777;
  if ((mode & 0o6000) !== 0 || (entry.type === "File" && (mode & 0o002) !== 0 && (mode & 0o111) !== 0)) fail("unsafe_mode", "Quirt archive contains an unsafe mode");
  if ((entry.type === "File" && mode !== 0o444) || (entry.type === "Directory" && mode !== 0o555)) fail("unsafe_mode", "Quirt archive mode differs from its immutable contract");
  if (entry.uid !== 0 || entry.gid !== 0) fail("unsafe_owner", "Quirt archive ownership is not explicitly root");
  if (!Number.isSafeInteger(entry.size ?? 0) || (entry.size ?? 0) < 0 || (entry.size ?? 0) > MAX_EXPANDED_BYTES) fail("artifact_too_large", "Quirt archive entry exceeds its bounds");
  return path;
}

async function inspectArchiveEntries(archivePath: string): Promise<void> {
  const seen = new Set<string>();
  let size = 0, count = 0;
  let failure: unknown = null;
  await tar.list({ file: archivePath, strict: true, onReadEntry: (entry: ArchiveEntryLike) => {
    if (failure !== null) return;
    try {
      const path = assertSafeArchiveEntry(entry, seen);
      if (path !== null) { count += 1; size += entry.size ?? 0; }
      if (count > MAX_FILE_COUNT || size > MAX_EXPANDED_BYTES) fail("artifact_too_large", "Quirt archive exceeds its bounds");
    } catch (cause) { failure = cause; }
  } });
  if (failure !== null) throw failure;
}

async function readMarker(root: string, name: string, pattern: RegExp): Promise<string> {
  const path = join(root, name), details = await lstat(path).catch(() => null);
  if (details === null || details.isSymbolicLink() || !details.isFile() || details.size < 2 || details.size > 256) fail("identity_mismatch", "Quirt release marker is missing or unsafe");
  const value = (await readFile(path, "utf8")).trim();
  if (!pattern.test(value)) fail("identity_mismatch", "Quirt release marker is invalid");
  return value;
}

async function verifyImmutableTree(root: string, ownerUid: number, groupGid: number, immutableDirectories: boolean): Promise<void> {
  const stack = [root];
  while (stack.length > 0) {
    const path = stack.pop()!;
    const details = await lstat(path);
    if (details.isSymbolicLink() || (path !== root && (details.uid !== ownerUid || details.gid !== groupGid))) fail("immutability_mismatch", "Quirt release ownership differs from its contract");
    if (details.isDirectory()) {
      if (path !== root && ((details.mode & (immutableDirectories ? 0o222 : 0o022)) !== 0)) fail("immutability_mismatch", "Quirt release directory mode differs from its contract");
      for (const name of await readdir(path)) stack.push(join(path, name));
    } else if (details.isFile()) {
      if ((details.mode & 0o222) !== 0) fail("immutability_mismatch", "Quirt release file is writable");
    } else fail("special_file_rejected", "Quirt release tree contains an unsupported file type");
  }
}

function assertRuntime(manifest: QuirtReleaseManifest, runtime: QuirtReleaseRuntimeIdentity): void {
  if (runtime.operatingSystem !== manifest.target.operatingSystem || runtime.architecture !== manifest.target.architecture) fail("runtime_incompatible", "Quirt target platform is incompatible");
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/u.exec(runtime.nodeVersion.replace(/^v/u, ""));
  if (match === null) fail("runtime_incompatible", "Quirt Node runtime version is invalid");
  const version = match.slice(1, 4).map(Number), minimum = QUIRT_RELEASE_NODE_MINIMUM.split(".").map(Number);
  const below = (version[0] ?? 0) < (minimum[0] ?? 0) || ((version[0] ?? 0) === (minimum[0] ?? 0) && ((version[1] ?? 0) < (minimum[1] ?? 0) || ((version[1] ?? 0) === (minimum[1] ?? 0) && (version[2] ?? 0) < (minimum[2] ?? 0))));
  if ((version[0] ?? 0) !== 24 || below) fail("runtime_incompatible", "Quirt requires its pinned Node 24 runtime envelope");
}

export async function verifyQuirtReleaseTree(root: string, expected?: QuirtReleaseArtifactDescriptor, runtime?: QuirtReleaseRuntimeIdentity, filesystemOwner: { ownerUid: number; groupGid: number; immutableDirectories?: boolean } = { ownerUid: process.getuid?.() ?? 0, groupGid: process.getgid?.() ?? 0 }): Promise<QuirtReleaseManifest> {
  const manifestPath = join(root, MANIFEST_PATH), details = await lstat(manifestPath).catch(() => null);
  if (details === null || details.isSymbolicLink() || !details.isFile() || details.size < 2 || details.size > MAX_MANIFEST_BYTES) fail("manifest_invalid", "Quirt manifest is missing or unsafe");
  const bytes = await readFile(manifestPath), manifest = parseQuirtReleaseManifest(JSON.parse(bytes.toString("utf8")));
  if (expected !== undefined) {
    if (sha256(bytes) !== expected.manifestSha256 || manifest.releaseId !== expected.releaseId || manifest.source.commit !== expected.sourceCommit || manifest.source.tree !== expected.sourceTree || manifest.source.epoch !== expected.sourceEpoch || manifest.build.sbomSha256 !== expected.sbomSha256 || manifest.build.payloadInventorySha256 !== expected.payloadInventorySha256) fail("identity_mismatch", "Quirt artifact descriptor disagrees with its manifest");
  }
  if (runtime !== undefined) assertRuntime(manifest, runtime);
  if (await readMarker(root, RELEASE_MARKER, RELEASE_ID) !== manifest.releaseId || await readMarker(root, COMMIT_MARKER, COMMIT) !== manifest.source.commit || await readMarker(root, TREE_MARKER, COMMIT) !== manifest.source.tree) fail("identity_mismatch", "Quirt release marker identity mismatch");
  const all = await treeFiles(root);
  const metadata = new Set([MANIFEST_PATH, RELEASE_MARKER, COMMIT_MARKER, TREE_MARKER]);
  const payload = all.filter(file => !metadata.has(file.path));
  if (canonicalJson(payload as unknown as Json) !== canonicalJson(manifest.files as unknown as Json)) fail("inventory_mismatch", "Quirt installed payload differs from its manifest");
  const sbom = payload.find(file => file.path === SBOM_PATH), lock = payload.find(file => file.path === "package-lock.json");
  if (sbom?.sha256 !== manifest.build.sbomSha256 || lock?.sha256 !== manifest.build.packageLockSha256) fail("digest_mismatch", "Quirt SBOM or lockfile digest mismatch");
  await assertNoSecrets(root, payload);
  await verifyImmutableTree(root, filesystemOwner.ownerUid, filesystemOwner.groupGid, filesystemOwner.immutableDirectories ?? false);
  return manifest;
}

async function extractArchive(archivePath: string, destination: string): Promise<void> {
  const seen = new Set<string>();
  let failure: unknown = null;
  await tar.extract({ file: archivePath, cwd: destination, strict: true, preservePaths: false, filter: (_path, entry) => {
    if (failure !== null) return false;
    try { assertSafeArchiveEntry(entry as unknown as ArchiveEntryLike, seen); return true; }
    catch (cause) { failure = cause; return false; }
  } });
  if (failure !== null) throw failure;
}

export async function inspectQuirtReleaseArtifact(archivePath: string, descriptorValue: unknown, runtime?: QuirtReleaseRuntimeIdentity, extractionRoot?: string): Promise<QuirtReleaseInspection> {
  const descriptor = parseQuirtArtifactDescriptor(descriptorValue), details = await lstat(archivePath).catch(() => null);
  if (details === null || details.isSymbolicLink() || !details.isFile() || details.size !== descriptor.archiveSize || details.size > MAX_ARCHIVE_BYTES || basename(archivePath) !== descriptor.archiveFile) fail("artifact_mismatch", "Quirt archive path or size does not match its descriptor");
  if (await sha256File(archivePath) !== descriptor.archiveSha256) fail("artifact_mismatch", "Quirt archive digest mismatch");
  await inspectArchiveEntries(archivePath);
  const temporaryParent = extractionRoot ?? tmpdir();
  const parentDetails = await lstat(temporaryParent).catch(() => null);
  if (parentDetails === null || parentDetails.isSymbolicLink() || !parentDetails.isDirectory() || await realpath(temporaryParent) !== resolve(temporaryParent)) fail("unsafe_root", "Quirt verification temporary root is unsafe");
  const temporary = await mkdtemp(join(temporaryParent, "quirt-release-verify-"));
  try {
    await extractArchive(archivePath, temporary);
    const manifest = await verifyQuirtReleaseTree(temporary, descriptor, runtime);
    return { descriptor, manifest, archivePath, verified: true };
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

async function snapshotFile(sourcePath: string, destinationPath: string): Promise<void> {
  const source = await open(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const destination = await open(destinationPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o400);
  try {
    const details = await source.stat();
    if (!details.isFile() || details.size < 1 || details.size > MAX_ARCHIVE_BYTES) fail("artifact_invalid", "Quirt archive source is unsafe");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (offset < details.size) {
      const { bytesRead } = await source.read(buffer, 0, Math.min(buffer.length, details.size - offset), offset);
      if (bytesRead < 1) fail("artifact_invalid", "Quirt archive changed while being copied");
      await destination.write(buffer, 0, bytesRead, offset);
      offset += bytesRead;
    }
    if ((await source.stat()).size !== details.size) fail("artifact_invalid", "Quirt archive changed while being copied");
    await destination.sync();
  } finally { await source.close(); await destination.close(); }
}

async function directPointer(layout: QuirtReleaseLayout, path: string): Promise<string | null> {
  const details = await lstat(path).catch(() => null);
  if (details === null) return null;
  if (!details.isSymbolicLink()) fail("pointer_unsafe", "Quirt release pointer is not a symbolic link");
  const target = resolve(dirname(path), await readlink(path));
  if (!inside(layout.releasesRoot, target)) fail("pointer_escape", "Quirt release pointer escaped its root");
  const canonical = await realpath(target).catch(() => null);
  if (canonical === null || canonical !== target) fail("pointer_unsafe", "Quirt release pointer target is missing or indirect");
  return target;
}

async function atomicPointer(path: string, target: string, id: string): Promise<void> {
  const temporary = `${path}.tmp-${id}`;
  await symlink(target, temporary);
  try { await rename(temporary, path); await fsyncDirectory(dirname(path)); } finally { await rm(temporary, { force: true }); }
}

export class QuirtReleaseManager {
  constructor(
    private readonly layout: QuirtReleaseLayout = QUIRT_RELEASE_LAYOUT,
    private readonly runtime: QuirtReleaseRuntimeIdentity = { operatingSystem: process.platform, architecture: process.arch, nodeVersion: process.version },
    private readonly actorRef = "jamie-currier",
    private readonly now: () => Date = () => new Date(),
    private readonly id: () => string = () => randomUUID(),
    private readonly fault: (phase: string) => void = () => undefined
  ) {}

  private async roots(): Promise<void> {
    await safeDirectory(this.layout.root, this.layout.ownerUid, this.layout.groupGid, true, 0o750);
    for (const path of [this.layout.releasesRoot, this.layout.stagingRoot]) await safeDirectory(path, this.layout.ownerUid, this.layout.groupGid, true, 0o750);
    await safeDirectory(this.layout.receiptsRoot, this.layout.ownerUid, this.layout.groupGid, true, 0o750);
  }

  private async locked<T>(operation: () => Promise<T>): Promise<T> {
    await this.roots();
    const handle = await open(this.layout.lockPath, "wx", 0o600).catch(cause => { if ((cause as NodeJS.ErrnoException).code === "EEXIST") fail("release_busy", "Quirt release transition is already locked"); throw cause; });
    try {
      await handle.writeFile(`${canonicalJson({ version: 1, pid: process.pid, startedAt: this.now().toISOString() })}\n`); await handle.sync();
      return await operation();
    } finally { await handle.close(); await rm(this.layout.lockPath, { force: true }); await fsyncDirectory(this.layout.root); }
  }

  private async receipt(input: Omit<QuirtReleaseReceipt, "receiptSchemaVersion" | "operationId" | "actorRef" | "component" | "completedAt" | "productionActivated">): Promise<{ path: string; sha256: string; receipt: QuirtReleaseReceipt }> {
    const receipt: QuirtReleaseReceipt = { receiptSchemaVersion: 1, operationId: this.id(), actorRef: this.actorRef, component: QUIRT_RELEASE_COMPONENT, completedAt: this.now().toISOString(), productionActivated: false, ...input };
    const serialized = `${canonicalJson(receipt as unknown as Json)}\n`;
    if (Buffer.byteLength(serialized) > 16_384) fail("receipt_too_large", "Quirt release receipt exceeds its bound");
    const name = `${receipt.completedAt.replace(/[:.]/gu, "-")}-${receipt.operationId}.json`, path = join(this.layout.receiptsRoot, name);
    const handle = await open(path, "wx", 0o440);
    try { await handle.writeFile(serialized); await handle.sync(); } finally { await handle.close(); }
    await fsyncDirectory(this.layout.receiptsRoot);
    return { path, sha256: sha256(serialized), receipt };
  }

  private async installed(releaseId: string, expected?: QuirtReleaseArtifactDescriptor): Promise<QuirtReleaseManifest> {
    const path = releasePath(this.layout, releaseId), details = await lstat(path).catch(() => null);
    if (details === null || details.isSymbolicLink() || !details.isDirectory() || await realpath(path) !== path || details.uid !== this.layout.ownerUid || details.gid !== this.layout.groupGid || (details.mode & 0o222) !== 0) fail("release_missing", "Verified immutable Quirt release is not installed");
    return await verifyQuirtReleaseTree(path, expected, this.runtime, { ownerUid: this.layout.ownerUid, groupGid: this.layout.groupGid, immutableDirectories: true });
  }

  async install(archivePath: string, descriptorValue: unknown): Promise<Record<string, Json>> {
    const descriptor = parseQuirtArtifactDescriptor(descriptorValue), startedAt = this.now().toISOString();
    return await this.locked(async () => {
      const finalPath = releasePath(this.layout, descriptor.releaseId), existing = await lstat(finalPath).catch(() => null);
      if (existing !== null) {
        let manifest: QuirtReleaseManifest;
        try {
          manifest = await this.installed(descriptor.releaseId, descriptor);
        } catch (cause) { fail("release_identity_conflict", `Existing Quirt release identity conflicts: ${safeDiagnostic(cause)}`); }
        const evidence = await this.receipt({ operation: "install", releaseId: descriptor.releaseId, sourceCommit: manifest.source.commit, sourceTree: manifest.source.tree, artifactSha256: descriptor.archiveSha256, manifestSha256: descriptor.manifestSha256, sbomSha256: descriptor.sbomSha256, previousReleaseId: null, newReleaseId: descriptor.releaseId, targetRef: relative(this.layout.root, finalPath), startedAt, result: "succeeded", classification: "idempotent_exact_install", verification: "passed", pointerTransition: null, diagnostic: "Exact immutable release already installed" });
        return { releaseId: descriptor.releaseId, release: finalPath, replayed: true, receiptSha256: evidence.sha256 } as unknown as Record<string, Json>;
      }
      const token = this.id(), stage = join(this.layout.releasesRoot, `.stage-${descriptor.releaseId}-${token}`), snapshot = join(this.layout.stagingRoot, `.artifact-${token}.tar.gz`);
      try {
        await mkdir(stage, { mode: 0o700 });
        await snapshotFile(archivePath, snapshot);
        const snapshotDetails = await lstat(snapshot);
        if (snapshotDetails.size !== descriptor.archiveSize || await sha256File(snapshot) !== descriptor.archiveSha256) fail("artifact_mismatch", "Quirt archive snapshot differs from its descriptor");
        await inspectArchiveEntries(snapshot);
        await extractArchive(snapshot, stage);
        const manifest = await verifyQuirtReleaseTree(stage, descriptor, this.runtime, { ownerUid: this.layout.ownerUid, groupGid: this.layout.groupGid });
        await normalizePayload(stage, this.layout.ownerUid, this.layout.groupGid);
        await verifyQuirtReleaseTree(stage, descriptor, this.runtime, { ownerUid: this.layout.ownerUid, groupGid: this.layout.groupGid, immutableDirectories: true });
        this.fault("beforePromotion");
        await rename(stage, finalPath);
        await fsyncDirectory(this.layout.releasesRoot);
        this.fault("afterPromotion");
        const evidence = await this.receipt({ operation: "install", releaseId: descriptor.releaseId, sourceCommit: manifest.source.commit, sourceTree: manifest.source.tree, artifactSha256: descriptor.archiveSha256, manifestSha256: descriptor.manifestSha256, sbomSha256: descriptor.sbomSha256, previousReleaseId: null, newReleaseId: descriptor.releaseId, targetRef: relative(this.layout.root, finalPath), startedAt, result: "succeeded", classification: "installed", verification: "passed", pointerTransition: null, diagnostic: "Verified immutable release promoted atomically" });
        return { releaseId: descriptor.releaseId, release: finalPath, replayed: false, receiptSha256: evidence.sha256 } as unknown as Record<string, Json>;
      } catch (cause) {
        if (await lstat(finalPath).catch(() => null) === null) {
          try { await removeControlledTree(stage, this.layout.releasesRoot); }
          catch { /* Preserve the primary classified failure; explicit recovery can inspect residual staging. */ }
        }
        await this.receipt({ operation: "install", releaseId: descriptor.releaseId, sourceCommit: descriptor.sourceCommit, sourceTree: descriptor.sourceTree, artifactSha256: descriptor.archiveSha256, manifestSha256: descriptor.manifestSha256, sbomSha256: descriptor.sbomSha256, previousReleaseId: null, newReleaseId: null, targetRef: relative(this.layout.root, finalPath), startedAt, result: "failed", classification: cause instanceof QuirtReleaseError ? cause.classification : "install_failed", verification: "failed", pointerTransition: null, diagnostic: safeDiagnostic(cause) });
        throw cause;
      } finally { await rm(snapshot, { force: true }); }
    });
  }

  private async writeTransition(record: TransitionRecord): Promise<void> {
    const temporary = `${this.layout.transitionPath}.tmp-${this.id()}`, serialized = `${canonicalJson(record as unknown as Json)}\n`;
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(serialized); await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, this.layout.transitionPath); await fsyncDirectory(this.layout.root);
  }

  private async readTransition(): Promise<TransitionRecord | null> {
    const details = await lstat(this.layout.transitionPath).catch(() => null);
    if (details === null) return null;
    if (details.isSymbolicLink() || !details.isFile() || details.size < 2 || details.size > 8192) fail("transition_invalid", "Quirt release transition journal is unsafe");
    let value: unknown; try { value = JSON.parse(await readFile(this.layout.transitionPath, "utf8")); } catch { fail("transition_invalid", "Quirt release transition journal is invalid"); }
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail("transition_invalid", "Quirt release transition journal is invalid");
    const record = value as Partial<TransitionRecord>, keys = Object.keys(value).sort().join(",");
    if (keys !== "action,newCurrent,newPrevious,oldCurrent,oldPrevious,version" || record.version !== 1 || (record.action !== "activate" && record.action !== "rollback") || typeof record.newCurrent !== "string" || (record.newPrevious !== null && typeof record.newPrevious !== "string") || (record.oldCurrent !== null && typeof record.oldCurrent !== "string") || (record.oldPrevious !== null && typeof record.oldPrevious !== "string")) fail("transition_invalid", "Quirt release transition journal is invalid");
    for (const path of [record.newCurrent, record.newPrevious, record.oldCurrent, record.oldPrevious]) if (path !== null && !inside(this.layout.releasesRoot, path)) fail("transition_invalid", "Quirt transition escaped its release root");
    return record as TransitionRecord;
  }

  private async setOptionalPointer(path: string, target: string | null): Promise<void> {
    if (target === null) {
      const details = await lstat(path).catch(() => null);
      if (details !== null && !details.isSymbolicLink()) fail("pointer_unsafe", "Quirt release pointer is unsafe");
      await rm(path, { force: true }); await fsyncDirectory(dirname(path));
    } else await atomicPointer(path, target, this.id());
  }

  private async transition(action: "activate" | "rollback", newCurrent: string, oldCurrent: string | null, oldPrevious: string | null): Promise<void> {
    const record: TransitionRecord = { version: 1, action, oldCurrent, oldPrevious, newCurrent, newPrevious: oldCurrent };
    await this.writeTransition(record);
    await this.setOptionalPointer(this.layout.previousLink, record.newPrevious);
    this.fault("afterPreviousPointer");
    await atomicPointer(this.layout.currentLink, record.newCurrent, this.id());
    this.fault("afterCurrentPointer");
    await rm(this.layout.transitionPath, { force: true }); await fsyncDirectory(this.layout.root);
  }

  async recover(): Promise<Record<string, Json>> {
    const startedAt = this.now().toISOString();
    return await this.locked(async () => {
      const record = await this.readTransition();
      if (record === null) return { recovered: false };
      const current = await directPointer(this.layout, this.layout.currentLink);
      if (current === record.newCurrent) await this.setOptionalPointer(this.layout.previousLink, record.newPrevious);
      else if (current === record.oldCurrent) await this.setOptionalPointer(this.layout.previousLink, record.oldPrevious);
      else fail("transition_ambiguous", "Quirt release transition cannot be recovered safely");
      await rm(this.layout.transitionPath, { force: true }); await fsyncDirectory(this.layout.root);
      const effective = current === record.newCurrent ? record.newCurrent : record.oldCurrent;
      const evidenceTarget = effective ?? record.newCurrent;
      const manifest = await this.installed(evidenceTarget.split(sep).at(-1) ?? "");
      const evidence = await this.receipt({ operation: "recover", releaseId: manifest.releaseId, sourceCommit: manifest.source.commit, sourceTree: manifest.source.tree, artifactSha256: null, manifestSha256: sha256(await readFile(join(releasePath(this.layout, manifest.releaseId), MANIFEST_PATH))), sbomSha256: manifest.build.sbomSha256, previousReleaseId: record.oldCurrent?.split(sep).at(-1) ?? null, newReleaseId: effective?.split(sep).at(-1) ?? null, targetRef: relative(this.layout.root, this.layout.currentLink), startedAt, result: "succeeded", classification: current === record.newCurrent ? "completed_durable_transition" : "restored_prior_transition", verification: "passed", pointerTransition: { current: effective?.split(sep).at(-1) ?? null, previous: (await directPointer(this.layout, this.layout.previousLink))?.split(sep).at(-1) ?? null }, diagnostic: "Transition journal reconciled without service mutation" });
      return { recovered: true, receiptSha256: evidence.sha256 } as unknown as Record<string, Json>;
    });
  }

  async activate(releaseId: string): Promise<Record<string, Json>> {
    const startedAt = this.now().toISOString();
    return await this.locked(async () => {
      if (await this.readTransition() !== null) fail("recovery_required", "Quirt release transition requires explicit recovery");
      const targetPath = releasePath(this.layout, releaseId), target = await this.installed(releaseId), currentPath = await directPointer(this.layout, this.layout.currentLink), previousPath = await directPointer(this.layout, this.layout.previousLink);
      if (currentPath === targetPath) return { releaseId, replayed: true };
      let currentManifest: QuirtReleaseManifest | null = null;
      if (currentPath !== null) currentManifest = await this.installed(currentPath.split(sep).at(-1) ?? "");
      if (currentManifest !== null && target.source.epoch < currentManifest.source.epoch) fail("downgrade_rejected", "Forward Quirt activation cannot downgrade source identity");
      try {
        await this.transition("activate", targetPath, currentPath, previousPath);
        const evidence = await this.receipt({ operation: "activate", releaseId, sourceCommit: target.source.commit, sourceTree: target.source.tree, artifactSha256: null, manifestSha256: sha256(await readFile(join(targetPath, MANIFEST_PATH))), sbomSha256: target.build.sbomSha256, previousReleaseId: currentManifest?.releaseId ?? null, newReleaseId: releaseId, targetRef: relative(this.layout.root, this.layout.currentLink), startedAt, result: "succeeded", classification: "pointer_activated", verification: "passed", pointerTransition: { current: releaseId, previous: currentManifest?.releaseId ?? null }, diagnostic: "Atomic pointer transition completed without service restart" });
        return { releaseId, previousReleaseId: currentManifest?.releaseId ?? null, replayed: false, receiptSha256: evidence.sha256 } as unknown as Record<string, Json>;
      } catch (cause) {
        await this.receipt({ operation: "activate", releaseId, sourceCommit: target.source.commit, sourceTree: target.source.tree, artifactSha256: null, manifestSha256: sha256(await readFile(join(targetPath, MANIFEST_PATH))), sbomSha256: target.build.sbomSha256, previousReleaseId: currentManifest?.releaseId ?? null, newReleaseId: null, targetRef: relative(this.layout.root, this.layout.currentLink), startedAt, result: "failed", classification: cause instanceof QuirtReleaseError ? cause.classification : "activation_failed", verification: "passed", pointerTransition: null, diagnostic: safeDiagnostic(cause) });
        throw cause;
      }
    });
  }

  async rollback(): Promise<Record<string, Json>> {
    const startedAt = this.now().toISOString();
    return await this.locked(async () => {
      if (await this.readTransition() !== null) fail("recovery_required", "Quirt release transition requires explicit recovery");
      const currentPath = await directPointer(this.layout, this.layout.currentLink), previousPath = await directPointer(this.layout, this.layout.previousLink);
      if (currentPath === null || previousPath === null) fail("rollback_unavailable", "Quirt rollback requires verified current and previous releases");
      const current = await this.installed(currentPath.split(sep).at(-1) ?? ""), previous = await this.installed(previousPath.split(sep).at(-1) ?? "");
      try {
        await this.transition("rollback", previousPath, currentPath, previousPath);
        const evidence = await this.receipt({ operation: "rollback", releaseId: previous.releaseId, sourceCommit: previous.source.commit, sourceTree: previous.source.tree, artifactSha256: null, manifestSha256: sha256(await readFile(join(previousPath, MANIFEST_PATH))), sbomSha256: previous.build.sbomSha256, previousReleaseId: current.releaseId, newReleaseId: previous.releaseId, targetRef: relative(this.layout.root, this.layout.currentLink), startedAt, result: "succeeded", classification: "explicit_verified_rollback", verification: "passed", pointerTransition: { current: previous.releaseId, previous: current.releaseId }, diagnostic: "Explicit offline rollback pointer transition completed" });
        return { releaseId: previous.releaseId, previousReleaseId: current.releaseId, receiptSha256: evidence.sha256 } as unknown as Record<string, Json>;
      } catch (cause) {
        await this.receipt({ operation: "rollback", releaseId: previous.releaseId, sourceCommit: previous.source.commit, sourceTree: previous.source.tree, artifactSha256: null, manifestSha256: sha256(await readFile(join(previousPath, MANIFEST_PATH))), sbomSha256: previous.build.sbomSha256, previousReleaseId: current.releaseId, newReleaseId: null, targetRef: relative(this.layout.root, this.layout.currentLink), startedAt, result: "failed", classification: cause instanceof QuirtReleaseError ? cause.classification : "rollback_failed", verification: "passed", pointerTransition: null, diagnostic: safeDiagnostic(cause) });
        throw cause;
      }
    });
  }

  async status(): Promise<Record<string, Json>> {
    const root = await lstat(this.layout.root).catch(() => null);
    if (root === null) return { component: QUIRT_RELEASE_COMPONENT, root: this.layout.root, current: null, previous: null, transitionPending: false, staged: [], locked: false, serviceRestarted: false } as unknown as Record<string, Json>;
    await safeDirectory(this.layout.root, this.layout.ownerUid, this.layout.groupGid);
    await safeDirectory(this.layout.releasesRoot, this.layout.ownerUid, this.layout.groupGid);
    await safeDirectory(this.layout.stagingRoot, this.layout.ownerUid, this.layout.groupGid);
    const current = await directPointer(this.layout, this.layout.currentLink), previous = await directPointer(this.layout, this.layout.previousLink), transition = await this.readTransition();
    const staged = (await readdir(this.layout.releasesRoot)).filter(name => name.startsWith(".stage-")).sort();
    return { component: QUIRT_RELEASE_COMPONENT, root: this.layout.root, current: current?.split(sep).at(-1) ?? null, previous: previous?.split(sep).at(-1) ?? null, transitionPending: transition !== null, staged, locked: await lstat(this.layout.lockPath).then(() => true, () => false), serviceRestarted: false } as unknown as Record<string, Json>;
  }

  async inspectInstalled(releaseId: string): Promise<Record<string, Json>> {
    const manifest = await this.installed(releaseId);
    const path = releasePath(this.layout, releaseId);
    return { verified: true, releaseId, release: path, manifest: manifest as unknown as Json, manifestSha256: sha256(await readFile(join(path, MANIFEST_PATH))), sbomSha256: manifest.build.sbomSha256 } as unknown as Record<string, Json>;
  }

  async listReceipts(): Promise<Record<string, Json>> {
    const root = await lstat(this.layout.receiptsRoot).catch(() => null);
    if (root === null) return { receipts: [] } as unknown as Record<string, Json>;
    await safeDirectory(this.layout.receiptsRoot, this.layout.ownerUid, this.layout.groupGid);
    const receipts: Json[] = [];
    for (const name of (await readdir(this.layout.receiptsRoot)).sort()) {
      if (!/^\d{4}-\d{2}-\d{2}T[0-9Z-]+-[a-f0-9-]+\.json$/u.test(name)) fail("receipt_invalid", "Quirt receipt filename is invalid");
      const path = join(this.layout.receiptsRoot, name), details = await lstat(path);
      if (details.isSymbolicLink() || !details.isFile() || details.size < 2 || details.size > 16_384) fail("receipt_invalid", "Quirt receipt is unsafe");
      const value: unknown = JSON.parse(await readFile(path, "utf8"));
      receipts.push({ name, sha256: await sha256File(path), receipt: value } as unknown as Json);
    }
    return { receipts } as unknown as Record<string, Json>;
  }
}
