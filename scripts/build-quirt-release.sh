#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
umask 022

commit="${1:-}"
tree="${2:-}"
output_root="${3:-}"
epoch="${4:-}"
[[ "$commit" =~ ^[a-f0-9]{40}$ ]] || { printf '%s\n' 'invalid Quirt build commit' >&2; exit 2; }
[[ "$tree" =~ ^[a-f0-9]{40}$ ]] || { printf '%s\n' 'invalid Quirt build tree' >&2; exit 2; }
[[ -n "$output_root" && "$output_root" != / && ! -L "$output_root" ]] || { printf '%s\n' 'invalid Quirt output root' >&2; exit 2; }
[[ "$epoch" =~ ^[0-9]+$ ]] || { printf '%s\n' 'invalid Quirt build epoch' >&2; exit 2; }

actual_commit="$(git rev-parse HEAD)"
actual_tree="$(git rev-parse 'HEAD^{tree}')"
actual_epoch="$(git show -s --format=%ct HEAD)"
[[ "$commit" == "$actual_commit" ]] || { printf '%s\n' 'requested build commit differs from HEAD' >&2; exit 2; }
[[ "$tree" == "$actual_tree" ]] || { printf '%s\n' 'requested build tree differs from HEAD' >&2; exit 2; }
[[ "$epoch" == "$actual_epoch" ]] || { printf '%s\n' 'requested build epoch differs from HEAD' >&2; exit 2; }
git diff --quiet
git diff --cached --quiet

node --input-type=module <<'NODE'
import { readFileSync } from "node:fs";
const manifest = JSON.parse(readFileSync("provenance/extraction-manifest.json", "utf8"));
const expected = {
  sourceCommit: "6b4968e9443653af6636f2490bf3c4fc14da4cea",
  verifiedSourceTree: "358516dd79dc18c2080b99779ce0b3e428fc9b63",
  evidenceCommit: "f103c0377c73c3831af31544d14842832516499a",
  verifiedEvidenceTree: "26174a31e20cabed9c5d9d00751984f3d8591ec0"
};
for (const [key, value] of Object.entries(expected)) {
  if (manifest[key] !== value) throw new Error(`standalone provenance ${key} differs from the audited authority`);
}
NODE

if [[ -n "${SOURCE_DATE_EPOCH:-}" && "$SOURCE_DATE_EPOCH" != "$epoch" ]]; then
  printf '%s\n' 'SOURCE_DATE_EPOCH differs from the audited build epoch' >&2
  exit 2
fi
export SOURCE_DATE_EPOCH="$epoch"

mkdir -p -- "$output_root"
[[ -d "$output_root" && ! -L "$output_root" ]] || { printf '%s\n' 'Quirt output root is unsafe' >&2; exit 2; }
work="$(mktemp -d)"
cleanup() {
  local status=$? cleanup_status=0
  if [[ -d "$work" && ! -L "$work" ]]; then
    find "$work" -type d -exec chmod u+rwx {} + >/dev/null 2>&1 || cleanup_status=1
    find "$work" -type f -exec chmod u+rw {} + >/dev/null 2>&1 || cleanup_status=1
    rm -rf -- "$work" >/dev/null 2>&1 || cleanup_status=1
  fi
  if (( status != 0 )); then return "$status"; fi
  return "$cleanup_status"
}
trap cleanup EXIT
release="$work/release"
mkdir -p -- "$release/evidence" "$release/dist"

cp package.json package-lock.json "$release/"
npm ci --omit=dev --omit=optional --ignore-scripts --prefix "$release"
[[ ! -e "$release/node_modules/@modelcontextprotocol" ]] || { printf '%s\n' 'operator MCP SDK entered the standalone runtime dependency tree' >&2; exit 1; }

node --input-type=module - "$release/package.json" <<'NODE'
import { writeFile } from "node:fs/promises";
const path = process.argv[2];
const value = {
  dependencies: { "node-pty": "1.1.0", "playwright-core": "1.61.1", "tar": "7.5.19", "zod": "4.4.3" },
  engines: { node: ">=24.18.0 <25" },
  main: "dist/quirt/supervisor-main.js",
  name: "@stealtheye/quirt-release",
  private: true,
  type: "module",
  version: "0.0.0-private"
};
await writeFile(path, `${JSON.stringify(value)}\n`);
NODE
npm install --package-lock-only --omit=dev --ignore-scripts --offline --prefix "$release"
rm -rf -- "$release/node_modules/.bin"
[[ -z "$(find "$release/node_modules" -type l -print -quit)" ]] || { printf '%s\n' 'production dependency tree contains a symbolic link' >&2; exit 1; }
node --input-type=module - "$release/node_modules" <<'NODE'
import { readdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
const root = resolve(process.argv[2]);
const discardedDirectories = new Set([".github", ".gitlab", ".idea", ".vscode", "__tests__", "benchmark", "benchmarks", "coverage", "doc", "docs", "example", "examples", "samples", "test", "tests"]);
const discardedDotfiles = /^(?:\.editorconfig|\.eslint.*|\.npmignore|\.npmrc|\.nyc.*|\.prettier.*)$/iu;
const discardedDocuments = /^(?:changelog|code_of_conduct|contributing|funding|history|readme|security)(?:\..*)?$/iu;
const discardedExtensions = /\.(?:cts|d\.cts|d\.mts|d\.ts|key|map|markdown|md|mts|pem|ppk|ts|tsx)$/iu;
const discardedTests = /\.(?:spec|test)\.(?:cjs|js|mjs)$/iu;
async function prune(directory, depth = 0) {
  if (depth > 64) throw new Error("production dependency tree exceeds the pruning depth bound");
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    const path = join(directory, entry.name), normalized = entry.name.toLowerCase();
    if (entry.isSymbolicLink()) throw new Error("production dependency tree contains a symbolic link");
    if (entry.isDirectory()) {
      if (discardedDirectories.has(normalized)) await rm(path, { force: true, recursive: true });
      else await prune(path, depth + 1);
    } else if (entry.isFile()) {
      if (discardedDotfiles.test(entry.name) || discardedDocuments.test(entry.name) || discardedExtensions.test(entry.name) || discardedTests.test(entry.name)) await rm(path);
    } else throw new Error("production dependency tree contains a special file");
  }
}
await prune(root);
NODE

mkdir -p -- "$release/dist/quirt"
while IFS= read -r file; do
  target="$release/${file}"
  mkdir -p -- "$(dirname "$target")"
  cp -- "$file" "$target"
done < <(find dist/quirt -type f -name '*.js' -printf '%p\n' | sort)
cp -- dist/canonical.js "$release/dist/"
[[ -f "$release/dist/quirt/supervisor-main.js" ]] || { printf '%s\n' 'compiled Quirt supervisor entrypoint is missing' >&2; exit 1; }
[[ ! -e "$release/dist/principal-grant.js" ]] || { printf '%s\n' 'operator grant code entered the standalone release' >&2; exit 1; }
if grep -RIl -- '@modelcontextprotocol\|McpServer\|registerTool' "$release/dist" | grep -q .; then
  printf '%s\n' 'public MCP registration code entered the standalone release' >&2
  exit 1
fi
cp -- provenance/extraction-manifest.json "$release/evidence/extraction-manifest.json"

npm sbom --omit=dev --omit=optional --package-lock-only --sbom-format cyclonedx \
  --prefix "$release" | node scripts/normalize-quirt-sbom.mjs "$commit" "$tree" "$epoch" \
  > "$release/evidence/sbom.cdx.json"

[[ -z "$(find "$release" -type l -print -quit)" ]] || { printf '%s\n' 'Quirt release contains a symbolic link' >&2; exit 1; }
[[ -z "$(find "$release" \( -type s -o -type p -o -type b -o -type c \) -print -quit)" ]] || { printf '%s\n' 'Quirt release contains a special file' >&2; exit 1; }
finalized="$(node dist/quirt/release-admin.js finalize "$release" "$commit" "$tree" "$epoch")"
release_id="$(printf '%s' "$finalized" | node --input-type=module -e 'let s=""; for await (const c of process.stdin) s+=c; process.stdout.write(JSON.parse(s).manifest.releaseId)')"
archive="$output_root/stealtheye-quirt-$release_id.tar.gz"
descriptor="$output_root/stealtheye-quirt-$release_id.descriptor.json"
manifest="$output_root/stealtheye-quirt-$release_id.manifest.json"
sbom="$output_root/stealtheye-quirt-$release_id.sbom.cdx.json"
marker="$output_root/stealtheye-quirt-$release_id.release-id"
for path in "$archive" "$descriptor" "$manifest" "$sbom" "$marker"; do [[ ! -e "$path" && ! -L "$path" ]] || { printf '%s\n' 'Quirt release output already exists' >&2; exit 2; }; done

tar --format=gnu --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
  --no-acls --no-selinux --no-xattrs -C "$release" -cf - . | gzip -n -9 > "$archive"
cp -- "$release/evidence/manifest.json" "$manifest"
cp -- "$release/evidence/sbom.cdx.json" "$sbom"
cp -- "$release/.quirt-release-id" "$marker"
node dist/quirt/release-admin.js descriptor "$archive" "$manifest" > "$descriptor"
node dist/quirt/release-admin.js inspect "$archive" "$descriptor" >/dev/null

sha256sum "$archive" "$descriptor" "$manifest" "$sbom" "$marker"
printf 'release_id=%s\nbuild_commit=%s\nbuild_tree=%s\nbuild_epoch=%s\n' "$release_id" "$commit" "$tree" "$epoch"
