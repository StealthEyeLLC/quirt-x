#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC

commit="${1:-}"
tree="${2:-}"
epoch="${3:-}"
[[ "$commit" =~ ^[a-f0-9]{40}$ && "$tree" =~ ^[a-f0-9]{40}$ && "$epoch" =~ ^[0-9]+$ ]] || { printf '%s\n' 'usage: test-quirt-release-reproducibility.sh <commit> <tree> <source-epoch>' >&2; exit 2; }
[[ "$(node -p 'process.versions.node.split(`.`)[0]')" == 24 ]] || { printf '%s\n' 'Quirt reproducibility requires Node 24' >&2; exit 2; }
manifest_source_tree="$(node --input-type=module -e "import {readFileSync} from 'node:fs'; const m=JSON.parse(readFileSync('provenance/extraction-manifest.json','utf8')); process.stdout.write(m.verifiedSourceTree)")"
[[ "$tree" == "$manifest_source_tree" ]] || { printf '%s\n' 'requested tree differs from standalone provenance' >&2; exit 2; }

work="$(mktemp -d)"
cleanup() {
  local status=$? cleanup_status=0 root
  for build in one two; do git worktree remove --force "$work/$build" >/dev/null 2>&1 || true; done
  for root in "$work/unpacked-one" "$work/unpacked-two"; do
    if [[ -d "$root" && ! -L "$root" ]]; then
      find "$root" -xdev -type d -exec chmod u+rwx {} + >/dev/null 2>&1 || cleanup_status=1
      find "$root" -xdev -type f -exec chmod u+rw {} + >/dev/null 2>&1 || cleanup_status=1
    fi
  done
  rm -rf -- "$work" >/dev/null 2>&1 || cleanup_status=1
  if (( status != 0 )); then return "$status"; fi
  return "$cleanup_status"
}
trap cleanup EXIT

for build in one two; do git worktree add --detach "$work/$build" HEAD >/dev/null; done
find "$work/one" -exec touch -h -d "@$((epoch + 101))" {} +
find "$work/two" -exec touch -h -d "@$((epoch + 707))" {} +

for build in one two; do
  (
    cd "$work/$build"
    npm ci
    npm run build
    scripts/build-quirt-release.sh "$commit" "$tree" "$work/${build}-output" "$epoch" > "$work/${build}-build.log"
  )
done

first="$(find "$work/one-output" -maxdepth 1 -type f -name 'stealtheye-quirt-*.tar.gz' -print)"
second="$(find "$work/two-output" -maxdepth 1 -type f -name 'stealtheye-quirt-*.tar.gz' -print)"
[[ -n "$first" && -n "$second" && "$(basename "$first")" == "$(basename "$second")" ]] || { printf '%s\n' 'Quirt reproducibility produced inconsistent archive identities' >&2; exit 1; }

for suffix in tar.gz descriptor.json manifest.json sbom.cdx.json release-id; do
  left="$(find "$work/one-output" -maxdepth 1 -type f -name "stealtheye-quirt-*.$suffix" -print)"
  right="$(find "$work/two-output" -maxdepth 1 -type f -name "stealtheye-quirt-*.$suffix" -print)"
  cmp -s "$left" "$right" || { printf 'Quirt reproducibility mismatch: %s\n' "$suffix" >&2; exit 1; }
done

mkdir "$work/unpacked-one" "$work/unpacked-two"
tar -xzf "$first" -C "$work/unpacked-one"
tar -xzf "$second" -C "$work/unpacked-two"
for build in one two; do
  root="$work/unpacked-$build"
  find "$root" -type f -printf '%P\0' | sort -z | xargs -0 -r -I{} sha256sum "$root/{}" | sed "s#$root/##" > "$work/$build-files.sha256"
  find "$root" -printf '%P %y %m %u %g\n' | LC_ALL=C sort > "$work/$build-modes.txt"
done
cmp -s "$work/one-files.sha256" "$work/two-files.sha256"
cmp -s "$work/one-modes.txt" "$work/two-modes.txt"
tar -tvzf "$first" --full-time > "$work/one-archive.txt"
tar -tvzf "$second" --full-time > "$work/two-archive.txt"
cmp -s "$work/one-archive.txt" "$work/two-archive.txt"

manifest="$(find "$work/one-output" -maxdepth 1 -type f -name 'stealtheye-quirt-*.manifest.json' -print)"
sbom="$(find "$work/one-output" -maxdepth 1 -type f -name 'stealtheye-quirt-*.sbom.cdx.json' -print)"
descriptor="$(find "$work/one-output" -maxdepth 1 -type f -name 'stealtheye-quirt-*.descriptor.json' -print)"
sha256sum "$first" "$manifest" "$sbom" "$descriptor"
node --input-type=module - "$manifest" <<'NODE'
import { readFile } from "node:fs/promises";
const manifest = JSON.parse(await readFile(process.argv[2], "utf8"));
process.stdout.write(`${JSON.stringify({ archiveByteIdentical: true, fileCount: manifest.files.length, manifestReleaseId: manifest.releaseId, payloadInventorySha256: manifest.build.payloadInventorySha256, source: manifest.source })}\n`);
NODE
