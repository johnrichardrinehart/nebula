#!/usr/bin/env bash
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -a "$repo"/. "$tmp/repo"
rm -rf "$tmp/repo/.git" "$tmp/repo/result"*

source_path() {
  nix eval --raw "path:$1#packages.x86_64-linux.nebula.src.outPath"
}

baseline=$(source_path "$tmp/repo")
printf '\nunrelated source-filter probe\n' >> "$tmp/repo/README.md"
unrelated=$(source_path "$tmp/repo")
printf '\n// required source-filter probe\n' >> "$tmp/repo/handshake/curve.go"
required=$(source_path "$tmp/repo")

[[ "$baseline" == "$unrelated" ]]
[[ "$baseline" != "$required" ]]
printf 'baseline=%s\nunrelated=%s\nrequired=%s\n' "$baseline" "$unrelated" "$required"
