#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Write a release directory from built packages: the packages, release.json (the debs: one per
# arch for the nodes), NOTES.md (the notes file, then the package sums), SHA256SUMS over every
# file, SHA256SUMS.sig when PELAGOS_RELEASE_KEY is set, then verify it.
#
# Usage: release-assemble.sh --notes FILE [--published-at UTC] [--tree DIR] OUT VERSION PACKAGE...
#   OUT must not exist or be empty. --tree: the released tree (default: this checkout), whose
#   release tooling, state schema and public keys are used. PELAGOS_PYTHON: interpreter with
#   the backend dependencies (default backend/.venv/bin/python).
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)"
notes="" published="" tree=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --notes) notes="${2:?--notes needs a file}"; shift ;;
    --published-at) published="${2:?--published-at needs a time}"; shift ;;
    --tree) tree="${2:?--tree needs a directory}"; shift ;;
    -h|--help) sed -n '3,10p' "$0"; exit 0 ;;
    -*) echo "release-assemble: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
[[ $# -ge 3 && -n "$notes" ]] || { sed -n '7,10p' "$0" >&2; exit 2; }
out="$1" version="$2"; shift 2
[[ -f "$notes" ]] || { echo "release-assemble: notes $notes missing" >&2; exit 1; }
PY="${PELAGOS_PYTHON:-$src/backend/.venv/bin/python}"
tree="$(cd "${tree:-$src}" && pwd)"
release_py() { PYTHONPATH="$tree/backend" "$PY" -m pelagos.core.release "$@"; }

mkdir -p "$out"
out="$(cd "$out" && pwd)" notes="$(realpath "$notes")"
[[ -z "$(ls -A "$out")" ]] || { echo "release-assemble: $out is not empty" >&2; exit 1; }
for p in "$@"; do
  case "$p" in *.deb|*.rpm) ;; *) echo "release-assemble: $p is not a package" >&2; exit 1 ;; esac
  [[ ! -e "$out/$(basename "$p")" ]] || { echo "release-assemble: $(basename "$p") given twice" >&2; exit 1; }
  cp -- "$p" "$out/"
done
# release.json lists the debs only (one package per format and arch for the nodes): the el9
# and el10 rpms ship beside it.
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
for p in "$out"/*.deb; do ln -s "$p" "$staging/"; done
release_py manifest "$staging" "$version" ${published:+--published-at "$published"}
mv "$staging/release.json" "$out/"
cd "$out"
export LC_ALL=C
shopt -s nullglob
{
  cat "$notes"
  printf '\n## Files\n\n'
  sha256sum -- *.deb *.rpm | sed 's/^/    /'
} > NOTES.md
files=()
for f in *; do [[ "$f" == SHA256SUMS || "$f" == SHA256SUMS.sig ]] || files+=("$f"); done
sha256sum -- "${files[@]}" > SHA256SUMS
release_py sign "$out"
release_py verify "$out" >&2 || { echo "release-assemble: $out does not verify" >&2; exit 1; }
