#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cut a release. Tagged (default): commit the version with its notes, tag it, open the next .dev0
# version; the release workflow builds, tests and drafts the GitHub release from the pushed tag.
# --no-tag: local build of HEAD for lab tests: amd64 and arm64 debs (Debian 13 containers, arm64
# through qemu binfmt) in a release directory (scripts/release-assemble.sh). Never deploy it.
#
# Usage: release.sh [--no-tag] [--since REF] [--out DIR] VERSION
#   VERSION   0.1.1 (tagged), or 0.1.1rc1 (0.1.1~rc1 is accepted too) for a local build
#   --no-tag  local build: HEAD with the version patched in a copy, no commit, no tag
#   --since   start of the commit list of a local build's notes (default: the previous v* tag)
#   --out     parent of the local release directory (default: build/release); files in OUT/VERSION
# Tagged, the tree must be clean except docs/releases/VERSION.md and CHANGELOG.md, which the
# release commit "chore(release): VERSION" carries; scripts/release-check.sh must pass on it.
# Nothing is pushed. Environment: DOCKER (default docker), ARCHES (default "amd64 arm64"),
# PELAGOS_RELEASE_KEY (Ed25519 private key outside the repository; unset: unsigned release),
# PELAGOS_RELEASE_KEY_PASSWORD (its passphrase, if any), PELAGOS_PYTHON (default backend/.venv).
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)"
init="backend/pelagos/__init__.py"
tag_it=1 since="" out="$src/build/release"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-tag) tag_it=0 ;;
    --since) since="${2:?--since needs a ref}"; shift ;;
    --out) out="${2:?--out needs a directory}"; shift ;;
    -h|--help) sed -n '3,18p' "$0"; exit 0 ;;
    -*) echo "release: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
version="${1:?usage: release.sh [--no-tag] [--since REF] [--out DIR] VERSION}"
version="${version/\~/}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?$ ]] ||
  { echo "release: $version is not X.Y.Z or X.Y.Z(a|b|rc)N" >&2; exit 2; }
tag="v$version"
DOCKER="${DOCKER:-docker}"
ARCHES="${ARCHES:-amd64 arm64}"
PY="${PELAGOS_PYTHON:-$src/backend/.venv/bin/python}"
cd "$src"

key="${PELAGOS_RELEASE_KEY:-}"
if [[ -n "$key" ]]; then
  [[ -f "$key" ]] || { echo "release: PELAGOS_RELEASE_KEY $key is not a file" >&2; exit 1; }
  # A private key never lives in the source tree, where git could pick it up.
  case "$(realpath "$key")/" in "$src"/*) echo "release: the release key must be outside $src" >&2; exit 1 ;; esac
fi
"$PY" -c 'import cryptography' 2>/dev/null || { echo "release: $PY lacks cryptography (make venv)" >&2; exit 1; }

set_version() { sed -i "s/^__version__ = \".*\"/__version__ = \"$2\"/" "$1/$init"; }

if [[ "$tag_it" == 1 ]]; then
  notes="docs/releases/$version.md"
  dirty="$(git status --porcelain --untracked-files=all | cut -c4- | grep -Evx "$notes|CHANGELOG.md" || true)"
  [[ -z "$dirty" ]] || { echo "release: the tree is not clean: $dirty" >&2; exit 1; }
  ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "release: tag $tag exists" >&2; exit 1; }
  set_version . "$version"
  scripts/release-check.sh --tag "$tag" || {
    git checkout -q -- "$init"
    echo "release: fix the checks above, then run it again" >&2
    exit 1
  }
  git add -- "$init" "$notes" CHANGELOG.md
  git commit -q -m "chore(release): $version"
  git tag -a "$tag" -m "Pelagos $version"
  IFS=. read -r major minor patch <<<"$version"
  next="$major.$minor.$((patch + 1)).dev0"
  set_version . "$next"
  git commit -q -m "chore(release): open $next" -- "$init"
  echo "release: tagged $tag, main moves to $next. Push both: git push origin main $tag" >&2
  echo "release: the release workflow drafts the GitHub release; review it, then Publish" >&2
  exit 0
fi
ref="HEAD"
since="${since:-$(git describe --tags --abbrev=0 --match 'v*' "$ref^" 2>/dev/null || true)}"

# Build from an export of the ref, never from the working tree.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive "$ref" | tar -C "$work" -xf -
set_version "$work" "$version"
epoch="$(git log -1 --format=%ct "$ref")"
echo "release: $version from $(git rev-parse --short "$ref^{commit}") in $work" >&2

(cd "$work/frontend" && npm ci --no-fund --no-audit --loglevel=error && npm run build --silent) >&2
read -ra arches <<<"$ARCHES"
pids=()
for arch in "${arches[@]}"; do
  # lintian under qemu takes longer than the build: the amd64 report covers the same contents.
  lint=yes; [[ "$arch" == "$(dpkg --print-architecture)" ]] || lint=no
  SOURCE_DATE_EPOCH="$epoch" PELAGOS_SNAPSHOT="" DOCKER="$DOCKER" LINTIAN="$lint" \
    "$work/packaging/deb/container-build.sh" "$arch" "$work/out" >"$work/build-$arch.log" 2>&1 &
  pids+=("$!")
done
for i in "${!pids[@]}"; do
  wait "${pids[$i]}" || { tail -40 "$work/build-${arches[$i]}.log" >&2; echo "release: ${arches[$i]} build failed" >&2; exit 1; }
done

debver="$(packaging/version.sh deb "$work")-1"
dest="$out/$version"
rm -rf "$dest"
pkgs=()
for arch in "${arches[@]}"; do
  deb="$work/out/pelagos_${debver}_$arch.deb"
  [[ "$(dpkg-deb -f "$deb" Version) $(dpkg-deb -f "$deb" Architecture)" == "$debver $arch" ]] ||
    { echo "release: $deb has unexpected control fields" >&2; exit 1; }
  pkgs+=("$deb")
done
published="$(TZ=UTC0 git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd "$ref")"
{
  echo "# Pelagos $version"
  echo
  echo "Local build of commit $(git rev-parse --short "$ref^{commit}"), $(git log -1 --format=%cs "$ref")${since:+, changes since $since}."
  range="${since:+$since..}$ref"
  for kind in feat fix; do
    lines="$(git log --no-merges --format=%s "$range" | grep -E "^$kind(\(|:)" || true)"
    [[ -n "$lines" ]] || continue
    [[ "$kind" == feat ]] && echo -e "\n## Features\n" || echo -e "\n## Fixes\n"
    echo "$lines" | sed 's/^/- /'
  done
  other="$(git log --no-merges --format=%s "$range" | grep -cvE '^(feat|fix)(\(|:)' || true)"
  echo -e "\n$other other commits (tests, docs, CI, refactoring)."
} > "$work/notes.md"
# The tooling and the packaged public keys of the built tree, not of the working tree.
PELAGOS_PYTHON="$PY" "$work/scripts/release-assemble.sh" --notes "$work/notes.md" \
  --published-at "$published" "$dest" "${debver%-1}" "${pkgs[@]}"
ls -l "$dest" >&2
