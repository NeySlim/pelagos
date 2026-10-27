#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cut a release: set the version, tag it, build the amd64 and arm64 debs from the tagged tree
# (Debian 13 containers, arm64 through qemu binfmt), write SHA256SUMS and short release notes.
#
# Usage: release.sh [--no-tag] [--since REF] [--out DIR] VERSION
#   VERSION   0.1.1, or a pre-release 0.1.1rc1 (0.1.1~rc1 is accepted too)
#   --no-tag  throwaway build: HEAD with the version patched in a copy, no commit, no tag
#   --since   start of the release notes (default: the previous v* tag)
#   --out     parent of the release directory (default: build/release); files land in OUT/VERSION
# Without --no-tag the tree must be clean: the script commits "chore(release): VERSION" when
# backend/pelagos/__init__.py differs, tags vVERSION, then commits the next .dev0 version.
# Nothing is pushed. Environment: DOCKER (default docker), ARCHES (default "amd64 arm64").
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)"
init="backend/pelagos/__init__.py"
tag_it=1 since="" out="$src/build/release"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-tag) tag_it=0 ;;
    --since) since="${2:?--since needs a ref}"; shift ;;
    --out) out="${2:?--out needs a directory}"; shift ;;
    -h|--help) sed -n '3,15p' "$0"; exit 0 ;;
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
cd "$src"

set_version() { sed -i "s/^__version__ = \".*\"/__version__ = \"$2\"/" "$1/$init"; }

if [[ "$tag_it" == 1 ]]; then
  [[ -z "$(git status --porcelain --untracked-files=no)" ]] || { echo "release: the tree is not clean" >&2; exit 1; }
  ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "release: tag $tag exists" >&2; exit 1; }
  if [[ "$(packaging/version.sh python)" != "$version" ]]; then
    set_version . "$version"
    git commit -q -m "chore(release): $version" -- "$init"
  fi
  git tag -a "$tag" -m "Pelagos $version"
  ref="$tag"
else
  ref="HEAD"
fi
since="${since:-$(git describe --tags --abbrev=0 --match 'v*' "$ref^" 2>/dev/null || true)}"

# Build from an export of the ref, never from the working tree.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive "$ref" | tar -C "$work" -xf -
[[ "$tag_it" == 1 ]] || set_version "$work" "$version"
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
mkdir -p "$dest"
for arch in "${arches[@]}"; do
  deb="$work/out/pelagos_${debver}_$arch.deb"
  [[ "$(dpkg-deb -f "$deb" Version) $(dpkg-deb -f "$deb" Architecture)" == "$debver $arch" ]] ||
    { echo "release: $deb has unexpected control fields" >&2; exit 1; }
  cp "$deb" "$dest/"
done
(cd "$dest" && sha256sum -- *.deb > SHA256SUMS)

{
  echo "# Pelagos $version"
  echo
  echo "Commit $(git rev-parse --short "$ref^{commit}"), $(git log -1 --format=%cs "$ref")${since:+, changes since $since}."
  range="${since:+$since..}$ref"
  for kind in feat fix; do
    lines="$(git log --no-merges --format=%s "$range" | grep -E "^$kind(\(|:)" || true)"
    [[ -n "$lines" ]] || continue
    [[ "$kind" == feat ]] && echo -e "\n## Features\n" || echo -e "\n## Fixes\n"
    echo "$lines" | sed 's/^/- /'
  done
  other="$(git log --no-merges --format=%s "$range" | grep -cvE '^(feat|fix)(\(|:)' || true)"
  echo -e "\n$other other commits (tests, docs, CI, refactoring)."
  echo -e "\n## Files\n"
  sed 's/^/    /' "$dest/SHA256SUMS"
} > "$dest/NOTES.md"

if [[ "$tag_it" == 1 ]]; then
  IFS=. read -r major minor patch <<<"${version%%[abr]*}"
  if [[ "$version" =~ (a|b|rc) ]]; then next="$major.$minor.$patch.dev0"; else next="$major.$minor.$((patch + 1)).dev0"; fi
  set_version . "$next"
  git commit -q -m "chore(release): open $next" -- "$init"
  echo "release: tagged $tag, main moves to $next. Publish with: git push origin main $tag" >&2
fi
ls -l "$dest" >&2
