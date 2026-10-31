#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Blocking checks of a release, run by the release workflow before the draft and runnable locally.
#
# Usage: release-check.sh --tag vX.Y.Z [--src DIR] [--tree DIR] [--require LIST]
#                         [--tested FILE]... [RELEASE_DIR]
#   --tag      the release tag; a final version only (GitHub renames asset names with "~")
#   --src      tree holding docs/releases/<version>.md, CHANGELOG.md, README.md (default: this repo)
#   --tree     tree the packages were built from, for its version (default: --src)
#   --require  packages RELEASE_DIR must hold (default deb:amd64,deb:arm64; also rpm:el9, rpm:el10)
#   --tested   sha256sum lines of the packages the tests ran on: every package must match one
# Without RELEASE_DIR only the source checks run (tag, version, notes, CHANGELOG, README).
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd)" tree="" tag="" require="deb:amd64,deb:arm64" dir=""
tested=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:?--tag needs a tag}"; shift ;;
    --src) src="${2:?--src needs a directory}"; shift ;;
    --tree) tree="${2:?--tree needs a directory}"; shift ;;
    --require) require="${2?--require needs a list}"; shift ;;
    --tested) tested+=("${2:?--tested needs a file}"); shift ;;
    -h|--help) sed -n '3,12p' "$0"; exit 0 ;;
    -*) echo "release-check: unknown option $1" >&2; exit 2 ;;
    *) [[ -z "$dir" ]] || { echo "release-check: one release directory only" >&2; exit 2; }; dir="$1" ;;
  esac
  shift
done
[[ -n "$tag" ]] || { sed -n '5,6p' "$0" >&2; exit 2; }
tree="${tree:-$src}"
failures=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Source: tag, version of the built tree, notes, CHANGELOG, README.
version="${tag#v}"
if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  ok "tag $tag is a final version"
else
  fail "tag $tag is not vX.Y.Z (pre-release packages carry \"~\", which GitHub renames in asset names)"
fi
tree_version="$("$src/packaging/version.sh" python "$tree" 2>/dev/null || true)"
if [[ "$tree_version" == "$version" ]]; then ok "built tree version $tree_version"; else fail "built tree version ${tree_version:-unknown} is not $version"; fi
notes="$src/docs/releases/$version.md"
if [[ ! -s "$notes" ]]; then
  fail "release notes docs/releases/$version.md missing or empty"
elif [[ "$(head -n 1 "$notes")" != "# Pelagos $version" ]]; then
  fail "docs/releases/$version.md does not start with \"# Pelagos $version\""
elif [[ "$(grep -cv '^[[:space:]]*$' "$notes")" -lt 2 ]]; then
  fail "docs/releases/$version.md has a title only"
elif grep -q '^## Files' "$notes"; then
  fail "docs/releases/$version.md has a Files section (the release adds it)"
else
  ok "release notes docs/releases/$version.md"
fi
v_re="${version//./\\.}"
if [[ -f "$src/CHANGELOG.md" ]] && grep -Eq "^## \[?$v_re\]?([[:space:]]|$)" "$src/CHANGELOG.md"; then
  ok "CHANGELOG.md has $version"
else
  fail "CHANGELOG.md has no \"## $version\" section"
fi
# The README points at the latest release instead of naming one.
if [[ ! -f "$src/README.md" ]]; then
  fail "README.md missing"
elif hits="$(grep -nE "(^|[^0-9.])v?$v_re([^0-9]|$)|pelagos[_-][0-9]+\.[0-9]+\.[0-9]+|releases/(download|tag)/v[0-9]" "$src/README.md")"; then
  fail "README.md names a version: $(head -n 3 <<<"$hits" | tr '\n' ' ')"
else
  ok "README.md names no version"
fi

if [[ -n "$dir" ]]; then
  [[ -d "$dir" ]] || { fail "release directory $dir missing"; dir=""; }
fi
if [[ -n "$dir" ]]; then
  deb_version="$version-1"
  mapfile -t files < <(cd "$dir" && find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
  # Asset names GitHub keeps as they are (letters, digits and . _ + @ -).
  bad="$(printf '%s\n' "${files[@]}" | grep -Ev '^[A-Za-z0-9][A-Za-z0-9._+@-]*[A-Za-z0-9]$' || true)"
  if [[ -z "$bad" ]]; then ok "asset names kept by GitHub"; else fail "asset names GitHub would rename: $(tr '\n' ' ' <<<"$bad")"; fi
  if [[ ! -f "$dir/SHA256SUMS" ]]; then
    fail "SHA256SUMS missing"
  else
    listed="$(sed -E 's/^[0-9a-f]{64} [ *]//' "$dir/SHA256SUMS" | LC_ALL=C sort)"
    if grep -Evq '^[0-9a-f]{64} [ *][^/ ]+$' "$dir/SHA256SUMS"; then fail "SHA256SUMS has malformed lines"; fi
    expected="$(printf '%s\n' "${files[@]}" | grep -Evx 'SHA256SUMS(\.sig)?' || true)"
    if [[ "$listed" == "$expected" ]]; then
      ok "SHA256SUMS lists every file"
    else
      fail "SHA256SUMS and the directory differ: $(diff <(echo "$listed") <(echo "$expected") | grep '^[<>]' | tr '\n' ' ')"
    fi
    if (cd "$dir" && sha256sum -c --quiet --strict SHA256SUMS >/dev/null 2>&1); then ok "sums recomputed match SHA256SUMS"; else fail "a sum of SHA256SUMS does not match"; fi
  fi

  packages=()
  for f in "${files[@]}"; do
    case "$f" in
      *.deb)
        packages+=("$f")
        if [[ "$f" =~ ^pelagos_${v_re}-1_(amd64|arm64)\.deb$ ]]; then
          arch="${BASH_REMATCH[1]}"
          if command -v dpkg-deb >/dev/null; then
            control="$(dpkg-deb -f "$dir/$f" Package Version Architecture 2>/dev/null | tr '\n' ' ' || true)"
            if [[ "$control" == "Package: pelagos Version: $deb_version Architecture: $arch " ]]; then
              ok "$f control fields"
            else
              fail "$f control fields: ${control:-unreadable}"
            fi
          fi
        else
          fail "$f is not pelagos_${deb_version}_<amd64|arm64>.deb"
        fi ;;
      *.rpm)
        packages+=("$f")
        [[ "$f" =~ ^pelagos-${v_re}-1\.el[0-9]+\.(x86_64|aarch64)\.rpm$ ]] ||
          fail "$f is not pelagos-$deb_version.el<N>.<x86_64|aarch64>.rpm" ;;
    esac
  done
  IFS=, read -ra wanted <<<"$require"
  for w in "${wanted[@]}"; do
    case "$w" in
      deb:*) pat="^pelagos_${v_re}-1_${w#deb:}\.deb$" ;;
      rpm:*) pat="^pelagos-${v_re}-1\.${w#rpm:}\.[a-z0-9_]+\.rpm$" ;;
      *) fail "unknown requirement $w"; continue ;;
    esac
    if printf '%s\n' "${packages[@]}" | grep -Eq "$pat"; then ok "package $w present"; else fail "package $w missing"; fi
  done

  # release.json: the version, and exactly the debs of the directory (nodes pick theirs in it).
  if [[ ! -f "$dir/release.json" ]]; then
    fail "release.json missing"
  else
    debs="$(printf '%s\n' "${packages[@]}" | grep '\.deb$' | tr '\n' ' ' || true)"
    if msg="$(python3 -I - "$dir/release.json" "$version" "$deb_version" "$debs" <<'PY'
import json, sys
path, version, deb_version, debs = sys.argv[1:]
data = json.load(open(path))
problems = []
if data.get("version") != version:
    problems.append(f"version {data.get('version')!r}")
pkgs = data.get("packages") or []
names = sorted(p.get("file") for p in pkgs)
if names != sorted(debs.split()):
    problems.append(f"packages {names} are not the debs {sorted(debs.split())}")
for p in pkgs:
    if p.get("format") != "deb" or p.get("version") != deb_version or f"_{p.get('arch')}.deb" not in str(p.get("file")):
        problems.append(f"entry {p}")
print("; ".join(problems))
sys.exit(1 if problems else 0)
PY
    )"; then ok "release.json $version with the debs"; else fail "release.json: $msg"; fi
  fi

  if [[ ! -f "$dir/NOTES.md" ]]; then
    fail "NOTES.md missing"
  elif [[ -s "$notes" ]] && [[ "$(head -c "$(stat -c %s "$notes")" "$dir/NOTES.md")" == "$(cat "$notes")" ]]; then
    ok "NOTES.md starts with docs/releases/$version.md"
  else
    fail "NOTES.md does not start with docs/releases/$version.md"
  fi

  if [[ ${#tested[@]} -gt 0 ]]; then
    for p in "${packages[@]}"; do
      sum="$(sha256sum "$dir/$p" | cut -d' ' -f1)"
      if cat "${tested[@]}" | sed -E 's#^([0-9a-f]{64}) [ *](.*/)?#\1 #' | grep -qx "$sum $p"; then
        ok "$p is the tested file"
      else
        fail "$p differs from the tested file (or was not tested)"
      fi
    done
  fi
fi

if [[ "$failures" -gt 0 ]]; then
  echo "release-check: $failures check(s) failed for $tag" >&2
  exit 1
fi
echo "release-check: $tag ready${dir:+ in $dir}"
