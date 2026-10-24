#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the rpm: make the source tarball from the working tree and run rpmbuild with the
# project version passed as macros (the spec never hardcodes it).
#
# Usage: build.sh [output dir]      (default: build/rpm at the repository root)
# Environment:
#   PELAGOS_WHEELS   pre-downloaded wheels for an offline build (see packaging/build-tree.sh)
#   RPM_RELEASE      release number (default 1)
# Needs: rpm-build, python3-devel, python3-pip, systemd-rpm-macros.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../.." && pwd)"
out="$(mkdir -p "${1:-$src/build/rpm}" && cd "${1:-$src/build/rpm}" && pwd)"
version="$("$src/packaging/version.sh" rpm "$src")"
release="${RPM_RELEASE:-1}"
top="$out/rpmbuild"
name="pelagos-$version"

echo "rpm: version $version release $release, topdir $top" >&2
rm -rf "$top"
mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS} "$top/stage/$name"
for item in backend packaging LICENSE NOTICE README.md; do
  cp -a "$src/$item" "$top/stage/$name/"
done
if [[ -f "$src/frontend/dist/index.html" ]]; then
  mkdir -p "$top/stage/$name/frontend"
  cp -a "$src/frontend/dist" "$top/stage/$name/frontend/dist"
fi
find "$top/stage/$name" \( -name __pycache__ -o -name .venv -o -name .pytest_cache -o -name .ruff_cache -o -name node_modules \) \
  -prune -exec rm -rf {} +
tar -C "$top/stage" -czf "$top/SOURCES/$name.tar.gz" "$name"
cp "$here/pelagos.spec" "$top/SPECS/pelagos.spec"

PELAGOS_WHEELS="${PELAGOS_WHEELS:-}" rpmbuild -ba \
  --define "_topdir $top" \
  --define "pelagos_version $version" \
  --define "pelagos_release $release" \
  "$top/SPECS/pelagos.spec"

find "$top/RPMS" "$top/SRPMS" -name '*.rpm' -exec cp -f {} "$out/" \;
echo "rpm: built" >&2
ls -1 "$out"/*.rpm >&2
