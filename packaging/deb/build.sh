#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the Debian package: stage a clean source tree with debian/ at its root,
# generate the changelog from the project version and run dpkg-buildpackage.
#
# Usage: build.sh [output dir]      (default: build/deb at the repository root)
# Environment:
#   PELAGOS_WHEELS   pre-downloaded wheels for an offline build (see packaging/build-tree.sh)
#   DEB_REVISION     Debian revision (default 1)
#   DEB_BUILD_OPTIONS passed through to dpkg-buildpackage (for instance "nocheck")
# Needs: dpkg-dev, debhelper (>= 13), fakeroot, python3-venv, python3-pip (and lintian for the report).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../.." && pwd)"
out="$(mkdir -p "${1:-$src/build/deb}" && cd "${1:-$src/build/deb}" && pwd)"
version="$("$src/packaging/version.sh" deb "$src")-${DEB_REVISION:-1}"
stage="$out/pelagos-$version"

echo "deb: version $version, staging in $stage" >&2
rm -rf "$stage"
mkdir -p "$stage"
# Only what the package needs; the frontend dist is taken when it exists.
for item in backend packaging LICENSE NOTICE README.md; do
  cp -a "$src/$item" "$stage/"
done
if [[ -f "$src/frontend/dist/index.html" ]]; then
  mkdir -p "$stage/frontend"
  cp -a "$src/frontend/dist" "$stage/frontend/dist"
fi
find "$stage" \( -name __pycache__ -o -name .venv -o -name .pytest_cache -o -name .ruff_cache -o -name node_modules \) \
  -prune -exec rm -rf {} +

cp -a "$here/debian" "$stage/debian"
cat > "$stage/debian/changelog" <<EOF
pelagos ($version) unstable; urgency=medium

  * Build of pelagos $("$src/packaging/version.sh" python "$src").

 -- Pelagos maintainers <pelagos@example.org>  $(date -R -u)
EOF
chmod 0755 "$stage/debian/rules"

(
  cd "$stage"
  export PELAGOS_WHEELS="${PELAGOS_WHEELS:-}"
  dpkg-buildpackage -us -uc -b --no-pre-clean
)
echo "deb: built" >&2
ls -1 "$out"/pelagos_"$version"_*.deb >&2
if command -v lintian >/dev/null 2>&1; then
  lintian --no-tag-display-limit --suppress-tags-from-file /dev/null "$out"/pelagos_"$version"_*.changes || true
fi
