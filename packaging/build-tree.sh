#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the /opt/pelagos payload shared by the deb, the rpm and the Docker images.
#
# Usage: build-tree.sh <buildroot> [source dir]
#   <buildroot>   staging root; the payload lands in <buildroot>/opt/pelagos
#   [source dir]  repository root (default: the parent of this script's directory)
#
# Produces, under <buildroot>/opt/pelagos:
#   venv/            Python virtualenv with the pelagos package and its dependencies,
#                    shebangs pointing at /opt/pelagos/venv so it works once installed
#   gunicorn_conf.py copy of backend/pelagos/gunicorn_conf.py (path used by the unit)
#   frontend/dist/   the built UI when frontend/dist/index.html exists in the source,
#                    otherwise the API-only notice page from packaging/notice
#   bin/             helper scripts (pelagos-prestart, pelagos wrapper)
#
# Environment:
#   PELAGOS_PYTHON   interpreter used to create the venv (default: python3 on PATH)
#   PELAGOS_WHEELS   directory of pre-downloaded wheels (make wheels); when set the install
#                    is offline
#   PELAGOS_LOCK     pinned, hashed dependencies (default packaging/requirements.lock)
#   PELAGOS_PREFIX   final install prefix (default /opt/pelagos), only for unusual layouts
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
buildroot="${1:?buildroot required}"
src="${2:-$(cd "$here/.." && pwd)}"
prefix="${PELAGOS_PREFIX:-/opt/pelagos}"
python="${PELAGOS_PYTHON:-python3}"
dest="$buildroot$prefix"
venv="$dest/venv"

log() { echo "build-tree: $*" >&2; }

[[ -f "$src/backend/pyproject.toml" ]] || { log "no backend/pyproject.toml under $src"; exit 1; }
command -v "$python" >/dev/null || { log "interpreter $python not found"; exit 1; }
pyver="$("$python" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
# The venv links to the versioned interpreter (python3.13, not python3), matching the
# package dependency, so a later default python3 bump cannot break it.
python="$(command -v "python$pyver" || command -v "$python")"
log "python $pyver ($python), prefix $prefix, buildroot $buildroot"

rm -rf "$dest"
mkdir -p "$dest/bin" "$dest/frontend"

# Dependencies come from the hashed lock so every package and image ships the same versions;
# a wheels directory (make wheels) also makes the build offline.
lock="${PELAGOS_LOCK:-$src/packaging/requirements.lock}"
[[ -f "$lock" ]] || { log "lock file $lock not found"; exit 1; }
pip_opts=()
if [[ -n "${PELAGOS_WHEELS:-}" ]]; then
  [[ -d "$PELAGOS_WHEELS" ]] || { log "PELAGOS_WHEELS=$PELAGOS_WHEELS is not a directory"; exit 1; }
  pip_opts=(--no-index --find-links "$PELAGOS_WHEELS")
  log "offline install from $PELAGOS_WHEELS"
fi

# uv when present (fast, relocatable venv), stock venv + pip otherwise.
if command -v uv >/dev/null 2>&1; then
  log "creating venv with uv"
  uv venv --quiet --python "$python" --relocatable "$venv"
  uv pip install --quiet --python "$venv/bin/python" "${pip_opts[@]}" --require-hashes -r "$lock"
  uv pip install --quiet --python "$venv/bin/python" "${pip_opts[@]}" --no-deps "$src/backend"
  pip_check=(uv pip check --quiet --python "$venv/bin/python")
else
  log "creating venv with $python -m venv"
  "$python" -m venv --without-pip "$venv"
  "$python" -m pip --python "$venv/bin/python" install --quiet --no-warn-script-location \
    "${pip_opts[@]}" --require-hashes -r "$lock"
  "$python" -m pip --python "$venv/bin/python" install --quiet --no-warn-script-location \
    "${pip_opts[@]}" --no-deps "$src/backend"
  pip_check=("$python" -m pip --python "$venv/bin/python" check)
fi
# A dependency missing from the lock fails the build instead of shipping a broken venv.
"${pip_check[@]}" >&2 || { log "packaging/requirements.lock is stale: run make lock"; exit 1; }

# The venv is built under the staging root but runs from $prefix: every text file in bin/
# must name $prefix/venv. pip writes a /bin/sh trampoline instead of a shebang when the
# staging path is longer than the kernel limit; turn it back into a plain shebang.
for f in "$venv"/bin/*; do
  [[ -f "$f" && ! -L "$f" ]] || continue
  grep -Iq . "$f" || continue
  if [[ "$(sed -n 1p "$f")" == "#!/bin/sh" && "$(sed -n 2p "$f")" == "'''exec' "* ]]; then
    sed -i "1,3d" "$f"
    sed -i "1i #!$prefix/venv/bin/python" "$f"
  fi
  sed -i "s|$venv|$prefix/venv|g" "$f"
done
find "$venv/lib" -name direct_url.json -delete
rm -f "$venv/.gitignore"
# pyvenv.cfg may record the staging path (uv writes the venv location in it).
sed -i "s|$venv|$prefix/venv|g" "$venv/pyvenv.cfg"
if grep -rIlF --exclude="*.pyc" "$venv" "$venv" >/dev/null 2>&1; then
  log "staging path still referenced in:"
  grep -rIlF --exclude="*.pyc" "$venv" "$venv" | head -n 20 >&2
  exit 1
fi

# Bytecode recompiled (-f: pip already wrote some with the staging path) with the final
# path, so the service user, who cannot write to /opt, never recompiles at import time.
"$venv/bin/python" -m compileall -f -q -s "$buildroot" -p / "$venv/lib" >/dev/null

cp "$src/backend/pelagos/gunicorn_conf.py" "$dest/gunicorn_conf.py"

if [[ -f "$src/frontend/dist/index.html" ]]; then
  log "frontend: using $src/frontend/dist"
  cp -a "$src/frontend/dist" "$dest/frontend/dist"
else
  log "frontend: no frontend/dist, shipping the API-only notice page"
  mkdir -p "$dest/frontend/dist"
  cp "$here/notice/index.html" "$dest/frontend/dist/index.html"
fi

install -m 0755 "$here/bin/pelagos-prestart" "$dest/bin/pelagos-prestart"
install -m 0755 "$here/bin/pelagos" "$dest/bin/pelagos"

# Everything in /opt/pelagos belongs to root and is world readable.
find "$dest" -type d -exec chmod 0755 {} +
find "$dest" -type f ! -perm -u+x -exec chmod 0644 {} +
find "$dest" -type f -perm -u+x -exec chmod 0755 {} +

log "payload ready in $dest ($(du -sh "$dest" | cut -f1))"
