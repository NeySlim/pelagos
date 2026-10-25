#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Print the project version in the flavour each packaging tool expects.
#
# Usage: version.sh [python|deb|rpm|docker] [source dir]
#   python  the PEP 440 string from backend/pelagos/__init__.py (0.1.0.dev0)
#   deb     Debian upstream version: pre-release markers sort before the release (0.1.0~dev0)
#   rpm     rpm Version: same tilde rule (0.1.0~dev0)
#   docker  image tag: no tilde allowed (0.1.0-dev0)
#
# A dev version is the same string on every commit, so the package manager would take a newer
# build for the installed one: deb and rpm add a snapshot of the commit, which sorts after the
# previous snapshot and before the release (0.1.0~dev0+git20261025041500.6cc80c2 for the deb,
# 0.1.0~dev0^git20261025041500.6cc80c2 for the rpm). PELAGOS_SNAPSHOT sets it (empty: none);
# otherwise it comes from git, and a tree without git gets none.
set -euo pipefail

flavour="${1:-python}"
src="${2:-$(cd "$(dirname "$0")/.." && pwd)}"
init="$src/backend/pelagos/__init__.py"
[[ -f "$init" ]] || { echo "version.sh: $init not found" >&2; exit 1; }

py="$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$init")"
[[ -n "$py" ]] || { echo "version.sh: no __version__ in $init" >&2; exit 1; }

snapshot() {
  if [[ -n "${PELAGOS_SNAPSHOT+set}" ]]; then
    echo "$PELAGOS_SNAPSHOT"
  elif git -C "$src" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    TZ=UTC0 git -C "$src" log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd.%h 2>/dev/null || true
  fi
}

# 1.2.3.dev0 -> 1.2.3~dev0, 1.2.3a1 -> 1.2.3~a1, 1.2.3rc1 -> 1.2.3~rc1 (pre-releases sort before the release).
tilde="$(echo "$py" | sed -E 's/\.?(dev|a|b|rc)([0-9]*)$/~\1\2/')"
stamp=""
[[ "$py" == *.dev* ]] && stamp="$(snapshot)"
case "$flavour" in
  python) echo "$py" ;;
  deb) echo "$tilde${stamp:++git$stamp}" ;;
  rpm) echo "$tilde${stamp:+^git$stamp}" ;;
  docker) echo "${tilde//\~/-}" ;;
  *) echo "version.sh: unknown flavour $flavour" >&2; exit 2 ;;
esac
