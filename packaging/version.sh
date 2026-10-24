#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Print the project version in the flavour each packaging tool expects.
#
# Usage: version.sh [python|deb|rpm|docker] [source dir]
#   python  the PEP 440 string from backend/pelagos/__init__.py (0.1.0.dev0)
#   deb     Debian upstream version: pre-release markers sort before the release (0.1.0~dev0)
#   rpm     rpm Version: same tilde rule (0.1.0~dev0)
#   docker  image tag: no tilde allowed (0.1.0-dev0)
set -euo pipefail

flavour="${1:-python}"
src="${2:-$(cd "$(dirname "$0")/.." && pwd)}"
init="$src/backend/pelagos/__init__.py"
[[ -f "$init" ]] || { echo "version.sh: $init not found" >&2; exit 1; }

py="$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$init")"
[[ -n "$py" ]] || { echo "version.sh: no __version__ in $init" >&2; exit 1; }

# 1.2.3.dev0 -> 1.2.3~dev0, 1.2.3a1 -> 1.2.3~a1, 1.2.3rc1 -> 1.2.3~rc1 (pre-releases sort before the release).
tilde="$(echo "$py" | sed -E 's/\.?(dev|a|b|rc)([0-9]*)$/~\1\2/')"
case "$flavour" in
  python) echo "$py" ;;
  deb | rpm) echo "$tilde" ;;
  docker) echo "${tilde//\~/-}" ;;
  *) echo "version.sh: unknown flavour $flavour" >&2; exit 2 ;;
esac
