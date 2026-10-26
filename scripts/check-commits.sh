#!/usr/bin/env bash
# Commit rules: subject of 72 characters at most, no body, no trailer, no em dash.
set -euo pipefail
base="${1:-}"
head="${2:-HEAD}"
case "$base" in ""|0000000000000000000000000000000000000000) exit 0 ;; esac
git cat-file -e "$base" 2>/dev/null || exit 0
bad=0
for c in $(git rev-list "$base..$head"); do
  msg=$(git log -1 --format=%B "$c")
  subject=$(printf '%s\n' "$msg" | head -n1)
  if [ "${#subject}" -gt 72 ]; then echo "$c: subject over 72 characters (${#subject})"; bad=1; fi
  if printf '%s\n' "$msg" | grep -qiE '^(Co-Authored-By|Signed-off-by):'; then echo "$c: trailer"; bad=1; fi
  if printf '%s' "$msg" | grep -q '—'; then echo "$c: em dash"; bad=1; fi
done
exit "$bad"
