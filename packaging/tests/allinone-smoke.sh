#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Smoke test of the all-in-one image: /api/v1/health answers, and kea-dhcp4 runs with the
# seeded config and its hooks (lease_cmds answers on the control socket). With
# KEA_SOURCE=distro the seed is docker/kea-2.6, whose hooks are bare file names.
#
# Usage: allinone-smoke.sh [image]      (default: pelagos-allinone:latest)
# Environment: DOCKER (default docker), HTTPS_PORT (default 9443), NAME (container name).
set -euo pipefail

image="${1:-pelagos-allinone:latest}"
DOCKER="${DOCKER:-docker}"
port="${HTTPS_PORT:-9443}"
name="${NAME:-pelagos-aio-smoke-$$}"
failures=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
cleanup() {
  if [[ $failures -gt 0 ]]; then
    $DOCKER exec "$name" supervisorctl status || true
    $DOCKER logs --tail 80 "$name" || true
  fi
  $DOCKER rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The first start refuses a missing or weak admin password (exit 78, nothing initialized).
for weak in "" short alllowercaseletters; do
  if out="$($DOCKER run --rm -e PELAGOS_ADMIN_PASSWORD="$weak" "$image" init 2>&1)"; then
    fail "first start accepted the admin password '$weak'"
  elif grep -q PELAGOS_ADMIN_PASSWORD <<<"$out"; then
    ok "first start refuses the admin password '$weak'"
  else
    fail "first start without a usable admin password: $out"
  fi
done

# Admin password of the run (mixed prefix for the policy).
password="Smoke-$(openssl rand -hex 12)"
$DOCKER run -d --name "$name" -e PELAGOS_ADMIN_PASSWORD="$password" -p "127.0.0.1:$port:8443" "$image" >/dev/null
health=""
for _ in $(seq 1 90); do
  health="$(curl -fsk "https://127.0.0.1:$port/api/v1/health" 2>/dev/null || true)"
  [[ -n "$health" ]] && break
  sleep 2
done
echo "health: $health"
if grep -q '"status": *"ok"' <<<"$health"; then ok "health answers ok"; else fail "health"; fi

echo "image: $($DOCKER exec "$name" uname -m), Kea $($DOCKER exec "$name" kea-dhcp4 -V | head -n 1)"
probe='import json, socket, sys, time
for _ in range(60):
    try:
        s = socket.socket(socket.AF_UNIX)
        s.connect("/run/kea/kea4-ctrl-socket")
        break
    except OSError:
        time.sleep(1)
s.sendall(json.dumps({"command": sys.argv[1]}).encode())
data = b""
while chunk := s.recv(65536):
    data += chunk
print(json.dumps(json.loads(data)))'
hooks="$($DOCKER exec "$name" python3 -c "$probe" config-get 2>/dev/null || true)"
echo "hooks: $(grep -o '"library": "[^"]*"' <<<"$hooks" | tr '\n' ' ')"
if grep -q 'libdhcp_lease_cmds.so"' <<<"$hooks"; then ok "kea-dhcp4 loaded its hooks"; else fail "kea-dhcp4 hooks"; fi
leases="$($DOCKER exec "$name" python3 -c "$probe" lease4-get-all 2>/dev/null || true)"
# 0: leases, 3: none; 2 is "command not supported", the hook did not load.
if grep -qE '"result": (0|3)' <<<"$leases"; then ok "lease_cmds answers"; else fail "lease_cmds: $leases"; fi

if [[ $failures -gt 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
