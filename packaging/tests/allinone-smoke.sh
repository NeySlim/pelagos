#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Smoke test of the all-in-one image: /api/v1/health answers, and kea-dhcp4 runs with the
# seeded config and its hooks (lease_cmds answers on the control socket), then pelagos import and
# a DHCP plan that Kea writes back to its config file under the container's AppArmor profile. With
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

# A DHCP plan that rewrites kea-dhcp4.conf (config-write) must pass the permission guard with
# Kea under the container's AppArmor profile (docker-default is not a Kea profile).
# shellcheck disable=SC2016  # expands inside the container
label="$($DOCKER exec "$name" sh -c 'for p in /proc/[0-9]*; do
  [ "$(cat "$p/comm" 2>/dev/null)" = kea-dhcp4 ] && cat "$p/attr/current" 2>/dev/null && break; done' || true)"
echo "kea-dhcp4 AppArmor label: ${label:-none}"
out="$(mktemp)"
if $DOCKER exec "$name" pelagos import --engines bind,kea4,d2 --yes >"$out" 2>&1 \
  && grep -q '^done: import' "$out"; then
  ok "import adopts the bundled BIND and Kea"
else
  fail "import of the bundled engines"
  tail -n 20 "$out"
fi
rm -f "$out"
api="https://127.0.0.1:$port/api/v1"
jar="$(mktemp)"
csrf=""
for _ in $(seq 1 30); do
  csrf="$(curl -sk -c "$jar" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$password\"}" "$api/auth/login" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("csrf_token", ""))' 2>/dev/null || true)"
  [[ -n "$csrf" ]] && [[ "$(curl -sk -b "$jar" -o /dev/null -w '%{http_code}' "$api/dhcp/v4/subnets")" == 200 ]] && break
  sleep 2
done
post() { curl -sk -b "$jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d "$2" "$api$1"; }
field() { python3 -c 'import json, sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1" 2>/dev/null || true; }
subnet='{"change": {"op": "add", "target": "", "after": {"id": 77, "subnet": "198.51.100.0/24",
  "family": "v4", "pools": [{"pool": "198.51.100.10 - 198.51.100.20"}]}}}'
plan="$(post /dhcp/v4/subnets/plan "$subnet")"
if [[ "$(field state <<<"$plan")" == validated ]]; then
  ok "DHCP subnet plan validated"
  applied="$(post "/plans/$(field id <<<"$plan")/apply" '{"confirm": false}')"
  if [[ "$(field state <<<"$applied")" == applied ]]; then ok "DHCP subnet plan applied"; else fail "apply: $applied"; fi
else
  fail "DHCP subnet plan refused: $(field detail <<<"$plan")"
fi
rm -f "$jar"
if $DOCKER exec "$name" grep -q '198.51.100.0/24' /etc/kea/kea-dhcp4.conf; then
  ok "kea-dhcp4.conf rewritten by Kea with the new subnet"
else
  fail "kea-dhcp4.conf does not hold the new subnet"
fi

if [[ $failures -gt 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
