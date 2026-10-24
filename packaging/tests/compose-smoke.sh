#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Smoke test of docker/compose.yaml on a Docker host: the stack comes up, the node answers
# /api/v1/health, reaches named over rndc and the statistics channel on the compose
# network and talks to both Kea control sockets through the shared volume.
#
# Usage: compose-smoke.sh [image]      (default: pelagos:latest, built with make docker)
# Environment: DOCKER (default docker), BIND_DNS_PORT (default 5300, the host port 53 is
# often taken by a local resolver), PELAGOS_HTTPS_PORT (default 8443), PELAGOS_REPL_PORT
# (default 8444), KEEP=1 leaves the stack running.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
compose_dir="$(cd "$here/../../docker" && pwd)"
DOCKER="${DOCKER:-docker}"
PELAGOS_IMAGE="${1:-pelagos:latest}"
PELAGOS_ADMIN_PASSWORD="${PELAGOS_ADMIN_PASSWORD:-compose-smoke-password}"
BIND_DNS_PORT="${BIND_DNS_PORT:-5300}"
PELAGOS_HTTPS_PORT="${PELAGOS_HTTPS_PORT:-8443}"
PELAGOS_REPL_PORT="${PELAGOS_REPL_PORT:-8444}"
project="pelagos-smoke-$$"
# An env file rather than exported variables: DOCKER="sudo docker" resets the environment.
envfile="$(mktemp)"
cat >"$envfile" <<EOF
PELAGOS_IMAGE=$PELAGOS_IMAGE
PELAGOS_ADMIN_PASSWORD=$PELAGOS_ADMIN_PASSWORD
BIND_DNS_PORT=$BIND_DNS_PORT
PELAGOS_HTTPS_PORT=$PELAGOS_HTTPS_PORT
PELAGOS_REPL_PORT=$PELAGOS_REPL_PORT
EOF
dc() { $DOCKER compose --env-file "$envfile" -p "$project" -f "$compose_dir/compose.yaml" "$@"; }
failures=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  if [[ $failures -gt 0 ]]; then dc ps -a || true; dc logs --tail 40 || true; fi
  [[ "${KEEP:-0}" == 1 ]] || dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$envfile"
}
trap cleanup EXIT

dc up -d

health=""
for _ in $(seq 1 60); do
  health="$(curl -fsk "https://127.0.0.1:$PELAGOS_HTTPS_PORT/api/v1/health" 2>/dev/null || true)"
  [[ -n "$health" ]] && break
  sleep 2
done
echo "health: $health"
if grep -q '"status": *"ok"' <<<"$health"; then ok "health answers ok"; else fail "health"; fi

# docker-proxy accepts any TCP connection: only a server certificate proves the listener.
repl=""
for _ in $(seq 1 30); do
  repl="$(openssl s_client -connect "127.0.0.1:$PELAGOS_REPL_PORT" -showcerts </dev/null 2>/dev/null || true)"
  grep -q 'BEGIN CERTIFICATE' <<<"$repl" && break
  sleep 2
done
if grep -q 'BEGIN CERTIFICATE' <<<"$repl"; then
  ok "replication listener answers TLS on the published port"
else
  fail "replication listener on port $PELAGOS_REPL_PORT"
fi
for svc in pelagos pelagos-collector; do
  if $DOCKER inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$(dc ps -q "$svc")" \
    | grep -q '^PELAGOS_ADMIN_PASSWORD='; then
    fail "$svc carries the admin password"
  else
    ok "$svc does not carry the admin password"
  fi
done

as_pelagos=(dc exec -T pelagos setpriv --reuid pelagos --regid pelagos --init-groups)
if "${as_pelagos[@]}" rndc -c /etc/bind/pelagos/rndc-pelagos.conf status >/dev/null 2>&1; then
  ok "rndc status against the bind service"
else
  fail "rndc status against the bind service"
fi
if "${as_pelagos[@]}" curl -fs http://bind:8053/json/v1/server >/dev/null; then
  ok "statistics channel of the bind service"
else
  fail "statistics channel of the bind service"
fi
if dc exec -T pelagos id -nG pelagos | grep -qw root; then
  fail "pelagos is a member of the root group"
else
  ok "pelagos is not a member of the root group"
fi
for sock in kea4-ctrl-socket kea-ddns-ctrl-socket; do
  probe="import json, socket
s = socket.socket(socket.AF_UNIX)
s.connect('/run/kea/$sock')
s.sendall(json.dumps({'command': 'version-get'}).encode())
assert json.loads(s.recv(65536))['result'] == 0"
  if "${as_pelagos[@]}" /opt/pelagos/venv/bin/python -c "$probe" >/dev/null 2>&1; then
    ok "Kea control socket $sock"
  else
    fail "Kea control socket $sock"
  fi
done

if [[ $failures -gt 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
