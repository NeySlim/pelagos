#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install smoke test of the deb or the rpm on a fresh, disposable host (lab VM or CI
# container booted with systemd). Run as root or with passwordless sudo.
#
# Usage: install-smoke.sh <package file>
# Checks: install, service user and groups, directory modes, units enabled but not started
# before init, `pelagos init`, both units active, /api/v1/health over HTTPS, the API-only
# notice or the UI on /, restart survives, a reinstall restarts both units (upgrade path),
# removal keeps the state.
set -euo pipefail

pkg="$(readlink -f "${1:?package file required}")"
SUDO=""
[[ $(id -u) -eq 0 ]] || SUDO="sudo -n"
failures=0

ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
check() {
  # check <description> <command...>
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}

case "$pkg" in
  *.deb)
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkg"
    ;;
  *.rpm)
    $SUDO dnf install -y -q "$pkg"
    ;;
  *) echo "unknown package type: $pkg" >&2; exit 2 ;;
esac

check "pelagos user exists" getent passwd pelagos
check "/usr/bin/pelagos runs" pelagos version
check "/opt/pelagos owned by root" test "$(stat -c %U /opt/pelagos)" = root
for d in /etc/pelagos /var/lib/pelagos; do
  check "$d is pelagos 0750" test "$(stat -c '%U %a' "$d")" = "pelagos 750"
done
for unit in pelagos.service pelagos-collector.service; do
  check "$unit enabled" test "$(systemctl is-enabled "$unit")" = enabled
  check "$unit inactive before init" test "$(systemctl is-active "$unit" || true)" = inactive
done

check "helper socket listening" systemctl is-active pelagos-helper.socket
check "helper socket is root:pelagos 0660" test "$(stat -c '%U:%G %a' /run/pelagos-helper.sock)" = "root:pelagos 660"

# The unit condition keeps the services down until the node is initialized.
$SUDO systemctl start pelagos.service pelagos-collector.service
check "start before init is skipped" test "$(systemctl is-active pelagos.service || true)" = inactive

$SUDO env PELAGOS_ADMIN_PASSWORD=smoke-test-password pelagos init --name smoke
$SUDO systemctl start pelagos.service pelagos-collector.service

health=""
for _ in $(seq 1 30); do
  health="$(curl -fsk https://127.0.0.1:8443/api/v1/health 2>/dev/null || true)"
  [[ -n "$health" ]] && break
  sleep 1
done
echo "health: $health"
check "health answers ok" grep -q '"status": *"ok"' <<<"$health"
check "pelagos.service active" systemctl is-active pelagos.service
check "pelagos-collector.service active" systemctl is-active pelagos-collector.service
check "web process runs as pelagos" test "$(ps -o user= -p "$(systemctl show -p MainPID --value pelagos.service)")" = pelagos
check "TLS key is pelagos 0600" test "$($SUDO stat -c '%U %a' /etc/pelagos/tls/server.key)" = "pelagos 600"
check "pelagos.env stays root 0644" test "$($SUDO stat -c '%U %a' /etc/pelagos/pelagos.env)" = "root 644"
check "state owned by pelagos" test "$($SUDO stat -c %U /var/lib/pelagos/cluster.toml)" = pelagos
for d in /etc/pelagos /var/lib/pelagos; do
  check "$d still 0750 with the units running" test "$($SUDO stat -c %a "$d")" = 750
done
# Certificates and pelagos.env (no secrets, root's) are public; nothing else is readable.
check "no world-readable state" test -z "$($SUDO find /etc/pelagos /var/lib/pelagos -perm -o=r ! -name '*.crt' ! -name pelagos.env)"
check "/ serves the UI or the API-only notice" bash -c \
  "curl -fsk https://127.0.0.1:8443/ | grep -qiE 'Pelagos|<div id=\"root\"'"

$SUDO systemctl restart pelagos.service
sleep 3
check "health after restart" curl -fsk https://127.0.0.1:8443/api/v1/health

# Upgrade path: reinstalling the package must restart both running units on the new payload.
web_pid="$(systemctl show -p MainPID --value pelagos.service)"
col_pid="$(systemctl show -p MainPID --value pelagos-collector.service)"
case "$pkg" in
  *.deb) $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall "$pkg" ;;
  *.rpm) $SUDO dnf reinstall -y -q "$pkg" ;;
esac
version=""
for _ in $(seq 1 30); do
  version="$(curl -fsk https://127.0.0.1:8443/api/v1/version 2>/dev/null || true)"
  [[ -n "$version" ]] && break
  sleep 1
done
echo "version after upgrade: $version"
check "web process restarted by the upgrade" \
  test "$(systemctl show -p MainPID --value pelagos.service)" != "$web_pid"
check "collector restarted by the upgrade" \
  test "$(systemctl show -p MainPID --value pelagos-collector.service)" != "$col_pid"
check "version answers after the upgrade" grep -q '"version"' <<<"$version"

if [[ "${SMOKE_KEEP:-0}" != 1 ]]; then
  case "$pkg" in
    *.deb) $SUDO env DEBIAN_FRONTEND=noninteractive apt-get remove -y -q pelagos ;;
    *.rpm) $SUDO dnf remove -y -q pelagos ;;
  esac
  check "units stopped after removal" test "$(systemctl is-active pelagos.service || true)" != active
  check "state kept after removal" $SUDO test -f /var/lib/pelagos/cluster.toml
  check "/opt/pelagos removed" test ! -e /opt/pelagos/venv
fi

if [[ "$failures" -gt 0 ]]; then
  echo "$failures check(s) failed"
  $SUDO journalctl -u pelagos.service -u pelagos-collector.service --no-pager -n 60 || true
  exit 1
fi
echo "all checks passed"
