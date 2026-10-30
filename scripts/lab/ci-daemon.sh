#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the daemon tier the way the CI `daemon` job does: in a debian:trixie container under Docker's
# default AppArmor profile, ISC Kea 3.2 from Cloudsmith, as an unprivileged user in bind and _kea.
#
# Usage: ci-daemon.sh [host] [pytest args...]    default host lab-docker, args "-rs"
#
# The working tree (or the commit CI_DAEMON_REF) is copied to ~/ci-daemon on the host, a Docker
# host with AppArmor; the container is removed at the end.
# shellcheck disable=SC2016  # the steps expand inside the container
set -euo pipefail

HOST="${1:-lab-docker}"
shift || true
ARGS="${*:--rs}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ -n "${CI_DAEMON_REF:-}" ]]; then
  git -C "$ROOT" archive "$CI_DAEMON_REF" backend scripts packaging/version.sh Makefile
else
  tar -C "$ROOT" -cf - --exclude .venv --exclude __pycache__ backend scripts packaging/version.sh Makefile
fi | ssh "$HOST" 'rm -rf ci-daemon && mkdir ci-daemon && tar -C ci-daemon -xf -'
# Like the runner: an idle container, each step through docker exec with stdin closed.
NAME="ci-daemon-$$"
ssh "$HOST" docker run -d --name "$NAME" -v '$HOME/ci-daemon:/src:ro' -e DEBIAN_FRONTEND=noninteractive \
  debian:trixie tail -f /dev/null >/dev/null
trap 'ssh "$HOST" docker rm -f "$NAME" >/dev/null' EXIT
step() { ssh "$HOST" docker exec "$NAME" bash -euo pipefail -c "$(printf '%q' "$1")" </dev/null; }

step 'apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends ca-certificates curl gnupg git make python3 \
  python3-venv util-linux bind9 bind9-utils bind9-dnsutils >/dev/null
curl -1sLf https://dl.cloudsmith.io/public/isc/kea-3-2/setup.deb.sh | distro=debian codename=trixie bash >/dev/null
apt-get install -y -q --no-install-recommends isc-kea-dhcp4 isc-kea-dhcp6 isc-kea-dhcp-ddns \
  isc-kea-hooks >/dev/null
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh >/dev/null 2>&1
echo "AppArmor label: $(cat /proc/self/attr/apparmor/current 2>/dev/null || echo none)"
useradd -m -G bind,_kea ci
cp -a /src /work && chown -R ci:ci /work'
step 'cd /work && runuser -u ci -- env HOME=/home/ci make venv PYTHON=3.13 UV=/usr/local/bin/uv >/dev/null 2>&1'
# The tier runs detached with its log in the container, like the job's tee: no ssh pipe to lose.
step "cd /work && (runuser -u ci -- env HOME=/home/ci make test-daemon PYTEST_ARGS='$ARGS' >daemon.log 2>&1;
  echo \$? >daemon.rc) </dev/null >/dev/null 2>&1 &"
until step 'test -e /work/daemon.rc'; do sleep 30; done 2>/dev/null
step 'cat /work/daemon.log; exit "$(cat /work/daemon.rc)"'
