#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the deb for one architecture in a Debian 13 container: native when the host has that
# architecture, emulated through qemu-user-static (binfmt) otherwise. Run from any directory.
#
# Usage: container-build.sh <amd64|arm64> [output dir]   (default: build/deb at the repository root)
# Environment: DOCKER (default docker), DEBIAN_IMAGE (default debian:trixie).
set -euo pipefail

arch="${1:?architecture required (amd64 or arm64)}"
src="$(cd "$(dirname "$0")/../.." && pwd)"
out="$(mkdir -p "${2:-$src/build/deb}" && cd "${2:-$src/build/deb}" && pwd)"
DOCKER="${DOCKER:-docker}"

# The version stamp comes from git on the host: the container gets the tree without .git.
if [[ -z "${PELAGOS_SNAPSHOT+set}" ]]; then
  PELAGOS_SNAPSHOT="$(TZ=UTC0 git -C "$src" log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd.%h 2>/dev/null || true)"
fi
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$src" log -1 --format=%ct 2>/dev/null || date +%s)}"

# The source is mounted read-only and copied, so the container never writes into the checkout
# and the output comes back owned by the caller.
$DOCKER run --rm --platform "linux/$arch" \
  -v "$src:/src:ro" -v "$out:/out" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -e SOURCE_DATE_EPOCH="$epoch" -e PELAGOS_SNAPSHOT="$PELAGOS_SNAPSHOT" \
  "${DEBIAN_IMAGE:-debian:trixie}" bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q --no-install-recommends \
      ca-certificates git make build-essential dpkg-dev debhelper fakeroot lintian \
      python3 python3-venv python3-pip >/dev/null
    echo "build host: $(uname -m), dpkg $(dpkg --print-architecture)"
    mkdir /build
    tar -C /src --exclude=./.git --exclude=./build --exclude=./frontend/node_modules \
      --exclude=./backend/.venv --exclude=./.claude -cf - . | tar -C /build -xf -
    cd /build
    packaging/deb/build.sh /build/out
    cp /build/out/*.deb /out/
    chown "$HOST_UID:$HOST_GID" /out/*.deb'
ls -l "$out"/*_"$arch".deb
