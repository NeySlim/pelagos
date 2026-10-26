#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build UCM (Ultimate CA Manager) from its git repository and run it in Docker on a lab VM, for
# the certificate tests of the lab tier (backend/tests/lab/test_ucm_lab.py).
#
# Usage: ucm.sh [host] [ref]      default host 10.99.0.22 (lab-ucm), ref UCM_REF or v2.245
#
# The checkout and the frontend build happen on lab-dev (Node 22), the image is built on the VM
# from UCM's own Dockerfile and runs as container "ucm" on 8443 (API, ACME) and 8080 (CRL, OCSP).
# Idempotent: an image already built from the same commit is reused and a running container kept.
# Needs: git access to the UCM repository (ssh alias github-ucm), npm, ssh to the VM as lab.
set -euo pipefail

HOST="${1:-10.99.0.22}"
REF="${2:-${UCM_REF:-v2.245}}"
REPO="${UCM_REPO:-git@github-ucm:NeySlim/ultimate-ca-manager.git}"
CACHE="${UCM_CACHE:-$HOME/.cache/pelagos-lab/ucm}"
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "lab@$HOST")

if [[ ! -d "$CACHE/.git" ]]; then
  mkdir -p "$(dirname "$CACHE")"
  git clone -q "$REPO" "$CACHE"
fi
git -C "$CACHE" fetch -q --tags origin
git -C "$CACHE" checkout -q --detach "$REF"
COMMIT="$(git -C "$CACHE" rev-parse --short HEAD)"
TAG="ucm:git-$COMMIT"
echo "UCM $REF ($COMMIT) on $HOST"

"${SSH[@]}" 'command -v docker >/dev/null || { sudo DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null;
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io >/dev/null; sudo usermod -aG docker lab; }'

if ! "${SSH[@]}" "sudo docker image inspect $TAG >/dev/null 2>&1"; then
  if [[ ! -f "$CACHE/frontend/dist/.commit" || "$(cat "$CACHE/frontend/dist/.commit")" != "$COMMIT" ]]; then
    (cd "$CACHE/frontend" && npm ci --no-fund --no-audit >/dev/null && npm run build >/dev/null)
    echo "$COMMIT" > "$CACHE/frontend/dist/.commit"
  fi
  tar -C "$CACHE" --exclude=.git --exclude=frontend/node_modules -czf - . \
    | "${SSH[@]}" "rm -rf ucm-src && mkdir ucm-src && tar -C ucm-src -xzf - && cd ucm-src && sudo docker build -q -t $TAG ."
fi

"${SSH[@]}" "if [ \"\$(sudo docker inspect -f '{{.Config.Image}}' ucm 2>/dev/null)\" != '$TAG' ]; then
  sudo docker rm -f ucm >/dev/null 2>&1 || true
  sudo docker run -d --name ucm --restart unless-stopped -p 8443:8443 -p 8080:8080 \
    -e UCM_FQDN=$HOST -v ucm-data:/opt/ucm/data -v ucm-config:/etc/ucm $TAG >/dev/null
fi"
for _ in $(seq 1 60); do
  if curl -ksf "https://$HOST:8443/health" >/dev/null; then
    echo "UCM up: https://$HOST:8443"
    exit 0
  fi
  sleep 3
done
echo "UCM did not answer on https://$HOST:8443/health" >&2
exit 1
