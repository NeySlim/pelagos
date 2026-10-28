#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Roll lab VMs back to their base snapshot through the Proxmox API.
#
# Usage: rollback.sh <vmid|name|all> [--list] [--no-start] [--no-wait]
#   all          every target VM (lab-ns1, lab-ns2, lab-rpm, lab-client, lab-pkg-rpm,
#                lab-docker, lab-arm64), never lab-dev nor the gateway
#   --list       show the snapshots of the VM(s) and exit
#   --no-start   leave the VM stopped after the rollback
#   --no-wait    do not wait for ssh and cloud-init after the start
#
# After the rollback the VM's cloud-init ssh keys get the key of LAB_SSH_PUBKEY (default
# ~/.ssh/id_ed25519.pub): the new instance id reruns cloud-init, so lab-dev can log in.
#
# Needs: curl, jq, python3, the API token header value in ~/.config/pelagos-lab/pve-token
# (the whole "PVEAPIToken=user@realm!name=uuid" string) and the API base URL in
# ~/.config/pelagos-lab/pve-api (for instance https://pve.example.lan:8006/api2/json)
# or in PVE_API. The Proxmox node name comes from PVE_NODE (default pve).
set -euo pipefail

CONF_DIR="${PVE_CONF_DIR:-$HOME/.config/pelagos-lab}"
TOKEN_FILE="${PVE_TOKEN_FILE:-$CONF_DIR/pve-token}"
if [[ -z "${PVE_API:-}" ]]; then
  [[ -r "$CONF_DIR/pve-api" ]] || { echo "set PVE_API or write the API base URL to $CONF_DIR/pve-api" >&2; exit 1; }
  PVE_API="$(tr -d '\n' < "$CONF_DIR/pve-api")"
fi
PVE_NODE="${PVE_NODE:-pve}"
PUBKEY_FILE="${LAB_SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"

# vmid:name:snapshot:address. lab-dev (9115) runs this script and the gateway (9110) is shared:
# neither is listed, so neither resolves; lab-dev is restored from the workstation only.
VMS=(
  "9111:lab-ns1:clean:10.99.0.11"
  "9112:lab-ns2:clean:10.99.0.12"
  "9113:lab-rpm:clean:10.99.0.13"
  "9114:lab-client:clean:10.99.0.14"
  "9116:lab-pkg-rpm:rpmbuild:10.99.0.16"
  "9117:lab-docker:docker:10.99.0.17"
  "9118:lab-arm64:emul:10.99.0.18"
  "9171:lab-d3a:legacy:10.99.0.71"
  "9172:lab-d3b:legacy:10.99.0.72"
  "9173:lab-d3c:legacy:10.99.0.73"
)
# "all" targets only the disposable test VMs; the gateway (9110) is never rolled back.
ALL_TARGETS=(9111 9112 9113 9114 9116 9117)

usage() { sed -n '3,18p' "$0"; exit 2; }

[[ $# -ge 1 ]] || usage
target="$1"; shift
list=0; start=1; wait_up=1
for arg in "$@"; do
  case "$arg" in
    --list) list=1 ;;
    --no-start) start=0 ;;
    --no-wait) wait_up=0 ;;
    *) usage ;;
  esac
done

[[ -r "$TOKEN_FILE" ]] || { echo "token file $TOKEN_FILE not readable" >&2; exit 1; }
AUTH="Authorization: $(tr -d '\n' < "$TOKEN_FILE")"

api() {
  # api <method> <path> [curl data args...]
  local method="$1" path="$2"; shift 2
  curl -fsS -k -X "$method" -H "$AUTH" "$PVE_API/nodes/$PVE_NODE/qemu$path" "$@"
}

resolve() {
  local entry vmid name
  for entry in "${VMS[@]}"; do
    IFS=: read -r vmid name _ <<<"$entry"
    if [[ "$1" == "$vmid" || "$1" == "$name" ]]; then echo "$entry"; return 0; fi
  done
  echo "unknown VM $1" >&2; return 1
}

wait_task() {
  # wait_task <upid>
  local upid="$1" status
  while :; do
    status=$(curl -fsS -k -H "$AUTH" "$PVE_API/nodes/$PVE_NODE/tasks/$upid/status" | jq -r '.data.status')
    [[ "$status" == "running" ]] || break
    sleep 2
  done
  local exit_status
  exit_status=$(curl -fsS -k -H "$AUTH" "$PVE_API/nodes/$PVE_NODE/tasks/$upid/status" | jq -r '.data.exitstatus')
  [[ "$exit_status" == "OK" ]] || { echo "task $upid ended with $exit_status" >&2; return 1; }
}

ensure_sshkey() {
  # ensure_sshkey <vmid>: appends our public key to the VM's cloud-init keys when missing.
  # Proxmox stores sshkeys percent-encoded; curl form-encodes the value once more.
  local vmid="$1" current encoded
  [[ -r "$PUBKEY_FILE" ]] || return 0
  current="$(api GET "/$vmid/config" | jq -r '.data.sshkeys // ""')"
  encoded="$(python3 -c '
import sys, urllib.parse
keys = urllib.parse.unquote(sys.argv[1])
pub = open(sys.argv[2]).read().strip()
if pub in keys:
    sys.exit(0)
keys = keys.rstrip("\n") + ("\n" if keys.strip() else "") + pub + "\n"
print(urllib.parse.quote(keys, safe=""))
' "$current" "$PUBKEY_FILE")"
  [[ -n "$encoded" ]] || return 0
  api PUT "/$vmid/config" --data-urlencode "sshkeys=$encoded" >/dev/null
  echo "   cloud-init ssh key added"
}

wait_ssh() {
  # wait_ssh <address>: until ssh answers and cloud-init is done (at most 6 minutes).
  local addr="$1" i
  for i in $(seq 1 72); do
    if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "lab@$addr" \
      'cloud-init status --wait >/dev/null 2>&1 || true' 2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  echo "   $addr: ssh did not come up" >&2
  return 1
}

rollback_one() {
  local vmid name snap addr
  IFS=: read -r vmid name snap addr <<<"$(resolve "$1")"
  if [[ $list -eq 1 ]]; then
    echo "== $name ($vmid)"
    api GET "/$vmid/snapshot" | jq -r '.data[] | select(.name != "current") | "\(.name)\t\(.snaptime // 0 | todate)\t\(.description // "")"'
    return 0
  fi
  echo "== $name ($vmid): rollback to '$snap'"
  local upid
  upid=$(api POST "/$vmid/snapshot/$snap/rollback" --data-urlencode "start=0" | jq -r '.data')
  wait_task "$upid"
  ensure_sshkey "$vmid"
  ssh-keygen -R "$addr" >/dev/null 2>&1 || true
  ssh-keygen -R "$name" >/dev/null 2>&1 || true
  if [[ $start -eq 1 ]]; then
    if [[ "$(api GET "/$vmid/status/current" | jq -r '.data.status')" != "running" ]]; then
      upid=$(api POST "/$vmid/status/start" | jq -r '.data')
      wait_task "$upid"
    fi
  fi
  echo "   rolled back (start=$start)"
}

targets=()
if [[ "$target" == "all" ]]; then
  targets=("${ALL_TARGETS[@]}")
else
  targets=("$target")
fi
for t in "${targets[@]}"; do rollback_one "$t"; done
if [[ $list -eq 0 && $start -eq 1 && $wait_up -eq 1 ]]; then
  for t in "${targets[@]}"; do
    IFS=: read -r _ name _ addr <<<"$(resolve "$t")"
    wait_ssh "$addr" && echo "== $name: ssh up"
  done
fi
