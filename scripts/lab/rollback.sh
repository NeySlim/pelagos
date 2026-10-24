#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Roll lab VMs back to their base snapshot through the Proxmox API.
#
# Usage: rollback.sh <vmid|name|all> [--list] [--no-start]
#   all          every target VM (lab-ns1, lab-ns2, lab-rpm, lab-client), never lab-dev
#   --list       show the snapshots of the VM(s) and exit
#   --no-start   leave the VM stopped after the rollback
#
# Needs: curl, jq, the API token header value in ~/.config/pelagos-lab/pve-token
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

# vmid:name:snapshot
VMS=(
  "9111:lab-ns1:clean"
  "9112:lab-ns2:clean"
  "9113:lab-rpm:clean"
  "9114:lab-client:clean"
  "9115:lab-dev:ready"
  "9116:lab-pkg-rpm:clean"
  "9117:lab-docker:clean"
)
# "all" targets only the disposable test VMs; the gateway (9110) is never rolled back.
ALL_TARGETS=(9111 9112 9113 9114)

usage() { sed -n '3,12p' "$0"; exit 2; }

[[ $# -ge 1 ]] || usage
target="$1"; shift
list=0; start=1
for arg in "$@"; do
  case "$arg" in
    --list) list=1 ;;
    --no-start) start=0 ;;
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
  local entry
  for entry in "${VMS[@]}"; do
    IFS=: read -r vmid name snap <<<"$entry"
    if [[ "$1" == "$vmid" || "$1" == "$name" ]]; then echo "$vmid:$name:$snap"; return 0; fi
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

rollback_one() {
  IFS=: read -r vmid name snap <<<"$(resolve "$1")"
  if [[ $list -eq 1 ]]; then
    echo "== $name ($vmid)"
    api GET "/$vmid/snapshot" | jq -r '.data[] | select(.name != "current") | "\(.name)\t\(.snaptime // 0 | todate)\t\(.description // "")"'
    return 0
  fi
  echo "== $name ($vmid): rollback to '$snap'"
  local upid
  upid=$(api POST "/$vmid/snapshot/$snap/rollback" --data-urlencode "start=$start" | jq -r '.data')
  wait_task "$upid"
  echo "   done (start=$start)"
}

if [[ "$target" == "all" ]]; then
  for vmid in "${ALL_TARGETS[@]}"; do rollback_one "$vmid"; done
else
  rollback_one "$target"
fi
