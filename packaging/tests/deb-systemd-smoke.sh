#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install and start the deb on Debian 13 of the package's architecture booted with systemd,
# next to BIND 9.20 and Kea 2.6 from Debian (the production engines).
#   container  a privileged Debian 13 container running systemd, when the host has the
#              package's architecture (native CI runners)
#   vm         a Debian 13 cloud image under qemu-system (full emulation) otherwise: systemd
#              sandboxing (namespaces, seccomp) does not work under qemu-user, so an emulated
#              container cannot start the hardened units
#
# Usage: deb-systemd-smoke.sh <pelagos_<version>_<arch>.deb>
# Checks: the box really runs the package's architecture; Kea 2.6 resolves the hooks named by
# bare file name in docker/kea-2.6; install-smoke.sh (install, init, units, health, upgrade
# restart); `pelagos import` adopts BIND and Kea; the API reads zones and Kea leases.
# Environment: SMOKE_MODE (auto, container or vm), DOCKER (default docker), DEBIAN_IMAGE
# (default debian:trixie), SMOKE_CACHE (cloud image cache, default ~/.cache/pelagos-smoke),
# KEEP=1 leaves the container or VM running. vm needs qemu-system-arm, qemu-efi-aarch64,
# cloud-image-utils and qemu-utils.
set -euo pipefail

deb="$(readlink -f "${1:?deb file required}")"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
DOCKER="${DOCKER:-docker}"
arch="${deb##*_}"
arch="${arch%.deb}"
case "$arch" in
  amd64) machine=x86_64 ;;
  arm64) machine=aarch64 ;;
  *) echo "unsupported architecture in $deb: $arch" >&2; exit 2 ;;
esac
mode="${SMOKE_MODE:-auto}"
if [[ "$mode" == auto ]]; then
  if [[ "$(uname -m)" == "$machine" ]]; then mode=container; else mode=vm; fi
fi
password=Smoke-Test-Password-1
packages="systemd systemd-sysv dbus ca-certificates curl openssl procps python3 sudo bind9 bind9-utils"
packages="$packages bind9-dnsutils kea-dhcp4-server kea-dhcp-ddns-server"
work="$(mktemp -d)"
failures=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Backend: in_box <command...> runs as root in the box; put_box <file> <path> copies a file in.
name="pelagos-debsmoke-$arch-$$"
ssh_port=""
qemu_pid=""
ssh_box() {
  ssh -i "$work/key" -p "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 smoke@127.0.0.1 "$@"
}
in_box() {
  if [[ "$mode" == container ]]; then
    $DOCKER exec -i "$name" "$@"
  else
    ssh_box "sudo $(printf '%q ' "$@")"
  fi
}
put_box() {
  if [[ "$mode" == container ]]; then
    $DOCKER cp "$1" "$name:$2"
  else
    ssh_box "cat > /tmp/put.$$ && sudo install -m 0644 /tmp/put.$$ $(printf '%q' "$2") && rm -f /tmp/put.$$" <"$1"
  fi
}

cleanup() {
  if [[ $failures -gt 0 ]]; then
    in_box journalctl --no-pager -n 80 -u kea-dhcp4-server -u kea-dhcp-ddns-server -u named \
      -u pelagos -u pelagos-collector 2>/dev/null || true
  fi
  if [[ "${KEEP:-0}" != 1 ]]; then
    if [[ "$mode" == container ]]; then
      $DOCKER rm -f "$name" >/dev/null 2>&1 || true
    elif [[ -n "$qemu_pid" ]]; then
      kill "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
  elif [[ "$mode" == container ]]; then
    echo "kept: container $name"
  else
    echo "kept: VM pid $qemu_pid, ssh -p $ssh_port -i $work/key smoke@127.0.0.1"
  fi
}
trap cleanup EXIT

start_container() {
  local image="pelagos-debsmoke:$arch"
  # No policy-rc.d, so maintainer scripts start units as on a host. No AppArmor userspace: a
  # profile loaded from a privileged container would land in the runner's kernel. systemd-binfmt
  # masked: at shutdown it unregisters every binfmt handler of the host, qemu's included.
  $DOCKER build --platform "linux/$arch" -t "$image" - <<EOF
FROM ${DEBIAN_IMAGE:-debian:trixie}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get install -y -q --no-install-recommends $packages \
 && rm -f /usr/sbin/policy-rc.d \
 && systemctl mask getty@.service systemd-logind.service console-getty.service \
      systemd-binfmt.service systemd-modules-load.service proc-sys-fs-binfmt_misc.automount \
      proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
  $DOCKER run -d --name "$name" --platform "linux/$arch" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock "$image" >/dev/null
}

start_vm() {
  [[ "$arch" == arm64 ]] || { echo "vm mode emulates arm64 only" >&2; exit 2; }
  local cache="${SMOKE_CACHE:-$HOME/.cache/pelagos-smoke}"
  local base=https://cloud.debian.org/images/cloud/trixie/latest
  local img=debian-13-genericcloud-arm64.qcow2
  mkdir -p "$cache"
  curl -fsSL "$base/SHA512SUMS" -o "$work/SHA512SUMS"
  if ! (cd "$cache" && grep " $img\$" "$work/SHA512SUMS" | sha512sum -c --status 2>/dev/null); then
    curl -fsSL "$base/$img" -o "$cache/$img.part"
    mv "$cache/$img.part" "$cache/$img"
    (cd "$cache" && grep " $img\$" "$work/SHA512SUMS" | sha512sum -c)
  fi
  qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$img" "$work/disk.qcow2" 12G
  ssh-keygen -q -t ed25519 -N '' -f "$work/key"
  cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: smoke
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$work/key.pub")"]
EOF
  printf 'instance-id: pelagos-smoke-%s\nlocal-hostname: smoke\n' "$$" >"$work/meta-data"
  cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
  ssh_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  cp /usr/share/AAVMF/AAVMF_VARS.fd "$work/vars.fd"
  qemu-system-aarch64 -M virt -cpu max -accel tcg,thread=multi -smp "${SMOKE_CPUS:-4}" -m "${SMOKE_MEM:-3072}" \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
    -drive if=pflash,format=raw,file="$work/vars.fd" \
    -drive if=virtio,format=qcow2,file="$work/disk.qcow2" \
    -drive if=virtio,format=raw,file="$work/seed.img" \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$ssh_port"-:22 -device virtio-net-pci,netdev=net0 \
    -display none -serial file:"$work/console.log" -daemonize -pidfile "$work/qemu.pid"
  qemu_pid="$(cat "$work/qemu.pid")"
  for _ in $(seq 1 180); do
    ssh_box true 2>/dev/null && break
    sleep 5
  done
  ssh_box true || { tail -n 40 "$work/console.log"; fail "VM did not answer ssh"; exit 1; }
  in_box cloud-init status --wait >/dev/null || true
  in_box env DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null
  # shellcheck disable=SC2086
  in_box env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $packages >/dev/null
}

echo "mode: $mode (host $(uname -m), package $arch)"
if [[ "$mode" == container ]]; then start_container; else start_vm; fi
state=""
for _ in $(seq 1 120); do
  state="$(in_box systemctl is-system-running 2>/dev/null || true)"
  [[ "$state" == running || "$state" == degraded ]] && break
  sleep 2
done
echo "systemd: $state"
[[ "$state" == running || "$state" == degraded ]] || { fail "systemd did not boot"; exit 1; }
[[ "$state" == running ]] || in_box systemctl --failed --no-pager --no-legend || true

echo "box: $(in_box uname -m) dpkg $(in_box dpkg --print-architecture), $(in_box sh -c '. /etc/os-release; echo $PRETTY_NAME')"
echo "engines: Kea $(in_box kea-dhcp4 -V | head -n 1), $(in_box named -v)"
if [[ "$(in_box uname -m)" == "$machine" ]]; then ok "runs on $machine"; else fail "not on $machine"; fi

# The repository's Kea 2.6 configs name hooks by file name only; Kea resolves them in its
# compiled-in hooks directory, whatever the architecture.
put_box "$repo/docker/kea-2.6/kea-dhcp4.conf" /etc/kea/kea-dhcp4.conf
put_box "$repo/docker/kea-2.6/kea-dhcp-ddns.conf" /etc/kea/kea-dhcp-ddns.conf
in_box sh -c 'chown root:_kea /etc/kea/*.conf && chmod 0640 /etc/kea/*.conf'
in_box systemctl restart kea-dhcp4-server kea-dhcp-ddns-server
probe='import json, socket, sys, time
for _ in range(60):
    try:
        s = socket.socket(socket.AF_UNIX)
        s.connect(sys.argv[1])
        break
    except OSError:
        time.sleep(1)
s.sendall(json.dumps({"command": sys.argv[2]}).encode())
data = b""
while chunk := s.recv(65536):
    data += chunk
print(json.dumps(json.loads(data)))'
hooks="$(in_box python3 -c "$probe" /run/kea/kea4-ctrl-socket config-get 2>/dev/null || true)"
echo "hooks: $(grep -o '"library": "[^"]*"' <<<"$hooks" | tr '\n' ' ')"
# config-get reports the library resolved in the hooks directory of this architecture.
if grep -q "\"library\": \"/usr/lib/$machine-linux-gnu/kea/hooks/libdhcp_lease_cmds.so\"" <<<"$hooks"; then
  ok "Kea 2.6 resolved the bare hook names in /usr/lib/$machine-linux-gnu/kea/hooks"
else
  fail "Kea 2.6 config-get with the hooks"
fi
leases="$(in_box python3 -c "$probe" /run/kea/kea4-ctrl-socket lease4-get-all 2>/dev/null || true)"
# 0: leases, 3: none; 2 would be "command not supported" (hook not loaded).
if grep -qE '"result": (0|3)' <<<"$leases"; then ok "lease_cmds answers"; else fail "lease_cmds: $leases"; fi

put_box "$deb" "/root/$(basename "$deb")"
put_box "$here/install-smoke.sh" /root/install-smoke.sh
in_box apt-get update -q >/dev/null
# Emulation is slow: the units get longer to answer.
wait=30
[[ "$mode" == vm ]] && wait=300
if in_box env SMOKE_KEEP=1 SMOKE_WAIT="$wait" bash /root/install-smoke.sh "/root/$(basename "$deb")"; then
  ok "install-smoke.sh"
else
  fail "install-smoke.sh"
fi

import_log="$work/import.log"
if in_box pelagos import --engines bind,kea4,d2 --yes >"$import_log" 2>&1 \
  && grep -q '^done: import' "$import_log"; then
  ok "import adopts BIND and Kea"
else
  fail "import of BIND and Kea"
  tail -n 30 "$import_log"
fi
in_box systemctl restart pelagos pelagos-collector
api='import json, ssl, sys, time, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
base = "https://127.0.0.1:8443/api/v1"
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor())
def call(path, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json"})
    return json.loads(opener.open(req, timeout=120).read())
for _ in range(int(sys.argv[2])):
    try:
        call("/auth/login", {"username": "admin", "password": sys.argv[1]})
        break
    except Exception:
        time.sleep(2)
print("zones", len(call("/dns/zones")["items"]))
print("leases", len(call("/dhcp/v4/leases")["items"]))'
if out="$(in_box python3 -c "$api" "$password" "$wait" 2>&1)"; then
  ok "API reads zones and Kea leases ($(tr '\n' ' ' <<<"$out"))"
else
  fail "API after the import: $out"
fi

if [[ $failures -gt 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed ($arch, $mode)"
