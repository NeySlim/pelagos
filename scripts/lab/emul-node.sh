#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boot a Debian 13 arm64 guest under qemu-system on the lab host it runs on (an amd64 VM with
# qemu-system-arm, qemu-efi-aarch64, cloud-image-utils and qemu-utils) and give it a real
# address of the lab network through a macvtap on the host NIC. Run it ON the emulation host.
#
# Usage: emul-node.sh start <name> <address> [--mem MB] [--cpus N] [--disk SIZE]
#        emul-node.sh stop <name>
# The guest answers ssh for user lab (key ~/.ssh/id_ed25519.pub of the host user); its NIC is
# named eth0. State lives in ~/emul/<name>; the cloud image is cached in ~/.cache/pelagos-smoke
# and checked against Debian's SHA512SUMS. The host cannot reach a macvtap guest: reach it from
# another machine of the lab.
set -euo pipefail

cmd="${1:?start or stop}"
name="${2:?guest name}"
dir="$HOME/emul/$name"
case "$cmd" in
  stop)
    [[ -f "$dir/qemu.pid" ]] && sudo kill "$(cat "$dir/qemu.pid")" 2>/dev/null || true
    sudo ip link del "mvt-$name" 2>/dev/null || true
    exit 0 ;;
  start) ;;
  *) sed -n '3,12p' "$0"; exit 2 ;;
esac
address="${3:?guest address}"
shift 3
mem=3072 cpus=4 disk=16G
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mem) mem="$2"; shift 2 ;;
    --cpus) cpus="$2"; shift 2 ;;
    --disk) disk="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

nic="$(ip -o -4 route show default | awk '{print $5; exit}')"
cache="$HOME/.cache/pelagos-smoke"
base=https://cloud.debian.org/images/cloud/trixie/latest
img=debian-13-genericcloud-arm64.qcow2
mkdir -p "$cache" "$dir"
curl -fsSL "$base/SHA512SUMS" -o "$dir/SHA512SUMS"
if ! (cd "$cache" && grep " $img\$" "$dir/SHA512SUMS" | sha512sum -c --status 2>/dev/null); then
  curl -fsSL "$base/$img" -o "$cache/$img.part"
  mv "$cache/$img.part" "$cache/$img"
  (cd "$cache" && grep " $img\$" "$dir/SHA512SUMS" | sha512sum -c)
fi

mac="52:54:00:$(printf '%s' "$name" | md5sum | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')"
rm -f "$dir/disk.qcow2"
qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$img" "$dir/disk.qcow2" "$disk"
cat >"$dir/user-data" <<EOF
#cloud-config
hostname: $name
users:
  - name: lab
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat ~/.ssh/authorized_keys | head -n 1)"]
EOF
printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$name" "$(date +%s)" "$name" >"$dir/meta-data"
cat >"$dir/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match: { macaddress: "$mac" }
    set-name: eth0
    addresses: ["$address/24"]
    routes: [ { to: default, via: 10.99.0.1 } ]
    nameservers: { addresses: [1.1.1.1] }
EOF
cloud-localds --network-config="$dir/network-config" "$dir/seed.img" "$dir/user-data" "$dir/meta-data"
cp /usr/share/AAVMF/AAVMF_VARS.fd "$dir/vars.fd"

sudo ip link del "mvt-$name" 2>/dev/null || true
sudo ip link add link "$nic" name "mvt-$name" address "$mac" type macvtap mode bridge
sudo ip link set "mvt-$name" up
tap="/dev/tap$(cat "/sys/class/net/mvt-$name/ifindex")"
sudo sh -c 'exec 3<>"$0"; exec "$@"' "$tap" qemu-system-aarch64 -M virt -cpu max -accel tcg,thread=multi -smp "$cpus" -m "$mem" \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
  -drive if=pflash,format=raw,file="$dir/vars.fd" \
  -drive if=virtio,format=qcow2,file="$dir/disk.qcow2" \
  -drive if=virtio,format=raw,file="$dir/seed.img" \
  -netdev tap,id=net0,fd=3 -device virtio-net-pci,netdev=net0,mac="$mac" \
  -display none -serial file:"$dir/console.log" -daemonize -pidfile "$dir/qemu.pid"
echo "started $name at $address (mac $mac, pid $(sudo cat "$dir/qemu.pid"))"
