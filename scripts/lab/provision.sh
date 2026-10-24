#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Provision the reference pair, without Pelagos, from lab-dev (idempotent).
#
# Usage: provision.sh [all|ns1|ns2|client] [--force]
#
#   lab-ns1   BIND primary for example.lan, 0.99.10.in-addr.arpa and 1.99.10.in-addr.arpa
#             (dynamic, updates signed by the hmac-md5 key kea-ddns), Kea DHCPv4 HA primary
#             (hot-standby), D2 sending updates to the primary with kea-ddns.
#   lab-ns2   BIND secondary of the same zones, Kea DHCPv4 HA standby, D2 like ns1.
#   lab-client DHCP client (systemd-networkd through netplan) on its second NIC.
#
# DHCP segment: the second NIC of lab-client shares the lab bridge, so the servers answer on
# eth0 for the dedicated subnet 10.99.1.0/24 (pool .100-.199), selected by interface name.
# BIND and Kea come from Debian 13 (Kea 2.6). The md5 secret is generated on ns1 once and
# copied to ns2; nothing secret is stored in the repository.
# --force rewrites the configurations even when Pelagos manages the host already.
set -euo pipefail

NS1=lab-ns1
NS2=lab-ns2
CLIENT=lab-client
NS1_IP=10.99.0.11
NS2_IP=10.99.0.12
HOOKS=/usr/lib/x86_64-linux-gnu/kea/hooks
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

target="${1:-all}"
force=0
[[ "${2:-}" == "--force" || "${1:-}" == "--force" ]] && force=1
[[ "$target" == "--force" ]] && target=all

on() {
  # on <host> <script on stdin>: runs as root on the host.
  "${SSH[@]}" "$1" sudo bash -s
}

put() {
  # put <host> <path> <mode> <owner:group> <content on stdin>
  "${SSH[@]}" "$1" "sudo install -D -m $3 -o ${4%%:*} -g ${4##*:} /dev/stdin $2"
}

guard() {
  if [[ $force -eq 0 ]] && "${SSH[@]}" "$1" test -e /etc/pelagos/node.toml; then
    echo "$1: Pelagos manages this host already; rerun with --force to reset its engines" >&2
    exit 1
  fi
}

packages() {
  on "$1" <<'EOF'
set -e
export DEBIAN_FRONTEND=noninteractive
need=""
for p in bind9 bind9-utils bind9-dnsutils kea-dhcp4-server kea-dhcp-ddns-server curl jq; do
  dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || need="$need $p"
done
if [ -n "$need" ]; then
  apt-get update -q >/dev/null
  apt-get install -y -q $need >/dev/null
fi
EOF
}

ddns_secret() {
  # The weak legacy key: generated on ns1 once, then reused.
  on "$NS1" <<'EOF'
set -e
if [ ! -s /etc/bind/kea-ddns.key ]; then
  tsig-keygen -a hmac-md5 kea-ddns > /etc/bind/kea-ddns.key
  chown root:bind /etc/bind/kea-ddns.key
  chmod 0640 /etc/bind/kea-ddns.key
fi
sed -n 's/.*secret "\(.*\)";.*/\1/p' /etc/bind/kea-ddns.key
EOF
}

zone_file() {
  # zone_file <origin>
  local serial
  serial="$(date -u +%Y%m%d)01"
  cat <<EOF
\$ORIGIN $1.
\$TTL 300
@ IN SOA ns1.example.lan. hostmaster.example.lan. $serial 3600 600 86400 300
@ IN NS ns1.example.lan.
@ IN NS ns2.example.lan.
EOF
  case "$1" in
    example.lan)
      printf 'ns1 IN A %s\nns2 IN A %s\nlab-dev IN A 10.99.0.15\n' "$NS1_IP" "$NS2_IP" ;;
    0.99.10.in-addr.arpa)
      printf '11 IN PTR ns1.example.lan.\n12 IN PTR ns2.example.lan.\n15 IN PTR lab-dev.example.lan.\n' ;;
  esac
}

ZONES=(example.lan 0.99.10.in-addr.arpa 1.99.10.in-addr.arpa)

bind_options() {
  cat <<'EOF'
options {
	directory "/var/cache/bind";
	listen-on { any; };
	listen-on-v6 { any; };
	recursion no;
	dnssec-validation auto;
};
EOF
}

bind_primary() {
  local zones="" z
  for z in "${ZONES[@]}"; do
    zones+="zone \"$z\" {
	type primary;
	file \"/var/lib/bind/db.$z\";
	allow-update { key kea-ddns; };
	allow-transfer { $NS2_IP; };
	also-notify { $NS2_IP; };
	notify yes;
};
"
  done
  bind_options | put "$NS1" /etc/bind/named.conf.options 0644 root:bind
  printf 'include "/etc/bind/kea-ddns.key";\n\n%s' "$zones" | put "$NS1" /etc/bind/named.conf.local 0644 root:bind
  for z in "${ZONES[@]}"; do
    zone_file "$z" | put "$NS1" "/var/lib/bind/db.$z" 0644 bind:bind
  done
  on "$NS1" <<'EOF'
set -e
rm -f /var/lib/bind/db.*.jnl
named-checkconf
systemctl enable -q named
systemctl restart named
for i in $(seq 1 20); do rndc status >/dev/null 2>&1 && break; sleep 1; done
rndc status >/dev/null
EOF
}

bind_secondary() {
  local zones="" z
  for z in "${ZONES[@]}"; do
    zones+="zone \"$z\" {
	type secondary;
	primaries { $NS1_IP; };
	file \"/var/cache/bind/db.$z\";
};
"
  done
  bind_options | put "$NS2" /etc/bind/named.conf.options 0644 root:bind
  printf '%s' "$zones" | put "$NS2" /etc/bind/named.conf.local 0644 root:bind
  on "$NS2" <<'EOF'
set -e
rm -f /var/cache/bind/db.*
named-checkconf
systemctl enable -q named
systemctl restart named
for i in $(seq 1 30); do
  dig +short @127.0.0.1 example.lan SOA | grep -q . && break
  sleep 1
done
dig +short @127.0.0.1 example.lan SOA | grep -q .
EOF
}

kea_dhcp4() {
  # kea_dhcp4 <host> <this server name>
  local host="$1" me="$2"
  cat <<EOF | put "$host" /etc/kea/kea-dhcp4.conf 0640 root:_kea
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "eth0" ] },
    "control-socket": { "socket-type": "unix", "socket-name": "kea4-ctrl-socket" },
    "lease-database": { "type": "memfile", "lfc-interval": 3600 },
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "rebind-timer": 1800,
    "multi-threading": { "enable-multi-threading": true, "thread-pool-size": 4, "packet-queue-size": 64 },
    "hooks-libraries": [
      { "library": "$HOOKS/libdhcp_lease_cmds.so" },
      { "library": "$HOOKS/libdhcp_stat_cmds.so" },
      {
        "library": "$HOOKS/libdhcp_ha.so",
        "parameters": {
          "high-availability": [ {
            "this-server-name": "$me",
            "mode": "hot-standby",
            "heartbeat-delay": 5000,
            "max-response-delay": 15000,
            "max-ack-delay": 5000,
            "max-unacked-clients": 0,
            "multi-threading": {
              "enable-multi-threading": true,
              "http-dedicated-listener": true,
              "http-listener-threads": 2,
              "http-client-threads": 2
            },
            "peers": [
              { "name": "ns1", "url": "http://$NS1_IP:8001/", "role": "primary", "auto-failover": true },
              { "name": "ns2", "url": "http://$NS2_IP:8001/", "role": "standby", "auto-failover": true }
            ]
          } ]
        }
      }
    ],
    "dhcp-ddns": { "enable-updates": true, "server-ip": "127.0.0.1", "server-port": 53001 },
    "ddns-send-updates": true,
    "ddns-override-client-update": true,
    "ddns-replace-client-name": "when-not-present",
    "ddns-generated-prefix": "dyn",
    "ddns-qualifying-suffix": "example.lan.",
    "ddns-update-on-renew": true,
    "subnet4": [
      {
        "id": 1,
        "subnet": "10.99.1.0/24",
        "interface": "eth0",
        "pools": [ { "pool": "10.99.1.100 - 10.99.1.199" } ],
        "option-data": [
          { "name": "domain-name", "data": "example.lan" },
          { "name": "domain-name-servers", "data": "$NS1_IP, $NS2_IP" }
        ]
      }
    ],
    "loggers": [
      { "name": "kea-dhcp4", "output-options": [ { "output": "stdout" } ], "severity": "INFO" }
    ]
  }
}
EOF
}

kea_d2() {
  # kea_d2 <host> <md5 secret>
  local host="$1" secret="$2" rev="" z
  for z in 1.99.10.in-addr.arpa 0.99.10.in-addr.arpa; do
    rev+="${rev:+, }{ \"name\": \"$z.\", \"key-name\": \"kea-ddns\", \"dns-servers\": [ { \"ip-address\": \"$NS1_IP\", \"port\": 53 } ] }"
  done
  cat <<EOF | put "$host" /etc/kea/kea-dhcp-ddns.conf 0640 root:_kea
{
  "DhcpDdns": {
    "ip-address": "127.0.0.1",
    "port": 53001,
    "control-socket": { "socket-type": "unix", "socket-name": "kea-ddns-ctrl-socket" },
    "tsig-keys": [ { "name": "kea-ddns", "algorithm": "HMAC-MD5", "secret": "$secret" } ],
    "forward-ddns": {
      "ddns-domains": [
        { "name": "example.lan.", "key-name": "kea-ddns", "dns-servers": [ { "ip-address": "$NS1_IP", "port": 53 } ] }
      ]
    },
    "reverse-ddns": { "ddns-domains": [ $rev ] },
    "loggers": [
      { "name": "kea-dhcp-ddns", "output-options": [ { "output": "stdout" } ], "severity": "INFO" }
    ]
  }
}
EOF
}

kea_restart() {
  on "$1" <<'EOF'
set -e
# AppArmor denies root DAC overrides for Kea: check the files as the Kea user.
runuser -u _kea -- kea-dhcp4 -t /etc/kea/kea-dhcp4.conf >/dev/null
runuser -u _kea -- kea-dhcp-ddns -t /etc/kea/kea-dhcp-ddns.conf >/dev/null
systemctl enable -q kea-dhcp4-server kea-dhcp-ddns-server
systemctl restart kea-dhcp-ddns-server kea-dhcp4-server
for i in $(seq 1 20); do [ -S /run/kea/kea4-ctrl-socket ] && break; sleep 1; done
test -S /run/kea/kea4-ctrl-socket
EOF
}

provision_ns() {
  # provision_ns <host> <name> <secret>
  local host="$1" name="$2" secret="$3"
  kea_dhcp4 "$host" "$name"
  kea_d2 "$host" "$secret"
  kea_restart "$host"
}

provision_client() {
  on "$CLIENT" <<'EOF'
set -e
nic="$(ip -o link show | awk -F': ' '$2 != "lo" && $2 != "eth0" {print $2; exit}')"
[ -n "$nic" ] || { echo "no second NIC" >&2; exit 1; }
mac="$(cat "/sys/class/net/$nic/address")"
cat > /etc/netplan/60-lab-dhcp.yaml <<NETPLAN
network:
  version: 2
  ethernets:
    lab-dhcp:
      match:
        macaddress: "$mac"
      set-name: "$nic"
      dhcp4: true
      dhcp4-overrides:
        use-routes: false
        use-dns: false
        send-hostname: true
        hostname: lab-client
      dhcp6: false
      accept-ra: false
      link-local: []
NETPLAN
chmod 0600 /etc/netplan/60-lab-dhcp.yaml
netplan apply
echo "$nic $mac"
EOF
}

wait_ha() {
  # Both peers report a hot-standby state once they have synchronized.
  local i out
  for i in $(seq 1 60); do
    out="$("${SSH[@]}" "$NS1" 'echo "{\"command\": \"ha-heartbeat\"}" | sudo socat - UNIX-CONNECT:/run/kea/kea4-ctrl-socket 2>/dev/null' || true)"
    if grep -q '"state": "hot-standby"' <<<"$out"; then echo "HA: hot-standby"; return 0; fi
    sleep 3
  done
  echo "HA did not reach hot-standby: $out" >&2
  return 1
}

case "$target" in
  all | ns1 | ns2) ;;
  client) provision_client; exit 0 ;;
  *) sed -n '3,19p' "$0"; exit 2 ;;
esac

[[ "$target" == ns2 ]] || guard "$NS1"
[[ "$target" == ns1 ]] || guard "$NS2"
packages "$NS1"
[[ "$target" == ns1 ]] || packages "$NS2"
secret="$(ddns_secret)"
[[ -n "$secret" ]] || { echo "no kea-ddns secret on $NS1" >&2; exit 1; }
for h in "$NS1" "$NS2"; do
  on "$h" <<'EOF'
command -v socat >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q socat >/dev/null
EOF
done
if [[ "$target" != ns2 ]]; then
  bind_primary
  provision_ns "$NS1" ns1 "$secret"
fi
if [[ "$target" != ns1 ]]; then
  bind_secondary
  provision_ns "$NS2" ns2 "$secret"
fi
[[ "$target" == all ]] && wait_ha
[[ "$target" == all ]] && provision_client
echo "provisioned: $target"
