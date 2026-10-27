#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Upgrade a Pelagos cluster node by node with the procedure of docs/user/upgrade.md. Run it from
# a machine that reaches every node over ssh (key login, passwordless sudo on the nodes).
#
# Usage: deploy-prod.sh [--dry-run] [--timeout SECONDS] [--ssh-option OPT]... RELEASE_DIR HOST...
#   RELEASE_DIR  a release directory (make release): pelagos_<version>_<arch>.deb and SHA256SUMS
#   HOST         ssh destinations in upgrade order: standby and secondaries first, primary last
#   --dry-run    check everything (checksums, access, health, convergence, Kea HA), change nothing
#   --timeout    seconds to wait for health and convergence after each node (default 300)
#   --settle     seconds to let the restarted collector poll before checking (default 30)
# For each node: copy the deb and check its SHA256 there, back up /etc/pelagos and
# /var/lib/pelagos to /root, apt install, wait for health, wait until cluster.toml and the audit
# log converge on every node, check Kea HA and the journal. The first problem stops the run.
set -euo pipefail

dry=0 timeout=300 settle=30 ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry=1 ;;
    --timeout) timeout="${2:?--timeout needs seconds}"; shift ;;
    --settle) settle="${2:?--settle needs seconds}"; shift ;;
    --ssh-option) ssh_opts+=(-o "${2:?--ssh-option needs an option}"); shift ;;
    -h|--help) sed -n '3,15p' "$0"; exit 0 ;;
    -*) echo "deploy: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
[[ $# -ge 2 ]] || { sed -n '6,11p' "$0" >&2; exit 2; }
release="$(cd "$1" && pwd)"; shift
hosts=("$@")

say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf '\nSTOP: %s\n' "$*" >&2; exit 1; }
field() { sed -n "s/^$1=//p" <<<"$2" | head -n 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# Runs as root on a node and prints key=value lines; argument: epoch for the journal count.
read -r -d '' PROBE <<'PY' || true
import json, re, socket, ssl, subprocess, sys, hashlib, urllib.request

def out(k, v): print(f"{k}={v}")
def run(*a):
    try:
        r = subprocess.run(a, capture_output=True, text=True)
    except OSError:
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""
def toml_value(text, section, key):
    m = re.search(r"^\[" + re.escape(section) + r"\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    v = m and re.search(r"^" + key + r"\s*=\s*(.+?)\s*$", m.group(1), re.M)
    return v.group(1).strip('"') if v else ""

out("version", run("dpkg-query", "-W", "-f=${Version}", "pelagos") or "none")
out("arch", run("dpkg", "--print-architecture") or "unknown")
units = {u: run("systemctl", "is-active", u) or "inactive" for u in ("pelagos", "pelagos-collector")}
out("units", ",".join(f"{u}:{s}" for u, s in units.items()))
out("units_ok", "yes" if all(s == "active" for s in units.values()) else "no")
try:
    node = open("/etc/pelagos/node.toml").read()
except OSError:
    node = ""
listen = toml_value(node, "node", "web_listen") or "127.0.0.1:8443"
host, port = listen.rsplit(":", 1)
host = host.strip("[]")
host = {"0.0.0.0": "127.0.0.1", "::": "::1", "": "127.0.0.1"}.get(host, host)
try:
    ctx = ssl._create_unverified_context()
    url = f"https://{'[' + host + ']' if ':' in host else host}:{port}/api/v1/health"
    out("health", json.load(urllib.request.urlopen(url, context=ctx, timeout=5)).get("status", "?"))
except Exception as e:
    out("health", f"unreachable({type(e).__name__})")
try:
    text = open("/var/lib/pelagos/cluster.toml").read()
    import tomllib
    doc = tomllib.loads(text)
    out("cluster_version", doc.get("version", "?"))
    # Parsed content, not text: a mixed-version pair orders keys differently; the header may differ.
    for k in ("version", "updated_at", "updated_by"):
        doc.pop(k, None)
    out("cluster_hash", hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()[:16])
except (OSError, ValueError):
    out("cluster_version", "none"); out("cluster_hash", "none")
try:
    with open("/var/lib/pelagos/audit/audit.jsonl", "rb") as f:
        out("audit", sum(1 for _ in f))
except OSError:
    out("audit", "0")
ha = "none"
if toml_value(node, "engines", "kea4") == "true":
    path = (toml_value(node, "engines.kea", "socket_dir") or "/run/kea") + "/" + \
        (toml_value(node, "engines.kea", "dhcp4_socket") or "kea4-ctrl-socket")
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(path)
        s.sendall(b'{"command": "status-get"}'); s.shutdown(socket.SHUT_WR)
        reply = json.loads(b"".join(iter(lambda: s.recv(65536), b"")))
        rels = reply.get("arguments", {}).get("high-availability", [])
        good = {"hot-standby", "load-balancing", "backup", "passive-backup"}
        states = []
        for rel in rels:
            local, remote = rel["ha-servers"]["local"], rel["ha-servers"].get("remote", {})
            ok = local.get("state") in good and not remote.get("communication-interrupted", False)
            states.append(f"{local.get('server-name')}:{local.get('state')}:{'ok' if ok else 'bad'}")
        ha = ",".join(states) or "none"
    except Exception as e:
        ha = f"unreachable({type(e).__name__}):bad"
out("ha", ha)
since = sys.argv[1] if len(sys.argv) > 1 else "0"
log = run("journalctl", "-u", "pelagos", "-u", "pelagos-collector", "--since", f"@{since}", "--no-pager")
out("errors", sum(1 for l in log.splitlines() if " ERROR " in l))
PY

probe() { ssh "${ssh_opts[@]}" "$1" "sudo -n python3 - ${2:-0}" <<<"$PROBE"; }
remote() { local h="$1"; shift; ssh "${ssh_opts[@]}" "$h" "$@"; }

# Every node healthy, same cluster.toml content and audit count, Kea HA in a normal state.
# Prints one line per node, then problems=<empty when all is well>.
cluster_state() {
  local h p hashes="" audits="" problems=""
  for h in "${hosts[@]}"; do
    p="$(probe "$h")" || { problems+="$h: ssh or sudo failed; "; continue; }
    [[ "$(field units_ok "$p")" == yes ]] || problems+="$h: units $(field units "$p"); "
    [[ "$(field health "$p")" == ok ]] || problems+="$h: health $(field health "$p"); "
    [[ "$(field ha "$p")" != *:bad* ]] || problems+="$h: Kea HA $(field ha "$p"); "
    hashes+="$(field cluster_hash "$p") "; audits+="$(field audit "$p") "
    echo "  $h: $(field version "$p"), cluster.toml v$(field cluster_version "$p") ($(field cluster_hash "$p")), audit $(field audit "$p"), HA $(field ha "$p")"
  done
  [[ "$(tr ' ' '\n' <<<"$hashes" | sed '/^$/d' | sort -u | wc -l)" -le 1 ]] || problems+="cluster.toml differs: $hashes; "
  [[ "$(tr ' ' '\n' <<<"$audits" | sed '/^$/d' | sort -u | wc -l)" -le 1 ]] || problems+="audit counts differ: $audits; "
  echo "problems=$problems"
}

check_cluster() {
  local out
  out="$(cluster_state)"
  problems="$(field problems "$out")"
  state_lines="$(grep -v '^problems=' <<<"$out")"$'\n'
}

wait_cluster() {
  local deadline=$((SECONDS + timeout)) problems
  while :; do
    check_cluster
    [[ -n "$problems" ]] || return 0
    ((SECONDS < deadline)) || { printf '%s' "$state_lines" >&2; die "not converged after ${timeout}s: $problems"; }
    sleep 5
  done
}

# Release directory: one version, checksums verified here before anything moves.
[[ -f "$release/SHA256SUMS" ]] || die "$release/SHA256SUMS missing"
(cd "$release" && sha256 -c --quiet SHA256SUMS) || die "checksum mismatch in $release"
target="$(cd "$release" && ls pelagos_*_*.deb | sed -E 's/^pelagos_(.*)_[^_]+\.deb$/\1/' | sort -u)"
[[ -n "$target" && "$(wc -l <<<"$target")" -eq 1 ]] || die "expected debs of one version in $release, found: ${target:-none}"
say "release $target from $release, nodes in order: ${hosts[*]}"

for h in "${hosts[@]}"; do
  p="$(probe "$h")" || die "$h: ssh login or passwordless sudo failed (or python3 missing)"
  arch="$(field arch "$p")"
  [[ "$arch" != unknown ]] || die "$h: no dpkg, only Debian nodes are supported (upgrade the others by hand)"
  [[ -f "$release/pelagos_${target}_$arch.deb" ]] || die "$h: no pelagos_${target}_$arch.deb in $release"
  installed="$(field version "$p")"
  [[ "$installed" == none || "$installed" == "$target" ]] || remote "$h" dpkg --compare-versions "'$installed'" lt "'$target'" ||
    die "$h: $installed is newer than $target; a rollback is manual (docs/user/upgrade.md, Rollback)"
  say "$h: $arch, installed $(field version "$p"), health $(field health "$p"), units $(field units "$p")"
done
say "cluster before the upgrade"
check_cluster
printf '%s' "$state_lines"
[[ -z "$problems" ]] || die "cluster not healthy before the upgrade: $problems"

if [[ "$dry" == 1 ]]; then
  for h in "${hosts[@]}"; do
    [[ "$(field version "$(probe "$h")")" == "$target" ]] && say "dry run: $h already on $target, skipped" ||
      say "dry run: $h would be backed up and upgraded to $target"
  done
  say "dry run: all checks passed, nothing changed"
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
for h in "${hosts[@]}"; do
  p="$(probe "$h")"
  before="$(field version "$p")" audit_before="$(field audit "$p")" arch="$(field arch "$p")"
  if [[ "$before" == "$target" ]]; then say "$h: already on $target, skipped"; continue; fi
  deb="pelagos_${target}_$arch.deb"
  sum="$(sed -n "s/^\([0-9a-f]\{64\}\)  *\*\{0,1\}$deb\$/\1/p" "$release/SHA256SUMS")"
  say "$h: upgrade $before -> $target"

  tmp="$(remote "$h" mktemp -d)"
  scp -q "${ssh_opts[@]}" "$release/$deb" "$h:$tmp/$deb" || die "$h: copy of $deb failed"
  remote "$h" "chmod 755 $tmp && chmod 644 $tmp/$deb && echo '$sum  $tmp/$deb' | sha256sum -c --quiet" ||
    die "$h: SHA256 of the copied deb does not match"

  backup="/root/pelagos-state-$stamp-$before.tar.gz"
  remote "$h" "sudo -n sh -euc 'systemctl stop pelagos pelagos-collector
    trap \"systemctl start pelagos pelagos-collector\" EXIT
    tar -C / --exclude=\"var/lib/pelagos/series.sqlite*\" -czf $backup etc/pelagos var/lib/pelagos'" ||
    die "$h: backup failed (services restarted, nothing installed)"
  say "$h: state saved in $backup"

  since="$(remote "$h" date +%s)"
  remote "$h" "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -q $tmp/$deb" >/dev/null ||
    die "$h: apt install failed. Backup: $backup"
  remote "$h" "rm -rf $tmp"
  now="$(field version "$(probe "$h")")"
  [[ "$now" == "$target" ]] || die "$h: installed version is $now, expected $target"

  say "$h: installed, waiting ${settle}s, then for health and convergence (up to ${timeout}s)"
  sleep "$settle"
  wait_cluster
  p="$(probe "$h" "$since")"
  (($(field audit "$p") >= audit_before)) || die "$h: audit count went down ($audit_before -> $(field audit "$p"))"
  [[ "$(field errors "$p")" == 0 ]] ||
    die "$h: $(field errors "$p") ERROR lines in the journal since the install (journalctl -u pelagos -u pelagos-collector)"
  printf '%s' "$state_lines"
  say "$h: done"
done
say "all nodes on $target"
