#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Entrypoint of the Pelagos images. Runs as root to prepare the shared volumes, then drops
# to the pelagos user. Modes: init (prepare and exit), serve, collector, allinone, or any
# other command which is executed as given.
#
# Environment:
#   PELAGOS_ADMIN_PASSWORD  when set and node.toml is absent, runs "pelagos init" on first start
#   PELAGOS_ADMIN_PASSWORD_FILE  file holding that password (a compose or swarm secret)
#   PELAGOS_NODE_NAME       node name for init (default: pelagos)
#   PELAGOS_WEB_URL, PELAGOS_REPLICATION_URL  advertised URLs for init (optional)
#   PELAGOS_KEA_GID         group allowed to use the Kea sockets in /run/kea (default 8450, the
#                           kea group, primary group of the root Kea daemons in compose)
#   PELAGOS_BIND_GID        group of the BIND container (default 53, the ISC image)
#   PELAGOS_BIND_UID        user of named, owner of its working directory (default 53)
#   PELAGOS_BIND_HOST      address of named for rndc (default 127.0.0.1; "bind" in compose); when
#                           not local, node.toml [engines.bind] gets rndc_address, statistics_url
#                           and query_address for that host
set -eu

mode="${1:-serve}"
[ $# -gt 0 ] && shift
ETC="${PELAGOS_ETC:-/etc/pelagos}"
VAR="${PELAGOS_VAR:-/var/lib/pelagos}"
RUN="${PELAGOS_RUN:-/run/pelagos}"
SEED=/usr/share/pelagos/seed
KEA_GID="${PELAGOS_KEA_GID:-8450}"
BIND_GID="${PELAGOS_BIND_GID:-53}"
BIND_HOST="${PELAGOS_BIND_HOST:-127.0.0.1}"
BIND_UID="${PELAGOS_BIND_UID:-53}"

log() { echo "pelagos-entrypoint: $*" >&2; }

if [ -z "${PELAGOS_ADMIN_PASSWORD:-}" ] && [ -n "${PELAGOS_ADMIN_PASSWORD_FILE:-}" ]; then
  [ -r "$PELAGOS_ADMIN_PASSWORD_FILE" ] || { log "cannot read $PELAGOS_ADMIN_PASSWORD_FILE"; exit 78; }
  PELAGOS_ADMIN_PASSWORD="$(cat "$PELAGOS_ADMIN_PASSWORD_FILE")"
  export PELAGOS_ADMIN_PASSWORD
fi

group_name() {
  # group_name <gid> <fallback name>: existing name for the gid, created when missing
  name="$(getent group "$1" | cut -d: -f1 || true)"
  if [ -z "$name" ]; then
    groupadd -g "$1" "$2"
    name="$2"
  fi
  echo "$name"
}

prepare_bind() {
  [ -d /etc/bind ] || return 0
  bind_group="$(group_name "$BIND_GID" bind)"
  usermod -a -G "$bind_group" pelagos
  if [ ! -f /etc/bind/named.conf ] && [ -d "$SEED/bind" ]; then
    log "seeding /etc/bind"
    cp -a "$SEED/bind/." /etc/bind/
  fi
  if [ ! -s /etc/bind/rndc.key ]; then
    log "generating /etc/bind/rndc.key (rndc-pelagos)"
    # Same format as tsig-keygen, which bind9-utils does not ship.
    printf 'key "rndc-pelagos" {\n\talgorithm hmac-sha256;\n\tsecret "%s";\n};\n' \
      "$(openssl rand -base64 32)" > /etc/bind/rndc.key
  fi
  chown "root:$bind_group" /etc/bind
  chmod 0775 /etc/bind
  chown "pelagos:$bind_group" /etc/bind/rndc.key
  chmod 0640 /etc/bind/rndc.key
  # Pelagos writes its include directory; named only reads it (setgid keeps the group).
  install -d -o pelagos -g "$bind_group" -m 2770 /etc/bind/pelagos
  # rndc config of node.toml [engines.bind] rndc_conf; the server is the BIND container.
  if [ ! -f /etc/bind/pelagos/rndc-pelagos.conf ]; then
    printf 'include "/etc/bind/rndc.key";\noptions {\n\tdefault-key "rndc-pelagos";\n\tdefault-server %s;\n\tdefault-port 953;\n};\n' \
      "$BIND_HOST" > /etc/bind/pelagos/rndc-pelagos.conf
    chown "pelagos:$bind_group" /etc/bind/pelagos/rndc-pelagos.conf
    chmod 0640 /etc/bind/pelagos/rndc-pelagos.conf
  fi
  # named writes its working directory and the dynamic zones; pelagos reads them by group.
  for d in /var/cache/bind /var/lib/bind; do
    [ -d "$d" ] || continue
    chown "$BIND_UID:$bind_group" "$d"
    chmod 0775 "$d"
    install -d -o "$BIND_UID" -g "$bind_group" -m 2775 "$d/pelagos"
  done
}

prepare_kea() {
  [ -d /etc/kea ] || [ -d /run/kea ] || return 0
  kea_group="$(group_name "$KEA_GID" kea)"
  usermod -a -G "$kea_group" pelagos
  if [ -d /etc/kea ]; then
    for f in kea-dhcp4.conf kea-dhcp6.conf kea-dhcp-ddns.conf; do
      if [ ! -f "/etc/kea/$f" ] && [ -f "$SEED/kea/$f" ]; then
        log "seeding /etc/kea/$f"
        cp "$SEED/kea/$f" "/etc/kea/$f"
      fi
    done
    chgrp -R "$kea_group" /etc/kea
    chmod 2770 /etc/kea
    find /etc/kea -type f -exec chmod 0660 {} +
  fi
  if [ -d /run/kea ]; then
    # Kea accepts a socket directory of mode 0750 or stricter; the group lets pelagos connect.
    chgrp "$kea_group" /run/kea
    chmod 0750 /run/kea
  fi
}

prepare_node() {
  install -d -o pelagos -g pelagos -m 0750 "$ETC" "$ETC/tls" "$VAR" "$RUN"
  if [ ! -f "$ETC/node.toml" ]; then
    if [ -n "${PELAGOS_ADMIN_PASSWORD:-}" ]; then
      log "initializing the first node (${PELAGOS_NODE_NAME:-pelagos})"
      set -- --name "${PELAGOS_NODE_NAME:-pelagos}" --admin-user "${PELAGOS_ADMIN_USER:-admin}"
      [ -n "${PELAGOS_WEB_URL:-}" ] && set -- "$@" --web-url "$PELAGOS_WEB_URL"
      [ -n "${PELAGOS_REPLICATION_URL:-}" ] && set -- "$@" --replication-url "$PELAGOS_REPLICATION_URL"
      runuser -u pelagos -- /opt/pelagos/venv/bin/pelagos init "$@"
    else
      log "no $ETC/node.toml and PELAGOS_ADMIN_PASSWORD is not set: run 'pelagos init' or 'pelagos enroll' in this container"
    fi
  fi
}

configure_bind_engine() {
  # A BIND container (PELAGOS_BIND_HOST not local): node.toml [engines.bind] says where named
  # listens. Keys already present are kept; "pelagos import" keeps them too.
  [ -f "$ETC/node.toml" ] && [ -d /etc/bind ] || return 0
  case "$BIND_HOST" in 127.0.0.1|::1|localhost) return 0 ;; esac
  # rndc and the statistics URL take a name; DNS queries and UPDATEs need an address.
  # The BIND container starts after pelagos-init: the long-running modes wait for its name.
  tries=30
  [ "$mode" = init ] && tries=1
  bind_ip=""
  while [ -z "$bind_ip" ] && [ "$tries" -gt 0 ]; do
    bind_ip="$(getent ahostsv4 "$BIND_HOST" | awk 'NR == 1 { print $1 }')"
    [ -n "$bind_ip" ] || bind_ip="$(getent hosts "$BIND_HOST" | awk 'NR == 1 { print $1 }')"
    tries=$((tries - 1))
    [ -n "$bind_ip" ] || [ "$tries" -eq 0 ] || sleep 1
  done
  if [ -z "$bind_ip" ]; then
    log "cannot resolve $BIND_HOST; node.toml [engines.bind] left as is"
    return 0
  fi
  bind_group="$(group_name "$BIND_GID" bind)"
  runuser -u pelagos -- /opt/pelagos/venv/bin/python -I - \
    "$ETC/node.toml" "$VAR/cluster.toml" "$BIND_HOST" "$bind_ip" "$bind_group" <<'PY'
import sys
from pathlib import Path

from pelagos.core.config_store import ConfigStore

node_toml, cluster_toml = Path(sys.argv[1]), Path(sys.argv[2])
host, address, group = sys.argv[3], sys.argv[4], sys.argv[5]
store = ConfigStore(node_toml, cluster_toml)
node = store.load_node()
table = node.engines.get("bind")
parked = (node.engines.get("disabled") or {}).get("bind")
# An engine turned off keeps its table under [engines.disabled.bind] (section 10): update that one,
# never turn BIND back on here. A boolean true becomes a table, which stays on.
target = "bind" if table is True or isinstance(table, dict) else "parked"
current = table if isinstance(table, dict) else (parked if isinstance(parked, dict) else {})
wanted = {
    "rndc_address": host,
    "statistics_url": f"http://{host}:8053/json/v1",
    "query_address": address,
    "named_conf": "/etc/bind/named.conf",
    "include_dir": "/etc/bind/pelagos",
    "rndc_conf": "/etc/bind/pelagos/rndc-pelagos.conf",
    "group": group,
}
missing = {k: v for k, v in wanted.items() if not current.get(k)}
if missing:
    merged = {**current, **missing}
    if target == "bind":
        node.engines["bind"] = merged
    else:
        node.engines.setdefault("bind", False)
        node.engines["disabled"] = {**(node.engines.get("disabled") or {}), "bind": merged}
    store.save_node(node)
    print(f"pelagos-entrypoint: node.toml [engines.{'bind' if target == 'bind' else 'disabled.bind'}] "
          + ", ".join(sorted(missing)), file=sys.stderr)
PY
}

prepare() {
  prepare_bind
  prepare_kea
  prepare_node
  configure_bind_engine
}

as_pelagos() {
  # gunicorn keeps its control socket under $HOME, which must not stay /root. UMask=0027 like the units.
  umask 027
  HOME=/var/lib/pelagos exec setpriv --reuid pelagos --regid pelagos --init-groups "$@"
}

case "$mode" in
  init)
    prepare
    log "volumes prepared"
    exit 0
    ;;
  serve)
    prepare
    PELAGOS_ETC="$ETC" PELAGOS_VAR="$VAR" /opt/pelagos/bin/pelagos-prestart
    as_pelagos /opt/pelagos/venv/bin/gunicorn -c /opt/pelagos/gunicorn_conf.py 'pelagos.app:wsgi_app()'
    ;;
  collector)
    prepare
    [ -f "$ETC/node.toml" ] || { log "$ETC/node.toml not found; the collector needs an initialized node"; exit 78; }
    as_pelagos /opt/pelagos/venv/bin/pelagos collector "$@"
    ;;
  allinone)
    prepare
    PELAGOS_ETC="$ETC" PELAGOS_VAR="$VAR" /opt/pelagos/bin/pelagos-prestart
    exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
    ;;
  pelagos)
    as_pelagos /opt/pelagos/venv/bin/pelagos "$@"
    ;;
  *)
    exec "$mode" "$@"
    ;;
esac
