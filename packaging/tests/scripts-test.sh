#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests of the packaged shell helpers in throwaway directories: pelagos-prestart never
# follows symbolic links planted by the service user and leaves pelagos.env to root, and
# /usr/bin/pelagos parses pelagos.env without executing it. Run as root (chown) or with
# passwordless sudo; the service user is "nobody".
#
# Usage: scripts-test.sh
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then exec sudo -n "$0" "$@"; fi

here="$(cd "$(dirname "$0")" && pwd)"
bin="$here/../bin"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
ok() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
check() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}

user=nobody
group="$(id -gn nobody)"

# pelagos-prestart
etc="$work/etc"; var="$work/var"
mkdir -p "$etc/tls" "$var/backups"
touch "$etc/node.toml" "$var/cluster.toml"
printf 'X=1\n' >"$etc/pelagos.env"
chmod 0644 "$etc/pelagos.env"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj /CN=test -keyout "$etc/tls/server.key" -out "$etc/tls/server.crt" >/dev/null 2>&1
victim="$work/victim"; key_victim="$work/key-victim"
touch "$victim" "$key_victim"
chmod 0644 "$victim" "$key_victim"
ln -s "$victim" "$var/backups/planted"
chown -h "$user:$group" "$var/backups/planted"
ln -s "$victim" "$var/planted-root"

PELAGOS_ETC="$etc" PELAGOS_VAR="$var" PELAGOS_USER="$user" PELAGOS_GROUP="$group" \
  "$bin/pelagos-prestart" collector
check "prestart: victim behind a symlink keeps its owner" test "$(stat -c %U "$victim")" = root
check "prestart: victim behind a symlink keeps its mode" test "$(stat -c %a "$victim")" = 644
check "prestart: state chowned" test "$(stat -c %U "$var/cluster.toml")" = "$user"
check "prestart: pelagos.env stays root's" test "$(stat -c '%U %a' "$etc/pelagos.env")" = "root 644"
check "prestart: TLS key 0600" test "$(stat -c '%U %a' "$etc/tls/server.key")" = "$user 600"

rm -f "$etc/tls/server.key"
ln -s "$key_victim" "$etc/tls/server.key"
PELAGOS_ETC="$etc" PELAGOS_VAR="$var" PELAGOS_USER="$user" PELAGOS_GROUP="$group" \
  "$bin/pelagos-prestart" collector
check "prestart: symlinked server.key target not chmodded" test "$(stat -c '%U %a' "$key_victim")" = "root 644"

# /usr/bin/pelagos, with the venv replaced by env(1)
wrapper="$work/pelagos"
sed 's|^exec /opt/pelagos/venv/bin/pelagos "\$@"$|exec env "$@"|' "$bin/pelagos" >"$wrapper"
chmod 0755 "$wrapper"
envf="$work/pelagos.env"
cat >"$envf" <<EOF
# comment
PELAGOS_A=plain
PELAGOS_B="quoted value"
PELAGOS_C='single'
touch $work/pwned
PELAGOS_D=\$(touch $work/pwned2)
bad-key=1
EOF
chmod 0644 "$envf"
out="$(PELAGOS_ENV_FILE="$envf" "$wrapper")"
check "wrapper: plain value" grep -qx 'PELAGOS_A=plain' <<<"$out"
check "wrapper: double quotes stripped" grep -qx 'PELAGOS_B=quoted value' <<<"$out"
check "wrapper: single quotes stripped" grep -qx 'PELAGOS_C=single' <<<"$out"
check "wrapper: command substitution kept literal" grep -qxF "PELAGOS_D=\$(touch $work/pwned2)" <<<"$out"
check "wrapper: no command executed" test ! -e "$work/pwned" -a ! -e "$work/pwned2"

chown "$user" "$envf"
check "wrapper: refuses a file not owned by root" bash -c "! PELAGOS_ENV_FILE='$envf' '$wrapper'"
chown root "$envf"; chmod 0664 "$envf"
check "wrapper: refuses a group-writable file" bash -c "! PELAGOS_ENV_FILE='$envf' '$wrapper'"
chmod 0644 "$envf"
ln -s "$envf" "$work/link.env"
check "wrapper: refuses a symlink" bash -c "! PELAGOS_ENV_FILE='$work/link.env' '$wrapper'"
check "wrapper: missing file is fine" env PELAGOS_ENV_FILE="$work/absent" "$wrapper"

if [[ $failures -gt 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
