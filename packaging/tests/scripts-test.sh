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
# The prestart drops to the service user, which must traverse the work tree.
chmod 0755 "$work"
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
printf 'x' >"$var/series.sqlite"
chmod 0644 "$var/series.sqlite"

PELAGOS_ETC="$etc" PELAGOS_VAR="$var" PELAGOS_USER="$user" PELAGOS_GROUP="$group" \
  "$bin/pelagos-prestart" collector
check "prestart: victim behind a symlink keeps its owner" test "$(stat -c %U "$victim")" = root
check "prestart: victim behind a symlink keeps its mode" test "$(stat -c %a "$victim")" = 644
check "prestart: state chowned" test "$(stat -c %U "$var/cluster.toml")" = "$user"
check "prestart: world-readable state tightened" test "$(stat -c %a "$var/series.sqlite")" = 640
check "prestart: certificate stays readable" test "$(stat -c %a "$etc/tls/server.crt")" = 644
check "prestart: pelagos.env stays root's" test "$(stat -c '%U %a' "$etc/pelagos.env")" = "root 644"
check "prestart: TLS key 0600" test "$(stat -c '%U %a' "$etc/tls/server.key")" = "$user 600"

rm -f "$etc/tls/server.key"
ln -s "$key_victim" "$etc/tls/server.key"
PELAGOS_ETC="$etc" PELAGOS_VAR="$var" PELAGOS_USER="$user" PELAGOS_GROUP="$group" \
  "$bin/pelagos-prestart" collector
check "prestart: symlinked server.key target not chmodded" test "$(stat -c '%U %a' "$key_victim")" = "root 644"

# Certificate creation (web mode) with planted links: root must never write through them.
cert_victim="$work/cert-victim"
printf 'precious\n' >"$cert_victim"; chmod 0644 "$cert_victim"
rm -f "$etc/tls/server.key" "$etc/tls/server.crt"
ln -s "$cert_victim" "$etc/tls/server.key.new"
ln -s "$cert_victim" "$etc/tls/server.crt.new"
chown -h "$user:$group" "$etc/tls/server.key.new" "$etc/tls/server.crt.new"
PELAGOS_ETC="$etc" PELAGOS_VAR="$var" PELAGOS_USER="$user" PELAGOS_GROUP="$group" \
  "$bin/pelagos-prestart" web
check "prestart: planted server.key.new target untouched" grep -qx precious "$cert_victim"
check "prestart: planted target keeps owner and mode" test "$(stat -c '%U %a' "$cert_victim")" = "root 644"
check "prestart: new key is a regular file of the user, 0600" \
  test ! -L "$etc/tls/server.key" -a "$(stat -c '%U %a' "$etc/tls/server.key")" = "$user 600"
check "prestart: new certificate parses" openssl x509 -noout -in "$etc/tls/server.crt"
check "prestart: new certificate 0644" test "$(stat -c '%U %a' "$etc/tls/server.crt")" = "$user 644"

# A tls directory swapped for a link to a root directory: nothing is created there.
rootdir="$work/rootdir"; mkdir -m 0755 "$rootdir"
rm -rf "$etc/tls"
ln -s "$rootdir" "$etc/tls"
chown -h "$user:$group" "$etc/tls"
PELAGOS_ETC="$etc" PELAGOS_VAR="$var" PELAGOS_USER="$user" PELAGOS_GROUP="$group" \
  "$bin/pelagos-prestart" web >/dev/null 2>&1 || true
check "prestart: no key written through a tls symlink" test ! -e "$rootdir/server.key"
check "prestart: linked root directory keeps its mode" test "$(stat -c '%U %a' "$rootdir")" = "root 755"

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

# version.sh: dev builds carry a snapshot so the next build upgrades them; releases never do.
vsrc="$work/vsrc"
mkdir -p "$vsrc/backend/pelagos"
echo '__version__ = "0.1.0.dev0"' >"$vsrc/backend/pelagos/__init__.py"
version="$here/../version.sh"
check "version: no git, no snapshot" test "$(env -u PELAGOS_SNAPSHOT "$version" deb "$vsrc")" = "0.1.0~dev0"
check "version: deb snapshot" \
  test "$(PELAGOS_SNAPSHOT=20261025000000.abc1234 "$version" deb "$vsrc")" = "0.1.0~dev0+git20261025000000.abc1234"
check "version: rpm snapshot" \
  test "$(PELAGOS_SNAPSHOT=20261025000000.abc1234 "$version" rpm "$vsrc")" = "0.1.0~dev0^git20261025000000.abc1234"
check "version: docker tag has no snapshot" \
  test "$(PELAGOS_SNAPSHOT=20261025000000.abc1234 "$version" docker "$vsrc")" = "0.1.0-dev0"
if command -v dpkg >/dev/null 2>&1; then
  check "version: snapshot sorts after the bare dev version" \
    dpkg --compare-versions "0.1.0~dev0+git20261025000000.abc1234" gt "0.1.0~dev0"
  check "version: snapshot sorts before the release" \
    dpkg --compare-versions "0.1.0~dev0+git20261025000000.abc1234" lt "0.1.0"
fi
echo '__version__ = "0.1.0"' >"$vsrc/backend/pelagos/__init__.py"
check "version: a release is never stamped" \
  test "$(PELAGOS_SNAPSHOT=20261025000000.abc1234 "$version" deb "$vsrc")" = "0.1.0"

if [[ $failures -gt 0 ]]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
