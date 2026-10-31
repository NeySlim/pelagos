#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run suites on the shared test host: archive the tree once, feed it to `ssh $PELAGOS_TEST_HOST run
# <suite> <lot>-<suite>` per suite in parallel, keep one local log per suite, exit non-zero if any failed.
set -euo pipefail

usage() {
  cat <<'U'
Usage: scripts/dev/remote-test.sh [--worktree] [--logs DIR] <lot> <suite>...
       scripts/dev/remote-test.sh --self-test

Suites: lint unit vitest daemon e2e e2e-smoke build all (what the host accepts).
Needs PELAGOS_TEST_HOST (an ssh alias). Archives HEAD by default; --worktree archives tracked and
untracked files of the working tree instead (uncommitted changes included, gitignored files,
node_modules, .venv, dist and build excluded). Logs go to DIR/<lot>/<suite>.log
(default ${PELAGOS_TEST_LOGS:-${TMPDIR:-/tmp}/pelagos-remote-test}). The host manages its own queue
and cleanup: there is no --wait and no --purge.
U
}

die() { echo "remote-test: $*" >&2; exit 2; }

make_archive() { # <mode> <out>
  if [ "$1" = worktree ]; then
    git ls-files -co --exclude-standard -z |
      tar --exclude=node_modules --exclude=.venv --exclude=dist --exclude=build \
        --null --ignore-failed-read -T - -cf "$2"
  else
    git archive --format=tar -o "$2" HEAD
  fi
}

run_suites() { # <mode> <logdir> <lot> <suite>...
  local mode=$1 logdir=$2 lot=$3 tmp suite rc=0
  shift 3
  [ -n "${PELAGOS_TEST_HOST:-}" ] || die "set PELAGOS_TEST_HOST to the ssh alias of the test host"
  [[ $lot =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "lot must match [a-z0-9-]+"
  for suite in "$@"; do [[ $suite =~ ^[a-z0-9-]+$ ]] || die "bad suite name: $suite"; done
  mkdir -p "$logdir/$lot"
  tmp=$(mktemp -d)
  make_archive "$mode" "$tmp/tree.tar" || { rm -rf "$tmp"; die "cannot archive the tree"; }
  local -A pids=()
  for suite in "$@"; do
    echo "remote-test: start $suite (log $logdir/$lot/$suite.log)"
    (
      start=$(date +%s)
      set +e
      ssh -o BatchMode=yes "$PELAGOS_TEST_HOST" run "$suite" "$lot-$suite" <"$tmp/tree.tar" >"$logdir/$lot/$suite.log" 2>&1
      code=$?
      echo "remote-test: $suite exit $code after $(($(date +%s) - start))s" >>"$logdir/$lot/$suite.log"
      exit "$code"
    ) &
    pids[$suite]=$!
  done
  for suite in "$@"; do
    if wait "${pids[$suite]}"; then
      echo "remote-test: PASS $suite"
    else
      echo "remote-test: FAIL $suite (tail of $logdir/$lot/$suite.log)"
      tail -n 15 "$logdir/$lot/$suite.log" | sed 's/^/    /'
      rc=1
    fi
  done
  rm -rf "$tmp"
  return "$rc"
}

self_test() {
  command -v shellcheck >/dev/null || die "shellcheck not installed"
  shellcheck "$0"
  local here rc tmp
  here=$(readlink -f "$0")
  tmp=$(mktemp -d); selftmp=$tmp
  trap 'rm -rf "$selftmp"' EXIT
  mkdir "$tmp/bin" "$tmp/repo"
  # Fake ssh: store the archive listing, fail for the suite named "bad".
  cat >"$tmp/bin/ssh" <<'F'
#!/usr/bin/env bash
while [ "${1:-}" = -o ]; do shift 2; done
shift
suite=$2 label=$3
tar -tf - >"$FAKE_OUT/$suite.files"
echo "fake run $suite $label"
[ "$suite" != bad ] || exit 3
F
  chmod +x "$tmp/bin/ssh"
  export FAKE_OUT="$tmp/out"
  mkdir "$FAKE_OUT"
  (
    cd "$tmp/repo"
    git init -q . && git config user.email t@example.lan && git config user.name t
    mkdir node_modules && echo x >node_modules/n.js && echo x >tracked.txt
    git add tracked.txt && git -c commit.gpgsign=false commit -qm "chore(x): t"
    echo y >untracked.txt
    PATH="$tmp/bin:$PATH" PELAGOS_TEST_HOST=fake "$here" --logs "$tmp/logs" st unit vitest >/dev/null
    grep -qx tracked.txt "$FAKE_OUT/unit.files"
    grep -q untracked.txt "$FAKE_OUT/unit.files" && exit 1
    grep -q "fake run unit st-unit" "$tmp/logs/st/unit.log"
    PATH="$tmp/bin:$PATH" PELAGOS_TEST_HOST=fake "$here" --worktree --logs "$tmp/logs" st2 unit >/dev/null
    grep -qx untracked.txt "$FAKE_OUT/unit.files"
    grep -q node_modules "$FAKE_OUT/unit.files" && exit 1
    rc=0
    PATH="$tmp/bin:$PATH" PELAGOS_TEST_HOST=fake "$here" --logs "$tmp/logs" st3 unit bad >/dev/null || rc=$?
    [ "$rc" = 1 ] || { echo "aggregate exit code is $rc, expected 1"; exit 1; }
    grep -q "exit 3" "$tmp/logs/st3/bad.log"
    rc=0
    env -u PELAGOS_TEST_HOST PATH="$tmp/bin:$PATH" "$here" st4 unit >/dev/null 2>&1 || rc=$?
    [ "$rc" = 2 ] || { echo "missing host gave exit $rc, expected 2"; exit 1; }
  )
  echo "remote-test: self-test OK"
}

mode=head logdir=${PELAGOS_TEST_LOGS:-${TMPDIR:-/tmp}/pelagos-remote-test}
while [ $# -gt 0 ]; do
  case $1 in
    --self-test) self_test; exit ;;
    --worktree) mode=worktree; shift ;;
    --logs) logdir=${2:?--logs needs a directory}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --wait|--purge) die "$1 does not exist: the test host manages its queue and cleanup" ;;
    -*) usage >&2; die "unknown option $1" ;;
    *) break ;;
  esac
done
[ $# -ge 2 ] || { usage >&2; exit 2; }
run_suites "$mode" "$logdir" "$@"
