# Development scripts

## remote-test.sh

Runs the heavy suites on the shared test host instead of the development machine.

```
export PELAGOS_TEST_HOST=<ssh alias of the test host>
scripts/dev/remote-test.sh <lot> <suite>...        # archive of HEAD (commit first)
scripts/dev/remote-test.sh --worktree <lot> unit   # include uncommitted and untracked files
make test-remote LOT=<lot> SUITES="unit vitest daemon e2e-smoke"
```

- Suites: `lint`, `unit`, `vitest`, `daemon`, `e2e`, `e2e-smoke`, `build`, `all`.
- The tree is archived once and sent on stdin to `ssh $PELAGOS_TEST_HOST run <suite> <lot>-<suite>`,
  one ssh per suite, all in parallel. Different lots use different labels and do not interfere.
- Each suite logs to `$PELAGOS_TEST_LOGS/<lot>/<suite>.log` (default `/tmp/pelagos-remote-test`; `--logs DIR`).
  The exit code is 0 only if every suite passed; failed suites print the tail of their log.
- `--worktree` archives tracked and untracked, non-ignored files, minus `node_modules`, `.venv`, `dist`
  and `build`.
- There is no `--wait` and no `--purge`: the host queues suites beyond its concurrency limit and
  cleans up after each run. `ssh $PELAGOS_TEST_HOST status` lists the running suites.
- `scripts/dev/remote-test.sh --self-test` runs shellcheck and a scenario with a fake ssh (no network).
