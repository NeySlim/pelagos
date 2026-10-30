# SPDX-License-Identifier: Apache-2.0
"""A rollout of section 29 on two real collectors over real mTLS (design 13.6, tests, daemon tier).

Each node runs its replication service and a `Collector` whose rollout driver talks to the root
side of `installer.updates` in process: update_verify, update_start (the transient unit is a
thread running `upgrade apply`), update_status, journal_errors. Only the package tools and
systemd are fake: `apt-get install` marks the version a text "deb" declares, `systemctl
stop/start` stops the node's turns and starts new processes (a new collector, new invocation
ids). The release is uploaded on ns1 and fetched by ns2 over `/repl/v1/releases`.

Scenario: 0.2.5 -> 0.3.0 on both nodes; 0.3.0 -> 0.3.1 whose web process does not come up on
ns2, rolled back automatically to 0.3.0 (`rolled_back`, rollout `failed`, `update_failed`);
then "Roll back" from the screen brings ns1 back to 0.3.0 by a rollout of kind `rollback`.
"""

from __future__ import annotations

import hashlib
import io
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.rollout import LiveView, RolloutDriver
from pelagos.collector.series import SeriesStore, connect
from pelagos.core import release as rel
from pelagos.core import update_rollout as ur
from pelagos.core import update_sources as src
from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.config_store import ConfigStore, NodeConfig
from pelagos.core.context import NodeContext
from pelagos.core.enrollment import enroll_node
from pelagos.core.replication import ReplicationService
from pelagos.domain import AlertKind, Plan, PlanScope, PlanState
from pelagos.domain.common import new_id
from pelagos.domain.updates import CHECKSUMS, NodeState, RolloutState
from pelagos.installer import updates
from pelagos.platform import CommandResult
from pelagos.platform.runner import FakeRunner
from pelagos.services.updates_service import RolloutWriter, UpdatesService
from tests.conftest import ADMIN_PASSWORD
from tests.fixtures.ports import free_port

pytestmark = pytest.mark.daemon

SERVICES = ("pelagos.service", "pelagos-collector.service")


# The node's host: package tools and systemd ------------------------------------------------------


@dataclass
class Host:
    """dpkg, apt-get and systemd of one node. A deb is a text file of control fields."""

    env: Any = None
    installed: str = "0.2.5-1"
    up: bool = True
    generation: int = 0
    ids: dict[str, str] = field(default_factory=dict)
    # Package versions whose web process never answers (a unit that does not start).
    broken: set[str] = field(default_factory=set)
    units: dict[str, threading.Thread] = field(default_factory=dict)
    installs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._restart_ids()

    def _restart_ids(self) -> None:
        self.generation += 1
        self.ids = {u: f"{u}-{self.generation}" for u in SERVICES}

    def runner(self) -> FakeRunner:
        return FakeRunner(
            responses={
                "dpkg --print-architecture": "amd64\n",
                "dpkg --audit": "",
                "dpkg-query -W": self._query,
                "dpkg-deb -f": self._fields,
                "apt-get install": self._install,
                "systemctl list-units": self._active_units,
                "systemctl show -p LoadState": self._unit_state,
                "systemctl stop": self._stop,
                "systemctl start": self._start,
                "systemd-run": self._systemd_run,
                "journalctl": "",
            }
        )

    def _query(self, argv: list[str]) -> CommandResult:
        if argv[-1] != "pelagos":
            return CommandResult(argv, 1, "", "no packages found")
        return CommandResult(argv, 0, f"install ok installed|{self.installed}", "")

    def _fields(self, argv: list[str]) -> CommandResult:
        return CommandResult(argv, 0, Path(argv[2]).read_text(), "")

    def _install(self, argv: list[str]) -> CommandResult:
        fields = dict(line.split(": ", 1) for line in Path(argv[-1]).read_text().splitlines())
        self.installed = fields["Version"]
        self.installs.append(self.installed)
        return CommandResult(argv, 0, f"Setting up pelagos ({self.installed})", "")

    def _stop(self, argv: list[str]) -> CommandResult:
        self.up = False
        return CommandResult(argv, 0, "", "")

    def _start(self, argv: list[str]) -> CommandResult:
        self._restart_ids()
        self.up = True
        return CommandResult(argv, 0, "", "")

    def _systemd_run(self, argv: list[str]) -> CommandResult:
        rid = argv[-1]
        unit = threading.Thread(target=updates.apply, args=(self.env, rid), name=f"upgrade-{rid}")
        self.units[rid] = unit
        unit.start()
        return CommandResult(argv, 0, f"Running as unit: pelagos-upgrade-{rid}.service", "")

    def _rid(self, unit: str) -> str:
        return unit.removeprefix(updates.UNIT_PREFIX).removesuffix(".service")

    def _unit_state(self, argv: list[str]) -> CommandResult:
        unit = self.units.get(self._rid(argv[-1]))
        if unit is None:
            return CommandResult(argv, 0, "LoadState=not-found\nActiveState=inactive\n", "")
        state = "active" if unit.is_alive() else "inactive"
        return CommandResult(argv, 0, f"LoadState=loaded\nActiveState={state}\n", "")

    def _active_units(self, argv: list[str]) -> CommandResult:
        lines = [f"{updates.UNIT_PREFIX}{rid}.service loaded active running" for rid, t in self.units.items()]
        alive = [line for line, t in zip(lines, self.units.values(), strict=True) if t.is_alive()]
        return CommandResult(argv, 0, "\n".join(alive), "")

    def web_health(self) -> str:
        if not self.up:
            return "unreachable (ConnectionRefusedError)"
        return "error" if self.installed in self.broken else "ok"

    def join(self) -> None:
        for unit in self.units.values():
            unit.join(timeout=30)


class UnitHelper:
    """The privileged helper's update operations, run in process against the node's Host."""

    def __init__(self, host: Host, keys: dict[str, Any]) -> None:
        self.host = host
        self.keys = keys

    def _call(self, op: str, **request: Any) -> Any:
        return updates.handle(self.host.env, op, request, self.keys)

    def update_verify(self, version: str, allow_unsigned: bool = False) -> dict[str, Any]:
        return self._call("update_verify", version=version, allow_unsigned=allow_unsigned)

    def update_start(self, rollout_id: str, kind: str, **args: Any) -> dict[str, Any]:
        return self._call("update_start", rollout_id=rollout_id, kind=kind, **args)

    def update_status(self, rollout_id: str) -> dict[str, Any]:
        return self._call("update_status", rollout_id=rollout_id)

    def journal_errors(self, since: float | str) -> dict[str, Any]:
        return self._call("journal_errors", since=since)


class View(LiveView):
    """The live checks of the collector; only this node's web probe and units come from the Host."""

    def __init__(self, ctx: Any, client_for: Callable[[Any], Any], host: Host) -> None:
        super().__init__(ctx, client_for)
        self.host = host

    def _web_health(self) -> str:
        return self.host.web_health()

    def invocations(self) -> dict[str, str]:
        return dict(self.host.ids) if self.host.up else dict.fromkeys(SERVICES, "")


# Two nodes ---------------------------------------------------------------------------------------


@dataclass
class Node:
    ctx: NodeContext
    service: ReplicationService
    host: Host
    keys: dict[str, Any]
    skew: float = 0.0
    collector: Collector | None = None
    generation: int = 0
    log: list[str] = field(default_factory=list)
    _conn: Any = None

    @property
    def id(self) -> str:
        return self.ctx.node.id

    def clock(self) -> float:
        return time.time() + self.skew

    def start_processes(self) -> None:
        """A new collector, as systemd starts it after the install: state comes from disk only."""
        self.stop_processes()
        self._conn = connect(self.ctx.paths.series_db)
        c = Collector(
            self.ctx,
            SeriesStore(self._conn),
            Backends(),
            None,
            EventSink(self.ctx.paths.events_sock, self.id),
        )
        c.replication_client = self.service.replicator.client
        view = View(self.ctx, self.service.replicator.client, self.host)
        c.rollout_driver = RolloutDriver(
            self.ctx, view, helper=UnitHelper(self.host, self.keys), clock=self.clock
        )
        self.collector = c
        self.generation = self.host.generation

    def stop_processes(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        self.collector = None

    def tick_driver(self) -> str:
        """One turn of the driver alone, for its answer."""
        if not self.host.up:
            return "processes stopped"
        if self.collector is None or self.generation != self.host.generation:
            self.start_processes()
        assert self.collector is not None
        out = self.collector.rollout_driver.tick()
        self.log.append(out)
        return out

    def open_alerts(self) -> list[Any]:
        assert self.collector is not None
        return self.collector.alerts.open_alerts()


def deb(version: str, arch: str = "amd64") -> str:
    return f"Package: pelagos\nVersion: {version}\nArchitecture: {arch}\n"


def build_release(folder: Path, version: str, key: Path) -> Path:
    """A release directory as `make release` writes it: debs, release.json, NOTES.md, sums, signature."""
    folder.mkdir(parents=True)
    pkg = f"{version}-1"
    for arch in ("amd64", "arm64"):
        (folder / f"pelagos_{pkg}_{arch}.deb").write_text(deb(pkg, arch))
    (folder / "NOTES.md").write_text(f"# Pelagos {version}\n")
    rel.write_manifest(folder, rel.build_manifest(folder, version))
    sums = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(folder.iterdir())
    )
    (folder / CHECKSUMS).write_text(sums)
    rel.sign_release(folder, key)
    return folder


@dataclass
class Pair:
    ns1: Node
    ns2: Node
    key: Path
    releases: Path

    @property
    def nodes(self) -> tuple[Node, Node]:
        return self.ns1, self.ns2


def _host_env(ctx: NodeContext, host: Host) -> Any:
    env = SimpleNamespace(
        distro=SimpleNamespace(id="debian", package_manager="apt"),
        runner=host.runner(),
        node_paths=ctx.paths,
        node_id=ctx.node.id,
    )
    host.env = env
    return env


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[Pair]:
    port1, port2 = free_port(), free_port()
    paths1 = dev_paths(tmp_root / "ns1")
    bootstrap_first_node(
        paths1, name="ns1", admin_password=ADMIN_PASSWORD, replication_url=f"https://127.0.0.1:{port1}"
    )
    store = ConfigStore(paths1.node_toml, paths1.cluster_toml, paths1.locks_dir / "cluster.lock")
    node = store.load_node()
    node.replication_listen = f"127.0.0.1:{port1}"
    store.save_node(node)
    ctx1 = NodeContext.build(paths1)
    ctx1.config_store.update_cluster(
        lambda c: c.settings.setdefault("updates", {}).update(
            settle_seconds=0, pause_seconds=0, timeout_seconds=30
        ),
        updated_by="test",
    )
    service1 = ReplicationService(ctx1, peer_poll_seconds=300)
    service1.start()
    paths2 = dev_paths(tmp_root / "ns2")
    paths2.ensure()
    ConfigStore(paths2.node_toml, paths2.cluster_toml, paths2.locks_dir / "cluster.lock").save_node(
        NodeConfig(
            id=new_id(),
            name="ns2",
            replication_listen=f"127.0.0.1:{port2}",
            replication_url=f"https://127.0.0.1:{port2}",
            web_url="https://ns2.example.lan:8443",
            engines={},
        )
    )
    token = service1.enrollment.issue_token(f"user:admin@node:{ctx1.node.id}")
    enroll_node(
        paths2, url=token["url"], token=token["token"], ca_fingerprint=token["ca_fingerprint"], name="ns2"
    )
    ctx2 = NodeContext.build(paths2)
    service2 = ReplicationService(ctx2, peer_poll_seconds=300)
    service2.start()
    key = tmp_root / "keys" / "release.key"
    rel.generate_key(key)
    keys = rel.load_public_keys(key.parent)
    nodes = []
    for ctx, service in ((ctx1, service1), (ctx2, service2)):
        host = Host()
        _host_env(ctx, host)
        nodes.append(Node(ctx, service, host, keys))
    try:
        yield Pair(nodes[0], nodes[1], key, tmp_root / "releases")
    finally:
        for n in nodes:
            n.host.join()
            n.stop_processes()
        service2.stop()
        service1.stop()


# Steps -------------------------------------------------------------------------------------------


def upload(pair: Pair, version: str) -> dict[str, Any]:
    """What `POST /admin/updates/upload` does on ns1: stage the files, have the helper verify them."""
    folder = build_release(pair.releases / version, version, pair.key)
    files = [(p.name, io.BytesIO(p.read_bytes())) for p in sorted(folder.iterdir())]
    staged = src.stage_upload(pair.ns1.ctx.paths.upgrade_incoming, files)
    assert staged["version"] == version
    out = UnitHelper(pair.ns1.host, pair.ns1.keys).update_verify(version)
    assert out["signature"] == "valid" and out["direction"] == "upgrade", out
    return out


def start_rollout(pair: Pair, version: str, order: list[Node], previous: str) -> str:
    """The update plan applied on ns1 (RolloutWriter): the rollout lands in cluster.toml."""
    ns1 = pair.ns1
    folder = ns1.ctx.paths.upgrade_dir / "packages" / version
    sums = rel.verify_release(folder, ns1.keys).checksums
    artifacts = {
        f"deb/{arch}": {
            "file": f"pelagos_{version}-1_{arch}.deb",
            "sha256": sums[f"pelagos_{version}-1_{arch}.deb"],
        }
        for arch in ("amd64", "arm64")
    }
    plan = Plan(
        scope=PlanScope.UPDATE,
        node_id=ns1.id,
        created_by="admin",
        summary=f"update to {version}",
        target_node_ids=[ns1.id],
        requires_confirmation=True,
        state=PlanState.VALIDATED,
        update={
            "kind": "pelagos",
            "version": version,
            "order": [n.id for n in order],
            "from_versions": {n.id: previous for n in order},
            "source": "upload",
            "artifacts": artifacts,
            "auto_rollback": True,
            "state_schema_changed": False,
            "signature": "valid",
            "confirmed_by": "admin",
        },
    )
    result = RolloutWriter(ns1.ctx).apply(plan)
    assert result.ok, result.message
    rollout = ur.load(ns1.ctx.settings())
    assert rollout is not None
    return rollout.id


def drive(
    pair: Pair,
    until: Callable[[], bool],
    what: str,
    timeout: float = 90,
    on: Callable[[Node, str], None] | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for node in pair.nodes:
            out = node.tick_driver()
            if on is not None:
                on(node, out)
        if until():
            return
        time.sleep(0.2)
    logs = {n.ctx.node.name: n.log[-12:] for n in pair.nodes}
    raise AssertionError(f"timed out waiting for {what}: {logs}")


def rollout_of(node: Node) -> Any:
    return ur.load(node.ctx.settings())


def history(node: Node, rid: str) -> dict[str, Any] | None:
    return next((h for h in ur.history(node.ctx.settings()) if h["id"] == rid), None)


def actions(node: Node, prefix: str = "update.") -> list[tuple[str, str]]:
    return [(e.action, e.node_id) for e in node.ctx.audit_log.read() if e.action.startswith(prefix)]


# The test ----------------------------------------------------------------------------------------


def test_rollout_on_two_collectors_with_a_failure_and_the_way_back(pair: Pair) -> None:
    ns1, ns2 = pair.nodes

    # 1. 0.2.5 -> 0.3.0, ns2 first: ns2 fetches the release from ns1 over mTLS.
    upload(pair, "0.3.0")
    rid = start_rollout(pair, "0.3.0", [ns2, ns1], "0.2.5")
    drive(pair, lambda: history(ns1, rid) is not None and history(ns2, rid) is not None, "rollout 1 done")
    for node in pair.nodes:
        assert node.host.installed == "0.3.0-1" and node.host.installs == ["0.3.0-1"]
        assert rollout_of(node) is None
        entry = history(node, rid)
        assert entry is not None and entry["state"] == RolloutState.DONE.value, entry
        assert [n["state"] for n in entry["nodes"]] == ["done", "done"]
        assert {n["to_version"] for n in entry["nodes"]} == {"0.3.0-1"}
        assert (node.ctx.paths.upgrade_dir / "packages" / "0.3.0").is_dir()
    # Each node wrote its own start and done; both logs hold the four entries once replicated.
    want = sorted((f"update.node.{a}", n.id) for a in ("start", "done") for n in pair.nodes)
    drive(pair, lambda: all(sorted(actions(n)) == want for n in pair.nodes), "audit replicated", timeout=30)
    # ns1 started its turn only once ns2 was done.
    seen = actions(ns1)
    assert seen.index(("update.node.done", ns2.id)) < seen.index(("update.node.start", ns1.id)), seen

    # 2. 0.3.0 -> 0.3.1 whose web process does not start on ns2 (second in the order).
    ns2.host.broken.add("0.3.1-1")
    upload(pair, "0.3.1")
    rid2 = start_rollout(pair, "0.3.1", [ns1, ns2], "0.3.0")

    def stuck(node: Node, out: str) -> None:
        # The health check waits until settle + timeout_seconds (30 s minimum): time runs faster.
        if node is ns2 and out.startswith("health:"):
            node.skew += 31

    def failed() -> bool:
        r = rollout_of(ns1)
        return (
            r is not None
            and r.state == RolloutState.FAILED.value
            and r.nodes[ns2.id].state
            in (
                NodeState.ROLLED_BACK.value,
                NodeState.FAILED.value,
            )
        )

    drive(pair, failed, "ns2 rolled back", on=stuck)
    r = rollout_of(ns1)
    assert r.nodes[ns1.id].state == NodeState.DONE.value and r.nodes[ns1.id].to_version == "0.3.1-1"
    back = r.nodes[ns2.id]
    assert back.state == NodeState.ROLLED_BACK.value, back
    assert back.step == "health" and "health error" in (back.error or ""), back
    assert ns1.host.installed == "0.3.1-1"
    # ns2 installed 0.3.1, then its kept 0.3.0 again (downgrade), and runs it.
    assert ns2.host.installs == ["0.3.0-1", "0.3.1-1", "0.3.0-1"] and ns2.host.installed == "0.3.0-1"
    assert any(
        "--allow-downgrades" in " ".join(a)
        for a in ns2.host.env.runner.log
        if a[:2] == ["apt-get", "install"]
    )
    drive(
        pair, lambda: rollout_of(ns2) is not None and rollout_of(ns2).state == "failed", "failure replicated"
    )
    names = [a for a, n in actions(ns2) if n == ns2.id]
    assert "update.node.failed" in names and "update.node.rolled_back" in names
    # The service node raises update_failed (critical) for the cluster.
    for node in pair.nodes:
        node.collector.rollout()
    raised = [a for n in pair.nodes for a in n.open_alerts() if a.kind is AlertKind.UPDATE_FAILED]
    assert raised and raised[0].details["rolled_back"] is True and raised[0].node_id == ns2.id

    # 3. "Roll back" on the screen: ns1, the only node done, goes back to 0.3.0.
    svc = UpdatesService(ns1.ctx, helper=lambda: UnitHelper(ns1.host, ns1.keys))
    admin = next(u for u in ns1.ctx.cluster().users if u.username == "admin")
    out = svc.action(rid2, {"action": "rollback", "password": ADMIN_PASSWORD}, admin.id, "admin", None)
    assert out["kind"] == "rollback" and out["version"] == "0.3.0", out
    assert [n["node_id"] for n in out["nodes"]] == [ns1.id]
    rid3 = out["id"]
    drive(pair, lambda: history(ns1, rid3) is not None and history(ns2, rid3) is not None, "cluster rollback")
    assert ns1.host.installed == "0.3.0-1" and ns1.host.installs[-1] == "0.3.0-1"
    assert history(ns1, rid2)["state"] == RolloutState.CANCELLED.value
    assert history(ns1, rid3)["state"] == RolloutState.DONE.value
    assert ns2.host.installs == ["0.3.0-1", "0.3.1-1", "0.3.0-1"]  # not part of the rollback
    for node in pair.nodes:
        node.collector.rollout()
    assert not [a for n in pair.nodes for a in n.open_alerts() if a.kind is AlertKind.UPDATE_FAILED]
