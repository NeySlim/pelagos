# SPDX-License-Identifier: Apache-2.0
"""Hand over against a real named: user options and a user zone move to the managed files."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.bind import handover
from pelagos.domain.dns import ZoneSource
from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend, setup_includes
from tests.fixtures.ports import find_binary

pytestmark = pytest.mark.daemon

OPTIONS = """\
// user options
\tminimal-responses   yes ;   # keep answers short
\tmax-ncache-ttl 600;  /* five minutes */
\tallow-recursion {   127.0.0.1;
\t\t192.0.2.0/24; };
"""


@pytest.fixture
def server(tmp_root: Path):
    root = tmp_root / "hand"
    root.mkdir()
    (root / "named.conf.options").write_text(OPTIONS)
    zone_file = root / "zones" / "legacy.example.lan.db"
    (root / "named.conf.local").write_text(
        "// local zones\n"
        'zone "legacy.example.lan" {\n    type primary;   // old zone\n'
        f'    file "{zone_file}";\n}};\n'
    )
    srv = bind_custom.start(
        root,
        f'include "{root}/named.conf.local";\n',
        options=f'\tinclude "{root}/named.conf.options";\n',
        files={"legacy.example.lan.db": bind_custom.zone_text("legacy.example.lan")},
    )
    try:
        yield srv
    finally:
        srv.stop()


def test_options_and_zone_move_and_named_keeps_serving(server, tmp_root: Path) -> None:
    backend = make_backend(server, tmp_root)
    setup_includes(backend)
    options_file = server.root / "named.conf.options"
    local_file = server.root / "named.conf.local"
    before = backend.read_config()
    printed_before = handover.print_effective(find_binary("named-checkconf"), server.named_conf)

    targets = [r["target"] for r in handover.candidates(before)]
    for wanted in ("handover/options/max-ncache-ttl", "handover/zones/_default/legacy.example.lan."):
        assert wanted in targets
    plan = backend.plan_config_change(
        [
            Change(ChangeOp.REPLACE, "handover/options/minimal-responses", after={"comment": True}),
            Change(ChangeOp.REPLACE, "handover/options/max-ncache-ttl", after={"comment": True}),
            Change(ChangeOp.REPLACE, "handover/options/allow-recursion", after={"comment": True}),
            Change(ChangeOp.REPLACE, "handover/zones/_default/legacy.example.lan", after={"comment": True}),
        ]
    )
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message

    left = options_file.read_text()
    assert left.startswith("// user options\n") and left.count("# moved to options.conf by Pelagos") == 3
    assert "keep answers short" in left and "five minutes" in left
    assert "minimal-responses" not in left
    local = local_file.read_text()
    assert "// local zones" in local and "# moved to zones.conf by Pelagos" in local

    printed_after = handover.print_effective(find_binary("named-checkconf"), server.named_conf)
    for target in [c.target for c in plan.changes]:
        assert handover.effective_value(printed_before, target) == handover.effective_value(
            printed_after, target
        )
    assert "type: primary" in server.rndc("zonestatus", "legacy.example.lan")

    tree = backend.read_config()
    assert tree.pelagos["checkconf"]["ok"]
    assert all(e.managed for e in tree.options if e.name in ("minimal-responses", "max-ncache-ttl"))
    zone = next(z for z in tree.zones if z.name == "legacy.example.lan.")
    assert zone.source is ZoneSource.PELAGOS

    # The zone is now editable through the zone screen's plan.
    after = {**zone.to_dict(), "notes": "handed over"}
    edit = backend.plan_zone_change(Change(ChangeOp.REPLACE, "_default/legacy.example.lan", after=after))
    assert edit.state is PlanState.VALIDATED, edit.validations
    assert backend.apply(edit).ok


def test_rndc_key_is_never_offered_nor_moved(server, tmp_root: Path) -> None:
    backend = make_backend(server, tmp_root)
    setup_includes(backend)
    targets = {r["target"] for r in handover.candidates(backend.read_config())}
    assert "handover/keys/rndc-key" not in targets
    plan = backend.plan_config_change([Change(ChangeOp.REPLACE, "handover/keys/rndc-key")])
    assert plan.state is PlanState.FAILED and "stays in the user file" in (plan.error or "")
    assert "rndc-key" in (server.root / "rndc.key").read_text()


def test_zone_handover_of_a_file_only_root_may_write(server, tmp_root: Path, monkeypatch) -> None:
    """Debian keeps named.conf.local root:bind 0644 in /etc/bind (2755): the user file is written,
    then rolled back, by the privileged helper's bind_user_write operation; named keeps the zone."""
    from types import SimpleNamespace

    from pelagos.core import write_pipeline as wp
    from pelagos.installer import helper

    backend = make_backend(server, tmp_root)
    setup_includes(backend)
    local_file = server.root / "named.conf.local"
    original = local_file.read_text()
    real = wp._atomic_write

    def as_unprivileged(path, *args, **kw):
        if path == local_file:
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, *args, **kw)

    env = SimpleNamespace(
        paths=SimpleNamespace(named_conf=server.named_conf, bind_include_dir=backend.include_dir)
    )
    calls: list[str] = []

    class Client:
        def __init__(self, timeout: float = 0) -> None:
            pass

        def call(self, op: str, **args):
            calls.append(args["path"])
            return helper.handle({"op": op, **args}, lambda: env, lambda _m: None)

    monkeypatch.setattr(wp, "_atomic_write", as_unprivileged)
    monkeypatch.setattr(helper, "available", lambda: True)
    monkeypatch.setattr(helper, "HelperClient", Client)

    plan = backend.plan_config_change(
        [Change(ChangeOp.REPLACE, "handover/zones/_default/legacy.example.lan", after={"comment": True})]
    )
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    assert calls == [str(local_file)]
    assert "# moved to zones.conf by Pelagos" in local_file.read_text()
    assert "type: primary" in server.rndc("zonestatus", "legacy.example.lan")
    zone = next(z for z in backend.read_config().zones if z.name == "legacy.example.lan.")
    assert zone.source is ZoneSource.PELAGOS

    back = backend.rollback(plan)
    assert back.ok, back.message
    assert calls == [str(local_file)] * 2
    assert local_file.read_text() == original
    assert "type: primary" in server.rndc("zonestatus", "legacy.example.lan")
    zone = next(z for z in backend.read_config().zones if z.name == "legacy.example.lan.")
    assert zone.source is ZoneSource.USER_CONF
