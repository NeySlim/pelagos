# SPDX-License-Identifier: Apache-2.0
"""Translatable backend messages: catalog, producers, UI catalogs and storage."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest

from pelagos.api.errors import STATUS_BY_CODE, TITLES
from pelagos.collector import rules
from pelagos.collector.alerts import AlertStore
from pelagos.collector.series import connect
from pelagos.domain import Alert, AlertKind, Engine, Job, Severity, messages
from pelagos.domain.messages import CATALOG, msg, render, step_label
from pelagos.installer.jobs import JobRunner, Step
from pelagos.services import consistency

pytestmark = pytest.mark.unit

BACKEND = Path(__file__).resolve().parents[2]
FRONTEND_I18N = BACKEND.parent / "frontend" / "src" / "i18n"
PACKAGE = BACKEND / "pelagos"


def test_generated_key_list_is_up_to_date():
    """frontend/src/i18n/backendMessageKeys.json: `python -m pelagos.domain.messages > ...`."""
    generated = json.loads((FRONTEND_I18N / "backendMessageKeys.json").read_text())
    assert generated == messages.catalog_export()


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_every_key_is_in_the_ui_catalog_with_its_parameters(lang):
    catalog = json.loads((FRONTEND_I18N / "locales" / lang / "messages.json").read_text())
    for key, template in CATALOG.items():
        assert key in catalog, f"{lang}/messages.json lacks {key}"
        ui = sorted(set(re.findall(r"\{\{\s*(\w+)\s*\}\}", catalog[key])))
        assert ui == sorted(messages.placeholders(template)), f"{lang}/messages.json {key}"
        assert "—" not in catalog[key]
    assert set(catalog) == set(CATALOG)


def test_english_ui_catalog_matches_the_backend_text():
    catalog = json.loads((FRONTEND_I18N / "locales" / "en" / "messages.json").read_text())
    for key, template in CATALOG.items():
        params = {p: f"<{p}>" for p in messages.placeholders(template)}
        ui = re.sub(r"\{\{(\w+)\}\}", lambda m: f"<{m.group(1)}>", catalog[key])
        assert ui == template.format(**params), key


# Keys used as string literals by producers: every one must be in the catalog.
_LITERAL = re.compile(
    r"""["']((?:plan|alert|finding|job|problem|note|op|common)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*)["']"""
)


def test_every_literal_key_in_the_sources_exists():
    # Audit action names share the dotted shape but are not messages.
    actions = {"alert.ack", "alert.raise", "alert.resolve"}
    used: set[str] = set()
    for path in PACKAGE.rglob("*.py"):
        if path.name != "messages.py":
            used.update(_LITERAL.findall(path.read_text()))
    missing = sorted(used - set(CATALOG) - actions)
    assert not missing, missing
    assert {"alert.ha_partner_down", "plan.rrset.counts", "finding.view_key.proposal"} <= used


def test_message_shape_and_validation():
    m = msg("alert.peer_offline", node="ns2")
    assert m == {"key": "alert.peer_offline", "params": {"node": "ns2"}}
    assert render(m) == "node ns2 is unreachable"
    with pytest.raises(KeyError):
        msg("alert.peer_offline")
    with pytest.raises(KeyError):
        msg("alert.no_such_key")
    # A parameter may be called `key`; values are made JSON-safe.
    import ipaddress

    m = msg("finding.weak_tsig_key.description", key=ipaddress.ip_address("192.0.2.1"), algorithm=Engine.BIND)
    assert json.loads(json.dumps(m))["params"] == {"key": "192.0.2.1", "algorithm": "bind"}


def test_render_nested_lists_joins_and_escaped_braces():
    note = msg(
        "common.with_note",
        text=msg("plan.rrset.changes", zone="example.lan."),
        note=msg("note.static_file_edit"),
    )
    assert render(note) == "example.lan.: record changes (file edit, the zone stays static)"
    view = msg(
        "finding.view_key.description",
        view="internal",
        clients=messages.join(["10.0.0.0/8", "localhost"], "; "),
        read_key="ddi-read",
        admin_key="ddi-admin",
    )
    assert render(view).startswith("View internal is selected by match-clients { 10.0.0.0/8; localhost; }: ")
    assert render(msg("plan.kea.global", engine="kea4", targets=["a", "b"])) == "kea4: a, b"


def test_add_note_keeps_text_and_message_in_step():
    from pelagos.domain import Plan, PlanScope

    plan = Plan(scope=PlanScope.DNS_RRSET, node_id="n", summary="")
    messages.set_text(plan, "summary", msg("plan.rrset.changes", zone="example.lan."))
    messages.add_note(plan, "summary", msg("note.static_file_edit_on", node="ns1"))
    assert plan.summary == "example.lan.: record changes (file edit on ns1, the zone stays static)"
    assert plan.summary_message["key"] == "common.with_note"
    assert render(plan.summary_message) == plan.summary
    # A plan built without a message keeps working: the note goes on the text only.
    legacy = Plan(scope=PlanScope.DNS_RRSET, node_id="n", summary="old")
    messages.add_note(legacy, "summary", msg("note.no_difference"))
    assert legacy.summary == "old (no difference found)" and legacy.summary_message is None
    assert Plan.from_dict(plan.to_dict()).summary_message == plan.summary_message


@pytest.mark.parametrize(
    ("target", "key", "params"),
    [
        ("install/repo/isc-kea-3-0", "job.step.repo", {"repo": "isc-kea-3-0"}),
        ("install/packages", "job.step.packages", {}),
        ("import/user/pelagos", "job.step.user", {"user": "pelagos"}),
        ("install/service/kea4", "job.step.service", {"engine": "kea4"}),
        ("install/bind/adopt", "job.step.bind_adopt", {}),
        ("install/d2/config", "job.step.kea_config", {"engine": "d2"}),
        ("import/kea6/socket", "job.step.kea_socket", {"engine": "kea6"}),
        ("import/node", "job.step.node", {}),
        ("install/verify", "job.step.verify", {}),
        ("import/preconditions", "job.step.preconditions", {}),
        ("security/preconditions", "job.step.preconditions", {}),
        (
            "security/bind:open_recursion:options",
            "job.step.security",
            {"finding": "bind:open_recursion:options"},
        ),
        (
            "security/bind:weak_shared_kea_key:kea-ddns/2-d2-switch",
            "job.step.security_d2_switch",
            {"finding": "bind:weak_shared_kea_key:kea-ddns"},
        ),
        (
            "security/bind:static_zone:_default/example.lan./x",
            "job.step.security",
            {"finding": "bind:static_zone:_default/example.lan./x"},
        ),
        ("result", "job.step.result", {}),
    ],
)
def test_step_labels(target, key, params):
    assert step_label(target) == {"key": key, "params": params}


def test_unknown_step_has_no_label():
    assert step_label("changes/ns2/replicate") is None
    assert step_label("something") is None


def test_job_steps_carry_label_and_message():
    job = JobRunner(Job()).run([Step("install/packages", lambda: "ok"), Step("custom/thing", lambda: "ok")])
    first, second = job.steps
    assert first["label"] == "Install the packages"
    assert first["label_message"] == {"key": "job.step.packages", "params": {}}
    assert second["label"] == "custom/thing" and second["label_message"] is None


def test_problem_titles_are_catalog_keys():
    for code in STATUS_BY_CODE:
        assert CATALOG[f"problem.{code}"] == TITLES[code]


def test_problem_document_carries_title_and_detail_messages():
    from flask import Flask

    from pelagos.api.errors import ApiError

    with Flask(__name__).test_request_context("/api/v1/x"):
        default = ApiError("plan_expired").to_problem()
        free = ApiError("conflict", "subnet 7 already exists").to_problem()
    assert default["title_message"] == {"key": "problem.plan_expired", "params": {}}
    assert default["detail_message"] == default["title_message"]
    assert free["title_message"] == {"key": "problem.conflict", "params": {}}
    assert "detail_message" not in free


def test_alert_rules_emit_messages_with_the_same_text():
    alert = rules.d2_errors("n1", 0.1234, {}, 0.05)
    assert alert is not None
    assert alert.title == "DDNS updates failing: 12.3% over the last hour"
    assert alert.title_message == {"key": "alert.d2_errors", "params": {"percent": "12.3"}}
    down = rules.daemon_down("n1", Engine.KEA4, "refused")
    assert render(down.title_message) == down.title == "kea4 does not answer"


def test_consistency_titles_join_problems_with_semicolons():
    from pelagos.domain import RRset

    forward = [RRset(name="a.example.lan.", rtype="A", ttl=60, rdata=["192.0.2.10"])]
    reverse = [
        RRset(name="2.0.192.in-addr.arpa.", rtype="SOA", ttl=60, rdata=["ns1. h. 1 2 3 4 5"]),
        RRset(name="10.2.0.192.in-addr.arpa.", rtype="PTR", ttl=60, rdata=["b.example.lan."]),
    ]
    alerts = consistency.ptr_mismatches(
        [*forward, RRset(name="example.lan.", rtype="SOA", ttl=60, rdata=["ns1. h. 1 2 3 4 5"])], reverse
    )
    assert alerts
    a = alerts[0]
    assert a.title == render(a.title_message)
    assert a.title_message["params"]["problems"]["sep"] == "; "
    assert all(isinstance(p, str) for p in a.details["problems"])


def test_alert_store_keeps_title_message(tmp_path):
    conn = connect(tmp_path / "series.sqlite")
    store = AlertStore(conn)
    alert = rules.peer_offline("n2", "ns2", 3, "timeout")
    store.reconcile([alert], scope={AlertKind.PEER_OFFLINE.value})
    got = store.get(alert.id)
    assert got is not None and got.title_message == {"key": "alert.peer_offline", "params": {"node": "ns2"}}
    conn.close()


def test_old_cache_gains_the_column_and_reads_without_it(tmp_path):
    path = tmp_path / "series.sqlite"
    old = sqlite3.connect(path)
    old.executescript(
        """CREATE TABLE alerts (
          id TEXT PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL, state TEXT NOT NULL,
          node_id TEXT, engine TEXT, subject TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL,
          first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
          acked_by TEXT, acked_at INTEGER, resolved_at INTEGER);
        INSERT INTO alerts VALUES ('A','peer_offline','warning','open',NULL,NULL,'peer:x','old title','{}',
          1,1,NULL,NULL,NULL);"""
    )
    old.commit()
    # The web process reads an unmigrated cache read-only.
    ro = connect(path, readonly=True)
    legacy = AlertStore(ro).get("A")
    assert legacy is not None and legacy.title == "old title" and legacy.title_message is None
    ro.close()
    old.close()
    conn = connect(path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    assert "title_message" in columns
    store = AlertStore(conn)
    store.upsert(
        Alert(
            kind=AlertKind.PEER_OFFLINE,
            severity=Severity.WARNING,
            subject="peer:y",
            **messages.fields("title", msg("alert.peer_offline", node="ns2")),
        )
    )
    assert {a.subject: a.title_message for a in store.open_alerts()}["peer:y"]["key"] == "alert.peer_offline"
    conn.close()
