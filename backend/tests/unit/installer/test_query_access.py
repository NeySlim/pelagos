# SPDX-License-Identifier: Apache-2.0
"""Import picks a query address named accepts, and the audit reports zones that refuse queries."""

from __future__ import annotations

import pytest

from pelagos.installer import bindconf, bindsetup
from pelagos.installer.security_audit import audit_bind, collect_bind
from tests.unit.installer.fakes import legacy_tree

pytestmark = pytest.mark.unit


def _env(tmp_path):
    env = legacy_tree(tmp_path)
    env.services.active.add(env.bind_unit())
    return env


def test_loopback_kept_when_every_zone_answers(tmp_path):
    env = _env(tmp_path)
    env.t.addresses = ["192.0.2.10"]
    assert bindsetup.choose_query_address(env, ["example.lan."]) == ("127.0.0.1", [])


def test_host_address_chosen_when_allow_query_excludes_localhost(tmp_path):
    env = _env(tmp_path)
    env.t.addresses = ["192.0.2.10", "192.0.2.11"]
    env.t.refused = {("127.0.0.1", "example.lan."), ("192.0.2.10", "example.lan.")}
    assert bindsetup.choose_query_address(env, ["example.lan."]) == ("192.0.2.11", [])


def test_loopback_kept_and_zones_listed_when_nothing_answers(tmp_path):
    env = _env(tmp_path)
    env.t.addresses = ["192.0.2.10"]
    env.t.refused = {("127.0.0.1", "example.lan."), ("192.0.2.10", "example.lan.")}
    assert bindsetup.choose_query_address(env, ["example.lan."]) == ("127.0.0.1", ["example.lan."])


def test_audit_reports_refused_zones_with_the_query_address(tmp_path):
    env = _env(tmp_path)
    env.t.refused = {("127.0.0.1", "example.lan.")}
    inp = collect_bind(env)
    assert inp is not None and inp.query_refused == ["example.lan."]
    (f,) = [f for f in audit_bind(inp) if f.kind == "query_refused"]
    assert f.id == "bind:query_refused:127.0.0.1"
    assert f.details["zones"] == ["example.lan."] and not f.to_dict()["remediable"]
    assert "127.0.0.1" in f.proposal


def test_audit_silent_when_named_is_stopped(tmp_path):
    env = legacy_tree(tmp_path)
    env.t.refused = {("127.0.0.1", "example.lan.")}
    inp = collect_bind(env)
    assert inp is not None and inp.query_refused == []
    assert not [f for f in audit_bind(inp) if f.kind == "query_refused"]


def test_served_zones_skip_hints_and_builtin(tmp_path):
    env = _env(tmp_path)
    files = bindconf.load_files(env.paths.named_conf)
    zones = bindsetup.served_zones(files)
    assert "example.lan." in zones and "." not in zones and "localhost." not in zones


def test_silent_host_address_is_skipped(tmp_path):
    env = _env(tmp_path)
    env.t.addresses = ["192.0.2.10", "192.0.2.11"]
    env.t.refused = {("127.0.0.1", "example.lan.")}
    env.t.silent = {("192.0.2.10", "example.lan.")}
    assert bindsetup.choose_query_address(env, ["example.lan."]) == ("192.0.2.11", [])
