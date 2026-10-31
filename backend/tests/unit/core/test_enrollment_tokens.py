# SPDX-License-Identifier: Apache-2.0
"""TokenStore shared through a file, request validation, CLI engine parsing."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from pelagos.core.config_store import NodeConfig
from pelagos.core.enrollment import (
    MAX_TOKEN_TTL_SECONDS,
    EnrollError,
    EnrollmentService,
    EnrollRequest,
    EnrollResponse,
    TokenStore,
    _parse_engines,
    enroll_command,
)
from pelagos.domain.cluster import Peer, clean_web_url
from pelagos.domain.common import utcnow

pytestmark = pytest.mark.unit


def test_file_store_is_shared_between_two_instances(tmp_root):
    path = tmp_root / "enroll_tokens.json"
    web = TokenStore(path)
    collector = TokenStore(path)
    token, expires = web.issue("user:admin", ttl_seconds=60, ca=True)
    assert len(token) >= 43 and expires > utcnow() + timedelta(seconds=50)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    raw = json.loads(path.read_text())
    assert token not in path.read_text() and len(raw) == 1  # only the hash is stored
    rec = collector.consume(token)
    assert rec is not None and rec.ca is True and rec.used is True
    assert web.consume(token) is None
    assert json.loads(path.read_text()) == {}


def test_expired_tokens_are_purged_and_ttl_is_capped(tmp_root):
    store = TokenStore(tmp_root / "t.json")
    token, expires = store.issue("u", ttl_seconds=MAX_TOKEN_TTL_SECONDS * 10)
    assert expires <= utcnow() + timedelta(seconds=MAX_TOKEN_TTL_SECONDS + 1)
    rec = store._load()[store._hash(token)]
    rec.expires_at = utcnow() - timedelta(seconds=1)
    store._save({rec.token_hash: rec})
    assert store.pending() == 0
    assert store.purge() == 1
    assert store.consume(token) is None


def test_memory_store_without_path():
    store = TokenStore()
    token, _ = store.issue("u")
    assert store.pending() == 1
    assert store.consume(token) is not None
    assert store.consume("nope") is None


def test_corrupt_file_starts_empty(tmp_root):
    path = tmp_root / "t.json"
    path.write_text("{not json")
    store = TokenStore(path)
    assert store.pending() == 0
    token, _ = store.issue("u")
    assert store.consume(token) is not None


def test_request_and_response_validation():
    with pytest.raises(EnrollError) as err:
        EnrollRequest.from_dict({"token": "x"})
    assert err.value.status == 400
    req = EnrollRequest.from_dict(
        {"token": "t", "name": "ns2", "csr_pem": "-", "modules": {"bind": 1}, "url": "https://ns2:8444"}
    )
    assert req.modules == {"bind": True} and req.web_url is None and req.version == ""
    assert EnrollRequest.from_dict(req.to_dict()) == req
    with pytest.raises(EnrollError) as err:
        EnrollResponse.from_dict({"cert_pem": "x"})
    assert err.value.status == 502
    resp = EnrollResponse.from_dict(
        {"cert_pem": "c", "ca_pem": "a", "master_key": "m", "cluster_toml": "t", "node_id": "n"}
    )
    assert resp.ca_key_pem is None and resp.extra == {"node_id": "n"}
    assert "ca_key_pem" not in resp.to_dict() and resp.to_dict()["node_id"] == "n"


def test_parse_engines():
    assert _parse_engines(None) is None
    assert _parse_engines("bind, d2") == {"bind": True, "kea4": False, "kea6": False, "d2": True}
    with pytest.raises(ValueError, match="unknown engines"):
        _parse_engines("bind,dhcp")


@pytest.mark.parametrize(
    ("url", "web_url", "web", "repl"),
    [
        (
            "https://ns1.example.lan:8444",
            "https://ns1.example.lan:8443",
            "https://<name>.example.lan:8443",
            "https://<name>.example.lan:8444",
        ),
        ("https://ns1:9444", None, "https://<name>:8443", "https://<name>:9444"),
        ("https://192.0.2.11:8444", "https://192.0.2.11:443", "https://<name>:443", "https://<name>:8444"),
    ],
)
def test_enroll_command_runs_as_root_with_the_peer_urls(url, web_url, web, repl):
    cmd = enroll_command(url, "tok", "sha256:ab", web_url)
    assert cmd.startswith(f"sudo pelagos enroll --url {url} --token tok --ca-fingerprint sha256:ab ")
    assert "--name <name> " in cmd
    assert cmd.endswith(f"--web-url {web} --replication-url {repl}")


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "data:text/html,x",
        "ftp://ns2/",
        "https://",
        "//ns2/x",
        "https://ns2:99999",
        "https://ns2/ x",
        "https://a\\@evil.example",
        "https://ns2/\x7f",
        "https://ns2/" + "a" * 2100,
        "",
        5,
    ],
)
def test_clean_web_url_rejects_non_http_values(value):
    assert clean_web_url(value) is None


def test_clean_web_url_keeps_http_and_https():
    assert clean_web_url("https://ns2.example.lan:8443") == "https://ns2.example.lan:8443"
    assert clean_web_url("http://[2001:db8::2]:8443/") == "http://[2001:db8::2]:8443/"


def test_peer_ignores_a_stored_or_replicated_bad_web_url():
    base = {"id": "N1", "name": "ns2", "url": "https://ns2:8444", "cert_fingerprint": "aa"}
    assert Peer.from_dict({**base, "web_url": "javascript:alert(1)"}).web_url is None
    assert Peer.from_dict({**base, "web_url": "https://ns2:8443"}).web_url == "https://ns2:8443"


def test_node_toml_with_a_bad_web_url_loads_as_empty():
    node = NodeConfig.from_toml({"node": {"id": "N1", "name": "ns1", "web_url": "javascript:alert(1)"}})
    assert node.web_url == ""


def test_enroll_refuses_a_bad_web_url_before_burning_the_token(tmp_root, monkeypatch):
    svc = EnrollmentService.__new__(EnrollmentService)
    svc._ca = lambda: object()
    svc.tokens = TokenStore()
    token, _ = svc.tokens.issue("user:admin", ttl_seconds=60)
    monkeypatch.setattr("pelagos.core.enrollment.ca_mod.csr_node_id", lambda _csr: "N2")
    req = EnrollRequest(token, "ns2", "-", {}, "https://ns2:8444", "javascript:alert(1)", "")
    with pytest.raises(EnrollError) as err:
        svc.enroll(req)
    assert err.value.status == 400 and err.value.code == "validation_error" and err.value.field == "web_url"
    assert svc.tokens.pending() == 1  # the token is still usable


def test_enroll_accepts_an_empty_web_url_as_absent(tmp_root, monkeypatch):
    svc = EnrollmentService.__new__(EnrollmentService)
    svc._ca = lambda: object()
    monkeypatch.setattr("pelagos.core.enrollment.ca_mod.csr_node_id", lambda _csr: "N2")

    class Reached(Exception):
        pass

    def load_cluster():
        raise Reached

    svc.config_store = type("S", (), {"load_cluster": staticmethod(load_cluster)})()
    req = EnrollRequest("t", "ns2", "-", {}, "https://ns2:8444", "", "")
    with pytest.raises(Reached):  # past the web_url check
        svc.enroll(req)


def test_node_toml_keeps_a_legacy_web_url_on_disk_and_warns(caplog):
    node = NodeConfig.from_toml({"node": {"id": "N1", "name": "ns1", "web_url": "ns1.example.lan:8443"}})
    assert node.web_url == "" and "ns1.example.lan:8443" in caplog.text
    assert node.to_toml()["node"]["web_url"] == "ns1.example.lan:8443"
    node.web_url = "https://ns1.example.lan:8443"
    assert node.to_toml()["node"]["web_url"] == "https://ns1.example.lan:8443"
