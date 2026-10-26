# SPDX-License-Identifier: Apache-2.0
"""Administration > Certificates over the API: sources and their secrets, request made on the node,
checks, upload (PEM and PKCS#12), self-signed, the cluster source, audit without key material."""

from __future__ import annotations

import base64

import pytest

from pelagos.core.webcert import checks
from tests.unit.core.webcert_pki import key_pem_of, make_leaf, make_pki, p12, pem_of, sign_csr

pytestmark = pytest.mark.unit
BASE = "/api/v1/admin/certificates"
HOST = "ns1.example.lan"


@pytest.fixture(autouse=True)
def hermetic(monkeypatch, node_ctx):
    monkeypatch.setattr(checks.SYSTEM_TRUST, "roots", lambda: {})
    node_ctx.node.web_url = f"https://{HOST}:8443"


def _self(admin) -> dict:
    nodes = admin.get(BASE).get_json()["nodes"]
    return next(n for n in nodes if n["is_self"])


def test_overview_and_permissions(admin, login):
    data = admin.get(BASE).get_json()
    assert data["thresholds"] == {"warning_days": 30, "critical_days": 7}
    assert {p["type"] for p in data["providers"]} == {"hetzner"}
    me = _self(admin)
    assert me["source"]["source"] == "self_signed" and me["reachable"]
    assert login("dora").get(BASE).status_code == 403


def test_source_secrets_are_stored_encrypted_and_never_returned(admin, node_ctx):
    node = node_ctx.node.id
    body = {
        "source": "ucm",
        "ucm": {"url": "https://ucm.example.lan", "ca_id": 3, "validity_days": 365},
        "secrets": {"ucm_api_key": "ucm-key-value-1"},
    }
    r = admin.put(f"{BASE}/{node}/source", json=body)
    assert r.status_code == 200, r.get_json()
    out = r.get_json()
    assert out["source"]["secrets"] == {"eab_hmac": False, "dns_api_token": False, "ucm_api_key": True}
    assert out["job"] is None
    raw = node_ctx.paths.cluster_toml.read_text()
    assert "ucm-key-value-1" not in raw and f"certs/node-{node}/ucm_api_key" in raw
    assert "ucm-key-value-1" not in admin.get(BASE).get_data(as_text=True)
    assert "ucm-key-value-1" not in node_ctx.paths.audit_log.read_text()
    # Without the key, the UCM source is refused; null removes the stored one.
    body["secrets"] = {"ucm_api_key": None}
    r = admin.put(f"{BASE}/{node}/source", json=body)
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "secrets.ucm_api_key"


def test_cluster_source_is_inherited(admin, node_ctx):
    body = {
        "source": "acme",
        "node_ids": "all",
        "apply": False,
        "acme": {"profile": "letsencrypt-staging", "dns": {"method": "provider", "provider": "hetzner"}},
    }
    r = admin.put(f"{BASE}/cluster", json=body)
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "secrets.dns_api_token"
    body["secrets"] = {"dns_api_token": "hz-token-1"}
    r = admin.put(f"{BASE}/cluster", json=body)
    assert r.status_code == 200, r.get_json()
    me = _self(admin)
    assert me["inherited"] and me["source"]["source"] == "acme" and me["cluster_applies"]
    assert me["names"] == [HOST]
    assert admin.delete(f"{BASE}/cluster").status_code == 204
    assert _self(admin)["source"]["source"] == "self_signed"
    assert "certs/cluster/dns_api_token" not in node_ctx.cluster().secrets
    actions = [e["action"] for e in admin.get("/api/v1/audit?action=admin.cert").get_json()["items"]]
    assert actions == ["admin.cert.delete", "admin.cert.replace"]


def test_request_check_and_upload(admin, node_ctx):
    node = node_ctx.node.id
    pki = make_pki()
    csr = admin.post(f"{BASE}/{node}/request", json={"key_type": "ec-p256"}).get_json()
    assert csr["names"] == [HOST, "ns1"] and "BEGIN CERTIFICATE REQUEST" in csr["csr_pem"]
    assert _self(admin)["pending_request"]["names"] == [HOST, "ns1"]
    cert = sign_csr(pki.inter, csr["csr_pem"])
    body = {
        "cert_pem": pem_of(cert),
        "chain_pem": pem_of(pki.inter.cert) + pem_of(pki.root.cert),
        "use_pending_key": True,
    }
    report = admin.post(f"{BASE}/{node}/check", json=body).get_json()
    assert report["ok"] and report["certificate"]["san"] == [HOST, "ns1"]
    r = admin.post(f"{BASE}/{node}/upload", json=body)
    assert r.status_code == 200, r.get_json()
    me = _self(admin)
    assert me["current"]["fingerprint"] == report["certificate"]["fingerprint"]
    assert me["source"]["source"] == "manual" and me["pending_request"] is None
    log = node_ctx.paths.audit_log.read_text()
    assert "PRIVATE KEY" not in log and "BEGIN CERTIFICATE" not in log


def test_upload_refused_carries_the_checks(admin, node_ctx):
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, ["elsewhere.example.lan"])
    r = admin.post(
        f"{BASE}/{node_ctx.node.id}/upload",
        json={"cert_pem": pem_of(leaf) + pem_of(pki.inter.cert), "key_pem": key_pem_of(key)},
    )
    assert r.status_code == 400
    problem = r.get_json()
    failed = {c["id"] for c in problem["checks"]["checks"] if c["level"] == "error"}
    assert failed == {"names", "chain"}
    assert admin.post(f"{BASE}/{node_ctx.node.id}/upload", json={"cert_pem": "garbage"}).status_code == 400


def test_pkcs12_upload_and_self_signed(admin, node_ctx):
    pki = make_pki()
    leaf, key = make_leaf(pki.inter, [HOST, "ns1"])
    blob = p12(leaf, key, [pki.inter.cert, pki.root.cert], "Pass-1234")
    body = {"pkcs12_base64": base64.b64encode(blob).decode(), "password": "Pass-1234"}
    r = admin.post(f"{BASE}/{node_ctx.node.id}/upload", json=body)
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["certificate"]["issuer_common_name"] == "Test Intermediate"
    r = admin.post(f"{BASE}/{node_ctx.node.id}/self-signed")
    assert r.status_code == 200 and r.get_json()["certificate"]["self_signed"]
    assert _self(admin)["source"]["source"] == "self_signed"


def test_settings_page_never_sees_the_sources(admin):
    body = {"source": "ucm", "apply": False, "ucm": {"url": "https://ucm.example.lan", "ca_id": 1}}
    body["secrets"] = {"ucm_api_key": "k-12345678"}
    assert admin.put(f"{BASE}/cluster", json=body).status_code == 200
    settings = admin.get("/api/v1/admin/settings").get_json()
    assert settings["certificates"] == {
        "ucm_renew_days": 30,
        "retry_min_seconds": 300,
        "retry_max_seconds": 21600,
        "propagation_seconds": 180,
    }
    assert settings["alerts_cert_warning_days"] == 30 and settings["alerts_cert_critical_days"] == 7
    r = admin.put("/api/v1/admin/settings", json={"certificates": {"cluster": {"source": "acme"}}})
    assert r.status_code == 400
    r = admin.put(
        "/api/v1/admin/settings", json={"alerts_cert_warning_days": 5, "alerts_cert_critical_days": 7}
    )
    assert r.status_code == 400
    r = admin.put("/api/v1/admin/settings", json={"certificates": {"ucm_renew_days": 45}})
    assert r.status_code == 200 and r.get_json()["certificates"]["ucm_renew_days"] == 45
    assert admin.get(BASE).get_json()["cluster"]["source"] == "ucm"


def test_unknown_node_and_remote_tests(admin):
    assert admin.get(f"{BASE}/nope").status_code == 404
    r = admin.post(f"{BASE}/test/ucm", json={"ucm": {"url": "http://ucm.example.lan"}})
    assert r.get_json() == {"ok": False, "error": "the UCM URL must start with https://"}
    assert admin.post(f"{BASE}/test/dns", json={"dns": {"provider": "nope"}}).get_json()["ok"] is False
