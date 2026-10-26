# SPDX-License-Identifier: Apache-2.0
"""DNS-01 names and the Hetzner provider, the UCM client: routes, bodies, errors (fake HTTP)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from pelagos.core.webcert import dns01, http, ucm
from pelagos.core.webcert.acme import Challenge
from tests.unit.core.webcert_pki import make_leaf, make_pki, pem_of

pytestmark = pytest.mark.unit


class FakeHttp:
    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []

    def __call__(self, method: str, url: str, *, body: Any = None, headers=None, **_kw: Any) -> http.Response:
        self.calls.append((method, url, body, headers or {}))
        answer = self.routes.get((method, url))
        if answer is None:
            return http.Response(404, {}, b'{"error": {"message": "not found"}}')
        status, data = answer
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        return http.Response(status, {}, raw)


def test_challenge_names_and_delegation():
    assert dns01.challenge_name("*.ns1.example.lan") == "_acme-challenge.ns1.example.lan."
    assert dns01.challenge_name("ns1.example.lan", "acme.example.lan") == "ns1-example-lan.acme.example.lan."
    assert dns01.delegation_records(["ns1.example.lan", "*.ns1.example.lan"], "acme.example.lan") == [
        {
            "name": "_acme-challenge.ns1.example.lan.",
            "type": "CNAME",
            "value": "ns1-example-lan.acme.example.lan.",
        }
    ]


def test_hetzner_adds_to_and_removes_from_the_rrset(monkeypatch):
    api = "https://api.hetzner.cloud/v1"
    rrset = f"{api}/zones/z1/rrsets/_acme-challenge.ns1/TXT"
    fake = FakeHttp(
        {
            ("GET", f"{api}/zones?per_page=100"): (200, {"zones": [{"id": "z1", "name": "example.lan"}]}),
            ("GET", rrset): (200, {"rrset": {"records": [{"value": '"other"'}]}}),
            ("PATCH", rrset): (200, {}),
        }
    )
    monkeypatch.setattr(http, "request", fake)
    provider = dns01.HetznerProvider("tok-secret-1")
    provider.add_txt("_acme-challenge.ns1.example.lan.", "v1")
    method, url, body, headers = fake.calls[-1]
    assert (method, url) == ("PATCH", rrset)
    assert body == {"records": [{"value": '"other"'}, {"value": '"v1"'}], "ttl": dns01.TXT_TTL}
    assert headers["Authorization"] == "Bearer tok-secret-1"
    provider.delete_txt("_acme-challenge.ns1.example.lan.", "other")
    # The last value of the rrset goes: the rrset itself is deleted.
    assert fake.calls[-1][:2] == ("DELETE", rrset)


def test_hetzner_errors_never_echo_the_token(monkeypatch):
    api = "https://api.hetzner.cloud/v1"
    fake = FakeHttp(
        {("GET", f"{api}/zones?per_page=100"): (401, {"error": {"message": "bad token tok-secret-1"}})}
    )
    monkeypatch.setattr(http, "request", fake)
    with pytest.raises(dns01.DnsChallengeError) as err:
        dns01.HetznerProvider("tok-secret-1").test()
    assert "tok-secret-1" not in str(err.value)


def test_dns_solver_waits_for_every_server_and_cleans(monkeypatch):
    placed: list[tuple[str, str, str]] = []

    class Provider(dns01.DnsProvider):
        def add_txt(self, name, value):
            placed.append(("add", name, value))

        def delete_txt(self, name, value):
            placed.append(("del", name, value))

        def check_servers(self, name):
            return [dns01.Server("192.0.2.1"), dns01.Server("192.0.2.2")]

    seen = {"192.0.2.1": 0, "192.0.2.2": 0}

    def txt_values(name, server):
        seen[server.host] += 1
        # The second server catches up one poll later.
        return [] if server.host == "192.0.2.2" and seen[server.host] < 2 else [ch.txt_value]

    monkeypatch.setattr(dns01, "txt_values", txt_values)
    ch = Challenge("ns1.example.lan", "dns-01", "u", "tok", "tok.thumb", "a")
    solver = dns01.DnsSolver(Provider(), sleep=lambda _s: None)
    solver.present([ch])
    assert seen == {"192.0.2.1": 1, "192.0.2.2": 2}
    solver.cleanup([ch])
    assert [p[0] for p in placed] == ["add", "del"]
    assert placed[0][1] == "_acme-challenge.ns1.example.lan."

    monkeypatch.setattr(dns01, "txt_values", lambda name, server: [])
    solver = dns01.DnsSolver(Provider(), timeout=0, sleep=lambda _s: None)
    with pytest.raises(dns01.DnsChallengeError, match="not visible"):
        solver.present([ch])


def test_update_refused_by_a_secondary_goes_to_the_primary(monkeypatch):
    local = dns01.Server("127.0.0.1", 53)
    sent: list[str] = []
    monkeypatch.setattr(dns01, "zone_of", lambda name, server: "example.lan.")

    def send(self, zone, name, server, build):
        sent.append(str(server))
        return "NOERROR" if server.host == "192.0.2.53" else "REFUSED"

    monkeypatch.setattr(dns01.Rfc2136Provider, "_send", send)
    monkeypatch.setattr(dns01.Rfc2136Provider, "primary_of", lambda self, zone: dns01.Server("192.0.2.53"))
    provider = dns01.Rfc2136Provider(local, "ddi-acme", "c2VjcmV0", follow_primary=True)
    provider.add_txt("_acme-challenge.ns2.example.lan.", "v")
    assert sent == ["127.0.0.1", "192.0.2.53"]
    # A server given by the admin is the only one asked.
    sent.clear()
    fixed = dns01.Rfc2136Provider(local, "ddi-acme", "c2VjcmV0")
    with pytest.raises(dns01.DnsChallengeError, match="update-policy grant for key ddi-acme"):
        fixed.add_txt("_acme-challenge.ns2.example.lan.", "v")
    assert sent == ["127.0.0.1"]


def test_ucm_issue_flow_and_revoke(monkeypatch):
    pki = make_pki()
    leaf, _key = make_leaf(pki.inter, ["ns1.example.lan"])
    base = "https://ucm.example.lan"
    fake = FakeHttp(
        {
            ("POST", f"{base}/api/v2/csrs/upload"): (201, {"data": {"id": 41}}),
            ("POST", f"{base}/api/v2/csrs/41/sign"): (200, {"data": {"id": 41, "descr": "pelagos-ns1"}}),
            ("GET", f"{base}/api/v2/certificates/41/export?format=pem&include_chain=true"): (
                200,
                (pem_of(leaf) + pem_of(pki.inter.cert)).encode(),
            ),
            ("POST", f"{base}/api/v2/certificates/40/revoke"): (200, {"data": {}}),
            ("GET", f"{base}/api/v2/cas"): (
                200,
                {"data": [{"id": 3, "descr": "Lab CA", "has_private_key": True}]},
            ),
            ("GET", f"{base}/api/v2/templates"): (
                200,
                {"data": [{"id": 7, "name": "Server", "template_type": "server"}]},
            ),
        }
    )
    monkeypatch.setattr(http, "request", fake)
    client = ucm.UcmClient(base, "key-123")
    issued = client.issue("-----BEGIN CERTIFICATE REQUEST-----", "pelagos-ns1", 3, 365, 7)
    assert issued.cert_id == 41 and issued.fullchain_pem.count("BEGIN CERTIFICATE") == 2
    upload, sign = fake.calls[0], fake.calls[1]
    assert upload[2] == {"pem": "-----BEGIN CERTIFICATE REQUEST-----", "name": "pelagos-ns1"}
    assert sign[2] == {"ca_id": 3, "validity_days": 365, "cert_type": "server", "template_id": 7}
    assert all(c[3]["X-API-Key"] == "key-123" for c in fake.calls)
    client.revoke(40)
    assert fake.calls[-1][2] == {"reason": "superseded"}
    assert client.test() == {"cas": 1, "templates": 1}
    assert client.cas()[0] == {"id": 3, "name": "Lab CA", "status": None, "can_sign": True}


def test_ucm_approval_and_refused_key(monkeypatch):
    base = "https://ucm.example.lan"
    fake = FakeHttp(
        {
            ("POST", f"{base}/api/v2/csrs/upload"): (201, {"data": {"id": 5}}),
            ("POST", f"{base}/api/v2/csrs/5/sign"): (
                200,
                {
                    "data": {
                        "approval_required": True,
                        "message": "needs approval",
                        "status": "pending_approval",
                    }
                },
            ),
            ("GET", f"{base}/api/v2/cas"): (401, {"error": True, "message": "Invalid API key"}),
        }
    )
    monkeypatch.setattr(http, "request", fake)
    client = ucm.UcmClient(base, "key-123")
    with pytest.raises(ucm.UcmError, match="approval"):
        client.issue("csr", "n", 1)
    with pytest.raises(ucm.UcmError, match="refused the API key"):
        client.cas()
    with pytest.raises(ucm.UcmError, match="https"):
        ucm.UcmClient("http://ucm.example.lan", "k")
