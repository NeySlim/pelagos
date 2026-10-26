# SPDX-License-Identifier: Apache-2.0
"""The node's web certificate: request made here, upload, install pipeline with rollback, automatic
issuance with backoff and renewal, transfer from another node, expiry alerts, audit without keys."""

from __future__ import annotations

import stat
from datetime import timedelta

import pytest

from pelagos.core.webcert import checks, manager, pem
from pelagos.core.webcert import config as wc
from pelagos.domain import AlertKind, Severity
from pelagos.domain.common import utcnow
from tests.unit.core.webcert_pki import key_pem_of, make_leaf, make_pki, pem_of, sign_csr

pytestmark = pytest.mark.unit

HOST = "ns1.example.lan"


@pytest.fixture(autouse=True)
def no_system_store(monkeypatch):
    # The unit tier never reads the host's CA bundle.
    monkeypatch.setattr(checks.SYSTEM_TRUST, "roots", lambda: {})


@pytest.fixture
def ctx(node_ctx):
    node_ctx.node.web_url = f"https://{HOST}:8443"
    return node_ctx


@pytest.fixture
def pki():
    return make_pki()


class Clock:
    def __init__(self) -> None:
        self.now = utcnow()

    def __call__(self):
        return self.now


def set_source(ctx, src: dict) -> None:
    def mutate(c):
        c.settings.setdefault("certificates", {}).setdefault("nodes", {})[ctx.node.id] = src

    ctx.config_store.update_cluster(mutate, updated_by="test")


def audit_text(ctx) -> str:
    return ctx.paths.audit_log.read_text()


def test_request_made_here_then_signed_certificate_uploaded(ctx, pki):
    mgr = manager.CertManager(ctx)
    meta = mgr.make_request("ec-p256", ["alias.example.lan"], "admin")
    assert meta["names"] == [HOST, "ns1", "alias.example.lan"]
    assert stat.S_IMODE(mgr.pending_key_path.stat().st_mode) == 0o600
    cert = sign_csr(pki.inter, meta["csr_pem"])
    mat = mgr.material(pem_of(cert) + pem_of(pki.inter.cert) + pem_of(pki.root.cert), use_pending_key=True)
    out = mgr.upload(mat, "admin", used_pending=True)
    assert out["certificate"]["san"] == [HOST, "ns1", "alias.example.lan"]
    assert stat.S_IMODE(mgr.key_path.stat().st_mode) == 0o600
    assert mgr.current()[0] == cert and len(mgr.current()) == 3
    assert mgr.pending() is None and not mgr.pending_key_path.exists()
    assert "PRIVATE KEY" not in audit_text(ctx) and "admin.cert.apply" in audit_text(ctx)
    # The note in the pipeline: the web listener does not run in the unit tier.
    assert any("not checked" in n for n in out["notes"])


def test_upload_refused_by_checks_installs_nothing(ctx, pki):
    mgr = manager.CertManager(ctx)
    before = mgr.cert_path.read_bytes() if mgr.cert_path.exists() else None
    leaf, key = make_leaf(pki.inter, ["other.example.lan"])
    with pytest.raises(manager.CertFailure) as err:
        mgr.upload(
            pem.parse_material(
                pem_of(leaf) + pem_of(pki.inter.cert) + pem_of(pki.root.cert), key_pem_of(key)
            ),
            "admin",
        )
    assert any(c.id == "names" for c in err.value.report.errors)
    assert (mgr.cert_path.read_bytes() if mgr.cert_path.exists() else None) == before


def test_handshake_failure_rolls_back(ctx, pki):
    mgr = manager.CertManager(ctx)
    mgr.self_signed("admin")
    first = mgr.cert_path.read_bytes()
    failing = manager.CertManager(ctx, verify=lambda fp: False)
    with pytest.raises(manager.CertFailure, match="rolled back"):
        failing.self_signed("admin")
    assert mgr.cert_path.read_bytes() == first
    assert '"result":"error"' in audit_text(ctx).replace(" ", "")


def test_automatic_issuance_renewal_and_backoff(ctx, pki, monkeypatch):
    clock = Clock()
    mgr = manager.CertManager(ctx, clock=clock)
    mgr.self_signed("admin")
    set_source(
        ctx,
        {
            "source": "ucm",
            "revision": "r1",
            "ucm": {"url": "https://ucm.example.lan", "ca_id": 1, "revoke_old": True},
        },
    )
    calls = {"n": 0, "revoked": []}

    def issue_ucm(src, scope, csr_pem):
        calls["n"] += 1
        if calls["n"] == 2:
            raise manager.CertFailure("UCM: connection refused")
        cert = sign_csr(pki.inter, csr_pem, lifetime=timedelta(days=365))
        return pem_of(cert) + pem_of(pki.inter.cert) + pem_of(pki.root.cert), 100 + calls["n"]

    monkeypatch.setattr(mgr, "_issue_ucm", issue_ucm)
    monkeypatch.setattr(mgr, "_revoke_ucm", lambda src, scope, cid: calls["revoked"].append(cid))
    assert mgr.due() == "source changed"
    assert mgr.run_due() == "source changed"
    st = mgr.status()
    assert st["last_source"] == "ucm" and st["failures"] == 0
    assert mgr.due() is None
    # 30 days before the end of a one-year certificate the renewal is due; the first try fails.
    clock.now += timedelta(days=336)
    assert mgr.due() == "renewal due"
    mgr.run_due()
    st = mgr.state()
    assert st["failures"] == 1 and "connection refused" in st["last_error"]
    assert mgr.due() is None  # backoff: retry_min_seconds
    kinds = {a.kind for a in mgr.alerts()}
    assert AlertKind.CERT_RENEWAL_FAILED in kinds
    clock.now += timedelta(seconds=wc.retry_delay(1, ctx.settings()) + 1)
    assert mgr.run_due() == "renewal due"
    assert mgr.state()["failures"] == 0 and calls["revoked"] == [101]
    assert AlertKind.CERT_RENEWAL_FAILED not in {a.kind for a in mgr.alerts()}


def test_expiry_alerts_scale_with_lifetime(ctx, pki):
    clock = Clock()
    mgr = manager.CertManager(ctx, clock=clock)

    def install(lifetime: timedelta, start: timedelta) -> None:
        leaf, key = make_leaf(pki.inter, [HOST], start=start, lifetime=lifetime)
        mgr.cert_path.write_text(pem_of(leaf) + pem_of(pki.inter.cert))
        mgr.key_path.write_text(key_pem_of(key))

    def web_alert():
        return next((a for a in mgr.alerts() if a.subject == "cert:web"), None)

    install(timedelta(days=90), timedelta(days=-60))  # 30 days left at most
    assert web_alert() is None or web_alert().severity is Severity.WARNING
    install(timedelta(days=90), timedelta(days=-70))  # 20 days left
    assert web_alert().severity is Severity.WARNING
    install(timedelta(days=90), timedelta(days=-85))  # 5 days left
    alert = web_alert()
    assert alert.severity is Severity.CRITICAL and alert.details["days_left"] == 4
    assert alert.title_message["key"] == "alert.cert_expiry"
    # A 24 h certificate with 10 hours left is on schedule; with one hour left it is critical.
    install(timedelta(hours=24), timedelta(hours=-14))
    assert web_alert() is None
    install(timedelta(hours=24), timedelta(hours=-23))
    assert web_alert().severity is Severity.CRITICAL
    install(timedelta(days=90), timedelta(days=-91))
    assert web_alert().title_message["key"] == "alert.cert_expired"


def test_node_and_ca_certificates_are_watched(ctx, pki):
    mgr = manager.CertManager(ctx)
    assert {a.subject for a in mgr.alerts()} == set()
    leaf, _ = make_leaf(pki.inter, ["ns1"], start=timedelta(days=-725), lifetime=timedelta(days=730))
    (ctx.paths.pki_dir / "node.crt").write_text(pem_of(leaf))
    alerts = {a.subject: a for a in mgr.alerts()}
    assert alerts["cert:node"].severity is Severity.CRITICAL
    assert alerts["cert:node"].title_message["params"]["cert"]["key"] == "cert.kind.node"


def test_transfer_from_another_node(ctx, pki):
    mgr = manager.CertManager(ctx)
    leaf, key = make_leaf(pki.inter, [HOST])
    name = wc.transfer_secret(ctx.node.id)
    token = ctx.secrets.encrypt(name, key_pem_of(key))

    def mutate(c):
        c.secrets[name] = token
        c.settings.setdefault("certificates", {}).setdefault("nodes", {})[ctx.node.id] = {
            "source": "manual",
            "transfer": {
                "revision": "t1",
                "fullchain_pem": pem_of(leaf) + pem_of(pki.inter.cert) + pem_of(pki.root.cert),
                "from_node": "other",
                "by": "admin",
            },
        }

    ctx.config_store.update_cluster(mutate, updated_by="test")
    mgr.run_due()
    assert mgr.current()[0] == leaf
    cluster = ctx.cluster()
    assert name not in cluster.secrets
    assert "transfer" not in cluster.settings["certificates"]["nodes"][ctx.node.id]
    assert mgr.take_transfer() is None
