# SPDX-License-Identifier: Apache-2.0
"""WebAuthn helpers: rpId from the nodes' names, availability, ceremonies, counters, second factor policy."""

from __future__ import annotations

import pytest

from pelagos.auth import twofa
from pelagos.auth import webauthn as wa
from pelagos.domain import User, WebAuthnCredential
from tests.unit.auth.softkey import SoftKey

pytestmark = pytest.mark.unit

NODES = [("a", "ns1", "https://ns1.example.lan:8443"), ("b", "ns2", "https://ns2.example.lan:8443")]


@pytest.mark.parametrize(
    ("hosts", "expected"),
    [
        (["ns1.example.lan", "ns2.example.lan"], "example.lan"),
        (["ns1.dc1.example.lan", "ns2.dc2.example.lan"], "example.lan"),
        (["ns1.example.lan"], "example.lan"),
        (["ns1.lan"], "ns1.lan"),
        (["ns1"], None),
        (["ns1.a.lan", "ns2.b.lan"], None),  # "lan" alone is never an rpId
        (["ns1.example.lan", "192.0.2.10"], None),
        (["ns1", "ns2"], None),
    ],
)
def test_common_domain(hosts, expected):
    assert wa.common_domain(hosts) == expected


def test_rp_status_from_nodes_and_setting():
    st = wa.rp_status("auto", NODES)
    assert (st.rp_id, st.source, st.warning) == ("example.lan", "common_domain", None)
    assert all(n["covered"] for n in st.nodes)
    st = wa.rp_status("ns1.example.lan", NODES)
    assert (st.rp_id, st.source, st.warning) == ("ns1.example.lan", "setting", "node_outside_rp_id")
    st = wa.rp_status("auto", [("a", "ns1", "https://ns1:8443"), ("b", "ns2", "https://192.0.2.2:8443")])
    assert (st.rp_id, st.source, st.warning) == (None, "request_host", "no_common_domain")
    assert st.for_host("ns1.example.org") == "ns1.example.org"


def test_availability():
    assert wa.availability("example.lan", "ns1.example.lan", "https") is None
    assert wa.availability("example.lan", "example.lan", "https") is None
    assert wa.availability("example.lan", "192.0.2.1", "https") == "ip_address"
    assert wa.availability("example.lan", "ns1.example.lan", "http") == "insecure"
    assert wa.availability("example.lan", "ns1.other.lan", "https") == "outside_rp_id"
    assert wa.availability("example.lan", "badexample.lan", "https") == "outside_rp_id"
    assert wa.availability("localhost", "localhost", "http") is None
    assert wa.host_of("NS1.Example.LAN.:8443") == "ns1.example.lan"
    assert wa.host_of("[2001:db8::1]:8443") == "2001:db8::1"


def test_ceremonies_are_single_use_typed_and_expire():
    store = wa.CeremonyStore(ttl=60, cap=3)
    cer = store.open(wa.REGISTER, "example.lan", "https://ns1.example.lan", "u1")
    assert store.take(cer.id, wa.PASSKEY) is None
    assert store.take(cer.id, wa.REGISTER) is None  # consumed by the wrong-kind attempt
    ids = [store.open(wa.PASSKEY, "example.lan", "o", None).id for _ in range(5)]
    assert len(store) == 3 and store.take(ids[0], wa.PASSKEY) is None
    assert store.take(ids[-1], wa.PASSKEY) is not None
    old = store.open(wa.PASSKEY, "example.lan", "o", None)
    old.created -= 120
    assert store.take(old.id, wa.PASSKEY) is None
    assert store.take(None, wa.PASSKEY) is None


def _register(origin="https://ns1.example.lan:8443", rp="example.lan", **kw):
    key = SoftKey(origin, **kw)
    cer = wa.CeremonyStore().open(wa.REGISTER, rp, origin, "U1")
    options = wa.registration_options(cer, "U1", "alice", {})
    assert options["rp"]["id"] == rp and options["authenticatorSelection"]["residentKey"] == "preferred"
    reg = wa.verify_registration(cer, key.create(options))
    stored = WebAuthnCredential(name="k", public_key=reg.public_key, rp_id=rp, sign_count=reg.sign_count)
    return key, reg, stored


def test_register_then_assert_on_another_node_of_the_domain():
    key, reg, stored = _register(synced=True)
    assert reg.credential_id == key.id and reg.transports == ["usb"] and reg.backup_eligible
    other = "https://ns2.example.lan:8443"
    cer = wa.CeremonyStore().open(wa.PASSKEY, "example.lan", other, None)
    options = wa.authentication_options(cer, {})
    assert options["userVerification"] == "required" and options.get("allowCredentials", []) == []
    answer = key.get(options, origin=other)
    assert wa.user_handle(answer) == "U1"
    assert wa.verify_assertion(cer, answer, stored, 1) == 2


def test_assertion_refusals():
    key, _reg, stored = _register()
    store = wa.CeremonyStore()
    origin = "https://ns1.example.lan:8443"

    def attempt(kind=wa.SECOND_FACTOR, known=0, **kw):
        cer = store.open(kind, "example.lan", origin, "U1")
        return wa.verify_assertion(cer, key.get(wa.authentication_options(cer, {}), **kw), stored, known)

    with pytest.raises(wa.WebAuthnError):
        attempt(origin="https://evil.example.org")
    with pytest.raises(wa.WebAuthnError):
        attempt(rp_id="other.lan")
    with pytest.raises(wa.WebAuthnError):
        attempt(known=1000)  # the counter went backwards: cloned key
    key.user_verifies = False
    assert attempt() > 0  # user verification is optional for a second factor
    with pytest.raises(wa.WebAuthnError):
        attempt(kind=wa.PASSKEY)


def test_a_key_without_counter_is_accepted():
    key, _reg, stored = _register(counter_step=0)
    cer = wa.CeremonyStore().open(wa.SECOND_FACTOR, "example.lan", "https://ns1.example.lan:8443", "U1")
    assert wa.verify_assertion(cer, key.get(wa.authentication_options(cer, {})), stored, 0) == 0


def test_registration_refused_for_a_wrong_origin():
    key = SoftKey("https://evil.example.org")
    cer = wa.CeremonyStore().open(wa.REGISTER, "example.lan", "https://ns1.example.lan", "U1")
    with pytest.raises(wa.WebAuthnError):
        wa.verify_registration(cer, key.create(wa.registration_options(cer, "U1", "alice", {})))
    with pytest.raises(wa.WebAuthnError):
        wa.verify_registration(cer, {"id": 1})


def test_usage_store_keeps_newest_use_and_highest_counter(tmp_path):
    store = wa.UsageStore(tmp_path / "u.json", tmp_path / "u.lock")
    assert store.counter("c") == 0
    store.record("c", 5)
    store.record("c", 3)
    assert store.counter("c") == 5 and store.read()["c"]["last_used"]
    store.forget(["c"])
    assert store.read() == {}


def _user(roles=("admin",), totp=False, keys=()):
    return User(
        id="U1",
        username="alice",
        password_hash="x",
        roles=list(roles),
        totp_secret="enc" if totp else None,
        webauthn={k: WebAuthnCredential(name=k, public_key="p", rp_id=rp) for k, rp in keys},
    )


REQUIRE = {"auth": {"require_webauthn_roles": ["admin"]}}


def test_policy_after_password():
    d = twofa.after_password(_user(), {}, "example.lan")
    assert d.complete and d.restriction is None
    d = twofa.after_password(_user(totp=True), {}, "example.lan")
    assert d.methods == ["totp"]
    d = twofa.after_password(_user(totp=True, keys=[("k1", "example.lan")]), {}, "example.lan")
    assert d.methods == ["webauthn", "totp"] and list(d.keys) == ["k1"]
    d = twofa.after_password(_user(totp=True, keys=[("k1", "example.lan")]), REQUIRE, "example.lan")
    assert d.methods == ["webauthn"]
    d = twofa.after_password(_user(keys=[("k1", "example.lan")]), {}, None)
    assert not d.complete and d.methods == [] and d.keys_elsewhere == ["example.lan"]
    d = twofa.after_password(_user(totp=True, keys=[("k1", "example.lan")]), {}, None)
    assert d.methods == ["totp"]
    d = twofa.after_password(_user(), REQUIRE, "example.lan")
    assert d.complete and d.restriction == twofa.WEBAUTHN_ENROLLMENT
    d = twofa.after_password(_user(totp=True), REQUIRE, "example.lan")
    assert d.methods == ["totp"] and d.restriction == twofa.WEBAUTHN_ENROLLMENT
    d = twofa.after_password(_user(roles=["viewer"]), REQUIRE, "example.lan")
    assert d.complete and d.restriction is None
    d = twofa.after_password(_user(), {"auth": {"require_totp": True}}, "example.lan")
    assert d.restriction == twofa.TOTP_ENROLLMENT


def test_last_key_of_a_required_role_cannot_go():
    one = _user(keys=[("k1", "example.lan")])
    assert twofa.removal_refused(one, REQUIRE, "k1")
    assert not twofa.removal_refused(one, {}, "k1")
    two = _user(keys=[("k1", "example.lan"), ("k2", "example.lan")])
    assert not twofa.removal_refused(two, REQUIRE, "k1")


def test_keys_registered_on_two_nodes_at_once_both_replicate_and_removal_sticks():
    from pelagos.core.config_store import merge_configs
    from tests.unit.core.test_cluster_merge import _base, _write

    def add(cid):
        return lambda c: c.users[0].webauthn.__setitem__(
            cid, WebAuthnCredential(name=cid, public_key="p", rp_id="example.lan")
        )

    base = _base()
    a = _write(base, "A", add("kA"))
    b = _write(base, "B", add("kB"))
    ab, ba = merge_configs(a, b), merge_configs(b, a)
    assert ab.digest() == ba.digest()
    assert set(ab.users[0].webauthn) == {"kA", "kB"}
    removed = _write(ab, "B", lambda c: c.users[0].webauthn.pop("kA"))
    assert set(merge_configs(ab, removed).users[0].webauthn) == {"kB"}
    assert set(merge_configs(removed, a).users[0].webauthn) == {"kB"}
