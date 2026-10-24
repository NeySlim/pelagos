# SPDX-License-Identifier: Apache-2.0
"""Shared masking: every Kea `*-password` / `*-secret` string, never boolean flags or `*-file` paths."""

import pytest

from pelagos.services.masking import masked, masked_text

pytestmark = pytest.mark.unit


def test_masked_covers_kea_suffix_keys():
    value = {
        "peers": [
            {"name": "ns1", "basic-auth-password": "hunter2", "basic-auth-password-file": "/etc/kea/p"}
        ],
        "client_secret": "abc",
        "password": "x",
        "must_change_password": True,
        "secret-file": "/etc/kea/k.tsig",
    }
    out = masked(value)
    assert out["peers"][0]["basic-auth-password"] == "***"
    assert out["peers"][0]["basic-auth-password-file"] == "/etc/kea/p"
    assert out["client_secret"] == "***" and out["password"] == "***"
    assert out["must_change_password"] is True and out["secret-file"] == "/etc/kea/k.tsig"


def test_masked_text_covers_kea_suffix_keys():
    text = '+ "basic-auth-password": "hunter2",\n- "secret": "c2VjcmV0"\n  key "k" { secret "abc"; };'
    out = masked_text(text)
    assert "hunter2" not in out and "c2VjcmV0" not in out and "abc" not in out
    assert '"basic-auth-password": "***"' in out
    assert masked_text('"secret-file": "/etc/kea/k"') == '"secret-file": "/etc/kea/k"'
