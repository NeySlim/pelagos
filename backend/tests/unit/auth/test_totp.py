# SPDX-License-Identifier: Apache-2.0
"""TOTP verification window and replay protection."""

from __future__ import annotations

import pyotp
import pytest

from pelagos.auth import passwords, totp

pytestmark = pytest.mark.unit

NOW = 1_800_000_000.0


def test_matched_step_window():
    secret = totp.new_secret()
    t = pyotp.TOTP(secret)
    step = int(NOW // 30)
    assert totp.matched_step(secret, t.at(NOW), NOW) == step
    assert totp.matched_step(secret, t.at(NOW - 30), NOW) == step - 1
    assert totp.matched_step(secret, t.at(NOW + 30), NOW) == step + 1
    assert totp.matched_step(secret, t.at(NOW + 90), NOW) is None
    assert totp.matched_step(secret, "12a456", NOW) is None
    assert totp.matched_step(secret, f"{t.at(NOW)[:3]} {t.at(NOW)[3:]}", NOW) == step


def test_replay_guard_refuses_same_and_older_steps():
    secret = totp.new_secret()
    t = pyotp.TOTP(secret)
    guard = totp.ReplayGuard()
    code = t.at(NOW)
    assert guard.verify("u1", secret, code, NOW)
    assert not guard.verify("u1", secret, code, NOW)
    assert not guard.verify("u1", secret, t.at(NOW - 30), NOW)
    assert guard.verify("u2", secret, code, NOW)  # per user
    assert guard.verify("u1", secret, t.at(NOW + 30), NOW + 30)
    guard.forget("u1")
    assert guard.verify("u1", secret, code, NOW)


def test_dummy_hash_is_constant_and_never_matches():
    h = passwords.dummy_hash()
    assert h == passwords.dummy_hash() and h.startswith("$argon2id$")
    assert not passwords.verify_password(h, "anything")
