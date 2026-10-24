# SPDX-License-Identifier: Apache-2.0
"""Plan secrets sealed with the master key: round trip, binding to plan and target, digest check."""

from __future__ import annotations

import hashlib
import json

import pytest

from pelagos.core.plan_secrets import (
    SEALED,
    hand_secrets_to_backend,
    seal_backend_secrets,
    seal_plan_secrets,
    unseal_plan_secrets,
)
from pelagos.core.secrets import SecretBox, SecretError, generate_master_key
from pelagos.domain import Change, ChangeOp, Engine, Plan, PlanScope

pytestmark = pytest.mark.unit

SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQ="
PATH = "/etc/kea/ddi-extra.secret"


def d2_plan() -> Plan:
    digest = hashlib.sha256(SECRET.encode()).hexdigest()
    return Plan(
        scope=PlanScope.D2_CONFIG,
        node_id="n1",
        summary="d2",
        engine=Engine.D2,
        changes=[
            Change(ChangeOp.REPLACE, "config", before={}, after={"tsig-keys": []}),
            Change(ChangeOp.ADD, "secret-file/ddi-extra.secret", after={"path": PATH, "sha256": digest}),
        ],
    )


class Holder:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self.secrets = secrets or {}
        self.accepted: dict[str, str] = {}

    def plan_secrets(self, plan_id: str) -> dict[str, str]:
        return dict(self.secrets)

    def accept_plan_secrets(self, plan: Plan, secrets: dict[str, str]) -> None:
        self.accepted = secrets


def test_round_trip_over_the_plan_dict():
    box = SecretBox.from_b64(generate_master_key())
    plan = d2_plan()
    assert seal_backend_secrets(plan, Holder({PATH: SECRET}), box) == 1
    wire = json.dumps(plan.to_dict())
    assert SECRET not in wire and SEALED in wire
    received = Plan.from_dict(json.loads(wire))
    peer = Holder()
    assert hand_secrets_to_backend(received, peer, box) == 1
    assert peer.accepted == {PATH: SECRET}


def test_sealed_secret_is_bound_to_its_plan_and_key():
    box = SecretBox.from_b64(generate_master_key())
    plan = d2_plan()
    seal_plan_secrets(plan, {PATH: SECRET}, box)
    other = d2_plan()
    other.changes[1].after[SEALED] = plan.changes[1].after[SEALED]
    with pytest.raises(SecretError):
        unseal_plan_secrets(other, box)
    with pytest.raises(SecretError):
        unseal_plan_secrets(plan, SecretBox.from_b64(generate_master_key()))
    plan.changes[1].after["sha256"] = "0" * 64
    with pytest.raises(SecretError):
        unseal_plan_secrets(plan, box)


def test_nothing_to_seal_and_missing_master_key():
    plan = d2_plan()
    assert seal_backend_secrets(plan, object(), None) == 0
    assert seal_backend_secrets(plan, Holder(), None) == 0
    with pytest.raises(SecretError):
        seal_backend_secrets(plan, Holder({PATH: SECRET}), None)
    assert hand_secrets_to_backend(plan, Holder(), None) == 0
