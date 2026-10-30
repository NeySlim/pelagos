# SPDX-License-Identifier: Apache-2.0
"""Seals on the dual-key, Kea HA TLS and Kea migration steps a node sends to a peer (installer plans).

The sending node seals each step it sends with the cluster master key (section 12): `after.seal`
is the canonical change, the origin and receiving node ids, the time and a nonce, encrypted under
AAD `plan-step/<plan id>/<target>/<receiver>`. When it holds the new key's secret it adds
`after.sealed_secret` (AAD `plan-step-secret/<plan id>/<target>/<receiver>`) and its sha256.
The receiver opens the seal with its own copy of the master key: a step changed after sealing,
sealed for another node or another plan, or older than SEAL_MAX_AGE does not open.
"""

from __future__ import annotations

import hashlib
import json
import secrets as pysecrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from pelagos.core.kea_ha_tls import ALL_STEPS as HA_TLS_STEPS
from pelagos.core.kea_migration import HELPER_STEPS as KEA_MIGRATION_STEPS
from pelagos.core.secrets import SecretBox, SecretError
from pelagos.domain.common import from_rfc3339, to_rfc3339, utcnow
from pelagos.domain.plan import Change, Plan

SEAL = "seal"
SEALED_SECRET = "sealed_secret"  # noqa: S105 (a field name)
SECRET_SHA256 = "secret_sha256"  # noqa: S105 (a field name)
DUAL_KEY_STEPS = ("1-bind-add", "2-d2-switch", "3-bind-remove")
SEALED_STEPS = (*DUAL_KEY_STEPS, *HA_TLS_STEPS, *KEA_MIGRATION_STEPS)
SEAL_MAX_AGE = timedelta(hours=1)
CLOCK_SKEW = timedelta(minutes=5)


def _step(change: Change) -> str | None:
    after = change.after if isinstance(change.after, dict) else {}
    step = after.get("step")
    return step if step in SEALED_STEPS else None


def _canonical(change: Change) -> str:
    """The change as sealed: everything but the seal itself."""
    data = change.to_dict()
    after = dict(data.get("after") or {})
    after.pop(SEAL, None)
    data["after"] = after
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _aad(kind: str, plan: Plan, change: Change, receiver: str) -> str:
    return f"{kind}/{plan.id}/{change.target}/{receiver}"


def seal_steps(
    plan: Plan,
    box: SecretBox,
    origin: str,
    receiver: str,
    secret_of: Callable[[str], str | None] | None = None,
    now: datetime | None = None,
    secret_for: Callable[[Change], str | None] | None = None,
) -> int:
    """Seal every dual-key or HA TLS step of `plan` that `receiver` runs; returns how many were sealed.
    `secret_for` gives a step's own secret (the key of an HA TLS deposit)."""
    sealed = 0
    issued = to_rfc3339(now or utcnow())
    for change in plan.changes:
        step = _step(change)
        if step is None or receiver not in change.node_ids:
            continue
        after = change.after
        after.pop(SEAL, None)
        details = after.get("details") if isinstance(after.get("details"), dict) else {}
        new_key = str(details.get("new_key") or "")
        secret = secret_of(new_key) if (secret_of is not None and step == "2-d2-switch" and new_key) else None
        if secret_for is not None and secret is None:
            secret = secret_for(change)
        if secret:
            after[SEALED_SECRET] = box.encrypt(_aad("plan-step-secret", plan, change, receiver), secret)
            after[SECRET_SHA256] = hashlib.sha256(secret.encode()).hexdigest()
        payload = {
            "v": 1,
            "origin": origin,
            "receiver": receiver,
            "plan_id": plan.id,
            "target": change.target,
            "issued_at": issued,
            "nonce": pysecrets.token_hex(16),
            "change": _canonical(change),
        }
        after[SEAL] = box.encrypt(
            _aad("plan-step", plan, change, receiver), json.dumps(payload, sort_keys=True)
        )
        sealed += 1
    return sealed


def open_step(
    plan: Plan, change: Change, box: SecretBox, receiver: str, now: datetime | None = None
) -> dict[str, Any]:
    """The seal's payload once every check passed; SecretError otherwise."""
    after = change.after if isinstance(change.after, dict) else {}
    token = after.get(SEAL)
    if not token:
        raise SecretError(f"step {change.target} is not sealed by its origin node")
    try:
        payload = json.loads(box.decrypt(_aad("plan-step", plan, change, receiver), str(token)))
    except (SecretError, ValueError) as exc:
        raise SecretError(f"seal of {change.target} does not open on this node: {exc}") from None
    if not isinstance(payload, dict) or payload.get("change") != _canonical(change):
        raise SecretError(f"step {change.target} was modified after it was sealed")
    if payload.get("origin") != plan.node_id or payload.get("receiver") != receiver:
        raise SecretError(f"step {change.target} was sealed by another node or for another node")
    try:
        issued = from_rfc3339(str(payload.get("issued_at")))
    except ValueError:
        raise SecretError(f"seal of {change.target} has no valid time") from None
    current = now or utcnow()
    if issued > current + CLOCK_SKEW or current - issued > SEAL_MAX_AGE:
        raise SecretError(f"seal of {change.target} is too old or from the future: send the step again")
    return payload


def open_step_secret(plan: Plan, change: Change, box: SecretBox, receiver: str) -> str | None:
    """The new key's secret carried by a sealed step, checked against its digest; None when absent."""
    after = change.after if isinstance(change.after, dict) else {}
    token = after.get(SEALED_SECRET)
    if not token:
        return None
    secret = box.decrypt(_aad("plan-step-secret", plan, change, receiver), str(token))
    if hashlib.sha256(secret.encode()).hexdigest() != after.get(SECRET_SHA256):
        raise SecretError(f"sealed secret of {change.target} does not match its digest")
    return secret


def seal_digest(change: Change) -> str:
    """Identifies one sealed sending of a step: the receiver refuses to run the same one twice."""
    after = change.after if isinstance(change.after, dict) else {}
    return hashlib.sha256(str(after.get(SEAL, "")).encode()).hexdigest()
