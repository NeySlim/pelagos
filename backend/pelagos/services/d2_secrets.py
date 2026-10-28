# SPDX-License-Identifier: Apache-2.0
"""TSIG secrets of D2 plans carried to peers, sealed with the cluster master key.

A D2 plan built from a clear `secret` keeps the secret in the memory of the D2Backend that built
it (section 6: the secret never enters a plan). The copy sent to peers carries each secret sealed
by `core.plan_secrets.seal_backend_secrets` (change key `sealed`); the receiving ReplicationApp
opens it with `hand_secrets_to_backend`. The stored plan, API answers and audit never see it.
"""

from __future__ import annotations

from typing import Any

from pelagos.core import plan_secrets
from pelagos.domain import Plan, PlanScope

SEALED = plan_secrets.SEALED
SECRET_FILE_PREFIX = plan_secrets.SECRET_FILE_PREFIX


class SecretChannelError(Exception):
    pass


def needs_sealing(plan: Plan) -> bool:
    """A secret change without its sealed secret (a plan built by a peer arrives sealed)."""
    return plan.scope is PlanScope.D2_CONFIG and any(
        plan_secrets.is_secret_change(c.target, c.after) and not c.after.get(SEALED) for c in plan.changes
    )


def sealed_copy(box: Any, plan: Plan, backend: Any) -> Plan:
    """The plan as sent to peers: every secret change carries its secret sealed, or this raises."""
    if not callable(getattr(backend, "plan_secrets", None)):
        raise SecretChannelError("this D2 connector cannot carry plan secrets")
    sent = Plan.from_dict(plan.to_dict())
    try:
        sealed = plan_secrets.seal_backend_secrets(sent, backend, box)
    except Exception as exc:
        raise SecretChannelError(str(exc)) from None
    expected = sum(1 for c in sent.changes if plan_secrets.is_secret_change(c.target, c.after))
    if sealed < expected:
        raise SecretChannelError("the secrets of this plan are no longer held by this node")
    return sent
