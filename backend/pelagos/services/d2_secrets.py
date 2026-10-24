# SPDX-License-Identifier: Apache-2.0
"""TSIG secrets of D2 plans carried to peers, sealed with the cluster master key.

A D2 plan built from a clear `secret` keeps the secret in the memory of the
D2Backend that built it (section 6: the secret never enters a plan). Peers
applying the same plan need it too, so the copy sent over the replication
channel carries each secret sealed: AES-256-GCM under the master key every
node holds, bound to the plan id and the file name. The stored plan, API
answers and audit entries never see it; the receiving node opens it, checks
its sha256 against the plan and hands it to its own D2Backend.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

from pelagos.domain import Plan, PlanScope, utcnow

log = logging.getLogger(__name__)

SEALED = "sealed_secret"
SECRET_FILE_PREFIX = "secret-file/"  # noqa: S105 (a Change.target prefix)


class SecretChannelError(Exception):
    pass


def _aad(plan_id: str, file_name: str) -> str:
    return f"d2-plan/{plan_id}/{file_name}"


def held_secrets(backend: Any, plan_id: str) -> dict[str, str]:
    """{path: secret} the D2Backend holds for a plan it built; empty when none or already used.

    Prefers a public `plan_secrets(plan_id)` on the connector, else reads its private table."""
    public = getattr(backend, "plan_secrets", None)
    if callable(public):
        return {str(k): v for k, v in (public(plan_id) or {}).items()}
    private = getattr(backend, "_private", {}).get(plan_id)
    secrets = getattr(private, "secrets", None) or {}
    return {str(k): v for k, v in secrets.items()}


def hold_secrets(backend: Any, plan: Plan, secrets: dict[str, str]) -> None:
    """Give a received plan's secrets to the local D2Backend, as if it had built the plan."""
    paths = {Path(p): s for p, s in secrets.items()}
    public = getattr(backend, "hold_secrets", None)
    if callable(public):
        public(plan.id, paths)
        return
    table = getattr(backend, "_private", None)
    if table is None:
        raise SecretChannelError("this D2 connector cannot receive plan secrets")
    from pelagos.connectors.kea.d2 import _PlanPrivate

    ttl = int(getattr(backend, "plan_ttl", 600))
    entry = table.get(plan.id)
    if entry is None:
        table[plan.id] = _PlanPrivate(expires_at=utcnow() + timedelta(seconds=ttl), secrets=paths)
    else:
        entry.secrets = paths


def needs_sealing(plan: Plan) -> bool:
    return plan.scope is PlanScope.D2_CONFIG and any(
        c.target.startswith(SECRET_FILE_PREFIX) for c in plan.changes
    )


def seal(box: Any, plan: Plan, secrets: dict[str, str]) -> Plan:
    """Copy of `plan` whose secret-file changes carry their secret sealed; the original is untouched."""
    if box is None:
        raise SecretChannelError("no master key on this node: cannot carry D2 secrets to peers")
    sent = Plan.from_dict(plan.to_dict())
    for change in sent.changes:
        if not change.target.startswith(SECRET_FILE_PREFIX) or not isinstance(change.after, dict):
            continue
        path = str(change.after.get("path", ""))
        secret = secrets.get(path)
        if secret is None:
            raise SecretChannelError(f"the secret for {path} is no longer held by this node")
        name = change.target[len(SECRET_FILE_PREFIX) :]
        change.after = {**change.after, SEALED: box.encrypt(_aad(plan.id, name), secret)}
    return sent


def open_sealed(box: Any, plan: Plan) -> tuple[Plan, dict[str, str]]:
    """(plan without sealed values, {path: secret}); every secret is checked against its sha256."""
    secrets: dict[str, str] = {}
    clean = Plan.from_dict(plan.to_dict())
    for change in clean.changes:
        if not isinstance(change.after, dict) or SEALED not in change.after:
            continue
        if box is None:
            raise SecretChannelError("no master key on this node: cannot open D2 secrets")
        after = dict(change.after)
        token = after.pop(SEALED)
        name = change.target[len(SECRET_FILE_PREFIX) :]
        try:
            secret = box.decrypt(_aad(plan.id, name), token)
        except Exception as exc:
            raise SecretChannelError(f"sealed secret for {name} does not open: {exc}") from None
        if hashlib.sha256(secret.encode()).hexdigest() != after.get("sha256"):
            raise SecretChannelError(f"sealed secret for {name} does not match the plan")
        secrets[str(after.get("path", ""))] = secret
        change.after = after
    return clean, secrets
