# SPDX-License-Identifier: Apache-2.0
"""Secrets a plan must carry to other nodes (Kea D2 TSIG secret files), sealed with the master key.

A `secret-file/<name>` change keeps `after = {"path", "sha256"}` and gains `"sealed"`: the clear
secret encrypted with the cluster master key (section 12), AAD `plan/<plan id>/<change target>` so
it cannot be replayed into another plan or file. Every node holds the master key; nothing else can
read it, and the secret never appears in clear in a plan, a response or the audit log.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from pelagos.core.secrets import SecretBox, SecretError
from pelagos.domain.plan import Plan

SECRET_FILE_PREFIX = "secret-file/"  # noqa: S105 (a Change.target prefix)
SEALED = "sealed"


def _aad(plan: Plan, target: str) -> str:
    return f"plan/{plan.id}/{target}"


def seal_plan_secrets(plan: Plan, secrets: Mapping[str, str], box: SecretBox) -> int:
    """Encrypt each secret into the `secret-file/` change whose `after.path` names it; returns the count."""
    sealed = 0
    for change in plan.changes:
        if not change.target.startswith(SECRET_FILE_PREFIX) or not isinstance(change.after, dict):
            continue
        path = str(change.after.get("path", ""))
        if path in secrets:
            change.after[SEALED] = box.encrypt(_aad(plan, change.target), secrets[path])
            sealed += 1
    return sealed


def unseal_plan_secrets(plan: Plan, box: SecretBox) -> dict[str, str]:
    """{path: clear secret} of every sealed change; raises SecretError on a wrong key or digest."""
    out: dict[str, str] = {}
    for change in plan.changes:
        after = change.after
        if not change.target.startswith(SECRET_FILE_PREFIX) or not isinstance(after, dict):
            continue
        token = after.get(SEALED)
        if not token:
            continue
        secret = box.decrypt(_aad(plan, change.target), str(token))
        digest = after.get("sha256")
        if digest and hashlib.sha256(secret.encode()).hexdigest() != digest:
            raise SecretError(f"sealed secret of {change.target} does not match its digest")
        out[str(after.get("path", ""))] = secret
    return out


def seal_backend_secrets(plan: Plan, backend: Any, box: SecretBox | None) -> int:
    """For the plan service, right after a backend built `plan` and before it goes to peers.

    Takes what the backend holds in memory for the plan (`backend.plan_secrets(plan.id)`, the D2
    connector today) and seals it into the plan. Returns 0 when there is nothing to carry.
    """
    get = getattr(backend, "plan_secrets", None)
    if get is None:
        return 0
    secrets = get(plan.id)
    if not secrets:
        return 0
    if box is None:
        raise SecretError("the master key is needed to send this plan's secrets to other nodes")
    return seal_plan_secrets(plan, secrets, box)


def hand_secrets_to_backend(plan: Plan, backend: Any, box: SecretBox | None) -> int:
    """On the node applying a plan built elsewhere: unseal and give the secrets to the backend."""
    accept = getattr(backend, "accept_plan_secrets", None)
    if accept is None or box is None:
        return 0
    secrets = unseal_plan_secrets(plan, box)
    if secrets:
        accept(plan, secrets)
    return len(secrets)
