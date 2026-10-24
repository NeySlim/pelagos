# SPDX-License-Identifier: Apache-2.0
"""TOTP (RFC 6238): 30 s period, 6 digits, one step of drift, each step accepted once per user."""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from pathlib import Path

import pyotp

from pelagos.core.config_store import atomic_write

log = logging.getLogger(__name__)

ISSUER = "Pelagos"
DRIFT_STEPS = 1


def new_secret() -> str:
    return pyotp.random_base32()


def otpauth_url(secret: str, username: str, issuer: str = ISSUER) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def matched_step(secret: str, code: str, now: float | None = None) -> int | None:
    """The time step (Unix time // 30) whose code equals `code` within the drift window, else None."""
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // totp.interval)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def verify(secret: str, code: str) -> bool:
    return matched_step(secret, code) is not None


class ReplayGuard:
    """Last accepted time step per user: a code is refused once its step, or a later one, was used.

    With a path the steps survive restarts; they stay per node (a login never replicates).
    """

    def __init__(self, path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self.path = path
        self._last: dict[str, int] = self._load()

    def _load(self) -> dict[str, int]:
        if self.path is None:
            return {}
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("TOTP step file %s unreadable: %s", self.path, exc)
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, int) and not isinstance(v, bool)}

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self.path, json.dumps(self._last, sort_keys=True).encode(), mode=0o640)
        except OSError as exc:
            log.warning("TOTP step file %s not written: %s", self.path, exc)

    def verify(self, user_key: str, secret: str, code: str, now: float | None = None) -> bool:
        step = matched_step(secret, code, now)
        if step is None:
            return False
        with self._lock:
            if step <= self._last.get(user_key, -1):
                return False
            self._last[user_key] = step
            self._save()
            return True

    def forget(self, user_key: str) -> None:
        with self._lock:
            if self._last.pop(user_key, None) is not None:
                self._save()
