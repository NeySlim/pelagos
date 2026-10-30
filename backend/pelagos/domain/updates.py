# SPDX-License-Identifier: Apache-2.0
"""Updates from the UI (docs/architecture.md section 29): release files, signature, rollouts.

Pure data: the signature is checked with `cryptography` by the privileged helper (batch U1/U2),
the rollout is driven by the collectors (U3). What lives here is the wire and file format every
batch shares, so the web process, the collector, the helper and `make release` agree.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from pelagos.domain.common import Model

PACKAGE_NAME = "pelagos"
CHECKSUMS = "SHA256SUMS"
SIGNATURE = "SHA256SUMS.sig"
MANIFEST = "release.json"
NOTES = "NOTES.md"
SIGNATURE_FORMAT = "pelagos-release-signature-v1"
MANIFEST_FORMAT = 1
# Version of the node state (/etc/pelagos, /var/lib/pelagos) this release writes; a release that
# changes it cannot be undone by reinstalling the previous package (no automatic rollback).
STATE_SCHEMA = 1
PACKAGE_FORMATS = ("deb", "rpm")
ARCHES = ("amd64", "arm64", "x86_64", "aarch64")
VERSION_RE = re.compile(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([~+.-][A-Za-z0-9.~+-]{1,40})?$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$")
KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
ROLLOUT_ID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_SUM_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")


class SignatureState(enum.StrEnum):
    """What the helper found for SHA256SUMS.sig. INVALID is always refused; UNSIGNED and
    UNKNOWN_KEY install only after the extra confirmation (audit `update.unsigned_accepted`)."""

    VALID = "valid"
    UNSIGNED = "unsigned"
    UNKNOWN_KEY = "unknown_key"
    INVALID = "invalid"

    @property
    def needs_acceptance(self) -> bool:
        return self in (SignatureState.UNSIGNED, SignatureState.UNKNOWN_KEY)


class UpdateSource(enum.StrEnum):
    UPLOAD = "upload"
    GITHUB = "github"
    REPOSITORY = "repository"


class RolloutKind(enum.StrEnum):
    PELAGOS = "pelagos"
    ENGINE_PACKAGES = "engine_packages"
    ROLLBACK = "rollback"


class RolloutState(enum.StrEnum):
    RUNNING = "running"
    FAILED = "failed"
    DONE = "done"
    CANCELLED = "cancelled"


class NodeState(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class RolloutAction(enum.StrEnum):
    RESUME = "resume"
    CANCEL = "cancel"
    ROLLBACK = "rollback"


# Steps of one node, in order; `step` of a failed node names the one that failed.
STEPS = (
    "wait",
    "fetch",
    "verify",
    "precheck",
    "backup",
    "ha_maintenance",
    "install",
    "version",
    "restart",
    "settle",
    "health",
    "convergence",
    "audit",
    "journal",
    "ha",
    "engine_checks",
    "rollback",
)
# Operations of the privileged helper this feature adds (section 29, `installer.helper`).
HELPER_OPERATIONS = ("update_verify", "update_start", "update_status", "journal_errors")
# Units `journal_errors` may read: the node's own processes, nothing else.
JOURNAL_UNITS = ("pelagos.service", "pelagos-collector.service", "pelagos-helper@*.service")


def valid_version(text: str) -> bool:
    return bool(VERSION_RE.fullmatch(text or ""))


def safe_file(name: str) -> bool:
    return bool(FILE_RE.fullmatch(name or "")) and ".." not in name


def key_id(public_raw: bytes) -> str:
    """Id of an Ed25519 public key: the first 16 hex digits of sha256 of its 32 raw bytes."""
    if len(public_raw) != 32:
        raise ValueError("an Ed25519 public key has 32 bytes")
    return hashlib.sha256(public_raw).hexdigest()[:16]


def parse_checksums(text: str) -> dict[str, str]:
    """`sha256sum` output to {file: hex}; a malformed line, a duplicate or an unsafe name fails."""
    out: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = _SUM_LINE.match(line)
        if not m or not safe_file(m.group(2)):
            raise ValueError(f"{CHECKSUMS} line {number} is malformed")
        if m.group(2) in out:
            raise ValueError(f"{CHECKSUMS} lists {m.group(2)} twice")
        out[m.group(2)] = m.group(1)
    if not out:
        raise ValueError(f"{CHECKSUMS} is empty")
    return out


@dataclass(slots=True)
class ReleaseSignature:
    """SHA256SUMS.sig: one JSON object, the Ed25519 signature of the exact bytes of SHA256SUMS."""

    key_id: str
    signature: bytes

    def to_text(self) -> str:
        body = {
            "format": SIGNATURE_FORMAT,
            "algorithm": "ed25519",
            "key_id": self.key_id,
            "signature": base64.b64encode(self.signature).decode(),
        }
        return json.dumps(body, sort_keys=True) + "\n"

    @classmethod
    def from_text(cls, text: str) -> ReleaseSignature:
        """Raises ValueError on anything but a well-formed v1 signature (an INVALID release)."""
        try:
            data = json.loads(text)
        except ValueError:
            raise ValueError(f"{SIGNATURE} is not JSON") from None
        if not isinstance(data, dict) or data.get("format") != SIGNATURE_FORMAT:
            raise ValueError(f"{SIGNATURE}: unknown format")
        if data.get("algorithm") != "ed25519" or not KEY_ID_RE.fullmatch(str(data.get("key_id") or "")):
            raise ValueError(f"{SIGNATURE}: algorithm or key id")
        try:
            raw = base64.b64decode(str(data.get("signature") or ""), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(f"{SIGNATURE}: signature is not base64") from None
        if len(raw) != 64:
            raise ValueError(f"{SIGNATURE}: an Ed25519 signature has 64 bytes")
        return cls(str(data["key_id"]), raw)


@dataclass(slots=True)
class ReleasePackage(Model):
    file: str
    format: str  # deb | rpm
    arch: str  # amd64, arm64 (deb), x86_64, aarch64 (rpm)
    version: str  # package version, e.g. 0.3.0-1


@dataclass(slots=True)
class ReleaseManifest(Model):
    """release.json, listed in SHA256SUMS so the signature covers it."""

    version: str
    state_schema: int
    packages: list[ReleasePackage] = field(default_factory=list)
    name: str = PACKAGE_NAME
    format: int = MANIFEST_FORMAT
    published_at: str | None = None
    notes: str = NOTES
    min_upgrade_from: str | None = None

    def problems(self) -> list[str]:
        """Why the manifest cannot be used; empty when it can."""
        out: list[str] = []
        if self.format != MANIFEST_FORMAT:
            out.append(f"format {self.format} is not {MANIFEST_FORMAT}")
        if self.name != PACKAGE_NAME:
            out.append(f"name {self.name!r} is not {PACKAGE_NAME}")
        if not valid_version(self.version):
            out.append(f"version {self.version!r} is malformed")
        schema = self.state_schema
        if not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
            out.append("state_schema must be a positive integer")
        if self.min_upgrade_from is not None and not valid_version(self.min_upgrade_from):
            out.append(f"min_upgrade_from {self.min_upgrade_from!r} is malformed")
        seen: set[tuple[str, str]] = set()
        for p in self.packages:
            if not safe_file(p.file) or p.format not in PACKAGE_FORMATS or p.arch not in ARCHES:
                out.append(f"package {p.file!r}: file, format or arch")
            elif (p.format, p.arch) in seen:
                out.append(f"two {p.format} packages for {p.arch}")
            seen.add((p.format, p.arch))
        if not self.packages:
            out.append("no package")
        return out

    def package_for(self, package_format: str, arch: str) -> ReleasePackage | None:
        return next((p for p in self.packages if p.format == package_format and p.arch == arch), None)


@dataclass(slots=True)
class RolloutNode(Model):
    node_id: str
    state: str = NodeState.PENDING.value
    step: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    error_message: dict[str, Any] | None = None
    from_version: str | None = None
    to_version: str | None = None


@dataclass(slots=True)
class Rollout(Model):
    """`[settings.updates.rollout]`: the active rollout. Each node writes only its own
    `nodes.<node id>` table, so the per-entry merge of cluster.toml never conflicts."""

    id: str
    kind: str
    state: str = RolloutState.RUNNING.value
    version: str | None = None
    order: list[str] = field(default_factory=list)
    nodes: dict[str, RolloutNode] = field(default_factory=dict)
    created_by: str | None = None
    created_at: str | None = None
    plan_id: str | None = None
    source: str | None = None
    # {"<format>/<arch>": {"file", "sha256"}} of the release (pelagos and rollback kinds).
    artifacts: dict[str, dict[str, str]] = field(default_factory=dict)
    # {package: version} for the engine_packages kind.
    packages: dict[str, str] = field(default_factory=dict)
    auto_rollback: bool = True
    state_schema_changed: bool = False
    signature: str = SignatureState.VALID.value
    key_id: str | None = None
    unsigned_accepted_by: str | None = None
    unsigned_accepted_at: str | None = None
    finished_at: str | None = None

    def to_api(self) -> dict[str, Any]:
        """Wire form: `nodes` as a list in rollout order."""
        data = self.to_dict()
        ordered = [n for n in self.order if n in self.nodes] + [n for n in self.nodes if n not in self.order]
        data["nodes"] = [self.nodes[n].to_dict() for n in ordered]
        return data

    def to_toml(self) -> dict[str, Any]:
        """cluster.toml form: TOML has no null, so absent values are left out."""
        return _drop_none(self.to_dict())

    @classmethod
    def from_toml(cls, data: dict[str, Any]) -> Rollout | None:
        """None for an entry without id or kind (no rollout)."""
        if not isinstance(data, dict) or not data.get("id") or not data.get("kind"):
            return None
        nodes = data.get("nodes") if isinstance(data.get("nodes"), dict) else {}
        body = dict(data)
        body["nodes"] = {k: {"node_id": k, **v} for k, v in nodes.items() if isinstance(v, dict)}
        return cls.from_dict(body)

    def active(self) -> bool:
        return self.state in (RolloutState.RUNNING.value, RolloutState.FAILED.value)


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value if v is not None]
    return value
