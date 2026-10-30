# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x migration (section 28): the replicated state `[settings.kea.migration]`, its state
machine, the step vocabulary of the `kea.migration` plans and the lease copy a node serves its partner.

The state lives in cluster.toml so that any node shows the migration and can resume or roll it back
when the driving node restarts. TOML holds no null: null keys are left out and read back as null.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import zlib
from pathlib import Path
from typing import Any

from pelagos.domain.common import to_rfc3339, utcnow
from pelagos.domain.messages import Message, msg

DIR = "kea-migration"  # under the node's var dir, 0700 pelagos
ID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
FAMILIES = ("4", "6")

# Phases: one plan each (POST /install/kea-migration/{id}/plan).
PREPARE, MIGRATE, ROLLBACK = "prepare", "migrate", "rollback"
PHASES = (PREPARE, MIGRATE, ROLLBACK)

# Migration states and the moves between them; a move not listed is refused.
PREPARING = "preparing"
PREPARED = "prepared"
PREPARE_FAILED = "prepare_failed"
MIGRATING = "migrating"
MIGRATED = "migrated"
FAILED = "failed"
ROLLING_BACK = "rolling_back"
ROLLED_BACK = "rolled_back"
STATES = (PREPARING, PREPARED, PREPARE_FAILED, MIGRATING, MIGRATED, FAILED, ROLLING_BACK, ROLLED_BACK)
TRANSITIONS: dict[str, tuple[str, ...]] = {
    PREPARING: (PREPARED, PREPARE_FAILED),
    PREPARED: (MIGRATING, PREPARING),
    PREPARE_FAILED: (PREPARING,),
    MIGRATING: (MIGRATED, FAILED, ROLLING_BACK),
    FAILED: (MIGRATING, ROLLING_BACK),
    MIGRATED: (ROLLING_BACK,),
    ROLLING_BACK: (ROLLED_BACK, FAILED),
    ROLLED_BACK: (),
}
# States a new prepare plan may replace (a new migration id); any other one is in progress.
REPLACEABLE = (PREPARED, PREPARE_FAILED, MIGRATED, ROLLED_BACK)
# States with Kea stopped or changing somewhere: the lease copy is served only then.
ACTIVE = (MIGRATING, FAILED, ROLLING_BACK)

# Stages of the migrate phase (design 13.4 decision 5): time 1, the window, time 3.
STAGES = ("standby", "window", "primary", "done")
ROLES = ("primary", "standby", "backup", "single")
NODE_STATUSES = ("pending", "running", "done", "failed", "rolled_back")

# Steps a node's privileged helper runs; sealed with the master key when sent to a peer
# (core.step_seal), accepted by the helper only for the migration cluster.toml names.
H_PREPARE = "kea-mig-prepare"  # download packages, write 3.x files aside, note packages and files
H_MAINTENANCE = "kea-mig-ha-maintenance"  # details.action: start | cancel (sent to the serving peer)
H_STOP = "kea-mig-stop"  # stop the Kea units; details.export_leases: LFC, then the copy to serve
H_INSTALL = "kea-mig-install"  # details.direction: target | previous; packages and files, `-t`
H_VALIDATE_PARTNER = "kea-mig-validate-partner"  # the partner's 3.x files with this node's binaries
H_LEASES_IN = "kea-mig-leases-in"  # the fetched lease copy replaces this node's lease file
H_START = "kea-mig-start"  # start the Kea units (details.engines)
H_DELAYS = "kea-mig-delays"  # max-response-delay and max-unacked-clients back, config-write
H_FINISH = "kea-mig-finish"  # drop the migration files of this node except the lease backup
HELPER_STEPS = (
    H_PREPARE,
    H_MAINTENANCE,
    H_STOP,
    H_INSTALL,
    H_VALIDATE_PARTNER,
    H_LEASES_IN,
    H_START,
    H_DELAYS,
    H_FINISH,
)
# Steps the driving node's service runs itself (no helper, nothing sealed).
D_ARCHIVE = "kea-mig-archive"  # archive.run on the node, wait for a newer archive
D_FETCH_LEASES = "kea-mig-fetch-leases"  # peer action kea.migration.leases on the receiving node
D_WAIT_PARTNER_DOWN = "kea-mig-wait-partner-down"  # partner-down and lease4-get-all, bounded
D_WAIT_HA = "kea-mig-wait-ha"  # every relationship back to its normal state
DRIVER_STEPS = (D_ARCHIVE, D_FETCH_LEASES, D_WAIT_PARTNER_DOWN, D_WAIT_HA)
ALL_STEPS = (*HELPER_STEPS, *DRIVER_STEPS)
TARGET_PREFIX = "kea-migration"  # change target: kea-migration/<step>/<node id>


def target(step: str, node_id: str) -> str:
    return f"{TARGET_PREFIX}/{step}/{node_id}"


def step_message(step: str, node: str) -> Message:
    """Label of a job step: `job.step.kea_migration.<step without kea-mig->` with the node name."""
    return msg(f"job.step.kea_migration.{step.removeprefix('kea-mig-').replace('-', '_')}", node=node)


class MigrationStateError(ValueError):
    """A move the state machine does not allow, or a record that is not a migration."""


def to_toml(value: Any) -> Any:
    """TOML has no null: null keys are left out (read_migration gives them back as null)."""
    if isinstance(value, dict):
        return {k: to_toml(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [to_toml(v) for v in value]
    return value


def _str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _int(value: Any) -> int | None:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _packages(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    return [
        {"name": str(p["name"]), "version": str(p.get("version") or "")}
        for p in value
        if isinstance(p, dict) and p.get("name")
    ]


def _node(node_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    status = raw.get("status")
    role = raw.get("role")
    return {
        "node_id": node_id,
        "name": _str(raw.get("name")) or node_id,
        "role": role if role in ROLES else "single",
        "order": _int(raw.get("order")) or 0,
        "engines": [str(e) for e in raw.get("engines") or [] if e in ("kea4", "kea6", "d2")],
        "step": _str(raw.get("step")),
        "status": status if status in NODE_STATUSES else "pending",
        "ha_state": _str(raw.get("ha_state")),
        "from_version": _str(raw.get("from_version")),
        "to_version": _str(raw.get("to_version")),
        "packages_before": _packages(raw.get("packages_before")),
        "packages_target": _packages(raw.get("packages_target")),
        "archive_id": _str(raw.get("archive_id")),
        "rollback_ready": bool(raw.get("rollback_ready", False)),
        "prepared_at": _str(raw.get("prepared_at")),
        "started_at": _str(raw.get("started_at")),
        "finished_at": _str(raw.get("finished_at")),
        "error": _str(raw.get("error")),
        "files_sealed": _str(raw.get("files_sealed")),
    }


def read_migration(settings: dict[str, Any] | None) -> dict[str, Any] | None:
    """The migration record with every key of the contract (absent ones null), None when there is none.
    A record without its id, series or a known state (leaves of a concurrent removal) is none."""
    raw = ((settings or {}).get("kea") or {}).get("migration")
    if not isinstance(raw, dict):
        return None
    if not raw.get("id") or not raw.get("series") or raw.get("state") not in STATES:
        return None
    nodes_raw = raw.get("nodes") if isinstance(raw.get("nodes"), dict) else {}
    nodes = [_node(str(k), v) for k, v in nodes_raw.items() if isinstance(v, dict)]
    nodes.sort(key=lambda n: (n["order"], n["name"]))
    options = raw.get("options") if isinstance(raw.get("options"), dict) else {}
    phase, stage = raw.get("phase"), raw.get("stage")
    return {
        "id": str(raw["id"]),
        "analysis_id": _str(raw.get("analysis_id")),
        "series": str(raw["series"]),
        "source": _str(raw.get("source")) or "isc",
        "target_version": _str(raw.get("target_version")),
        "from_series": _str(raw.get("from_series")),
        "state": str(raw["state"]),
        "phase": phase if phase in PHASES else PREPARE,
        "stage": stage if stage in STAGES else None,
        "driver": _str(raw.get("driver")),
        "plan_id": _str(raw.get("plan_id")),
        "created_by": _str(raw.get("created_by")),
        "started_at": _str(raw.get("started_at")),
        "updated_at": _str(raw.get("updated_at")),
        "finished_at": _str(raw.get("finished_at")),
        "outage_started_at": _str(raw.get("outage_started_at")),
        "outage_seconds": raw.get("outage_seconds")
        if isinstance(raw.get("outage_seconds"), int | float)
        else None,
        "options": {
            "response_delay_milliseconds": _int(options.get("response_delay_milliseconds")),
            "https_sockets": bool(options.get("https_sockets", False)),
            "auto_rollback": options.get("auto_rollback")
            if isinstance(options.get("auto_rollback"), bool)
            else None,
        },
        "error": _str(raw.get("error")),
        "error_step": _str(raw.get("error_step")),
        "nodes": nodes,
    }


def rollback_possible(migration: dict[str, Any] | None) -> bool:
    """A return to the previous series is offered while Kea may change, or after a finished migration,
    and only when every node noted its previous packages and kept them cached (`rollback_ready`)."""
    if migration is None or migration["state"] not in (MIGRATING, FAILED, MIGRATED):
        return False
    return bool(migration["nodes"]) and all(n["rollback_ready"] for n in migration["nodes"])


def view(migration: dict[str, Any] | None, outage_max_seconds: int | None = None) -> dict[str, Any] | None:
    """The `Migration` answer of the API: the record, without package lists, plus `rollback_possible`."""
    if migration is None:
        return None
    out = {k: v for k, v in migration.items() if k != "nodes"}
    out["nodes"] = [
        {k: v for k, v in n.items() if not k.startswith("packages_") and k != "files_sealed"}
        for n in migration["nodes"]
    ]
    out["outage_max_seconds"] = outage_max_seconds
    out["rollback_possible"] = rollback_possible(migration)
    return out


def check_move(current: str | None, new: str) -> None:
    """Raises MigrationStateError unless the record may go from `current` (None: no record) to `new`."""
    if new not in STATES:
        raise MigrationStateError(f"unknown migration state {new!r}")
    if current is None:
        if new != PREPARING:
            raise MigrationStateError(f"a migration starts with {PREPARING}, not {new}")
        return
    if current in REPLACEABLE and new == PREPARING:
        return
    if new not in TRANSITIONS.get(current, ()):
        raise MigrationStateError(f"migration state {current} cannot move to {new}")


def phase_allowed(migration: dict[str, Any] | None, phase: str) -> str | None:
    """Why a plan of `phase` cannot be built now (None: it can)."""
    state = migration["state"] if migration else None
    if phase == PREPARE:
        if state is not None and state not in REPLACEABLE:
            return f"a migration is {state}: finish or roll it back first"
        return None
    if migration is None:
        return "no prepared migration"
    if phase == MIGRATE:
        if state == PREPARED or (state == FAILED and migration["phase"] == MIGRATE):
            return None
        return f"the migration is {state}: migrate needs it prepared"
    if phase == ROLLBACK:
        return None if rollback_possible(migration) else f"no rollback possible from {state}"
    return f"unknown phase {phase!r}"


def write(settings: dict[str, Any], record: dict[str, Any] | None) -> None:
    """Puts `record` (a read_migration dict, None to remove) into a cluster settings table in place."""
    table = settings.setdefault("kea", {})
    if record is None:
        table.pop("migration", None)
        return
    data = dict(record)
    nodes = data.pop("nodes", [])
    data["updated_at"] = to_rfc3339(utcnow())
    data["nodes"] = {n["node_id"]: {k: v for k, v in n.items() if k != "node_id"} for n in nodes}
    table["migration"] = to_toml(data)


def move(settings: dict[str, Any], new_state: str, **fields: Any) -> dict[str, Any]:
    """Moves the record of a cluster settings table to `new_state` (checked) with `fields` set."""
    current = read_migration(settings)
    if current is None:
        raise MigrationStateError("no Kea migration in cluster.toml")
    check_move(current["state"], new_state)
    current.update(fields)
    current["state"] = new_state
    write(settings, current)
    return current


# Converted files of a node, sealed for its partner's validate-partner step --------------------------


def _files_aad(migration_id: str, node_id: str) -> str:
    return f"kea-migration-files/{migration_id}/{node_id}"


def seal_files(box: Any, migration_id: str, node_id: str, bundle: dict[str, Any]) -> str:
    """The node's converted files and TSIG secrets ({"configs": {engine: config}, "secrets": {path:
    secret}}) under the cluster master key, bound to the migration and the node."""
    raw = zlib.compress(json.dumps(bundle, sort_keys=True).encode(), 9)
    return box.encrypt(_files_aad(migration_id, node_id), base64.b64encode(raw).decode())


def open_files(box: Any, migration_id: str, node_id: str, token: str) -> dict[str, Any]:
    """The bundle `seal_files` sealed; SecretError (or ValueError) when it does not open."""
    raw = box.decrypt(_files_aad(migration_id, node_id), token)
    data = json.loads(zlib.decompress(base64.b64decode(raw)))
    if not isinstance(data, dict) or not isinstance(data.get("configs"), dict):
        raise ValueError("sealed files of the partner are not a bundle")
    return data


# Lease copy served to the partner (GET /repl/v1/kea/leases/<family>) ------------------------------------


def migration_dir(var: Path, migration_id: str) -> Path:
    if not ID_RE.match(migration_id):
        raise MigrationStateError(f"invalid migration id {migration_id!r}")
    return var / DIR / migration_id


def lease_copy_path(var: Path, migration_id: str, family: str) -> Path:
    """Where the stop step leaves the lease file after its LFC: `leases<family>.csv`, 0600 pelagos."""
    if family not in FAMILIES:
        raise MigrationStateError(f"invalid family {family!r}")
    return migration_dir(var, migration_id) / f"leases{family}.csv"


def open_lease_copy(
    var: Path,
    settings: dict[str, Any],
    node_id: str,
    caller: str,
    migration_id: str,
    family: str,
    max_bytes: int,
) -> tuple[int, int]:
    """Opens this node's lease copy for `caller`; returns (fd, size). Raises LookupError (404) when the
    migration is not the active one or names neither node, PermissionError (403), OverflowError (413)."""
    migration = read_migration(settings)
    path = lease_copy_path(var, migration_id, family)
    if migration is None or migration["id"] != migration_id or migration["state"] not in ACTIVE:
        raise LookupError(f"no active Kea migration {migration_id}")
    ids = {n["node_id"] for n in migration["nodes"]}
    if node_id not in ids:
        raise LookupError(f"this node is not part of migration {migration_id}")
    if caller not in ids:
        raise PermissionError(f"node {caller} is not part of migration {migration_id}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise LookupError(f"no lease copy for DHCPv{family} in migration {migration_id}") from None
    except OSError as exc:
        raise LookupError(f"lease copy unreadable: {exc.strerror}") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise LookupError("the lease copy is not a regular file")
    if st.st_size > max_bytes:
        os.close(fd)
        raise OverflowError(f"lease copy of {st.st_size} bytes over kea.migration_lease_file_max_mb")
    return fd, st.st_size
