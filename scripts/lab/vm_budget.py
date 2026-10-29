#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lab VM budget: refuse to start a VM of the pool when too many test VMs already run.

Usage: vm_budget.py check <vmid>...   exit 0 when starting them all fits, 3 when refused
       vm_budget.py status            running test VMs of the pool

A test VM is a running VM of PELAGOS_LAB_POOL (default pelagos) that is not an infrastructure VM.
PELAGOS_LAB_MAX_VMS (default 10) caps them. The infrastructure VMIDs (gateway, dev VM) come from
PELAGOS_LAB_INFRA_VMIDS or the file infra-vmids of the lab config directory; without either, every
running VM counts, which only makes the budget stricter.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MAX_VMS = 10
REFUSED = 3


def conf_dir() -> Path:
    return Path(os.environ.get("PVE_CONF_DIR") or os.path.expanduser("~/.config/pelagos-lab"))


def max_vms() -> int:
    return int(os.environ.get("PELAGOS_LAB_MAX_VMS") or DEFAULT_MAX_VMS)


def infra_vmids() -> set[int] | None:
    raw = os.environ.get("PELAGOS_LAB_INFRA_VMIDS")
    if raw is None:
        path = conf_dir() / "infra-vmids"
        if not path.is_file():
            return None
        raw = path.read_text()
    return {int(tok) for tok in raw.replace(",", " ").split()}


def fetch_resources() -> list[dict[str, Any]]:
    """The VMs the lab token sees (/cluster/resources?type=vm)."""
    base = os.environ.get("PVE_API") or (conf_dir() / "pve-api").read_text().strip()
    token = Path(os.environ.get("PVE_TOKEN_FILE") or conf_dir() / "pve-token").read_text().strip()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(  # noqa: S310 - lab API only
        base.rstrip("/") + "/cluster/resources?type=vm", headers={"Authorization": token}
    )
    with urllib.request.urlopen(req, timeout=30, context=ctx) as res:  # noqa: S310
        return json.loads(res.read())["data"]


def running_tests(resources: list[dict[str, Any]], pool: str, infra: set[int]) -> list[dict[str, Any]]:
    return [
        r
        for r in resources
        if r.get("status") == "running"
        and (not pool or r.get("pool") == pool)
        and int(r["vmid"]) not in infra
    ]


def check(
    resources: list[dict[str, Any]], vmids: list[int], limit: int, pool: str, infra: set[int]
) -> tuple[bool, str]:
    """Whether starting `vmids` keeps the running test VMs at or under `limit`, with a message."""
    running = running_tests(resources, pool, infra)
    running_ids = {int(r["vmid"]) for r in resources if r.get("status") == "running"}
    to_start = sorted({v for v in vmids if v not in running_ids and v not in infra})
    total = len(running) + len(to_start)
    ordered = sorted(running, key=lambda r: r["vmid"])
    names = ", ".join(f"{r['vmid']} {r.get('name', '')}".strip() for r in ordered)
    if total <= limit:
        return True, f"lab budget: {total}/{limit} test VMs once started"
    return False, (
        f"lab budget exceeded: {len(running)} test VMs running ({names or 'none'}), "
        f"starting {' '.join(map(str, to_start))} would make {total} > PELAGOS_LAB_MAX_VMS={limit}. "
        "Stop a finished VM first (shutdown, never delete) or wait."
    )


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("check", "status") or (argv[0] == "check" and len(argv) < 2):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    if argv[0] == "check" and not all(v.isdigit() for v in argv[1:]):
        print(f"vm_budget.py: VMIDs must be integers, got {' '.join(argv[1:])!r}", file=sys.stderr)
        print(__doc__.strip(), file=sys.stderr)
        return 2
    infra = infra_vmids()
    if infra is None:
        print("lab budget: no infra-vmids configured, every running VM counts", file=sys.stderr)
        infra = set()
    pool = os.environ.get("PELAGOS_LAB_POOL", "pelagos")
    resources = fetch_resources()
    if argv[0] == "status":
        running = running_tests(resources, pool, infra)
        for r in sorted(running, key=lambda r: r["vmid"]):
            print(r["vmid"], r.get("name", ""))
        print(f"{len(running)}/{max_vms()} test VMs running")
        return 0
    ok, message = check(resources, [int(v) for v in argv[1:]], max_vms(), pool, infra)
    print(message, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else REFUSED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
