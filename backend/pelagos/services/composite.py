# SPDX-License-Identifier: Apache-2.0
"""Plans made of one engine plan per node (HA setup, zone secondaries): the parts are built where
their engine runs and applied in order by the plan service, every part rolled back when one fails."""

from __future__ import annotations

from pelagos.domain import Change, Plan, PlanState


def merge_parts(plan: Plan, parts: list[Plan], names: dict[str, str]) -> None:
    """Fill a plan made of node parts: their changes (tagged with the node), diffs under a header
    naming the node, preconditions, validations and targets; FAILED when a part failed."""
    for part in parts:
        node_ids = list(part.target_node_ids)
        for change in part.changes:
            plan.changes.append(Change.from_dict({**change.to_dict(), "node_ids": node_ids}))
        header = "".join(f"# {names.get(n, n)}\n" for n in node_ids)
        if part.diff:
            plan.diff += header + part.diff + ("" if part.diff.endswith("\n") else "\n")
        plan.preconditions.extend(part.preconditions)
        plan.validations.extend(part.validations)
        plan.requires_confirmation = plan.requires_confirmation or part.requires_confirmation
        for node_id in node_ids:
            if node_id not in plan.target_node_ids:
                plan.target_node_ids.append(node_id)
    failed = [p for p in parts if p.state is PlanState.FAILED]
    plan.state = PlanState.FAILED if failed else PlanState.VALIDATED
    plan.error = "; ".join(p.error or "validation failed" for p in failed) or None
