# SPDX-License-Identifier: Apache-2.0
"""Long-running applies as Jobs: ordered steps with progress, stop at the first failure."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pelagos.domain import Job, JobState, Plan, PlanScope, PlanState, utcnow

log = logging.getLogger(__name__)

Progress = Callable[[Job], None]


class StepFailed(Exception):
    pass


@dataclass(slots=True)
class Step:
    name: str
    run: Callable[[], Any]  # returns output text (or any object; str() is kept)
    weight: int = 1


class JobRunner:
    """Executes steps in order, recording each one on the Job and reporting progress after each."""

    def __init__(self, job: Job, progress: Progress | None = None) -> None:
        self.job = job
        self.progress = progress or (lambda _job: None)

    def _emit(self) -> None:
        try:
            self.progress(self.job)
        except Exception:  # a broken listener must not fail the job
            log.exception("job progress listener failed")

    def run(self, steps: list[Step]) -> Job:
        job = self.job
        total = sum(max(s.weight, 1) for s in steps) or 1
        done_weight = 0
        job.state = JobState.RUNNING
        job.progress = 0
        self._emit()
        for step in steps:
            record: dict[str, Any] = {
                "name": step.name,
                "state": "running",
                "output": "",
                "started_at": utcnow().isoformat().replace("+00:00", "Z"),
                "finished_at": None,
            }
            job.steps.append(record)
            self._emit()
            try:
                out = step.run()
                record["output"] = "" if out is None else str(out)
                record["state"] = "done"
            except Exception as exc:
                record["output"] = f"{exc}"
                record["state"] = "failed"
                record["finished_at"] = utcnow().isoformat().replace("+00:00", "Z")
                job.state = JobState.FAILED
                job.error = f"{step.name}: {exc}"
                job.finished_at = utcnow()
                log.debug("step %s failed:\n%s", step.name, traceback.format_exc())
                self._emit()
                return job
            record["finished_at"] = utcnow().isoformat().replace("+00:00", "Z")
            done_weight += max(step.weight, 1)
            job.progress = min(99, int(100 * done_weight / total))
            self._emit()
        job.progress = 100
        job.state = JobState.DONE
        job.finished_at = utcnow()
        self._emit()
        return job


def steps_for(plan: Plan, env: Any) -> list[Step]:
    """Builds the step list of an installer plan; imported lazily to avoid import cycles."""
    if plan.scope is PlanScope.INSTALL:
        from pelagos.installer.install import install_steps

        return install_steps(plan, env)
    if plan.scope is PlanScope.IMPORT:
        from pelagos.installer.importer import import_steps

        return import_steps(plan, env)
    if plan.scope is PlanScope.SECURITY:
        from pelagos.installer.security_audit import remediation_steps

        return remediation_steps(plan, env)
    raise ValueError(f"not an installer plan scope: {plan.scope}")


def apply_plan(plan: Plan, env: Any, job: Job | None = None, progress: Progress | None = None) -> Job:
    """Runs an install/import/security plan to completion; the Plan state follows the Job."""
    job = job or Job(plan_id=plan.id)
    plan.state = PlanState.APPLYING
    try:
        steps = steps_for(plan, env)
    except Exception as exc:
        job.state = JobState.FAILED
        job.error = f"cannot build steps: {exc}"
        job.finished_at = utcnow()
        plan.state = PlanState.FAILED
        plan.error = job.error
        return job
    JobRunner(job, progress).run(steps)
    if job.state is JobState.DONE:
        plan.state = PlanState.APPLIED
    else:
        plan.state = PlanState.FAILED
        plan.error = job.error
    return job
