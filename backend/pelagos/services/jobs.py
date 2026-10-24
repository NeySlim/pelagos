# SPDX-License-Identifier: Apache-2.0
"""In-memory jobs for long-running applies (install, import, security, consistency runs)."""

from __future__ import annotations

import logging
import threading
import traceback
from collections.abc import Callable
from typing import Any

from pelagos.domain import Job, JobState, utcnow
from pelagos.services.events import EventHub

log = logging.getLogger(__name__)

Runner = Callable[[Job, Callable[[Job], None]], Any]


class JobStore:
    def __init__(self, events: EventHub | None = None, keep: int = 200) -> None:
        self.events = events
        self.keep = keep
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self.on_finished: Callable[[Job], None] | None = None

    def active(self) -> bool:
        """True while a job is queued or running."""
        with self._lock:
            return any(j.state in (JobState.QUEUED, JobState.RUNNING) for j in self._jobs.values())

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _remember(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.keep:
                self._jobs.pop(self._order.pop(0), None)

    def progress(self, job: Job) -> None:
        job.progress = max(0, min(100, int(job.progress)))
        if self.events is not None:
            self.events.publish("jobs", "progress", job)

    def submit(self, runner: Runner, plan_id: str | None = None, background: bool = True) -> Job:
        """`runner(job, progress)` fills steps and progress; a return value becomes a final "result" step."""
        job = Job(plan_id=plan_id, state=JobState.QUEUED)
        self._remember(job)
        if background:
            threading.Thread(target=self._run, args=(runner, job), name=f"job-{job.id}", daemon=True).start()
        else:
            self._run(runner, job)
        return job

    def _run(self, runner: Runner, job: Job) -> None:
        job.state = JobState.RUNNING
        try:
            result = runner(job, self.progress)
            if result is not None:
                job.steps.append(
                    {
                        "name": "result",
                        "state": "done",
                        "output": result,
                        "started_at": None,
                        "finished_at": utcnow(),
                    }
                )
            job.state = JobState.DONE
            job.progress = 100
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            job.steps.append(
                {
                    "name": "error",
                    "state": "failed",
                    "output": traceback.format_exc(limit=5),
                    "started_at": None,
                    "finished_at": utcnow(),
                }
            )
        job.finished_at = utcnow()
        if self.events is not None:
            self.events.publish("jobs", "done" if job.state is JobState.DONE else "failed", job)
        if self.on_finished is not None:
            try:
                self.on_finished(job)
            except Exception:  # a hook never turns a finished job into a crash
                log.exception("job %s: finish hook failed", job.id)


def step(job: Job, name: str, fn: Callable[[], Any], progress: Callable[[Job], None], weight: int = 0) -> Any:
    """Runs one step and records it on the job; exceptions propagate after being recorded."""
    entry: dict[str, Any] = {
        "name": name,
        "state": "running",
        "output": None,
        "started_at": utcnow(),
        "finished_at": None,
    }
    job.steps.append(entry)
    progress(job)
    try:
        out = fn()
    except Exception as exc:
        entry.update(state="failed", output=str(exc), finished_at=utcnow())
        progress(job)
        raise
    entry.update(
        state="done",
        output=out if isinstance(out, str | int | float | list | dict | type(None)) else str(out),
        finished_at=utcnow(),
    )
    job.progress = min(100, job.progress + weight)
    progress(job)
    return out
