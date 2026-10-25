# SPDX-License-Identifier: Apache-2.0
"""Pelagos filesystem layout (section 3), overridable for development and tests."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, frozen=True)
class Paths:
    etc: Path
    var: Path
    run: Path
    opt: Path

    @classmethod
    def from_env(cls) -> Paths:
        """PELAGOS_ETC/VAR/RUN/OPT override the system defaults; PELAGOS_HOME sets all four."""
        home = os.environ.get("PELAGOS_HOME")
        if home:
            base = Path(home)
            return cls(
                etc=Path(os.environ.get("PELAGOS_ETC", base / "etc")),
                var=Path(os.environ.get("PELAGOS_VAR", base / "var")),
                run=Path(os.environ.get("PELAGOS_RUN", base / "run")),
                opt=Path(os.environ.get("PELAGOS_OPT", base / "opt")),
            )
        return cls(
            etc=Path(os.environ.get("PELAGOS_ETC", "/etc/pelagos")),
            var=Path(os.environ.get("PELAGOS_VAR", "/var/lib/pelagos")),
            run=Path(os.environ.get("PELAGOS_RUN", "/run/pelagos")),
            opt=Path(os.environ.get("PELAGOS_OPT", "/opt/pelagos")),
        )

    @property
    def node_toml(self) -> Path:
        return self.etc / "node.toml"

    @property
    def master_key(self) -> Path:
        return self.etc / "master.key"

    @property
    def tls_dir(self) -> Path:
        return self.etc / "tls"

    @property
    def cluster_toml(self) -> Path:
        return self.var / "cluster.toml"

    @property
    def audit_log(self) -> Path:
        return self.var / "audit" / "audit.jsonl"

    @property
    def series_db(self) -> Path:
        return self.var / "series.sqlite"

    @property
    def pki_dir(self) -> Path:
        return self.var / "pki"

    @property
    def backups_dir(self) -> Path:
        return self.var / "backups"

    @property
    def locks_dir(self) -> Path:
        return self.var / "locks"

    @property
    def collector_sock(self) -> Path:
        return self.run / "collector.sock"

    @property
    def events_sock(self) -> Path:
        return self.run / "events.sock"

    @property
    def replication_state_file(self) -> Path:
        return self.run / "replication.state"

    @property
    def plan_tombstones(self) -> Path:
        """Ids of plans this node built and when they expire (0600): 410 plan_expired after restarts."""
        return self.var / "plan_tombstones.json"

    @property
    def plans_dir(self) -> Path:
        """Plans built on this node, one encrypted file each (0700): apply and rollback survive a restart."""
        return self.var / "plans"

    @property
    def enroll_tokens(self) -> Path:
        return self.var / "enroll_tokens.json"

    def ensure(self) -> None:
        """Create the writable tree with private modes; never touches /opt."""
        for d, mode in ((self.etc, 0o750), (self.var, 0o750), (self.run, 0o750)):
            d.mkdir(parents=True, exist_ok=True, mode=mode)
        for d in (self.audit_log.parent, self.pki_dir, self.backups_dir, self.locks_dir, self.tls_dir):
            d.mkdir(parents=True, exist_ok=True, mode=0o750)
