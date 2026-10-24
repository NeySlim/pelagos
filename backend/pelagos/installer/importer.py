# SPDX-License-Identifier: Apache-2.0
"""Adopt an existing configuration without rewriting it (POST /install/import/plan).

The plan lists what was read (named-checkconf -p, the Kea files), the two include lines to add, the
Kea control sockets and statistics-channel to add when missing, the Pelagos TSIG keys to create and
the update-policy proposal per primary zone (applied later by the security plan, never here).
`verify_import` is gate 1 of the design: the configuration read back equals the one adopted.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pelagos.core.write_pipeline import sha256_file
from pelagos.domain import (
    Change,
    ChangeOp,
    Job,
    Plan,
    PlanScope,
    PlanState,
    Precondition,
    PreconditionKind,
    ValidationResult,
    messages,
)
from pelagos.installer import bindconf, bindsetup, keaconf, keasetup, managed
from pelagos.installer.jobs import Step
from pelagos.platform import (
    ENGINES,
    KEA_DAEMONS,
    PELAGOS_USER,
    ensure_supplementary_groups,
    ensure_system_user,
)

IMPORT_KEYS = (managed.READ_KEY, managed.ADMIN_KEY)


# Normalized views used by gate 1 ---------------------------------------------------------------


def bind_fingerprint(
    printed: str, ignore_keys: tuple[str, ...] = IMPORT_KEYS, ignore_stats: bool = False
) -> str:
    """sha256 of `named-checkconf -p` output without what Pelagos adds (its keys, its stats channel)."""
    stmts = bindconf.parse(printed)
    kept = []
    for s in stmts:
        if s.name == "key" and s.words and s.words[0] in ignore_keys:
            continue
        if ignore_stats and s.name == "statistics-channels":
            continue
        kept.append(_canonical(s))
    return hashlib.sha256("\n".join(kept).encode()).hexdigest()


def _canonical(stmt: bindconf.Statement) -> str:
    parts = [stmt.name]
    for a in stmt.args:
        if isinstance(a, bindconf.Block):
            parts.append("{ " + " ".join(_canonical(s) for s in a.statements) + " }")
        else:
            parts.append(a)
    return " ".join(parts) + ";"


def kea_fingerprint(text: str, path: str | None = None) -> str:
    """sha256 of the Kea config (includes resolved when `path` is given) without its control socket
    entries, the only thing import may add."""
    config = keaconf.loads(text, path)
    root = keaconf.root_key(config)
    body = dict(config[root])
    body.pop("control-socket", None)
    sockets = [s for s in body.pop("control-sockets", []) or [] if s.get("socket-type") != "unix"]
    if sockets:
        body["control-sockets"] = sockets
    return hashlib.sha256(json.dumps({root: body}, sort_keys=True).encode()).hexdigest()


# Plan ------------------------------------------------------------------------------------------


def _change(target: str, env: Any, after: Any, before: Any = None, op: ChangeOp = ChangeOp.ADD) -> Change:
    return Change(op=op, target=target, before=before, after=after, node_ids=[env.node_id])


def build_import_plan(env: Any, engines: list[str], created_by: str = "") -> Plan:
    unknown = [e for e in engines if e not in ENGINES]
    if unknown:
        raise ValueError(f"unknown engine(s) {', '.join(unknown)}")
    engines = [e for e in ENGINES if e in engines]
    paths = env.paths
    changes: list[Change] = []
    preconditions: list[Precondition] = []
    validations: list[ValidationResult] = []
    groups: list[str] = []

    if "bind" in engines:
        named_conf = paths.named_conf
        ok, output = env.t.checkconf(named_conf)
        validations.append(
            ValidationResult(ok=ok, tool="named-checkconf", output=output, node_id=env.node_id)
        )
        if not ok:
            raise ValueError(
                f"named-checkconf {named_conf} fails; fix the configuration before importing:\n{output}"
            )
        printed = env.t.checkconf_print(named_conf)
        insp = bindsetup.inspect(named_conf, paths.bind_include_dir, paths.rndc_key)
        stats_added = insp.stats is None
        read = {
            "named_conf": str(named_conf),
            "files": insp.files,
            "zones": insp.zones,
            "views": insp.views,
            "keys": insp.keys,
            "statistics_channel": insp.stats,
            "controls": insp.controls,
            "fingerprint": bind_fingerprint(printed),
            "stats_added": stats_added,
        }
        changes.append(_change("import/read/bind", env, read))
        for f in insp.files:
            preconditions.append(
                Precondition(PreconditionKind.FILE_SHA256, f, sha256_file(Path(f)), node_id=env.node_id)
            )
        groups.append(paths.bind_group)
        to_create = [k for k in IMPORT_KEYS if k not in insp.keys]
        changes.append(
            _change(
                "import/bind/adopt",
                env,
                {
                    "named_conf": str(named_conf),
                    "include_dir": str(paths.bind_include_dir),
                    "include_lines": [
                        line
                        for line, present in (
                            (managed.include_line(paths.pelagos_conf), insp.top_include_present),
                            (managed.include_line(paths.options_conf), insp.options_include_present),
                        )
                        if not present
                    ],
                    "options_file": insp.options_file,
                    "statistics_port": None if insp.stats else paths.bind_stats_port,
                    "keys": to_create,
                },
            )
        )
        for prop in insp.update_policy_proposals:
            changes.append(
                _change(
                    f"import/bind/update-policy/{prop['view']}/{prop['zone']}",
                    env,
                    {"proposal": prop["proposal"], "applied": False, "file": prop["file"]},
                    before={
                        "allow-update": prop["current_allow_update"],
                        "update-policy": prop["current_update_policy"],
                    },
                    op=ChangeOp.REPLACE,
                )
            )

    kea = [e for e in engines if e in KEA_DAEMONS]
    for engine in kea:
        daemon = KEA_DAEMONS[engine]
        conf = paths.kea_conf(daemon)
        text = conf.read_text()
        config = keaconf.loads(text, str(conf))
        ok, output = env.t.kea_test(daemon, conf)
        validations.append(ValidationResult(ok=ok, tool=f"{daemon} -t", output=output, node_id=env.node_id))
        sock = keaconf.control_socket_path(config, paths.kea_socket_dir)
        body = config[keaconf.root_key(config)]
        read = {
            "conf": str(conf),
            "fingerprint": kea_fingerprint(text, str(conf)),
            "socket": str(sock) if sock else None,
            "subnets": len(body.get("subnet4" if engine == "kea4" else "subnet6", []) or [])
            + sum(
                len(sn.get("subnet4", sn.get("subnet6", [])) or [])
                for sn in body.get("shared-networks", []) or []
            ),
            "hooks": [h.get("library", "") for h in body.get("hooks-libraries", []) or []],
            "tsig_keys": [k.get("name") for k in body.get("tsig-keys", []) or []] if engine == "d2" else [],
        }
        changes.append(_change(f"import/read/{engine}", env, read))
        for f in [conf, *keaconf.included_files(conf)]:
            preconditions.append(
                Precondition(PreconditionKind.FILE_SHA256, str(f), sha256_file(f), node_id=env.node_id)
            )
        changes.append(
            _change(
                f"import/{engine}/socket",
                env,
                {"conf": str(conf), "add": sock is None, "socket": str(sock or paths.kea_socket(engine))},
            )
        )
        if paths.kea_group not in groups:
            groups.append(paths.kea_group)

    changes.insert(0, _change(f"import/user/{PELAGOS_USER}", env, {"groups": groups}))
    changes.append(_change("import/node", env, {"engines": {e: True for e in engines}}))
    changes.append(_change("import/verify", env, {"engines": engines}))
    ok = all(v.ok for v in validations)
    return Plan(
        scope=PlanScope.IMPORT,
        node_id=env.node_id,
        summary=messages.render(messages.msg("plan.import", engines=list(engines))),
        summary_message=messages.msg("plan.import", engines=list(engines)),
        created_by=created_by,
        changes=changes,
        diff=render_diff(changes),
        preconditions=preconditions,
        validations=validations,
        target_node_ids=[env.node_id],
        requires_confirmation=True,
        state=PlanState.VALIDATED if ok else PlanState.FAILED,
        error=None if ok else "validation failed",
    )


def render_diff(changes: list[Change]) -> str:
    out = []
    for c in changes:
        a = c.after if isinstance(c.after, dict) else {}
        if c.target == "import/bind/adopt":
            for line in a.get("include_lines", []):
                out.append(f"+ {line}")
            for k in a.get("keys", []):
                out.append(f"+ key {k} (hmac-sha256) in keys.conf")
            if a.get("statistics_port"):
                out.append(f"+ statistics-channels on 127.0.0.1 port {a['statistics_port']}")
        elif c.target.startswith("import/bind/update-policy/"):
            out.append(f"? {c.target.split('/', 3)[3]}: proposal {a.get('proposal')} (not applied by import)")
        elif c.target.endswith("/socket") and a.get("add"):
            out.append(f"+ {a['conf']}: unix control socket {Path(a['socket']).name}")
    return "\n".join(out)


# Apply -----------------------------------------------------------------------------------------


def check_preconditions(env: Any, plan: Plan) -> list[str]:
    """Files read at plan time must not have moved; returns the ones that did."""
    moved = []
    for p in plan.preconditions:
        if p.kind is PreconditionKind.FILE_SHA256 and (p.node_id in (None, env.node_id)):
            try:
                current = sha256_file(Path(p.subject))
            except OSError:
                current = "absent"
            if current != p.value:
                moved.append(p.subject)
    return moved


def step_bind_adopt(env: Any, change: Change, ctx: dict[str, Any]) -> str:
    a = change.after
    # Every node of a cluster signs with the same ddi-read and ddi-admin: reuse the replicated secrets.
    shared = {k: s for k in a["keys"] if (s := env.stored_secret(f"tsig/{k}"))}
    result = bindsetup.adopt(
        env,
        Path(a["named_conf"]),
        bindsetup.AdoptOptions(
            stats_port=int(a["statistics_port"] or env.paths.bind_stats_port),
            create_keys=list(a["keys"]),
            extra_secrets=shared,
        ),
    )
    ctx.setdefault("engines", {})["bind"] = result.engine_config
    return "\n".join([*result.output, env.store_secrets(result.secrets)])


def step_kea_socket(env: Any, engine: str, change: Change, ctx: dict[str, Any]) -> str:
    daemon = KEA_DAEMONS[engine]
    conf = Path(change.after["conf"])
    version = env.t.kea_version(daemon)
    out = [f"{daemon} {version or 'version unknown'}"]
    files = keasetup.unix_socket_files(conf, engine, version)
    if files:
        out.append(keasetup.write_files(env, engine, conf, files, f"import-{engine}", restart=False))
    else:
        out.append("control socket present")
    out.append(keasetup.ensure_config_writable(env, conf, daemon))
    dropin = keasetup.ensure_socket_access(env, engine, version)
    out.append(dropin)
    if dropin.endswith("written") and env.services.is_active(env.kea_unit(engine)):
        out.append(env.services.restart(env.kea_unit(engine)) or "restarted for the socket drop-in")
    sock = keasetup.socket_path(env, engine, conf)
    kea_cfg = ctx.setdefault("engines", {}).setdefault("kea", {"socket_dir": str(sock.parent)})
    short = {"kea4": "dhcp4", "kea6": "dhcp6", "d2": "d2"}[engine]
    kea_cfg[f"{short}_socket"] = sock.name
    kea_cfg[f"{short}_conf"] = str(conf)
    return "\n".join(o for o in out if o)


def step_user(env: Any, change: Change) -> str:
    if env.dry_run:
        return "dry run: user not changed"
    return "; ".join(
        [
            ensure_system_user(env.runner),
            ensure_supplementary_groups(env.runner, PELAGOS_USER, change.after["groups"]),
        ]
    )


def import_steps(plan: Plan, env: Any) -> list[Step]:
    ctx: dict[str, Any] = {}
    reads = {c.target.split("/")[-1]: c.after for c in plan.changes if c.target.startswith("import/read/")}
    steps: list[Step] = []

    def preconditions() -> str:
        moved = check_preconditions(env, plan)
        if moved:
            raise RuntimeError(f"configuration changed since the plan was made: {', '.join(moved)}")
        return f"{len(plan.preconditions)} file(s) unchanged"

    steps.append(Step("import/preconditions", preconditions))
    for change in plan.changes:
        if env.node_id not in change.node_ids:
            continue
        t, c = change.target, change
        if t.startswith("import/read/") or t.startswith("import/bind/update-policy/"):
            continue  # informational: what was read, and proposals applied by the security plan
        if t.startswith("import/user/"):
            steps.append(Step(t, lambda c=c: step_user(env, c)))
        elif t == "import/bind/adopt":
            steps.append(Step(t, lambda c=c: step_bind_adopt(env, c, ctx), weight=2))
        elif t.endswith("/socket"):
            engine = t.split("/")[1]
            steps.append(Step(t, lambda e=engine, c=c: step_kea_socket(env, e, c, ctx), weight=2))
        elif t == "import/node":

            def node(c: Change = c) -> str:
                engines = dict(c.after["engines"])
                engines.update(ctx.get("engines", {}))
                return "dry run" if env.dry_run else env.update_node_engines(engines)

            steps.append(Step(t, node))
        elif t == "import/verify":

            def verify(c: Change = c) -> str:
                if env.dry_run:
                    return "dry run: nothing to verify"
                result = verify_import(env, list(c.after["engines"]), reads)
                failed = [k for k, v in result.items() if not v]
                report = ", ".join(f"{k}={'ok' if v else 'FAILED'}" for k, v in result.items())
                if failed:
                    raise RuntimeError(f"gate 1 failed: {report}")
                return report

            steps.append(Step(t, verify))
        else:
            raise ValueError(f"unknown import change {t}")
    return steps


# Checks ----------------------------------------------------------------------------------------


def check_engines(env: Any, engines: list[str]) -> dict[str, bool]:
    """Live checks the node relies on: rndc, statistics channel, include lines, keys, Kea sockets."""
    paths = env.paths
    out: dict[str, bool] = {}
    if "bind" in engines:
        rndc_conf = paths.rndc_conf_pelagos if paths.rndc_conf_pelagos.exists() else None
        out["bind.rndc"] = env.t.rndc(rndc_conf, "status")[0]
        insp = bindsetup.inspect(paths.named_conf, paths.bind_include_dir, paths.rndc_key)
        out["bind.include"] = insp.top_include_present
        out["bind.options_include"] = insp.options_include_present or insp.options_file is None
        out["bind.keys"] = all(k in insp.keys for k in IMPORT_KEYS)
        stats = insp.stats
        url = f"http://127.0.0.1:{stats['port']}/json/v1" if stats and stats["reachable"] else None
        out["bind.stats"] = bool(url) and env.t.http_get(url)[0] == 200
    for engine in engines:
        if engine not in KEA_DAEMONS:
            continue
        conf = paths.kea_conf(KEA_DAEMONS[engine])
        sock = keasetup.socket_path(env, engine, conf)
        out[f"{engine}.socket"] = keasetup._wait(lambda s=sock: env.t.socket_alive(s), seconds=10)
    return out


def verify_import(env: Any, engines: list[str], reads: dict[str, Any] | None = None) -> dict[str, bool]:
    """Gate 1: live checks pass and the configuration read back equals the one read before import."""
    out = check_engines(env, engines)
    reads = reads or {}
    paths = env.paths
    if "bind" in engines and "bind" in reads:
        printed = env.t.checkconf_print(paths.named_conf)
        before = reads["bind"]
        # The Pelagos keys are excluded on both sides; the stats channel only when this import added it.
        after = bind_fingerprint(printed, ignore_stats=bool(before.get("stats_added")))
        out["bind.unchanged"] = after == before["fingerprint"]
    for engine in engines:
        if engine in KEA_DAEMONS and engine in reads:
            conf = Path(reads[engine]["conf"])
            out[f"{engine}.unchanged"] = (
                kea_fingerprint(conf.read_text(), str(conf)) == reads[engine]["fingerprint"]
            )
    return out


# Compatibility entry points named in the package skeleton ---------------------------------------


def plan_import(paths: Any, engines: list[str], created_by: str, node_id: str) -> Plan:
    from pelagos.installer.env import InstallerEnv

    env = InstallerEnv.detect(node_id=node_id)
    env.paths = paths
    return build_import_plan(env, engines, created_by)


def run_import(plan: Plan, job: Job, progress: Any) -> Job:
    from pelagos.installer.env import InstallerEnv
    from pelagos.installer.jobs import apply_plan

    return apply_plan(plan, InstallerEnv.detect(node_id=plan.node_id), job, progress)
