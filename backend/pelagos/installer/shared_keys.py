# SPDX-License-Identifier: Apache-2.0
"""shared_key_divergence: a Pelagos read or admin key whose keys.conf secret differs from cluster.toml.

Every node signs transfers and updates with the same read and admin keys (global and per view), and
cluster.toml [secrets] holds the one secret they share (always hmac-sha256). A node imported before
replication brought its peers' keys made its own: its keys.conf then disagrees with cluster.toml and
transfers between nodes fail with BADSIG once a zone moves. The remediation rewrites the key in
keys.conf from cluster.toml, then named-checkconf, `rndc reconfig`, and the file back on any failure.
"""

from __future__ import annotations

from typing import Any

from pelagos.connectors.bind.viewkeys import GLOBAL_KEYS
from pelagos.domain import Severity
from pelagos.domain.messages import msg
from pelagos.installer import bindconf

KIND = "shared_key_divergence"
ALGORITHM = "hmac-sha256"


def shared_key_names(settings: dict[str, Any]) -> set[str]:
    """The global read and admin keys and every view's keys, from the cluster settings."""
    dns = settings.get("dns") or {}
    names = {str(dns.get(f"{role}_key") or default) for role, default in GLOBAL_KEYS.items()}
    for entry in (dns.get("view_keys") or {}).values():
        if isinstance(entry, dict):
            names |= {str(entry[r]) for r in GLOBAL_KEYS if entry.get(r)}
        elif entry:
            names.add(str(entry))
    return names


def _cluster(env: Any) -> tuple[Any, Any, str] | None:
    """(cluster config, secret box, node name), None before `pelagos init`."""
    if not (env.node_initialized() and env.node_paths.master_key.exists()):
        return None
    from pelagos.core.config_store import ConfigStore
    from pelagos.core.secrets import SecretBox

    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
    try:
        name = store.load_node().name
    except (OSError, KeyError, ValueError):
        name = env.node_id
    return store.load_cluster(), SecretBox.from_file(env.node_paths.master_key), name


def _differences(key: bindconf.KeyDef, secret: str) -> list[str]:
    out = []
    if (key.secret or "").strip('"') != secret:
        out.append("secret")
    if key.algorithm.lower() != ALGORITHM:
        out.append("algorithm")
    return out


def audit(env: Any) -> list[Any]:
    """One finding per shared key of keys.conf whose secret or algorithm differs from cluster.toml.
    Neither secret ever enters the finding."""
    from pelagos.installer.security_audit import Finding, finding_id

    path = env.paths.keys_conf
    found = _cluster(env) if path.exists() else None
    if found is None:
        return []
    cluster, box, node = found
    names = shared_key_names(cluster.settings)
    out = []
    for key in bindconf.keys(bindconf.parse(path.read_text(), str(path))):
        token = cluster.secrets.get(f"tsig/{key.name}")
        if key.name not in names or not token:
            continue
        differs = _differences(key, box.decrypt(f"tsig/{key.name}", token))
        if not differs:
            continue
        out.append(
            Finding.of(
                finding_id("bind", KIND, key.name),
                KIND,
                Severity.CRITICAL,
                "bind",
                key.name,
                msg("finding.shared_key_divergence.description", key=key.name, node=node),
                msg("finding.shared_key_divergence.proposal", key=key.name),
                msg("finding.shared_key_divergence.risk", key=key.name),
                {"remediation": "shared_key", "key": key.name, "file": str(path), "differs": differs},
            )
        )
    return out


def remediate(env: Any, d: dict[str, Any], ctx: dict[str, Any]) -> str:
    """keys.conf gets the cluster.toml secret of the key; the BIND pipeline validates, reconfigures
    and restores the file on failure."""
    from pelagos.installer.security_audit import _run_bind

    found = _cluster(env)
    if found is None:
        raise RuntimeError("this node has no cluster.toml: nothing to take the secret from")
    cluster, box, _node = found
    name = d["key"]
    token = cluster.secrets.get(f"tsig/{name}")
    if not token:
        raise RuntimeError(f"cluster.toml has no secret for {name} any more")
    secret = box.decrypt(f"tsig/{name}", token)
    path = env.paths.keys_conf
    text = path.read_text()
    key = next((k for k in bindconf.keys(bindconf.parse(text, str(path))) if k.name == name), None)
    if key is None:
        raise RuntimeError(f"key {name} is not in {path} any more")
    if not _differences(key, secret):
        return f"key {name} already matches cluster.toml"
    new = bindconf.format_key(name, ALGORITHM, secret).rstrip("\n")
    edits = {str(path): bindconf.replace_span(text, key.stmt.start, key.stmt.end, new)}
    out = _run_bind(env, edits, f"shared-key-{name}")
    return f"{out}\nkey {name} now matches cluster.toml"
