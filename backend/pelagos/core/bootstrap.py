# SPDX-License-Identifier: Apache-2.0
"""First-node bootstrap: node.toml, master key, CA, node certificate, cluster.toml with one admin."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

from pelagos.auth.passwords import hash_password
from pelagos.core import ca as ca_mod
from pelagos.core.config_store import ClusterConfig, ConfigStore, NodeConfig
from pelagos.core.listen import url_with_port
from pelagos.core.paths import Paths
from pelagos.core.secrets import SecretBox, write_master_key
from pelagos.domain.cluster import Peer, User
from pelagos.domain.common import new_id, utcnow


@dataclass(slots=True)
class BootstrapResult:
    node: NodeConfig
    cluster: ClusterConfig
    admin_username: str


def bootstrap_first_node(
    paths: Paths,
    *,
    name: str | None = None,
    admin_username: str = "admin",
    admin_password: str,
    web_url: str | None = None,
    replication_url: str | None = None,
    web_listen: str | None = None,
    replication_listen: str | None = None,
    engines: dict[str, object] | None = None,
) -> BootstrapResult:
    """Idempotent on an empty tree; refuses to overwrite an existing cluster.toml."""
    paths.ensure()
    store = ConfigStore(paths.node_toml, paths.cluster_toml, paths.locks_dir / "cluster.lock")
    if store.cluster_exists():
        raise FileExistsError(f"{paths.cluster_toml} exists; this node is already initialized")

    host = name or socket.gethostname().split(".")[0]
    node_id = new_id()
    node = NodeConfig(
        id=node_id,
        name=host,
        web_listen=web_listen or "0.0.0.0:8443",
        replication_listen=replication_listen or "0.0.0.0:8444",
        replication_url=replication_url or url_with_port(host, replication_listen or "0.0.0.0:8444"),
        web_url=web_url or url_with_port(host, web_listen or "0.0.0.0:8443"),
        engines=dict(engines or {"bind": False, "kea4": False, "kea6": False, "d2": False}),
    )
    store.save_node(node)

    if not paths.master_key.exists():
        write_master_key(paths.master_key)
    box = SecretBox.from_file(paths.master_key)

    cluster = ClusterConfig.new(created_by=f"node:{node_id}")
    root = ca_mod.create_root(cluster.cluster_id)
    ca_mod.write_pair(root, paths.pki_dir / "ca.key", paths.pki_dir / "ca.crt")
    key_pem, csr_pem = ca_mod.node_csr(node_id, host, [host])
    cert_pem = ca_mod.sign_node(root, csr_pem)
    (paths.pki_dir / "node.key").write_bytes(key_pem)
    (paths.pki_dir / "node.key").chmod(0o600)
    (paths.pki_dir / "node.crt").write_bytes(cert_pem)

    cluster.nodes.append(
        Peer(
            id=node_id,
            name=host,
            url=node.replication_url,
            web_url=node.web_url,
            cert_fingerprint=ca_mod.fingerprint(cert_pem),
            modules=node.modules,
            enrolled_at=utcnow(),
            enrolled_by=f"node:{node_id}",
        )
    )
    cluster.users.append(
        User(
            id=new_id(),
            username=admin_username,
            password_hash=hash_password(admin_password),
            roles=["admin"],
            must_change_password=False,
        )
    )
    # Encrypt a probe secret so a wrong master key is detected at the first start.
    cluster.secrets["pelagos/probe"] = box.encrypt("pelagos/probe", cluster.cluster_id)
    store.init_cluster(cluster)
    return BootstrapResult(node=node, cluster=cluster, admin_username=admin_username)


def dev_paths(root: Path) -> Paths:
    return Paths(etc=root / "etc", var=root / "var", run=root / "run", opt=root / "opt")
