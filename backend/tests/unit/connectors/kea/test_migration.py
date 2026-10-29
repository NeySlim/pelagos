# SPDX-License-Identifier: Apache-2.0
"""Kea 2.6 to 3.x conversion rules (architecture section 26) on an anonymized production layout."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pelagos.connectors.kea import migration as mig
from pelagos.domain.messages import CATALOG, render

pytestmark = pytest.mark.unit

DATA = Path(__file__).parent / "data"
HOOKS = "/usr/lib/x86_64-linux-gnu/kea/hooks"
TARGET = mig.TargetLayout(
    series="3.2",
    source="isc",
    hooks_dir=HOOKS,
    hooks=frozenset(
        {"libdhcp_lease_cmds.so", "libdhcp_stat_cmds.so", "libdhcp_ha.so", "libdhcp_run_script.so"}
    ),
    db_packages={"mysql": "isc-kea-mysql", "postgresql": "isc-kea-pgsql"},
)


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text())


def codes(conv: mig.Conversion) -> dict[str, list[mig.Finding]]:
    out: dict[str, list[mig.Finding]] = {}
    for f in conv.findings:
        out.setdefault(f.code, []).append(f)
    return out


def test_dhcp4_production_layout():
    conv = mig.convert("kea4", load("kea26-migration-dhcp4.json"), TARGET, node_id="n1")
    root = conv.after["Dhcp4"]
    by = codes(conv)
    # Renames, keeping both the key order and the value.
    assert root["subnet4"][0]["evaluate-additional-classes"] == ["late"]
    assert "require-client-classes" not in root["subnet4"][0]
    assert root["client-classes"][1] == {"name": "late", "only-in-additional-list": True}
    assert {f.params["old"] for f in by["renamed_key"]} == {"require-client-classes", "only-if-required"}
    # client-class becomes a list at the subnet and the pool.
    assert root["subnet4"][0]["client-classes"] == ["voip"]
    assert root["subnet4"][0]["pools"][0]["client-classes"] == ["voip"]
    assert [f.path for f in by["client_class"]] == [
        "Dhcp4/subnet4[0]/client-class",
        "Dhcp4/subnet4[0]/pools[0]/client-class",
    ]
    # Control socket: list form with a bare name (ISC and Debian compile different directories).
    assert root["control-sockets"] == [{"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}]
    assert "control-socket" not in root
    moved = {f.path: f.params for f in by["path_moved"]}
    assert moved["Dhcp4/control-sockets[0]/socket-name"]["target"] == "kea4-ctrl-socket"
    assert root["lease-database"]["name"] == "/var/lib/kea/kea-leases4.csv"
    assert root["loggers"][0]["output-options"] == [
        {"output": "stdout"},
        {"output": "/var/log/kea/kea-dhcp4.log"},
    ]
    # HA: restrict-commands written, TLS kept as it is.
    rel = root["hooks-libraries"][2]["parameters"]["high-availability"][0]
    assert rel["restrict-commands"] is True
    assert rel["key-file"] == "/etc/kea/tls/node.key" and rel["require-client-certs"] is True
    assert by["restrict_commands"][0].path.endswith("high-availability[0]/restrict-commands")
    # Behavior changes to read.
    assert [f.params["name"] for f in by["additional_class"]] == ["late"]
    assert [f.params["name"] for f in by["template_class_options"]] == ["per-mac"]
    assert by["lease_cache"][0].severity == "behavior"
    assert by["lease_checks"][0].severity == "info"
    assert not mig.blocking(conv.findings)
    assert all(f.node_id == "n1" for f in conv.findings)
    # The input is never modified.
    assert load("kea26-migration-dhcp4.json") == conv.before


def test_conversion_is_idempotent():
    for engine, name in (("kea4", "kea26-migration-dhcp4.json"), ("d2", "kea26-migration-d2.json")):
        first = mig.convert(engine, load(name), TARGET)
        again = mig.convert(engine, first.after, TARGET)
        assert again.after == first.after
        assert {f.severity for f in again.findings} <= {"behavior", "info"}


def test_d2_secret_file_and_masked_diff():
    conv = mig.convert("d2", load("kea26-migration-d2.json"), TARGET)
    key = conv.after["DhcpDdns"]["tsig-keys"][0]
    assert key == {"name": "kea-ddns", "algorithm": "HMAC-MD5", "secret-file": "/etc/kea/kea-ddns.tsig"}
    assert conv.files == {"/etc/kea/kea-ddns.tsig": "c2VjcmV0LWZvci10ZXN0cw=="}
    by = codes(conv)
    assert by["d2_secret_file"][0].params == {"key": "kea-ddns"}
    assert "control_socket" in by
    diff = conv.diff("/etc/kea/kea-dhcp-ddns.conf")
    assert "c2VjcmV0" not in diff and mig.MASK in diff and "+++ b/etc/kea/kea-dhcp-ddns.conf" in diff
    assert "c2VjcmV0" not in json.dumps([f.to_dict() for f in conv.findings])


def test_blocking_rules():
    cfg = load("kea26-migration-dhcp4.json")
    root = cfg["Dhcp4"]
    root["subnet4"][0]["client-classes"] = ["other"]
    root["subnet4"].append({"subnet": "198.51.100.0/24"})
    root["hooks-libraries"] += [
        {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_mysql_cb.so"},
        {"library": "libdhcp_radius.so"},
        {"library": f"{HOOKS}/libdhcp_run_script.so", "parameters": {"name": "/usr/local/bin/ddns.sh"}},
    ]
    conv = mig.convert("kea4", cfg, TARGET)
    by = codes(conv)
    assert by["client_class_both"][0].path == "Dhcp4/subnet4[0]/client-class"
    assert "client-class" in conv.after["Dhcp4"]["subnet4"][0]  # left for the administrator
    assert by["subnet_without_id"][0].params == {"subnet": "198.51.100.0/24"}
    assert by["hook_commercial"][0].params == {"library": "libdhcp_mysql_cb.so", "series": "3.2"}
    assert by["hook_missing"][0].params == {"library": "libdhcp_radius.so", "series": "3.2", "source": "isc"}
    assert by["script_path"][0].params == {
        "file": "/usr/local/bin/ddns.sh",
        "directory": "/usr/share/kea/scripts",
    }
    assert all(
        f.severity == "blocking"
        for c in ("client_class_both", "subnet_without_id", "hook_commercial", "hook_missing", "script_path")
        for f in by[c]
    )
    assert mig.blocking(conv.findings)
    assert mig.counts(conv.findings)["blocking"] == 5


def test_unknown_target_hooks_never_block():
    cfg = load("kea26-migration-dhcp4.json")
    cfg["Dhcp4"]["hooks-libraries"].append({"library": "libdhcp_radius.so"})
    conv = mig.convert("kea4", cfg, mig.TargetLayout("3.2", "isc", HOOKS))
    assert "hook_missing" not in codes(conv)


def test_hooks_move_to_the_target_directory():
    cfg = load("kea26-migration-dhcp4.json")
    for hook in cfg["Dhcp4"]["hooks-libraries"]:
        hook["library"] = hook["library"].replace("/usr/lib/x86_64-linux-gnu", "/usr/local/lib")
    conv = mig.convert("kea4", cfg, TARGET)
    libs = [h["library"] for h in conv.after["Dhcp4"]["hooks-libraries"]]
    assert libs == [
        f"{HOOKS}/libdhcp_lease_cmds.so",
        f"{HOOKS}/libdhcp_stat_cmds.so",
        f"{HOOKS}/libdhcp_ha.so",
    ]
    assert sum(f.path.endswith("/library") for f in conv.findings if f.code == "path_moved") == 3


def test_sql_databases_add_their_hook():
    cfg = load("kea26-migration-dhcp4.json")
    cfg["Dhcp4"]["lease-database"] = {"type": "mysql", "name": "kea", "host": "localhost"}
    cfg["Dhcp4"]["hosts-databases"] = [{"type": "postgresql", "name": "kea"}, {"type": "mysql", "name": "k2"}]
    conv = mig.convert("kea4", cfg, TARGET)
    libs = [h["library"] for h in conv.after["Dhcp4"]["hooks-libraries"]]
    assert libs[:2] == [f"{HOOKS}/libdhcp_pgsql.so", f"{HOOKS}/libdhcp_mysql.so"]
    assert conv.packages == ["isc-kea-mysql", "isc-kea-pgsql"]
    hooks = [f for f in conv.findings if f.code == "db_hook"]
    assert [(f.params["backend"], f.path) for f in hooks] == [
        ("mysql", "Dhcp4/lease-database"),
        ("postgresql", "Dhcp4/hosts-databases[0]"),
    ]
    assert "hook_missing" not in codes(conv)
    assert mig.convert("kea4", conv.after, TARGET).packages == []


def test_dhcp6_paths_and_pd_pools():
    cfg = {
        "Dhcp6": {
            "control-sockets": [{"socket-type": "unix", "socket-name": "kea6-ctrl-socket"}],
            "data-directory": "/srv/kea",
            "server-id": {"type": "LLT", "file": "/srv/kea/kea-dhcp6-serverid"},
            "cache-threshold": 0.0,
            "sanity-checks": {"lease-checks": "fix-del"},
            "subnet6": [
                {
                    "id": 1,
                    "subnet": "2001:db8::/64",
                    "pd-pools": [
                        {
                            "prefix": "2001:db8:1::",
                            "prefix-len": 48,
                            "delegated-len": 56,
                            "client-class": "cpe",
                        }
                    ],
                }
            ],
        }
    }
    conv = mig.convert("kea6", cfg, TARGET)
    root = conv.after["Dhcp6"]
    assert root["data-directory"] == "/var/lib/kea"
    assert root["server-id"]["file"] == "/var/lib/kea/kea-dhcp6-serverid"
    assert root["subnet6"][0]["pd-pools"][0]["client-classes"] == ["cpe"]
    by = codes(conv)
    assert "lease_cache" not in by and "lease_checks" not in by and "control_socket" not in by


def test_legal_log_path():
    cfg = load("kea26-migration-dhcp4.json")
    cfg["Dhcp4"]["hooks-libraries"].append(
        {"library": "libdhcp_legal_log.so", "parameters": {"path": "/srv/log"}}
    )
    target = mig.TargetLayout("3.2", "isc", HOOKS, None)
    conv = mig.convert("kea4", cfg, target)
    assert conv.after["Dhcp4"]["hooks-libraries"][-1]["parameters"]["path"] == "/var/log/kea"


def test_missing_root_refused():
    with pytest.raises(ValueError):
        mig.convert("kea4", {"Dhcp6": {}}, TARGET)


def test_ctrl_agent():
    assert mig.ctrl_agent(False, False, []) == []
    (stop,) = mig.ctrl_agent(True, False, [])
    assert (stop.code, stop.severity, stop.action, stop.engine) == (
        "ctrl_agent_stop",
        "converted",
        "stop_service",
        "ca",
    )
    (prop,) = mig.ctrl_agent(True, True, ["192.0.2.50", "isc-stork-agent"], "n1")
    assert prop.severity == "behavior" and prop.action == "propose" and prop.node_id == "n1"
    assert "192.0.2.50" in render(prop.message)


def test_ha_symmetry():
    a = load("kea26-migration-dhcp4.json")
    b = copy.deepcopy(a)
    rel_b = b["Dhcp4"]["hooks-libraries"][2]["parameters"]["high-availability"][0]
    rel_b["this-server-name"] = "ns2"
    assert mig.ha_symmetry("kea4", "n1", a, "n2", b) == []
    rel_b["max-response-delay"] = 60000
    rel_b["peers"][1]["url"] = "http://192.0.2.12:8001/"
    del rel_b["trust-anchor"]
    (f,) = mig.ha_symmetry("kea4", "n1", a, "n2", b)
    assert f.code == "ha_asymmetric" and f.severity == "blocking"
    assert f.params["fields"] == ["max-response-delay", "peers", "trust-anchor"]
    assert "n1" in render(f.message) and "n2" in render(f.message)
    rel_b["this-server-name"] = "ns1"
    rel_b["peers"][1]["name"] = "ns3"
    (f,) = mig.ha_symmetry("kea4", "n1", a, "n2", b)
    assert f.params["fields"] == ["peers"]


def test_every_finding_renders_with_its_catalog_key():
    cfg = load("kea26-migration-dhcp4.json")
    cfg["Dhcp4"]["hooks-libraries"].append({"library": "libdhcp_radius.so"})
    findings = (
        mig.convert("kea4", cfg, TARGET).findings
        + mig.convert("d2", load("kea26-migration-d2.json"), TARGET).findings
    )
    for f in findings:
        d = f.to_dict()
        assert d["message"]["key"] in CATALOG
        assert "{" not in render(d["message"])
        assert d["severity"] in mig.SEVERITIES and d["reference"].startswith("https://")
