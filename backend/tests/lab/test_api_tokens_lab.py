# SPDX-License-Identifier: Apache-2.0
"""API tokens on a real pair (item 70): lab-w66 ns1 and lab-w67 ns2, Debian 13, the deb of this checkout.

ns1 initialized and ns2 enrolled with web URLs ns1.example.lan and ns2.example.lan (rpId example.lan),
each node's web certificate trusted in a private NSS database as in test_webauthn_lab. The admin
registers a key and keys become mandatory for admins, so a password login answers 401
second_factor_required; a token created on ns1 behind a fresh assertion answers Bearer calls on ns1
and ns2, and stops on both once revoked (frontend/e2e-lab/api-tokens.spec.js). Then the files:
the hash replicated, the secret nowhere, every call audited with the token's name on both nodes.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

from tests.lab.labkit import ADMIN_PASSWORD, REPO, Api, deb_package, scp, ssh, sudo_cat, wait_for

pytestmark = pytest.mark.lab

VM1, VM2 = os.environ.get("TOKENS_NS1", "lab-w66"), os.environ.get("TOKENS_NS2", "lab-w67")
A1, A2 = os.environ.get("TOKENS_NS1_IP", "10.99.0.66"), os.environ.get("TOKENS_NS2_IP", "10.99.0.67")
N1, N2 = "ns1.example.lan", "ns2.example.lan"
STATE: dict[str, Any] = {}


def api(address: str = A1) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


class TestApiTokensPair:
    def test_01_install_init_enroll(self):
        deb = deb_package()
        for vm in (VM1, VM2):
            ssh(
                vm,
                "sudo systemctl stop pelagos pelagos-collector 2>/dev/null; sudo apt-get purge -y -q pelagos",
                check=False,
            )
            ssh(vm, "sudo rm -rf /etc/pelagos /var/lib/pelagos", check=False)
            scp(vm, deb, "/tmp/pelagos.deb")
            ssh(vm, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb", timeout=900)
        ssh(
            VM1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{N1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        token = api(A1).post("/nodes/enroll-token", {})
        ssh(
            VM2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
            f"--replication-url https://{A2}:8444 --web-url https://{N2}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )

        def both_online() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

        wait_for("both nodes online", both_online, timeout=180)

    def test_02_web_certificates_for_the_names(self):
        STATE["home"] = home = Path(tempfile.mkdtemp(prefix="tokens-lab-"))
        nss = home / ".pki" / "nssdb"
        nss.mkdir(parents=True)
        subprocess.run(["certutil", "-N", "-d", f"sql:{nss}", "--empty-password"], check=True)
        nodes = {n["peer"]["name"]: n["peer"]["id"] for n in api(A1).get("/nodes")["items"]}
        for name, address, host in (("ns1", A1, N1), ("ns2", A2, N2)):
            api(address).post(f"/admin/certificates/{nodes[name]}/self-signed", {})

            def served(addr: str = address, h: str = host) -> str | None:
                pem = ssl.get_server_certificate((addr, 8443), timeout=10)
                cert = x509.load_pem_x509_certificate(pem.encode())
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                return pem if h in san.get_values_for_type(x509.DNSName) else None

            pem = wait_for(f"{host} certificate served", served, timeout=60)
            path = home / f"{name}.pem"
            path.write_text(pem)
            subprocess.run(
                ["certutil", "-A", "-d", f"sql:{nss}", "-n", host, "-t", "CP,,", "-i", str(path)], check=True
            )

    def test_03_token_from_ns1_works_on_ns2_until_revoked(self):
        frontend = REPO / "frontend"
        if not (frontend / "node_modules" / ".bin" / "playwright").exists():
            pytest.skip("no frontend/node_modules")
        STATE["token_file"] = out = STATE["home"] / "token.txt"
        env = {
            **os.environ,
            "HOME": str(STATE["home"]),
            "PLAYWRIGHT_BROWSERS_PATH": os.environ.get(
                "PLAYWRIGHT_BROWSERS_PATH", str(Path.home() / ".cache" / "ms-playwright")
            ),
            "TEST_URL": f"https://{N1}:8443",
            "NS1_URL": f"https://{N1}:8443",
            "NS2_URL": f"https://{N2}:8443",
            "NS1_API": f"https://{A1}:8443",
            "NS2_API": f"https://{A2}:8443",
            "HOST_RULES": f"MAP {N1} {A1}, MAP {N2} {A2}",
            "LAB_PASSWORD": ADMIN_PASSWORD,
            "TOKEN_OUT": str(out),
            "TOKEN_CIDR": str(ipaddress.ip_network(f"{A1}/24", strict=False)),
        }
        res = subprocess.run(
            ["npx", "playwright", "test", "--config", "e2e-lab/lab.config.js", "api-tokens.spec.js"],
            cwd=frontend,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        assert res.returncode == 0, res.stdout[-4000:] + res.stderr[-2000:]
        assert "1 passed" in res.stdout, res.stdout[-2000:]

    def test_04_hash_replicated_secret_nowhere_calls_audited_everywhere(self):
        secret = STATE["token_file"].read_text().strip()
        token_id = secret.split("_")[1]
        for vm in (VM1, VM2):
            cluster = sudo_cat(vm, "/var/lib/pelagos/cluster.toml")
            # Revoked: the record is gone and its tombstone replicated.
            assert f'"api_tokens/{token_id}"' in cluster and "[[api_tokens]]" not in cluster, vm
            audit = sudo_cat(vm, "/var/lib/pelagos/audit/audit.jsonl")
            assert secret not in audit and secret.split("_", 2)[2] not in audit, vm
            assert '"action":"auth.token_call"' in audit and '"token":"lab-script"' in audit, vm
            usage = sudo_cat(vm, "/var/lib/pelagos/api_token_usage.json")
            assert secret not in usage, vm
            logs = ssh(vm, "sudo journalctl -u pelagos --no-pager -n 2000", check=False)
            assert secret.split("_", 2)[2] not in str(logs), vm
        # Each node recorded the calls it served, under its own id, and the revocation was audited.
        audit1 = sudo_cat(VM1, "/var/lib/pelagos/audit/audit.jsonl")
        assert '"op":"create"' in audit1 and '"op":"revoke"' in audit1 and "verified by webauthn" in audit1
