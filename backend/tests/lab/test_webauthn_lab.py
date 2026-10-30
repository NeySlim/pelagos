# SPDX-License-Identifier: Apache-2.0
"""Security keys on a real pair (item 66): lab-w66 ns1 and lab-w67 ns2, Debian 13 from the template.

The deb of this checkout on both, ns1 initialized and ns2 enrolled with web URLs ns1.example.lan and
ns2.example.lan, so the cluster rpId is example.lan. Each node's own self-signed web certificate
(regenerated for its name) is trusted in a private NSS database, as a browser that accepted it would;
Chrome maps the names to the lab addresses. With a virtual authenticator, a key registered on ns1
signs in on ns2, as second factor and as a passkey (frontend/e2e-lab/webauthn.spec.js). The key is
in ns2's replicated cluster.toml, and the role requirement then restricts a user without a key.
"""

from __future__ import annotations

import os
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

from tests.lab.labkit import (
    ADMIN_PASSWORD,
    REPO,
    Api,
    ApiError,
    deb_package,
    lab_password,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab
DORA_PASSWORD = lab_password("dora")

VM1, VM2 = os.environ.get("WEBAUTHN_NS1", "lab-w66"), os.environ.get("WEBAUTHN_NS2", "lab-w67")
A1, A2 = os.environ.get("WEBAUTHN_NS1_IP", "10.99.0.66"), os.environ.get("WEBAUTHN_NS2_IP", "10.99.0.67")
N1, N2 = "ns1.example.lan", "ns2.example.lan"
STATE: dict[str, Any] = {}


def api(address: str = A1) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


class TestWebAuthnPair:
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

    def test_02_rp_id_is_the_common_domain(self):
        status = api(A1).get("/admin/webauthn")
        assert status["rp_id"] == "example.lan" and status["source"] == "common_domain", status
        assert status["warning"] is None and {n["host"] for n in status["nodes"]} == {N1, N2}
        # Opened by its address, a node cannot use keys and says why.
        assert api(A2).get("/auth/webauthn")["reason"] == "ip_address"

    def test_03_web_certificates_for_the_names(self):
        STATE["home"] = home = Path(tempfile.mkdtemp(prefix="webauthn-lab-"))
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

    def test_04_key_registered_on_ns1_signs_in_on_ns2(self):
        frontend = REPO / "frontend"
        if not (frontend / "node_modules" / ".bin" / "playwright").exists():
            pytest.skip("no frontend/node_modules")
        env = {
            **os.environ,
            "HOME": str(STATE["home"]),
            "PLAYWRIGHT_BROWSERS_PATH": os.environ.get(
                "PLAYWRIGHT_BROWSERS_PATH", str(Path.home() / ".cache" / "ms-playwright")
            ),
            "TEST_URL": f"https://{N1}:8443",
            "NS1_URL": f"https://{N1}:8443",
            "NS2_URL": f"https://{N2}:8443",
            "HOST_RULES": f"MAP {N1} {A1}, MAP {N2} {A2}",
            "LAB_PASSWORD": ADMIN_PASSWORD,
        }
        res = subprocess.run(
            ["npx", "playwright", "test", "--config", "e2e-lab/lab.config.js", "webauthn.spec.js"],
            cwd=frontend,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        assert res.returncode == 0, res.stdout[-4000:] + res.stderr[-2000:]
        assert "1 passed" in res.stdout, res.stdout[-2000:]

    def test_05_key_replicated_and_used_on_ns2(self):
        admin_id = next(u["id"] for u in api(A2).get("/admin/users")["items"] if u["username"] == "admin")
        keys = api(A2).get(f"/admin/users/{admin_id}/webauthn")["items"]
        assert len(keys) == 1 and keys[0]["rp_id"] == "example.lan", keys
        ns1 = next(n["peer"]["id"] for n in api(A2).get("/nodes")["items"] if n["peer"]["name"] == "ns1")
        assert keys[0]["created_on"] == ns1 and keys[0]["last_used_at"], keys
        assert "[users.webauthn." in sudo_cat(VM2, "/var/lib/pelagos/cluster.toml")
        # Counters and last use stay on the node that saw them.
        assert "sign_count" in sudo_cat(VM2, "/var/lib/pelagos/webauthn_usage.json")
        # Without the key, the password alone opens a session only when no role requires a key.
        with pytest.raises(ApiError) as exc:
            Api(A2).login()
        assert exc.value.status == 401 and exc.value.body["code"] == "second_factor_required"
        assert exc.value.body["methods"] == [] and exc.value.body["rp_ids"] == ["example.lan"]

    def test_06_role_requirement_and_admin_removal(self):
        api(A1).call("PUT", "/admin/settings", {"auth": {"require_webauthn_roles": ["dns-operator"]}})
        api(A1).post(
            "/admin/users",
            {
                "username": "dora",
                "password": DORA_PASSWORD,
                "roles": ["dns-operator"],
                "must_change_password": False,
            },
        )

        def restricted() -> bool:
            out = Api(A2).login("dora", DORA_PASSWORD)
            return out["restriction"] == "webauthn_enrollment"

        wait_for("dora restricted on ns2", restricted, timeout=120)
        admin_id = next(u["id"] for u in api(A1).get("/admin/users")["items"] if u["username"] == "admin")
        api(A1).call("DELETE", f"/admin/users/{admin_id}/webauthn")
        wait_for("password login on ns2 again", lambda: Api(A2).login() is not None, timeout=120)
