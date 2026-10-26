# SPDX-License-Identifier: Apache-2.0
"""Optional tests against public services, off unless their credentials are given:

- PELAGOS_HETZNER_TOKEN and PELAGOS_HETZNER_ZONE (a zone of that Hetzner account): a TXT record
  placed and removed through the Hetzner Cloud API, seen on Hetzner's authoritative servers;
- PELAGOS_LE_STAGING_NAME (a public name whose _acme-challenge lives in that Hetzner zone, directly
  or by CNAME delegation with PELAGOS_LE_DELEGATION_ZONE), with the Hetzner variables: a DNS-01
  certificate from Let's Encrypt staging.

A public zone is required: neither can run on the lab's private zones.
"""

from __future__ import annotations

import os
import secrets

import pytest
from cryptography.hazmat.primitives import serialization

from pelagos.core.webcert import acme, dns01, pem

pytestmark = pytest.mark.lab

TOKEN = os.environ.get("PELAGOS_HETZNER_TOKEN", "")
ZONE = os.environ.get("PELAGOS_HETZNER_ZONE", "")
LE_NAME = os.environ.get("PELAGOS_LE_STAGING_NAME", "")
needs_hetzner = pytest.mark.skipif(
    not (TOKEN and ZONE), reason="PELAGOS_HETZNER_TOKEN and PELAGOS_HETZNER_ZONE are not set"
)


@needs_hetzner
def test_hetzner_txt_round_trip():
    provider = dns01.HetznerProvider(TOKEN)
    assert ZONE.rstrip(".") in provider.test()
    name = f"_pelagos-test-{secrets.token_hex(4)}.{ZONE.rstrip('.')}."
    value = secrets.token_urlsafe(32)
    provider.add_txt(name, value)
    try:
        solver = dns01.DnsSolver(provider, timeout=300)
        solver.wait_visible(name, value)
    finally:
        provider.delete_txt(name, value)


@needs_hetzner
@pytest.mark.skipif(not LE_NAME, reason="PELAGOS_LE_STAGING_NAME is not set")
def test_letsencrypt_staging_dns01_through_hetzner():
    provider = dns01.HetznerProvider(TOKEN)
    solver = dns01.DnsSolver(
        provider, delegation_zone=os.environ.get("PELAGOS_LE_DELEGATION_ZONE") or None, timeout=300
    )
    client = acme.AcmeClient(acme.LE_STAGING, acme.new_account_key())
    key = pem.generate_key()
    csr = pem.load_csr(pem.build_csr(key, [LE_NAME]))

    chain = client.issue([LE_NAME], csr.public_bytes(serialization.Encoding.DER), "dns-01", solver)
    certs = pem.parse_material(chain).certs
    assert pem.san_names(certs[0]) == [LE_NAME] and pem.key_matches(certs[0], key)
    assert "STAGING" in certs[0].issuer.rfc4514_string().upper()
