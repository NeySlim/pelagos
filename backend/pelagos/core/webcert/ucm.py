# SPDX-License-Identifier: Apache-2.0
"""UCM (Ultimate CA Manager) REST API v2 client: the key and CSR are made on this node, UCM only
signs. Routes and fields as served by UCM (backend/api/v2/csrs.py, certificates/export.py,
certificates/cert_lifecycle.py, cas/crud.py, templates.py):

  POST /api/v2/csrs/upload {"pem", "name"}                      -> {"data": {"id", ...}}
  POST /api/v2/csrs/<id>/sign {"ca_id", "validity_days", "cert_type", "template_id"?}
                                                                -> {"data": certificate} or approval
  GET  /api/v2/certificates/<id>/export?format=pem&include_chain=true   -> PEM, leaf then chain
  POST /api/v2/certificates/<id>/revoke {"reason"}
  GET  /api/v2/cas, GET /api/v2/templates                       -> {"data": [...]}

Authentication: the API key in X-API-Key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from pelagos.core.webcert import http

DEFAULT_VALIDITY_DAYS = 365
DEFAULT_RENEW_DAYS = 30


class UcmError(Exception):
    """UCM refused or could not be reached; the message is safe to show."""


@dataclass(slots=True)
class Issued:
    cert_id: int | str
    fullchain_pem: str


class UcmClient:
    def __init__(self, url: str, api_key: str, ca_pem: str | None = None, timeout: float = 30.0) -> None:
        if not url.lower().startswith("https://"):
            raise UcmError("the UCM URL must start with https://")
        if not api_key:
            raise UcmError("the UCM API key is missing")
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.ca_pem = ca_pem
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None) -> http.Response:
        try:
            return http.request(
                method,
                self.url + path,
                body=body,
                headers={"X-API-Key": self.api_key},
                ca_pem=self.ca_pem,
                timeout=self.timeout,
            )
        except http.HttpError as exc:
            raise UcmError(f"UCM: {exc}") from exc

    def _data(self, resp: http.Response, what: str) -> Any:
        if resp.status in (401, 403):
            raise UcmError(f"{what}: UCM refused the API key ({resp.excerpt()})")
        if not resp.ok:
            raise UcmError(f"{what}: {resp.excerpt()}")
        body = resp.json()
        if not isinstance(body, dict) or "data" not in body:
            raise UcmError(f"{what}: unexpected answer from UCM")
        return body["data"]

    def cas(self) -> list[dict[str, Any]]:
        items = self._data(self._call("GET", "/api/v2/cas"), "list CAs") or []
        return [
            {
                "id": c.get("id"),
                "name": c.get("descr") or c.get("name") or c.get("common_name"),
                "status": c.get("status"),
                "can_sign": bool(c.get("has_private_key", True)) and not c.get("offline"),
            }
            for c in items
            if isinstance(c, dict)
        ]

    def templates(self) -> list[dict[str, Any]]:
        items = self._data(self._call("GET", "/api/v2/templates"), "list templates") or []
        return [
            {"id": t.get("id"), "name": t.get("name"), "type": t.get("template_type")}
            for t in items
            if isinstance(t, dict) and t.get("is_active", True)
        ]

    def test(self) -> dict[str, Any]:
        cas = self.cas()
        return {"cas": len(cas), "templates": len(self.templates())}

    def issue(
        self,
        csr_pem: str,
        name: str,
        ca_id: Any,
        validity_days: int = DEFAULT_VALIDITY_DAYS,
        template_id: Any = None,
    ) -> Issued:
        uploaded = self._data(
            self._call("POST", "/api/v2/csrs/upload", {"pem": csr_pem, "name": name}), "upload CSR"
        )
        csr_id = uploaded.get("id") if isinstance(uploaded, dict) else None
        if csr_id is None:
            raise UcmError("upload CSR: UCM gave no id")
        body: dict[str, Any] = {"ca_id": ca_id, "validity_days": int(validity_days), "cert_type": "server"}
        if template_id not in (None, ""):
            body["template_id"] = template_id
        signed = self._data(self._call("POST", f"/api/v2/csrs/{quote(str(csr_id))}/sign", body), "sign CSR")
        if isinstance(signed, dict) and signed.get("approval_required"):
            raise UcmError(
                "UCM queued the request for approval "
                f"({signed.get('message') or signed.get('policy_name')}): "
                "approve it in UCM, then renew again"
            )
        cert_id = signed.get("id", csr_id) if isinstance(signed, dict) else csr_id
        return Issued(cert_id=cert_id, fullchain_pem=self.export(cert_id))

    def export(self, cert_id: Any) -> str:
        resp = self._call(
            "GET", f"/api/v2/certificates/{quote(str(cert_id))}/export?format=pem&include_chain=true"
        )
        if not resp.ok or b"BEGIN CERTIFICATE" not in resp.body:
            raise UcmError(f"export certificate {cert_id}: {resp.excerpt()}")
        return resp.text

    def revoke(self, cert_id: Any, reason: str = "superseded") -> None:
        done = self._data(
            self._call("POST", f"/api/v2/certificates/{quote(str(cert_id))}/revoke", {"reason": reason}),
            f"revoke certificate {cert_id}",
        )
        # A revocation policy may queue it (cert_lifecycle.py, approval_gate.approval_payload).
        if isinstance(done, dict) and done.get("approval_required"):
            raise UcmError(
                f"UCM queued the revocation of certificate {cert_id} for approval "
                f"({done.get('message') or done.get('policy_name')}): approve it in UCM"
            )
