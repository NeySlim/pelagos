# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import pytest

from pelagos.notify import catalog
from pelagos.notify.model import BatchEvent, EventKind, Reason
from pelagos.notify.render import SCHEMA, render, signature, verify_signature, webhook_payload

from .helpers import NOW, batch, failing_alert, ha_alert, probe_batch, resolved_batch

pytestmark = pytest.mark.unit

LOCALES = Path(__file__).resolve().parents[4] / "frontend" / "src" / "i18n" / "locales"


def test_events_subject_sorted_by_severity_and_counts():
    r = render(batch(), "en")
    assert r.subject == "[Pelagos] 1 critical, 1 warning: HA of kea4 terminated (+1)"
    assert r.lines[0] == "Opened: [critical] HA of kea4 terminated (ns1)"
    assert r.lines[1].startswith("Opened: [warning] notification channel <b>ntfy</b> has been failing")
    assert "Still open: 1 critical, 2 warnings." in r.lines
    assert "Open in Pelagos: https://ns1.example.lan:8443/alerts" in r.lines
    assert r.lines[-1] == "Sent by ns1 at 2026-10-28 10:00 UTC."
    assert r.level == "critical"
    assert r.click == "https://ns1.example.lan:8443/alerts"


def test_french_uses_the_ui_catalog_and_plurals():
    r = render(batch(), "fr")
    assert r.subject == "[Pelagos] 1 critique, 1 avertissement : HA of kea4 terminated (+1)"
    assert "le canal de notification <b>ntfy</b> échoue depuis 10:00" in r.lines[1]
    assert "Encore ouvertes : 1 critique, 2 avertissements." in r.lines


def test_unknown_language_falls_back_to_english():
    assert render(batch(), "de").subject.startswith("[Pelagos] 1 critical")


def test_single_event_links_to_the_alert():
    one = batch(events=[BatchEvent(EventKind.OPENED, ha_alert(), "ns1")])
    r = render(one)
    assert r.subject == "[Pelagos] 1 critical: HA of kea4 terminated"
    assert r.click == f"https://ns1.example.lan:8443/alerts?alert={one.events[0].alert.id}"


def test_resolved_only_and_no_base_url():
    r = render(resolved_batch())
    assert r.subject == "[Pelagos] resolved: HA of kea4 terminated"
    assert r.level == "resolved"
    assert r.lines[0] == "Resolved: [critical] HA of kea4 terminated (ns1)"
    assert "No alert is open." in r.lines
    r = render(batch(base_url=None))
    assert r.click is None and not any("Pelagos:" in line and "http" in line for line in r.lines)


def test_test_digest_and_held_back():
    r = render(probe_batch())
    assert r.subject == "[Pelagos] test from ns1" and r.level == "test"
    assert r.lines[0].startswith("Test message sent by ns1")
    d = render(batch(reason=Reason.DIGEST, events=[], open={"warning": 3}))
    assert d.subject == "[Pelagos] digest: 3 warnings" and d.level == "warning"
    assert (
        render(batch(reason=Reason.DIGEST, events=[], open={})).subject == "[Pelagos] digest: no open alert"
    )
    h = render(batch(events=[], held_back=7))
    assert h.subject == "[Pelagos] 7 more events held back"
    assert "7 more events were held back by the hourly limit: see the interface." in h.lines
    assert "1 more event was held back" in render(batch(held_back=1)).text


def test_engine_names_are_clipped_and_html_escaped():
    long_host = "h" * 500
    a = failing_alert()
    a.title_message = {
        "key": "alert.notification_failed",
        "params": {"channel": long_host, "since": "x", "error": "y"},
    }
    r = render(batch(events=[BatchEvent(EventKind.OPENED, a, "<script>")]))
    assert long_host not in r.text and "h" * 77 + "..." in r.text
    assert "<script>" not in r.html and "&lt;script&gt;" in r.html
    assert "<li>" in r.html and r.html.startswith("<p><strong>")
    assert "\n" not in r.subject


def test_webhook_payload_schema():
    b = batch()
    p = webhook_payload(b, "fr")
    assert p["schema"] == SCHEMA and p["id"] == b.id and p["reason"] == "events"
    assert p["sent_at"] == "2026-10-28T10:00:00Z"
    assert p["sender"] == {"node_id": "N1", "name": "ns1"}
    assert p["open"] == {"critical": 1, "warning": 2, "info": 0}
    first = p["events"][0]
    assert first["event"] == "opened"
    assert set(first["alert"]) == {
        "id", "kind", "severity", "state", "node_id", "node_name", "engine", "subject", "title",
        "title_message", "first_seen", "last_seen", "resolved_at", "url",
    }  # fmt: skip
    assert first["alert"]["kind"] == "ha_terminated" and first["alert"]["engine"] == "kea4"
    assert first["alert"]["url"].endswith("/alerts?alert=" + b.events[0].alert.id)
    assert p["events"][1]["alert"]["title"].startswith("le canal de notification")
    assert p["events"][1]["alert"]["title_message"]["key"] == "alert.notification_failed"
    assert "details" not in json.dumps(p)


def test_signature_matches_a_receiver():
    body = b'{"a":1}'
    sig = signature("s3cret", NOW, body)
    assert sig.startswith("sha256=") and len(sig) == 7 + 64
    assert verify_signature("s3cret", str(NOW), body, sig, NOW + 299)
    assert not verify_signature("s3cret", str(NOW), body, sig, NOW + 301)
    assert not verify_signature("other", str(NOW), body, sig, NOW)
    assert not verify_signature("s3cret", str(NOW), body + b" ", sig, NOW)


def test_packaged_catalogs_match_the_frontend():
    if not LOCALES.is_dir():
        pytest.skip("frontend catalogs not in this tree")
    for lang, built in catalog.build(LOCALES).items():
        packaged = (catalog.DATA / f"{lang}.json").read_text("utf-8")
        assert packaged == catalog.dump(built), f"run make notify-catalogs ({lang})"


def test_catalog_fallbacks():
    assert catalog.text("fr", "event.opened") == "Ouverte"
    assert catalog.text("fr", "no.such.key") == "no.such.key"
    msg = {"key": "alert.notification_failed", "params": {"channel": "c", "since": "s", "error": "e"}}
    assert catalog.message("en", msg) == "notification channel c has been failing since s: e"
    assert catalog.message("en", {"key": "nope", "params": {}}, "fallback") == "fallback"
