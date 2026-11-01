# SPDX-License-Identifier: Apache-2.0
"""Session resumption through the API: two apps over two nodes sharing one cluster secret (section 16,
"Sessions across nodes"). Contract skeleton: each test names one acceptance rule."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

TODO = "B1-SESSIONS: contract skeleton, implemented after the contract review"


@pytest.mark.skip(reason=TODO)
def test_cookie_from_node_one_opens_get_session_on_node_two():
    """GET /auth/session on the second app answers the user, the same csrf_token and restriction."""


@pytest.mark.skip(reason=TODO)
def test_unsafe_request_on_node_two_passes_with_the_csrf_of_node_one():
    """A POST with the login's X-CSRF-Token passes; without it, or with another session's, 403 csrf_failed."""


@pytest.mark.skip(reason=TODO)
def test_resume_is_audited_once_without_secrets():
    """One auth.resume with the handle and from_node; no sid, cookie, CSRF token or secret anywhere."""


@pytest.mark.skip(reason=TODO)
def test_logout_entry_carries_the_handle_only():
    """auth.logout request is {"session": handle}; the cookie is deleted."""


@pytest.mark.skip(reason=TODO)
def test_logout_merged_on_node_two_refuses_the_cookie():
    """After the auth.logout entry is merged into node two's log, the cookie answers 401."""


@pytest.mark.skip(reason=TODO)
def test_password_change_resigns_the_caller_and_refuses_older_cookies():
    """The caller keeps working on both apps; another cookie of the user issued earlier is refused."""


@pytest.mark.skip(reason=TODO)
def test_restriction_lift_resigns_the_cookie():
    """After TOTP confirm or the password change, the new cookie resumes without the restriction."""


@pytest.mark.skip(reason=TODO)
def test_forged_cookie_is_401_and_not_audited():
    """A forged mac, an unknown cluster secret or an expired cookie: 401 unauthenticated, no entry."""


@pytest.mark.skip(reason=TODO)
def test_legacy_cookie_is_401():
    """A 0.3.x bare id cookie is no session: 401 on /auth/session, login works and sets a v1 cookie."""


@pytest.mark.skip(reason=TODO)
def test_bearer_token_still_wins_over_a_cookie():
    """Authorization: Bearer with any cookie is the token's session, no CSRF needed."""


@pytest.mark.skip(reason=TODO)
def test_websocket_handshake_resumes_a_session():
    """The /ws handshake on node two with node one's cookie opens the socket."""


@pytest.mark.skip(reason=TODO)
def test_suite_audit_and_logs_hold_no_session_secret():
    """Grep of the audit log and captured logs of these tests for every sid, cookie, CSRF and secret."""
