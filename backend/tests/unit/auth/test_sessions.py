# SPDX-License-Identifier: Apache-2.0
"""Signed session cookies, CSRF derivation, resumption rules and audit-driven revocations (section 16,
"Sessions across nodes"). Contract skeleton: each test names one rule of the contract."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

TODO = "B1-SESSIONS: contract skeleton, implemented after the contract review"


# Cookie format --------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_cookie_round_trip_keeps_every_claim():
    """sign_cookie then verify_cookie gives back sid, node, user, issued, seen and restriction."""


@pytest.mark.skip(reason=TODO)
def test_cookie_with_any_field_changed_is_refused():
    """Flipping one character of each of the seven fields, or of the mac, fails verification."""


@pytest.mark.skip(reason=TODO)
def test_cookie_signed_with_another_secret_is_refused():
    """A cookie of another cluster (other `auth/session_signing`) never verifies."""


@pytest.mark.skip(reason=TODO)
def test_malformed_and_legacy_cookies_parse_to_none():
    """A bare 0.3.x id, a wrong version, a missing field or a character outside base64url is no claim."""


@pytest.mark.skip(reason=TODO)
def test_cookie_and_csrf_keys_are_derived_with_distinct_labels():
    """K_cookie differs from K_csrf, so a CSRF token can never serve as a cookie mac and back."""


# CSRF -----------------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_csrf_token_is_the_same_for_one_sid_on_every_node():
    """Two stores holding the same secret derive the same token for a sid, different for another sid."""


@pytest.mark.skip(reason=TODO)
def test_csrf_check_is_constant_time_and_refuses_empty():
    """csrf_ok goes through hmac.compare_digest and refuses a missing or empty header."""


# Local sessions -------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_login_always_creates_a_fresh_sid():
    """create() never reuses a presented sid (session fixation)."""


@pytest.mark.skip(reason=TODO)
def test_local_session_survives_a_secret_replaced_by_a_merge():
    """A session created under key A keeps working after the cluster key becomes B."""


@pytest.mark.skip(reason=TODO)
def test_local_session_with_a_cookie_of_another_user_is_refused():
    """A known sid with a valid mac but another user id is no session."""


# Resumption -----------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_resume_resolves_permissions_from_the_current_roles():
    """Permissions come from cluster.toml at resumption, never from the cookie."""


@pytest.mark.skip(reason=TODO)
def test_resume_refuses_a_disabled_or_deleted_user():
    """A cookie of a user disabled or deleted since is no session."""


@pytest.mark.skip(reason=TODO)
def test_resume_refuses_past_ttl_or_idle_and_future_timestamps():
    """issued older than the TTL, seen older than the idle timeout, or either over 120 s ahead."""


@pytest.mark.skip(reason=TODO)
def test_resume_keeps_a_pending_restriction_and_drops_a_satisfied_one():
    """password_change while the user must still change it; enrollment while after_enrollment says so."""


@pytest.mark.skip(reason=TODO)
def test_resume_does_not_write_last_login_or_cluster_toml():
    """The cluster.toml version and var/last_login are unchanged by a resumption."""


@pytest.mark.skip(reason=TODO)
def test_resume_disabled_by_setting_accepts_only_local_sessions():
    """auth.session_resume_enabled false: a valid cookie unknown to this process is no session."""


@pytest.mark.skip(reason=TODO)
def test_seen_is_refreshed_at_most_once_a_minute():
    """cookie(session) re-signs with seen = now; a request within 60 s of seen sets no cookie."""


# Revocations ----------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_logout_entry_revokes_the_session_and_refuses_its_cookie():
    """An auth.logout entry with the handle ends the local session and refuses resumption."""


@pytest.mark.skip(reason=TODO)
def test_user_entries_refuse_cookies_issued_before_them():
    """password_change, admin disable, roles, reset_password, delete and role.replace, per the table."""


@pytest.mark.skip(reason=TODO)
def test_every_revoke_user_call_site_has_an_audit_rule():
    """Each SessionStore.revoke_user caller in pelagos/ writes an action listed in the revocation table."""


@pytest.mark.skip(reason=TODO)
def test_revocations_rebuilt_from_the_audit_log_at_start():
    """A new Revocations over an existing log refuses a cookie logged out before the restart."""


@pytest.mark.skip(reason=TODO)
def test_revocations_forget_entries_past_the_ttl_and_stay_bounded():
    """Entries older than auth.session_ttl_seconds are dropped; at most 100000 handles are kept."""


@pytest.mark.skip(reason=TODO)
def test_entries_of_a_0_3_peer_without_session_are_ignored():
    """An auth.logout without request.session (written by 0.3.x) revokes nothing."""


# Secret ---------------------------------------------------------------------------------------


@pytest.mark.skip(reason=TODO)
def test_bootstrap_writes_the_signing_secret_sealed():
    """bootstrap_first_node stores [secrets] auth/session_signing, 32 bytes once decrypted."""


@pytest.mark.skip(reason=TODO)
def test_secret_generated_once_when_missing_and_never_while_syncing():
    """An upgraded cluster gets it at the first login when ready or isolated; syncing uses a process key."""


@pytest.mark.skip(reason=TODO)
def test_old_node_keeps_the_secret_entry():
    """A cluster.toml read and written by the 0.3.x model keeps [secrets] auth/session_signing."""


@pytest.mark.skip(reason=TODO)
def test_undecryptable_secret_falls_back_to_a_process_key():
    """A wrong master key or no master key: login works on this process, one warning logged."""
