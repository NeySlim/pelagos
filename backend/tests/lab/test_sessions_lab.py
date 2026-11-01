# SPDX-License-Identifier: Apache-2.0
"""Sessions resumed across the reference pair (section 16, "Sessions across nodes"): the deb of this
checkout on lab-ns1 and lab-ns2, a cookie issued by ns1 used on ns2, logout on ns1 refused on ns2,
a web restart that keeps sessions and a logged-out cookie refused after it, then ns2 on the previous
release refusing the new cookie cleanly. Contract skeleton (B1-SESSIONS)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.lab

TODO = "B1-SESSIONS: contract skeleton, implemented after the contract review"


@pytest.mark.skip(reason=TODO)
class TestSessionsAcrossThePair:
    def test_00_rollback_and_provision(self):
        """Roll back ns1 and ns2, install the deb, init ns1, enroll ns2."""

    def test_01_cookie_of_ns1_works_on_ns2(self):
        """Login on ns1; GET /auth/session and a PUT of a preference with the CSRF token on ns2."""

    def test_02_logout_on_ns1_refused_on_ns2(self):
        """Logout on ns1; within 5 s ns2 answers 401 to the same cookie."""

    def test_03_restart_keeps_sessions_and_revocations(self):
        """Restart pelagos on ns2: a live cookie still works, the logged-out one is still refused."""

    def test_04_password_change_on_ns2_ends_other_sessions_on_ns1(self):
        """Two logins of one user; a password change through one on ns2 refuses the other on ns1."""

    def test_05_previous_release_refuses_the_new_cookie(self):
        """ns2 back on the previous release: 401 on /auth/session, login there works, no loop."""
