# SPDX-License-Identifier: Apache-2.0
"""Certificates of the web UI (HTTPS on web_listen): parsing, checks, sources, install, renewal.

The replication mTLS certificates and the internal CA (core.ca) are never touched here.
Parts are derived from UCM (Ultimate CA Manager, same author, relicensed Apache-2.0, see NOTICE).
"""
