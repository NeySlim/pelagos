// SPDX-License-Identifier: Apache-2.0
// Alert kinds that take an admin exception; plain module so the mock server can import it.
export const INCONSISTENCY_KINDS = new Set(['lease_without_record', 'record_without_lease', 'reservation_mismatch', 'ptr_mismatch', 'duplicate_ip'])

// Health and audit checks an admin may keep as they are (backend EXCEPTABLE_KINDS); never an outage.
export const EXCEPTABLE_KINDS = new Set([
  'insecure_key', 'insecure_listener', 'custom_hook', 'disk_space', 'file_growth', 'reservation_risk',
  'declined_addresses', 'resolver_health', 'delegation_issue', 'version_mismatch', 'pool_forecast',
  'security_advisory', 'clock_unsynchronized', 'cert_expiry', 'archive_incomplete', 'kea_series_obsolete',
  'ipv6_missing_aaaa', 'ipv6_reverse_missing', 'ipv6_stale_aaaa',
])
