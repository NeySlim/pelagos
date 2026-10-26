// SPDX-License-Identifier: Apache-2.0
// Alert vocabulary (architecture section 15) and where an alert's subject leads.
import { crossingTime, valueAt } from '../../components/motion/traceMath'

export const SEVERITIES = ['critical', 'warning', 'info']
export const STATES = ['open', 'acked', 'resolved']
export const ENGINES = ['bind', 'kea4', 'kea6', 'd2']
export const KINDS = [
  'pool_near_full', 'pool_full', 'serial_divergence', 'secondary_stale', 'zone_error', 'ha_degraded',
  'ha_partner_down', 'ha_transition', 'ha_terminated', 'ha_backup_out_of_sync', 'clock_skew', 'clock_unsynchronized', 'd2_errors', 'daemon_down', 'peer_offline', 'config_divergence',
  'lease_without_record', 'record_without_lease', 'reservation_mismatch', 'ptr_mismatch', 'duplicate_ip',
  'insecure_key', 'insecure_listener', 'custom_hook', 'rpz_update',
  'disk_space', 'file_growth', 'reservation_risk', 'declined_addresses',
  'resolver_health', 'delegation_issue', 'version_mismatch', 'restart_loop', 'pool_forecast', 'security_advisory', 'cert_expiry', 'cert_renewal_failed',
