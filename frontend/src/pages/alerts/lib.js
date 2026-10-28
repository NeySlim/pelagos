// SPDX-License-Identifier: Apache-2.0
// Alert vocabulary (architecture section 15) and where an alert's subject leads.
import { crossingTime, valueAt } from '../../components/motion/traceMath'
import { EXCEPTABLE_KINDS, INCONSISTENCY_KINDS } from './kinds.js'

export const SEVERITIES = ['critical', 'warning', 'info']
export const STATES = ['open', 'acked', 'resolved']
export const ENGINES = ['bind', 'kea4', 'kea6', 'd2']
export const KINDS = [
  'pool_near_full', 'pool_full', 'serial_divergence', 'secondary_stale', 'zone_error', 'ha_degraded',
  'ha_partner_down', 'ha_transition', 'ha_terminated', 'ha_backup_out_of_sync', 'clock_skew', 'clock_unsynchronized', 'd2_errors', 'daemon_down', 'peer_offline', 'config_divergence',
  'lease_without_record', 'record_without_lease', 'reservation_mismatch', 'ptr_mismatch', 'duplicate_ip',
  'insecure_key', 'insecure_listener', 'custom_hook', 'rpz_update',
  'disk_space', 'file_growth', 'reservation_risk', 'declined_addresses',
  'resolver_health', 'delegation_issue', 'version_mismatch', 'restart_loop', 'pool_forecast', 'security_advisory', 'cert_expiry', 'cert_renewal_failed', 'ddns_advice', 'config_syntax_warning', 'managed_drift',
  'notification_failed', 'archive_failed', 'archive_stale', 'archive_incomplete', 'ddns_outage', 'ddns_replay', 'dns_stale_primary',
]
export { EXCEPTABLE_KINDS, INCONSISTENCY_KINDS }

// Objects of an alert that can be ignored as the admin's choice (details.exception_keys).
export function exceptionItems(alert, summary) {
  if (!INCONSISTENCY_KINDS.has(alert?.kind) && !EXCEPTABLE_KINDS.has(alert?.kind)) return []
  const keys = alert.details?.exception_keys || []
  return keys.map((key) => ({ kind: alert.kind, key, summary: keys.length === 1 && summary ? summary : key }))
}

const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 }
export const bySeverity = (a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3)

// Subjects are "ip:<addr>", "mac:<mac>", "name:<fqdn>/<type>", "zone:<zone>[@view]",
// "kea4:subnet:<id>:pool:<range>", "ha:<engine>", "ha-backup:<engine>", "peer:<id>", "d2:updates", ...
export function subjectLink(alert) {
  const subject = String(alert?.subject || '')
  const [kind, ...rest] = subject.split(':')
  const value = rest.join(':')
  if ((kind === 'ip' || kind === 'mac') && value) return { to: `/hosts?q=${encodeURIComponent(value)}`, label: 'openHost' }
  if (kind === 'name' && value) return { to: `/hosts?q=${encodeURIComponent(value.split('/')[0].replace(/\.$/, ''))}`, label: 'openHost' }
  if (kind === 'zone' && value) {
    const [zone, view] = value.split('@')
    const path = `/dns/zones/${encodeURIComponent(zone.replace(/\.$/, ''))}`
    return { to: view ? `${path}?view=${encodeURIComponent(view)}` : path, label: 'openZone' }
  }
  // Delegation subjects "ns-silent:<zone>[@view]:<ns>": the fix is an NS edit in the zone.
  if (['ns-silent', 'ns-unresolved', 'ns-transfer', 'ns-primary'].includes(kind) && rest[0]) {
    const [zone, view] = rest[0].split('@')
    const path = `/dns/zones/${encodeURIComponent(zone.replace(/\.$/, ''))}`
    return { to: view ? `${path}?view=${encodeURIComponent(view)}` : path, label: 'openZone' }
  }
  if ((kind === 'kea4' || kind === 'kea6') && rest[0] === 'subnet') return { to: `/dhcp/${kind === 'kea6' ? 'v6' : 'v4'}/subnets`, label: null }
  if ((kind === 'ha' || kind === 'ha-backup') && value) return { to: `/dhcp/${value === 'kea6' ? 'v6' : 'v4'}/ha`, label: null }
  if (kind === 'peer' || kind === 'clock' || kind === 'ntp') return { to: '/nodes', label: null }
  if (kind === 'd2') return { to: '/dhcp/v4/ddns', label: null }
  return null
}

// Final output of a finished job: the "result" step the jobs service appends.
export const jobResult = (job) => (job?.steps || []).find((s) => s.name === 'result')?.output ?? null

export const PRESSURE_BEFORE_MS = 2 * 3600000
export const PRESSURE_AFTER_MS = 30 * 60000

// "kea4:subnet:3:pool:192.0.2.200-192.0.2.219" -> the /series/pools query of that pool.
export function poolSeriesQuery(alert) {
  const m = /^(kea[46]):subnet:(\d+):pool:(.+)$/.exec(String(alert?.subject || ''))
  if (!m) return null
  return { engine: m[1], subnet_id: m[2], pool: m[3].replace(/-/g, ' - '), raw: m[3], node_id: alert.node_id || undefined }
}

// Latches of a pool alert: closed where the use crossed the alert's threshold, held once
// resolved, and released where it came back under.
export function pressureLatches(alert, points, threshold) {
  const opened = Date.parse(alert.first_seen)
  const crossed = crossingTime(points, threshold, opened - PRESSURE_BEFORE_MS)
  const at = crossed !== null && crossed <= opened + 60000 ? crossed : opened
  const v = crossed !== null && crossed <= opened + 60000 ? threshold : Number(alert.details?.percent ?? valueAt(points, at) ?? threshold)
  const out = [{ t: at, value: v, state: alert.state === 'resolved' ? 'held' : 'open' }]
  if (alert.state === 'resolved' && alert.resolved_at) {
    const rt = Date.parse(alert.resolved_at)
    out.push({ t: rt, value: Number(valueAt(points, rt) ?? threshold), state: 'released' })
  }
  return out
}

// Where an alert comes from in the cluster view: its node, or none for a cluster-wide alert, which
// the nodes in `reported_by` hold.
export function alertOrigin(alert) {
  const reporters = Array.isArray(alert?.reported_by) ? alert.reported_by : []
  return { node: alert?.node_id || null, reporters }
}

// Nodes whose alerts the API could not read (meta.unavailable of GET /alerts, or the summary's).
export function unavailableNodes(...sources) {
  const seen = new Map()
  for (const list of sources) for (const u of Array.isArray(list) ? list : []) if (u?.node_id && !seen.has(u.node_id)) seen.set(u.node_id, u)
  return [...seen.values()]
}
