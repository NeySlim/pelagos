// SPDX-License-Identifier: Apache-2.0
// DDNS failover screen (architecture section 24): what GET /dhcp/ddns/resilience and the
// ddns_outage / dns_stale_primary alerts say about each dynamic zone, and the inputs of the
// prepare, failover, switchover and replay plans.

export const DEFAULT_VIEW = '_default'
export const FAILOVER_TAB = 'failover'

export const zoneKey = (z) => `${z?.view || DEFAULT_VIEW}/${z?.zone || ''}`
export const zoneLabel = (z) => (z?.view && z.view !== DEFAULT_VIEW ? `${z.zone} (${z.view})` : z?.zone || '')

// The screen a failover alert or the D2 advice leads to; `zone` selects one row.
export function failoverPath(key) {
  const base = `/dhcp/v4/ddns?tab=${FAILOVER_TAB}`
  return key ? `${base}&zone=${encodeURIComponent(key)}` : base
}

// Open alerts by zone key: `ddns:<view>/<zone>` (ddns_outage), `ddns:stale:<view>/<zone>`.
export function alertsByZone(alerts = []) {
  const outage = new Map()
  const stale = new Map()
  for (const a of alerts) {
    if (!a || a.state === 'resolved') continue
    const subject = String(a.subject || '')
    if (a.kind === 'dns_stale_primary' && subject.startsWith('ddns:stale:')) stale.set(subject.slice('ddns:stale:'.length), a)
    else if (a.kind === 'ddns_outage' && subject.startsWith('ddns:')) outage.set(subject.slice('ddns:'.length), a)
  }
  return { outage, stale }
}

// The open ddns_outage of a zone, while it still names the active primary: once a copy is promoted
// the old primary's alert lasts until the next collector poll.
export function outageOf(zone, outage) {
  const alert = outage?.get(zoneKey(zone))
  if (!alert) return null
  return !alert.node_id || !zone?.primary_node_id || alert.node_id === zone.primary_node_id ? alert : null
}

// One state per zone, worst first: the primary receives no update, an old primary still serves
// the zone, a blocker the prepare plan cannot lift, not prepared yet, ready.
export function zoneState(zone, { outage, stale } = {}) {
  const key = zoneKey(zone)
  if (outageOf(zone, outage)) return 'outage'
  if ((zone.stale || []).length || stale?.has(key)) return 'stale'
  if (zone.ready) return 'ready'
  const blockers = zone.blockers || []
  if (blockers.length && blockers.every((b) => b?.key === 'ddns.blocker.not_prepared')) return 'not_prepared'
  return 'blocked'
}

export const STATE_TONE = { outage: 'danger', stale: 'danger', blocked: 'warning', not_prepared: 'gray', ready: 'success' }

// Zones a promotion or a switchover can move: the prepared ones (epoch recorded, no blocker).
export const isPrepared = (zone) => Boolean(zone?.ready) && Number(zone?.epoch) > 0
// Zones the prepare plan can take: only `not_prepared` remains.
export const isPreparable = (zone) => zoneState(zone) === 'not_prepared'

// Where a blocker is lifted: an unmanaged zone is handed over to Pelagos on its zone page (item
// 33); transfers are allowed there too. Other blockers have no screen action.
export function blockerAction(blocker, zone) {
  const name = String(blocker?.params?.zone || zone?.zone || '').replace(/\.$/, '')
  if (!name) return null
  const view = zone?.view && zone.view !== DEFAULT_VIEW ? `?view=${encodeURIComponent(zone.view)}` : ''
  const to = `/dns/zones/${encodeURIComponent(name)}${view}`
  if (blocker?.key === 'ddns.blocker.not_managed') return { to, label: 'adopt' }
  if (blocker?.key === 'ddns.blocker.no_transfer') return { to, label: 'openZone' }
  return null
}

// Nodes a zone can be moved to, by every selected zone: copies held by each of them, online.
export function targetNodes(zones = [], offline = []) {
  if (!zones.length) return []
  const [first, ...rest] = zones
  return (first.copies || []).filter((id) => !offline.includes(id) && rest.every((z) => (z.copies || []).includes(id)))
}

// The primary nodes of zones in outage, from the open ddns_outage alerts.
export function outageSummary(zones = [], outage = new Map()) {
  const items = zones.filter((z) => outageOf(z, outage)).map((z) => ({ zone: z, alert: outageOf(z, outage) }))
  const since = items.map((i) => i.alert.details?.since || i.alert.first_seen).filter(Boolean).sort()[0] || null
  return { items, since, promotable: items.filter((i) => isPrepared(i.zone)).map((i) => i.zone) }
}

// <input type="datetime-local"> value of an RFC 3339 time, in local time, minutes precision.
export function toLocalInput(value) {
  const t = Date.parse(value)
  if (Number.isNaN(t)) return ''
  const d = new Date(t)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function fromLocalInput(value) {
  if (!value) return null
  const t = Date.parse(value)
  return Number.isNaN(t) ? null : new Date(t).toISOString()
}

// Body of POST /dhcp/ddns/replay/plan; an error key when the window is not usable.
export function replayBody({ from, to, family, limit }, maxHours = 72) {
  const start = fromLocalInput(from)
  const end = fromLocalInput(to)
  if (from && !start) return { error: 'ddnsFailover.replay.badFrom' }
  if (to && !end) return { error: 'ddnsFailover.replay.badTo' }
  if (start && end && Date.parse(start) >= Date.parse(end)) return { error: 'ddnsFailover.replay.order' }
  if (start && end && Date.parse(end) - Date.parse(start) > maxHours * 3600000) return { error: 'ddnsFailover.replay.tooLong' }
  const body = {}
  if (start) body.from = start
  if (end) body.to = end
  if (family) body.family = family
  if (limit !== '' && limit !== undefined && limit !== null) {
    const n = Number(limit)
    if (!Number.isInteger(n) || n < 1) return { error: 'ddnsFailover.replay.badLimit' }
    body.limit = n
  }
  return { body }
}

// One line of the dashboard and zone badge: ready zones, outage, stale primaries.
export function resilienceSummary(res) {
  const zones = res?.zones || []
  const stale = zones.filter((z) => (z.stale || []).length).length
  const tone = res?.outage || stale ? 'danger' : zones.length && zones.every((z) => z.ready) ? 'success' : 'warning'
  return { total: zones.length, ready: zones.filter((z) => z.ready).length, outage: res?.outage || null, stale, replay: res?.replay?.candidates || 0, tone }
}

// The resilience entry of one zone (zone names absolute or not).
export function zoneResilience(res, name, view = DEFAULT_VIEW) {
  const abs = String(name || '').endsWith('.') ? name : `${name}.`
  return (res?.zones || []).find((z) => z.zone === abs && (z.view || DEFAULT_VIEW) === (view || DEFAULT_VIEW)) || null
}
