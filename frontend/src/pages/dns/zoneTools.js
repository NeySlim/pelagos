// SPDX-License-Identifier: Apache-2.0
// Pure helpers for the zone screens: how record changes reach a zone (dynamic UPDATE or
// static file edit), the zone edit plan, catalog member and DNSSEC plan bodies.
import { isIPv4, isIPv6 } from './records'

// Mirrors services.dns_extras.zone_mode: the API sends `mode`, older answers only the Zone.
export function zoneMode(item) {
  if (item?.mode) return item.mode
  const zone = item?.zone || item
  if (!zone) return null
  if (zone.kind === 'primary') return zone.dynamic ? 'dynamic' : 'static'
  return zone.kind
}

// Finding of the security audit that converts a static zone to dynamic.
export const staticFindingId = (zone) => `bind:static_zone:${zone.view || '_default'}/${zone.name}`

// Zones Pelagos can edit: its own zones.conf statements and zones added with rndc addzone.
export const editableZone = (zone) => Boolean(zone) && ['pelagos', 'addzone'].includes(zone.source)

// Textarea lines (or `;` separated) as a list, empty entries dropped.
export function splitList(text) {
  return String(text || '')
    .split(/[\n;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export const joinList = (items) => (items || []).join('\n')

export const ZONE_EDIT_FIELDS = ['primaries', 'also_notify', 'allow_transfer', 'allow_update', 'update_policy', 'forwarders']

// The form state of the edit modal from a Zone.
export function zoneForm(zone) {
  const form = { forward: zone.forward || '', dnssec_policy: zone.dnssec_policy || '', inline_signing: zone.inline_signing ?? null, notes: zone.notes || '' }
  for (const f of ZONE_EDIT_FIELDS) form[f] = joinList(zone[f])
  return form
}

// POST /dns/zones/plan change replacing a zone with the edited fields; the rest of the Zone
// (extra statements, file, kind) is kept as read.
export function zoneEditChange(zone, form) {
  const after = { ...zone }
  for (const f of ZONE_EDIT_FIELDS) after[f] = splitList(form[f])
  after.forward = form.forward || null
  after.dnssec_policy = form.dnssec_policy || null
  after.inline_signing = form.inline_signing === null || form.inline_signing === '' ? null : Boolean(form.inline_signing)
  after.notes = form.notes || null
  return { op: 'replace', target: `${zone.view || '_default'}/${zone.name}`, before: zone, after }
}

// Fields that changed between the zone and the form (the submit stays disabled without one).
export function zoneEditDiff(zone, form) {
  const next = zoneEditChange(zone, form).after
  const keys = [...ZONE_EDIT_FIELDS, 'forward', 'dnssec_policy', 'inline_signing', 'notes']
  return keys.filter((k) => JSON.stringify(zone[k] ?? (ZONE_EDIT_FIELDS.includes(k) ? [] : null)) !== JSON.stringify(next[k] ?? (ZONE_EDIT_FIELDS.includes(k) ? [] : null)))
}

// Views in which the zone exists, for the view selector (only shown with more than one).
export function zoneViews(items, name) {
  return [...new Set((items || []).filter((it) => it.zone.name === name).map((it) => it.zone.view))].sort()
}

// Zone list statistics: from the unfiltered list, so a search never shows "0 zones".
export function zoneStats(items, secondaryKinds) {
  const list = items || []
  return {
    total: list.length,
    primary: list.filter((it) => it.zone.kind === 'primary').length,
    secondary: list.filter((it) => secondaryKinds.includes(it.zone.kind)).length,
    static: list.filter((it) => zoneMode(it) === 'static').length,
    divergent: list.filter((it) => it.divergent).length,
  }
}

export function catalogMemberBody({ op, member, group, view }) {
  const body = { op, member: String(member || '').trim() }
  if (op === 'add' && group && String(group).trim()) body.group = String(group).trim()
  if (view && view !== '_default') body.view = view
  return body
}

// `name value` lines (one statement per line, `;` optional) for a dnssec-policy body.
export function policyStatements(text) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim().replace(/;\s*$/, ''))
    .filter(Boolean)
    .map((line) => {
      const space = line.search(/\s/)
      return space < 0 ? { name: line, value: '' } : { name: line.slice(0, space), value: line.slice(space + 1).trim() }
    })
}

export const policyText = (statements) => (statements || []).map((s) => `${s.name} ${s.value};`).join('\n')

// Statement names the grammar allows in a dnssec-policy block, sorted (GET /advanced/bind/grammar).
export function policyGrammarNames(grammar) {
  const contexts = grammar?.contexts || {}
  const block = contexts['dnssec-policy']?.statements || {}
  if (Object.keys(block).length) return Object.keys(block).sort()
  return (grammar?.statements || []).filter((s) => (s.contexts || []).includes('dnssec-policy')).map((s) => s.name).sort()
}

// Problems of a policy body before it is sent: unknown statements and empty values.
export function policyErrors(statements, allowed) {
  const known = new Set(allowed || [])
  const errors = []
  for (const s of statements) {
    if (known.size && !known.has(s.name)) errors.push({ name: s.name, error: 'unknown' })
    else if (!s.value) errors.push({ name: s.name, error: 'empty' })
  }
  return errors
}

export function dnssecOpBody({ action, key_id, state, when, view, node_id }) {
  const body = { action }
  if (key_id !== undefined && key_id !== null && key_id !== '') body.key_id = Number(key_id)
  if (action === 'checkds') body.state = state || 'published'
  if (when) body.when = when
  if (view && view !== '_default') body.view = view
  if (node_id) body.node_id = node_id
  return body
}

// Peers holding a Pelagos-managed primary as a secondary of this node (status kind per node).
export function secondaryPeers(detail, selfId) {
  const zone = detail?.zone
  if (!zone || zone.kind !== 'primary' || !editableZone(zone)) return []
  return Object.entries(detail.status || {})
    .filter(([id, st]) => id !== selfId && st?.kind === 'secondary')
    .map(([id]) => id)
}

// The nodes holding the zone, with the kind of their copy: the detail's `copies` (every
// reachable node that has it), else every status entry read without an error.
export function zoneCopies(detail) {
  if (detail?.copies && typeof detail.copies === 'object') return detail.copies
  return Object.fromEntries(
    Object.entries(detail?.status || {})
      .filter(([, st]) => st && !st.error && st.kind)
      .map(([id, st]) => [id, { kind: st.kind, source: null }]),
  )
}

// Who may hold the zone as a secondary of its primary node: the BIND nodes other than the
// primary, the ones holding a copy now ticked. Null when no node holds it as primary.
export function secondaryChoice(detail, nodes = []) {
  const copies = zoneCopies(detail)
  const primary = Object.keys(copies).find((id) => copies[id].kind === 'primary')
  if (!primary) return null
  const current = Object.keys(copies).filter((id) => copies[id].kind === 'secondary')
  const candidates = nodes.filter((n) => n.peer.id !== primary && n.peer.modules?.bind !== false).map((n) => n.peer.id)
  return { primary, current, candidates: [...new Set([...candidates, ...current])] }
}

// Delete plan request: with peers the plan also removes their secondary copies.
export function zoneDeleteRequest(zone, peers = []) {
  const change = { op: 'delete', target: `${zone.view}/${zone.name}`, before: zone, after: null }
  return { change, node_ids: peers.length ? peers : undefined }
}

// Zone kinds the creation form offers; mirror, static-stub, hint and redirect have no BIND
// object form of their own and are created here like the others.
export const CREATABLE_KINDS = ['primary', 'secondary', 'stub', 'forward', 'mirror', 'static-stub', 'hint', 'redirect']
// rndc addzone and peer secondaries are offered for these kinds only.
export const ADDZONE_KINDS = ['primary', 'secondary', 'stub', 'forward']
// Kinds named after the root: BIND requires "." for redirect, and hints are the root's.
export const ROOT_KINDS = ['hint', 'redirect']

const lines = (text) => String(text || '').split('\n').map((l) => l.trim()).filter(Boolean)

const urlHost = (url) => {
  try {
    return new URL(url).hostname.replace(/^\[|\]$/g, '')
  } catch {
    return ''
  }
}

const isIP = (host) => isIPv4(host) || isIPv6(host)
const isReverse = (apex) => /(^|\.)(in-addr|ip6)\.arpa$/.test(apex)

// Name server lines proposed for a new primary `zone`, one per node that runs BIND. A name
// inside the zone carries the node's address (its glue); a reverse zone never gets a name of
// its own, so a node known only by address is left out there (empty: dns.default_ns applies).
export function defaultNameServers(nodes, zone = '') {
  const apex = String(zone || '').trim().toLowerCase().replace(/\.$/, '')
  const withBind = (nodes || []).filter((n) => n.peer?.modules?.bind)
  return (withBind.length ? withBind : nodes || []).map((n) => {
    const hosts = [n.peer?.web_url, n.peer?.url].map(urlHost).filter(Boolean)
    const fqdn = hosts.find((h) => !isIP(h) && h.includes('.'))?.toLowerCase()
    const address = hosts.find(isIP)
    if (fqdn) {
      const inside = apex && (fqdn === apex || fqdn.endsWith(`.${apex}`))
      return inside && address ? `${fqdn}. ${address}` : `${fqdn}.`
    }
    if (!address || isReverse(apex)) return null
    return `${n.peer.name} ${address}`
  }).filter(Boolean).join('\n')
}

// NS lines `<name> [address]`: a one-label name hangs off the zone, a name inside the zone
// needs its address (it becomes an A or AAAA record of the new zone), localhost is refused.
export function nameServers(text, zone, validName) {
  const apex = zone === '.' ? '' : zone.replace(/\.$/, '')
  const ns = []
  const records = []
  for (const line of lines(text)) {
    const [raw, address, extra] = line.split(/\s+/)
    const name = (raw.endsWith('.') ? raw : raw.includes('.') || !apex ? `${raw}.` : `${raw}.${apex}.`).toLowerCase()
    if (extra !== undefined || !validName(name)) return { error: 'nsName' }
    if (name === 'localhost.' || name.endsWith('.localhost.')) return { error: 'nsLocalhost' }
    if (address !== undefined && !isIPv4(address) && !isIPv6(address)) return { error: 'nsAddress' }
    const inside = !apex || name === `${apex}.` || name.endsWith(`.${apex}.`)
    if (inside && address === undefined) return { error: 'nsGlue' }
    if (!ns.includes(name)) ns.push(name)
    if (inside) records.push({ name, rtype: isIPv6(address) ? 'AAAA' : 'A', ttl: 3600, rdata: [address] })
  }
  return { ns, records }
}
const bareName = (name) => String(name).replace(/\.$/, '')

// The Zone of a creation form, or the form fields in error (BIND's own rules per kind).
export function newZoneAfter(form, validName) {
  const kind = form.kind
  const name = ROOT_KINDS.includes(kind) ? '.' : String(form.name || '').trim().toLowerCase()
  const abs = name === '.' ? '.' : name.endsWith('.') ? name : `${name}.`
  const primaries = lines(form.primaries)
  const forwarders = lines(form.forwarders)
  const addresses = lines(form.serverAddresses)
  const names = lines(form.serverNames)
  const file = String(form.file || '').trim()
  const errors = {}
  if (name !== '.' && !validName(name)) errors.name = 'name'
  if (['secondary', 'stub'].includes(kind) && !primaries.length) errors.primaries = 'list'
  if (kind === 'mirror' && abs !== '.' && !primaries.length) errors.primaries = 'list'
  if (kind === 'forward' && !forwarders.length) errors.forwarders = 'list'
  if (kind === 'static-stub' && !addresses.length && !names.length) errors.serverAddresses = 'list'
  if (kind === 'hint' && !file) errors.file = 'required'
  if (kind === 'redirect' && !file && !primaries.length) errors.file = 'fileOrPrimaries'
  const servers = kind === 'primary' ? nameServers(form.ns, abs, validName) : { ns: [], records: [] }
  if (servers.error) errors.ns = servers.error
  if (Object.keys(errors).length) return { errors, after: null }

  const after = { name: abs, kind, view: form.view || '_default' }
  if (kind === 'primary') after.file = file || `db.${bareName(abs)}`
  // Empty: the backend falls back to dns.default_ns of the settings.
  if (servers.ns.length) after.ns = servers.ns
  if (servers.records.length) after.records = servers.records
  if (['secondary', 'stub'].includes(kind)) after.file = file || `sec/db.${bareName(abs)}`
  if (['mirror', 'hint', 'redirect'].includes(kind) && file) after.file = file
  if (['secondary', 'stub', 'mirror', 'redirect'].includes(kind) && primaries.length) after.primaries = primaries
  if (kind === 'forward') {
    after.forwarders = forwarders
    after.forward = 'only'
  }
  if (kind === 'static-stub') {
    after.extra = {}
    if (addresses.length) after.extra['server-addresses'] = `{ ${addresses.map((a) => `${a};`).join(' ')} }`
    if (names.length) after.extra['server-names'] = `{ ${names.map((n) => `"${bareName(n)}";`).join(' ')} }`
  }
  if (form.addzone && ADDZONE_KINDS.includes(kind)) after.source = 'addzone'
  return { errors: {}, after }
}
