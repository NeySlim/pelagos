// SPDX-License-Identifier: Apache-2.0
// Plain helpers shared by the DHCP, hosts and nodes areas: Kea naming, parsers and
// validators for the edit forms, durations, user-context fields.

export const keaEngine = (family) => (family === 'v6' ? 'kea6' : 'kea4')
export const subnetKey = (family) => (family === 'v6' ? 'subnet6' : 'subnet4')
export const optionSpace = (family) => (family === 'v6' ? 'dhcp6' : 'dhcp4')

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || seconds === '') return '-'
  const s = Number(seconds)
  if (!Number.isFinite(s)) return String(seconds)
  if (s % 86400 === 0 && s >= 86400) return `${s / 86400}d`
  if (s % 3600 === 0 && s >= 3600) return `${s / 3600}h`
  if (s % 60 === 0 && s >= 60) return `${s / 60}m`
  return `${s}s`
}

// Seconds until (positive) or since (negative) an RFC 3339 timestamp.
export function secondsFromNow(ts) {
  if (!ts) return null
  const t = new Date(ts).getTime()
  return Number.isNaN(t) ? null : Math.round((t - Date.now()) / 1000)
}

export function splitList(text) {
  return String(text || '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export function splitLines(text) {
  return String(text || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
}

export const isIPv4 = (s) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(String(s || ''))
export const isIPv6 = (s) => /^[0-9a-f:]+$/i.test(String(s || '')) && String(s).includes(':') && String(s).split('::').length <= 2
export const isIP = (s, family) => (family === 'v6' ? isIPv6(s) : isIPv4(s))
export function isPrefix(s, family) {
  const [addr, len, extra] = String(s || '').split('/')
  if (extra !== undefined || len === undefined || !/^\d+$/.test(len)) return false
  return isIP(addr, family) && Number(len) <= (family === 'v6' ? 128 : 32)
}
export const isMac = (s) => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(String(s || ''))

// "a - b" or a prefix, as Kea prints a pool.
export function isPool(s, family) {
  const text = String(s || '')
  if (text.includes('-')) {
    const [a, b, extra] = text.split('-').map((p) => p.trim())
    return extra === undefined && isIP(a, family) && isIP(b, family)
  }
  return isPrefix(text, family)
}

// Option data lines "name = data" (or "code = data") <-> OptionData objects; the
// objects already present keep their unknown fields.
export function optionsToText(options = []) {
  return options.map((o) => `${o.name ?? o.code} = ${o.data ?? ''}`).join('\n')
}

export function textToOptions(text, family, previous = []) {
  return splitLines(text).map((line) => {
    const at = line.indexOf('=')
    const key = (at >= 0 ? line.slice(0, at) : line).trim()
    const data = at >= 0 ? line.slice(at + 1).trim() : ''
    const code = /^\d+$/.test(key) ? Number(key) : null
    const name = code === null ? key : null
    const prev = previous.find((o) => (name ? o.name === name : o.code === code))
    return {
      ...(prev || { space: optionSpace(family), csv_format: null, always_send: null, never_send: null, raw: {} }),
      name: name ?? prev?.name ?? null,
      code: code ?? prev?.code ?? null,
      data,
    }
  })
}

// Pelagos metadata lives under user-context "pelagos" (architecture section 5):
// {notes, tags, owner, updated_by, updated_at}. Flat "pelagos:note" keys are read too.
export const META_KEY = 'pelagos'
const LEGACY_NOTE = 'pelagos:note'
const LEGACY_OWNER = 'pelagos:owner'

const metaOf = (context) => (context && typeof context[META_KEY] === 'object' && context[META_KEY]) || {}
export const noteOf = (context) => metaOf(context).notes || context?.[LEGACY_NOTE] || ''
export const ownerOf = (context) => metaOf(context).owner || context?.[LEGACY_OWNER] || ''
export const tagsOf = (context) => (Array.isArray(metaOf(context).tags) ? metaOf(context).tags : [])

// Merges the note and owner fields of a form into an existing user-context; other keys stay.
export function withNote(context, note, owner) {
  const next = { ...(context || {}) }
  const meta = { ...metaOf(context) }
  if (note !== undefined) {
    if (note) meta.notes = note
    else delete meta.notes
    delete next[LEGACY_NOTE]
  }
  if (owner !== undefined) {
    if (owner) meta.owner = owner
    else delete meta.owner
    delete next[LEGACY_OWNER]
  }
  if (Object.keys(meta).length) next[META_KEY] = meta
  else delete next[META_KEY]
  return next
}

// Flat key/value rows for display: the "pelagos" object is spread into its fields.
export function userContextEntries(context) {
  const rows = []
  for (const [key, value] of Object.entries(context || {})) {
    if (key === META_KEY && value && typeof value === 'object' && !Array.isArray(value)) {
      for (const [field, v] of Object.entries(value)) rows.push([`${META_KEY}.${field}`, v])
    } else rows.push([key, value])
  }
  return rows
}

// Field errors of a 400 problem, keyed by the last path segment.
export function fieldErrors(err) {
  const out = {}
  for (const e of err?.errors || []) {
    const key = String(e.field || '').split('.').pop()
    if (key) out[key] = e.message
  }
  return out
}

// Fields whose values must match between the HA partners' copies of a lease.
const AGREEMENT_FIELDS = ['state', 'hw_address', 'duid', 'client_id', 'hostname', 'subnet_id', 'lease_type', 'prefix_len']
// Partners stamp expiry a few seconds apart; beyond this it is a real disagreement.
const EXPIRY_TOLERANCE_MS = 60_000

// Compares one lease as read on each node: which nodes hold it, which expected
// nodes miss it, which fields differ.
export function leaseAgreement(copies = [], expectedNodes = []) {
  const present = [...new Set(copies.map((l) => l.node_id).filter(Boolean))]
  const nodes = [...new Set([...expectedNodes, ...present])]
  const missing = nodes.filter((id) => !present.includes(id))
  const differing = AGREEMENT_FIELDS.filter((field) => new Set(copies.map((l) => JSON.stringify(l[field] ?? null))).size > 1)
  const expiries = copies.map((l) => new Date(l.expires_at).getTime()).filter((n) => !Number.isNaN(n))
  if (expiries.length > 1 && Math.max(...expiries) - Math.min(...expiries) > EXPIRY_TOLERANCE_MS) differing.push('expires_at')
  return { nodes, present, missing, differing, agree: missing.length === 0 && differing.length === 0 }
}

export const reservationTarget = (family, r) =>
  `${r.subnet_id ? `${subnetKey(family)}/${r.subnet_id}` : 'global'}/reservations/${r.id_type}=${r.identifier}`

// A form value typed as JSON (true, 42, "text") or, failing that, as a plain string.
export function parseScalar(text) {
  const raw = String(text ?? '').trim()
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

// Value types of the known ddns-* parameters (Kea DHCP manual, DDNS section).
const DDNS_TYPES = {
  'ddns-send-updates': 'boolean',
  'ddns-override-no-update': 'boolean',
  'ddns-override-client-update': 'boolean',
  'ddns-update-on-renew': 'boolean',
  'ddns-ttl-percent': 'number',
  'ddns-ttl': 'integer',
  'ddns-ttl-min': 'integer',
  'ddns-ttl-max': 'integer',
  'ddns-replace-client-name': 'string',
  'ddns-generated-prefix': 'string',
  'ddns-qualifying-suffix': 'string',
  'ddns-conflict-resolution-mode': 'string',
  'hostname-char-set': 'string',
  'hostname-char-replacement': 'string',
}

// Checks the text typed for a ddns-* parameter. Returns `{ value }` or `{ error }`
// with a dhcp `form.*` i18n key; an empty string must be typed as "".
export function parseDdnsValue(key, text) {
  if (String(text ?? '').trim() === '') return { error: 'form.required' }
  const value = parseScalar(text)
  const type = DDNS_TYPES[key]
  if (type === 'boolean' && typeof value !== 'boolean') return { error: 'form.expectBoolean' }
  if (type === 'number' && (typeof value !== 'number' || value < 0)) return { error: 'form.expectNumber' }
  if (type === 'integer' && !(Number.isInteger(value) && value >= 0)) return { error: 'form.positiveInteger' }
  if (type === 'string' && typeof value !== 'string') return { error: 'form.expectString' }
  return { value }
}

// Library path for a hook name, in the directory the loaded hooks come from.
export function hookLibraryPath(loaded, name) {
  const sample = loaded.find((h) => String(h.library).includes('/'))?.library
  const dir = sample ? sample.slice(0, sample.lastIndexOf('/')) : '/usr/lib/kea/hooks'
  return `${dir}/libdhcp_${name}.so`
}

// Kea HA states in which a pair serves clients normally.
export const HEALTHY_HA_STATES = ['hot-standby', 'load-balancing', 'backup', 'passive-backup']

export const LEASE_STATES = ['default', 'declined', 'expired-reclaimed', 'released', 'registered']

// Most specific zone (from GET /dns/zones) that contains an absolute name.
export function zoneOf(name, zones = []) {
  const fqdn = String(name || '').toLowerCase()
  return zones
    .filter((z) => fqdn === z || fqdn.endsWith(`.${z}`))
    .sort((a, b) => b.length - a.length)[0] || null
}

export function absName(name) {
  const lower = String(name || '').toLowerCase()
  return !lower || lower.endsWith('.') ? lower : `${lower}.`
}

