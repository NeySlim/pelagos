// SPDX-License-Identifier: Apache-2.0
// Pure helpers for the record editor: owner names, rdata validation per type,
// presentation text of an RRset and the Change sent to POST .../records/plan.

// Types the editor offers; SOA and DNSSEC types stay with BIND (design section 4). Must equal
// ADMIN_UPDATE_TYPES (backend/pelagos/domain/zone_updates.py), the grant the audit installs.
export const EDITABLE_TYPES = [
  'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR', 'NS', 'CAA', 'DHCID',
  'SSHFP', 'TLSA', 'HTTPS', 'SVCB', 'NAPTR', 'LOC', 'DNAME', 'DS', 'URI',
]
export const READ_ONLY_TYPES = ['SOA', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY', 'TYPE65534']
export const SINGLETON_TYPES = ['CNAME', 'DNAME']
export const MAX_TTL = 2147483647

export const absZone = (zone) => {
  const z = String(zone || '').toLowerCase()
  return z.endsWith('.') ? z : `${z}.`
}

// "www" for "www.example.lan." in zone "example.lan.", "@" for the apex.
export function relativeName(name, zone) {
  const z = absZone(zone)
  const n = String(name || '').toLowerCase()
  if (!n || n === z || n === '@') return '@'
  if (n.endsWith(`.${z}`)) return n.slice(0, -(z.length + 1))
  return n
}

// Owner as typed (relative, "@" or absolute with trailing dot) to its absolute form.
export function absoluteName(owner, zone) {
  const z = absZone(zone)
  const o = String(owner || '').trim().toLowerCase()
  if (!o || o === '@') return z
  if (o.endsWith('.')) return o
  return `${o}.${z}`
}

const LABEL = /^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)$/i
// RFC 1123 host names: BIND check-names refuses other owners for these types (same rule in the API).
const HOST_LABEL = /^(\*|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)$/i
export const HOSTNAME_OWNER_TYPES = ['A', 'AAAA', 'MX']

export function validOwner(owner, zone, rtype = '') {
  const o = String(owner || '').trim()
  if (!o || o === '@') return true
  const abs = absoluteName(o, zone)
  if (abs.length > 254) return false
  const z = absZone(zone)
  if (o.endsWith('.') && abs !== z && !abs.endsWith(`.${z}`)) return false
  const rule = HOSTNAME_OWNER_TYPES.includes(String(rtype).toUpperCase()) ? HOST_LABEL : LABEL
  // Only the labels below the zone are checked: the zone's own name is already served.
  const own = abs === z ? [] : abs.slice(0, -(z.length + 1)).split('.')
  return own.every((label, i) => rule.test(label) && (label !== '*' || i === 0))
}

// A zone name: at least one label, no wildcard, trailing dot optional.
export function validDomainName(name) {
  const n = String(name || '').trim().replace(/\.$/, '')
  if (!n || n.length > 253) return false
  return n.split('.').every((label) => label !== '*' && LABEL.test(label))
}

export function isIPv4(value) {
  const parts = String(value).split('.')
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === '0' || !p.startsWith('0')))
}

export function isIPv6(value) {
  const v = String(value)
  if (!/^[0-9a-f:.]+$/i.test(v) || !v.includes(':')) return false
  const doubles = v.split('::').length - 1
  if (doubles > 1) return false
  let groups = v.split(':')
  const last = groups[groups.length - 1]
  let extra = 0
  if (last.includes('.')) {
    if (!isIPv4(last)) return false
    groups = groups.slice(0, -1)
    extra = 2
  }
  if (doubles === 0) return groups.length + extra === 8 && groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))
  const filled = groups.filter((g) => g !== '')
  return filled.length + extra <= 7 && filled.every((g) => /^[0-9a-f]{1,4}$/i.test(g))
}

// Forwarder or primary address: "192.0.2.1", "2001:db8::1", optionally " port N".
export function validForwarder(value) {
  const [addr, word, port, ...rest] = String(value).trim().split(/\s+/)
  if (rest.length) return false
  if (!isIPv4(addr) && !isIPv6(addr)) return false
  if (word === undefined) return true
  return word === 'port' && /^\d+$/.test(port || '') && Number(port) <= 65535
}

const isHost = (v) => v === '.' || /^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.?$/i.test(v)
const isUint16 = (v) => /^\d+$/.test(v) && Number(v) <= 65535

// Returns null when `rdata` is acceptable for `rtype`, else an i18n key under dns:editor.errors.
export function validateRdata(rtype, rdata) {
  const v = String(rdata || '').trim()
  if (!v) return 'rdataEmpty'
  const parts = v.split(/\s+/)
  switch (rtype) {
    case 'A':
      return isIPv4(v) ? null : 'ipv4'
    case 'AAAA':
      return isIPv6(v) ? null : 'ipv6'
    case 'CNAME':
    case 'PTR':
    case 'NS':
      return parts.length === 1 && isHost(v) ? null : 'hostname'
    case 'MX':
      return parts.length === 2 && isUint16(parts[0]) && isHost(parts[1]) ? null : 'mx'
    case 'SRV':
      return parts.length === 4 && parts.slice(0, 3).every(isUint16) && isHost(parts[3]) ? null : 'srv'
    case 'CAA':
      return /^\d{1,3}\s+[a-z0-9]+\s+"[^"]*"$/i.test(v) && Number(parts[0]) <= 255 ? null : 'caa'
    case 'TXT':
      return txtSegmentsOk(v) ? null : 'txt'
    case 'DNAME':
      return parts.length === 1 && isHost(v) ? null : 'hostname'
    default:
      return NEW_TYPE_CHECKS[rtype] ? (NEW_TYPE_CHECKS[rtype](v.replace(/\s+/g, ' ')) ? null : `records.types.errors.${rtype}`) : null
  }
}

const isUint8 = (v) => /^\d+$/.test(v) && Number(v) <= 255
const isHex = (v) => /^[0-9a-f]+$/i.test(v) && v.length % 2 === 0
// Digest lengths in hex by type: SSHFP (RFC 4255, 6594), TLSA matching (RFC 6698), DS (RFC 4509, 6605).
const SSHFP_HEX = { 1: 40, 2: 64 }
const TLSA_HEX = { 1: 64, 2: 128 }
const DS_HEX = { 1: 40, 2: 64, 4: 96 }
const hexOf = (lengths, kind, hex) => isHex(hex) && (!lengths[Number(kind)] || hex.length === lengths[Number(kind)])
const SVC_PARAM = /^[a-z0-9-]+(=("[^"]*"|[^\s"]+))?$/i
const LOC_RE = new RegExp(
  '^(\\d{1,2})( \\d{1,2}( \\d{1,2}(\\.\\d{1,3})?)?)? [NS] (\\d{1,3})( \\d{1,2}( \\d{1,2}(\\.\\d{1,3})?)?)? [EW]' +
    ' -?\\d+(\\.\\d{1,2})?m?( \\d+(\\.\\d{1,2})?m?){0,3}$',
  'i',
)

// Shape of the B1-RRTYPES types; the server parses each value with dnspython again (400 per field).
const NEW_TYPE_CHECKS = {
  SSHFP: (v) => {
    const [alg, kind, hex, ...rest] = v.split(' ')
    return !rest.length && isUint8(alg) && isUint8(kind) && hexOf(SSHFP_HEX, kind, (hex || '').toLowerCase())
  },
  TLSA: (v) => {
    const [usage, selector, matching, ...data] = v.split(' ')
    return isUint8(usage) && isUint8(selector) && isUint8(matching) && data.length > 0 && hexOf(TLSA_HEX, matching, data.join(''))
  },
  DS: (v) => {
    const [tag, alg, kind, ...digest] = v.split(' ')
    return isUint16(tag) && isUint8(alg) && isUint8(kind) && digest.length > 0 && hexOf(DS_HEX, kind, digest.join(''))
  },
  HTTPS: (v) => svcbOk(v),
  SVCB: (v) => svcbOk(v),
  NAPTR: (v) => {
    const m = v.match(/^(\d+) (\d+) "([^"]*)" "([^"]*)" "((?:[^"\\]|\\.)*)" (\S+)$/)
    return Boolean(m) && isUint16(m[1]) && isUint16(m[2]) && isHost(m[6])
  },
  LOC: (v) => LOC_RE.test(v),
  URI: (v) => {
    const m = v.match(/^(\d+) (\d+) "([^"]+)"$/)
    return Boolean(m) && isUint16(m[1]) && isUint16(m[2])
  },
}

// "<priority> <target> [key=value ...]"; priority 0 is AliasMode and takes no parameters (RFC 9460).
function svcbOk(v) {
  const [priority, target, ...params] = v.split(' ')
  if (!isUint16(priority) || !target || !isHost(target)) return false
  if (Number(priority) === 0) return params.length === 0
  return params.every((p) => SVC_PARAM.test(p))
}

// Fields of the assisted entry per type: each composes one value line (composeRdata). Lists start
// on the current practice (Ed25519 and SHA-256 for SSHFP, DANE-EE SPKI SHA-256 for TLSA).
export const fieldDefaults = (rtype) =>
  Object.fromEntries((RDATA_FIELDS[rtype] || []).filter((f) => f.default).map((f) => [f.key, f.default]))
export const RDATA_FIELDS = {
  SSHFP: [
    { key: 'algorithm', options: ['1', '2', '3', '4', '6'], default: '4' },
    { key: 'fpType', options: ['1', '2'], default: '2' },
    { key: 'fingerprint', wide: true },
  ],
  TLSA: [
    { key: 'usage', options: ['0', '1', '2', '3'], default: '3' },
    { key: 'selector', options: ['0', '1'], default: '1' },
    { key: 'matching', options: ['0', '1', '2'], default: '1' },
    { key: 'data', wide: true },
  ],
  HTTPS: [{ key: 'priority' }, { key: 'target' }, { key: 'params', wide: true }],
  SVCB: [{ key: 'priority' }, { key: 'target' }, { key: 'params', wide: true }],
  NAPTR: [
    { key: 'order' },
    { key: 'preference' },
    { key: 'flags' },
    { key: 'services' },
    { key: 'regexp', wide: true },
    { key: 'replacement' },
  ],
  LOC: [{ key: 'latitude' }, { key: 'longitude' }, { key: 'altitude' }, { key: 'size' }],
  DS: [{ key: 'keyTag' }, { key: 'algorithm' }, { key: 'digestType', options: ['1', '2', '4'], default: '2' }, { key: 'digest', wide: true }],
  URI: [{ key: 'priority' }, { key: 'weight' }, { key: 'target', wide: true }],
}

// Decimal degrees to LOC's "d m s.sss H".
function dms(value, pos, neg) {
  const n = Number(value)
  const hemi = n < 0 ? neg : pos
  let rest = Math.abs(n)
  const d = Math.floor(rest)
  rest = (rest - d) * 60
  const m = Math.floor(rest)
  const s = Math.round((rest - m) * 60 * 1000) / 1000
  return `${d} ${m} ${s.toFixed(3)} ${hemi}`
}

const quote = (v) => `"${String(v ?? '').replace(/(["\\])/g, '\\$1')}"`
const meters = (v) => `${String(v).trim().replace(/m$/i, '')}m`

// One value line from the assisted fields; '' while a required field is empty.
export function composeRdata(rtype, values) {
  const v = Object.fromEntries(Object.entries(values || {}).map(([k, x]) => [k, String(x ?? '').trim()]))
  const need = (...keys) => keys.every((k) => v[k] !== undefined && v[k] !== '')
  switch (rtype) {
    case 'SSHFP':
      return need('algorithm', 'fpType', 'fingerprint') ? `${v.algorithm} ${v.fpType} ${v.fingerprint.replace(/[\s:]/g, '').toLowerCase()}` : ''
    case 'TLSA':
      return need('usage', 'selector', 'matching', 'data') ? `${v.usage} ${v.selector} ${v.matching} ${v.data.replace(/\s/g, '').toLowerCase()}` : ''
    case 'DS':
      return need('keyTag', 'algorithm', 'digestType', 'digest') ? `${v.keyTag} ${v.algorithm} ${v.digestType} ${v.digest.replace(/\s/g, '').toLowerCase()}` : ''
    case 'HTTPS':
    case 'SVCB':
      return need('priority', 'target') ? [v.priority, v.target, v.params].filter(Boolean).join(' ') : ''
    case 'NAPTR':
      return need('order', 'preference', 'replacement')
        ? `${v.order} ${v.preference} ${quote(v.flags)} ${quote(v.services)} ${quote(v.regexp)} ${v.replacement}`
        : ''
    case 'LOC': {
      const lat = Number(v.latitude)
      const lon = Number(v.longitude)
      if (!need('latitude', 'longitude') || !Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return ''
      const alt = v.altitude ? meters(v.altitude) : '0m'
      return [dms(lat, 'N', 'S'), dms(lon, 'E', 'W'), alt, v.size ? meters(v.size) : ''].filter(Boolean).join(' ')
    }
    case 'URI':
      return need('priority', 'weight', 'target') ? `${v.priority} ${v.weight} ${quote(v.target)}` : ''
    default:
      return ''
  }
}

// TXT: one or more quoted strings of at most 255 characters, or a bare word.
function txtSegmentsOk(v) {
  if (!v.startsWith('"')) return !/\s/.test(v) && v.length <= 255
  const segments = v.match(/"((?:[^"\\]|\\.)*)"/g)
  if (!segments) return false
  const rest = v.replace(/"((?:[^"\\]|\\.)*)"/g, '').trim()
  return rest === '' && segments.every((s) => s.length - 2 <= 255)
}

// A bare TXT value with spaces is quoted for the user, as nsupdate would need.
export function normalizeRdata(rtype, rdata) {
  const v = String(rdata || '').trim().replace(/\s+/g, ' ')
  if (rtype === 'TXT' && !v.startsWith('"') && /\s/.test(v)) return `"${v.replace(/"/g, '\\"')}"`
  if (['CNAME', 'PTR', 'NS', 'DNAME'].includes(rtype)) return v.toLowerCase()
  // Hex digests as the server prints them: lowercase, in one piece.
  if (['SSHFP', 'TLSA', 'DS'].includes(rtype)) {
    const parts = v.split(' ')
    return [...parts.slice(0, rtype === 'SSHFP' ? 2 : 3), parts.slice(rtype === 'SSHFP' ? 2 : 3).join('').toLowerCase()].join(' ')
  }
  return v
}

export function splitRdata(text) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

export function rrsetText(rrset) {
  if (!rrset) return ''
  return (rrset.rdata || []).map((r) => `${rrset.name} ${rrset.ttl} IN ${rrset.rtype} ${r}`).join('\n')
}

// Minimal unified diff for the local before/after preview (the plan carries the server's).
export function localDiff(before, after, label = 'zone') {
  const a = rrsetText(before).split('\n').filter(Boolean)
  const b = rrsetText(after).split('\n').filter(Boolean)
  if (a.join('\n') === b.join('\n')) return ''
  const lines = [`--- a/${label}`, `+++ b/${label}`, `@@ -1,${a.length} +1,${b.length} @@`]
  for (const line of a) lines.push(b.includes(line) ? ` ${line}` : `-${line}`)
  for (const line of b) if (!a.includes(line)) lines.push(`+${line}`)
  return `${lines.join('\n')}\n`
}

// Checks the whole form; returns { errors: {field: key}, rrset } where rrset is the "after" RRset.
export function validateForm(form, zone) {
  const errors = {}
  const rtype = String(form.rtype || '').toUpperCase()
  if (!validOwner(form.owner, zone)) errors.owner = 'owner'
  else if (!validOwner(form.owner, zone, rtype)) errors.owner = 'hostOwner'
  if (!EDITABLE_TYPES.includes(rtype)) errors.rtype = 'type'
  const ttl = Number(form.ttl)
  if (String(form.ttl).trim() === '' || !Number.isInteger(ttl) || ttl < 0 || ttl > MAX_TTL) errors.ttl = 'ttl'
  const values = splitRdata(form.rdata)
  if (values.length === 0) errors.rdata = 'rdataEmpty'
  else if (SINGLETON_TYPES.includes(rtype) && values.length > 1) errors.rdata = rtype === 'CNAME' ? 'singleton' : 'records.types.errors.singleton'
  else {
    const bad = values.map((v) => validateRdata(rtype, v)).find(Boolean)
    if (bad) errors.rdata = bad
  }
  const normalized = [...new Set(values.map((v) => normalizeRdata(rtype, v)))]
  const rrset = { name: absoluteName(form.owner, zone), rtype, ttl, rdata: normalized }
  return { errors, rrset }
}

// The Change for POST /dns/zones/{zone}/records/plan (target grammar of section 6).
export function buildChange({ zone, mode, before, after }) {
  const z = absZone(zone)
  const subject = mode === 'delete' ? before : after
  const owner = relativeName(subject.name, z)
  if (mode === 'delete') {
    return { op: 'delete', target: `${z}/${owner}/${before.rtype}`, before, after: null, node_ids: [] }
  }
  // An edit that renames or retypes the RRset is a delete of the old one plus an add.
  if (mode === 'edit' && before && (before.name !== after.name || before.rtype !== after.rtype)) {
    return [
      { op: 'delete', target: `${z}/${relativeName(before.name, z)}/${before.rtype}`, before, after: null, node_ids: [] },
      { op: 'add', target: `${z}/${owner}/${after.rtype}`, before: null, after: { name: after.name, rtype: after.rtype, ttl: after.ttl, rdata: after.rdata }, node_ids: [] },
    ]
  }
  const op = mode === 'edit' || (before && mode === 'add') ? 'replace' : 'add'
  return { op, target: `${z}/${owner}/${after.rtype}`, before: before || null, after: { name: after.name, rtype: after.rtype, ttl: after.ttl, rdata: after.rdata }, node_ids: [] }
}

export function buildChanges(args) {
  return [].concat(buildChange(args))
}

export const isEditableType = (rtype) => EDITABLE_TYPES.includes(String(rtype).toUpperCase())

export const ADDRESS_TYPES = ['A', 'AAAA']
export const isAddressType = (rtype) => ADDRESS_TYPES.includes(String(rtype || '').toUpperCase())

// The editor's PTR option from POST /dns/ptr/coverage items: enabled when a reverse zone served
// by the cluster covers an address (on delete: when a PTR points to the name), else the reason.
export function ptrOption({ mode, before, after, coverage }) {
  if (!coverage) return { enabled: false, reason: null, conflicts: [], uncovered: [], zones: [], stays: [] }
  const covered = coverage.filter((i) => i.covered)
  if (mode === 'delete') {
    const pointing = covered.filter((i) => i.points_here)
    return {
      enabled: pointing.length > 0,
      reason: pointing.length ? null : 'noPtrHere',
      conflicts: [],
      uncovered: [],
      zones: [...new Set(pointing.map((i) => i.reverse_zone))],
      stays: [],
    }
  }
  const kept = new Set(before?.rdata || [])
  // Without `after`, every address of the coverage is one the record set will hold.
  const wanted = after ? new Set(after) : null
  const isWanted = (i) => !wanted || wanted.has(i.ip)
  return {
    enabled: covered.length > 0,
    reason: covered.length ? null : coverage.find((i) => i.reason)?.reason || 'no_reverse_zone',
    // Only a new address replaces a PTR naming another host; the plan then asks for confirmation.
    conflicts: covered.filter((i) => i.conflict && !kept.has(i.ip) && isWanted(i)),
    uncovered: coverage.filter((i) => !i.covered && isWanted(i)).map((i) => i.ip),
    zones: [...new Set(covered.map((i) => i.reverse_zone))],
    // Removed addresses whose PTR still names the record: left behind when the option is off.
    stays: covered.filter((i) => !isWanted(i) && (i.current || []).includes(before?.name)).map((i) => i.ip),
  }
}
