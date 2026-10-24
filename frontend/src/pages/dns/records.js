// SPDX-License-Identifier: Apache-2.0
// Pure helpers for the record editor: owner names, rdata validation per type,
// presentation text of an RRset and the Change sent to POST .../records/plan.

// Types the editor offers; SOA and DNSSEC types stay with BIND (design section 4).
export const EDITABLE_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR', 'NS', 'CAA', 'DHCID']
export const READ_ONLY_TYPES = ['SOA', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDS', 'CDNSKEY', 'TYPE65534']
export const SINGLETON_TYPES = ['CNAME']
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

export function validOwner(owner, zone) {
  const o = String(owner || '').trim()
  if (!o || o === '@') return true
  const abs = absoluteName(o, zone)
  if (abs.length > 254) return false
  if (o.endsWith('.') && abs !== absZone(zone) && !abs.endsWith(`.${absZone(zone)}`)) return false
  const labels = abs.slice(0, -1).split('.')
  return labels.every((label, i) => LABEL.test(label) && (label !== '*' || i === 0))
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

const isHost =(v) => v === '.' || /^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.?$/i.test(v)
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
    default:
      return null
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
  if (['CNAME', 'PTR', 'NS'].includes(rtype)) return v.toLowerCase()
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
  if (!EDITABLE_TYPES.includes(rtype)) errors.rtype = 'type'
  const ttl = Number(form.ttl)
  if (String(form.ttl).trim() === '' || !Number.isInteger(ttl) || ttl < 0 || ttl > MAX_TTL) errors.ttl = 'ttl'
  const values = splitRdata(form.rdata)
  if (values.length === 0) errors.rdata = 'rdataEmpty'
  else if (SINGLETON_TYPES.includes(rtype) && values.length > 1) errors.rdata = 'singleton'
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
      { op: 'add', target: `${z}/${owner}/${after.rtype}`, before: null, after: { ttl: after.ttl, rdata: after.rdata }, node_ids: [] },
    ]
  }
  const op = mode === 'edit' || (before && mode === 'add') ? 'replace' : 'add'
  return { op, target: `${z}/${owner}/${after.rtype}`, before: before || null, after: { ttl: after.ttl, rdata: after.rdata }, node_ids: [] }
}

export function buildChanges(args) {
  return [].concat(buildChange(args))
}

export const isEditableType = (rtype) => EDITABLE_TYPES.includes(String(rtype).toUpperCase())
