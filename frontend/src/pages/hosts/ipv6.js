// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 (architecture section 27): the server filters, the class badges and the
// exception targets of a row (ipv6_missing_aaaa and ipv6_stale_aaaa keys).

export const IPV6_TAB = 'ipv6'
export const FILTERS = ['missing_aaaa', 'missing_ptr', 'stale', 'unknown', 'random_mac']
export const CLASSES = ['eui64', 'stable', 'temporary', 'unknown']
export const CLASS_VARIANT = { eui64: 'teal', stable: 'success', temporary: 'gray', unknown: 'warning' }
const PROPOSABLE = new Set(['eui64', 'stable'])

export const validFilter = (value) => (FILTERS.includes(value) ? value : '')

// The hosts page link of an IPv6 view, as the alert links and the URL state use it; old and
// new prefixes (the ipv6_stale_aaaa details) open the prefix replacement prefilled.
export function ipv6Path({ filter, zone, reverse, oldPrefix, newPrefix } = {}) {
  const q = new URLSearchParams({ tab: IPV6_TAB })
  if (filter) q.set('filter', filter)
  if (zone) q.set('zone', zone)
  if (reverse) q.set('reverse', reverse)
  if (oldPrefix && newPrefix) {
    q.set('old', oldPrefix)
    q.set('new', newPrefix)
  }
  return `/hosts?${q.toString()}`
}

const DAY_MS = 86400000

// AAAA records the server counts as stale (row.stale, the ipv6_stale_aaaa rule).
export const staleAaaa = (row) => row.stale || []

// The server's notion of a current address (observed[].current: eui64 or stable, seen within
// stable_min_days); a row without the flag falls back to a proposable address seen in the last day.
const isCurrent = (o, now) => (typeof o.current === 'boolean' ? o.current : PROPOSABLE.has(o.class) && Boolean(o.last_seen) && now - Date.parse(o.last_seen) <= DAY_MS)

// What an admin may except on a row: the whole host or one address for the missing AAAA check
// (only while it applies: a proposal and no current address with an AAAA; the proposal and the
// current addresses without AAAA after it, the ones before it being excepted already), and the
// stale records for the stale check. Keys use the API's normalized MAC and address.
export function exceptionTargets(row, now = Date.now()) {
  const out = []
  const aaaa = new Set(row.aaaa || [])
  const observed = row.observed || []
  const current = observed.filter((o) => isCurrent(o, now))
  const covered = current.some((o) => aaaa.has(o.address))
  let missing = []
  if (row.proposal && !covered) {
    const from = Math.max(0, observed.findIndex((o) => o.address === row.proposal.address))
    missing = observed.slice(from).filter((o) => isCurrent(o, now) && !aaaa.has(o.address)).map((o) => o.address)
    if (!missing.includes(row.proposal.address)) missing.unshift(row.proposal.address)
  }
  if (row.mac && !row.excepted && missing.length) {
    out.push({ kind: 'ipv6_missing_aaaa', key: `mac:${row.mac}`, scope: 'host' })
  }
  for (const a of missing) out.push({ kind: 'ipv6_missing_aaaa', key: `addr:${a}`, scope: 'address', address: a })
  const stale = staleAaaa(row)
  if (stale.length && row.mac) out.push({ kind: 'ipv6_stale_aaaa', key: `mac:${row.mac}`, scope: 'host' })
  for (const a of stale) out.push({ kind: 'ipv6_stale_aaaa', key: `addr:${a}`, scope: 'address', address: a })
  return out
}

// "ns2 (neighbors): timed out" lines of meta.unavailable.
export function unavailableLines(unavailable = [], nameOf = (id) => id) {
  return unavailable.map((u) => `${nameOf(u.node_id)} (${u.source}${u.error ? `: ${u.error}` : ''})`)
}

// IPv6 address as 32 hex nibbles, or null when it is not one (no embedded IPv4 form).
export function expandIpv6(text) {
  const s = String(text || '').trim().toLowerCase()
  if (!/^[0-9a-f:]+$/.test(s) || s.split('::').length > 2) return null
  const [head, tail] = s.split('::')
  const h = head ? head.split(':') : []
  const t = tail ? tail.split(':') : []
  const fill = s.includes('::') ? 8 - h.length - t.length : 0
  if ((s.includes('::') && fill < 1) || (!s.includes('::') && h.length !== 8)) return null
  const groups = [...h, ...Array(fill).fill('0'), ...t]
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups.map((g) => g.padStart(4, '0')).join('')
}

function compress(nibbles) {
  const groups = nibbles.match(/.{4}/g).map((g) => g.replace(/^0+(?=.)/, ''))
  let best = [-1, 0]
  for (let i = 0; i < 8; i += 1) {
    let j = i
    while (j < 8 && groups[j] === '0') j += 1
    if (j - i > best[1] && j - i > 1) best = [i, j - i]
  }
  if (best[0] < 0) return groups.join(':')
  return `${groups.slice(0, best[0]).join(':')}::${groups.slice(best[0] + best[1]).join(':')}`
}

// "2001:db8::/64" as {nibbles, len} with the host bits cleared, or null.
export function parsePrefix(text) {
  const m = /^([^/]+)\/(\d{1,3})$/.exec(String(text || '').trim())
  const nibbles = m && expandIpv6(m[1])
  const len = m ? Number(m[2]) : NaN
  if (!nibbles || !(len >= 0 && len <= 128)) return null
  const bits = [...nibbles].map((n) => parseInt(n, 16).toString(2).padStart(4, '0')).join('')
  const masked = bits.slice(0, len).padEnd(128, '0')
  const out = masked.match(/.{4}/g).map((b) => parseInt(b, 2).toString(16)).join('')
  return { nibbles: out, len, text: `${compress(out)}/${len}` }
}

// The /64 holding an address, as text.
export const prefix64 = (address) => {
  const p = parsePrefix(`${address}/64`)
  return p ? p.text : null
}

// The ip6.arpa zone the reverse-zone plan builds for a prefix (cut at the nibble at or above it).
export function reverseZoneName(prefix) {
  const p = parsePrefix(prefix)
  if (!p) return null
  const nibbles = p.nibbles.slice(0, Math.floor(p.len / 4))
  return `${[...nibbles].reverse().map((n) => `${n}.`).join('')}ip6.arpa.`
}

// Errors of the replace-prefix form (route rules: both prefixes, same length /16 to /124, apart).
export function prefixSwapErrors(oldText, newText) {
  const errors = {}
  const a = parsePrefix(oldText)
  const b = parsePrefix(newText)
  if (!a) errors.old_prefix = 'format'
  if (!b) errors.new_prefix = 'format'
  if (a && (a.len < 16 || a.len > 124)) errors.old_prefix = 'length'
  if (b && (b.len < 16 || b.len > 124)) errors.new_prefix = 'length'
  if (a && b && !errors.old_prefix && !errors.new_prefix) {
    if (a.len !== b.len) errors.new_prefix = 'sameLength'
    else if (a.nibbles === b.nibbles) errors.new_prefix = 'overlap'
  }
  return errors
}

// A prefix swap the stale rows suggest: the /64 of a stale AAAA and the /64 of a current
// address of the same host outside it (as the ipv6_stale_aaaa alert reads a provider change).
export function suggestPrefixSwap(rows = []) {
  for (const row of rows) {
    for (const stale of staleAaaa(row)) {
      const old = prefix64(stale)
      const cur = (row.observed || []).find((o) => o.current && prefix64(o.address) !== old)
      if (old && cur) return { old_prefix: old, new_prefix: prefix64(cur.address) }
    }
  }
  return null
}

// The owner the selection plan writes for a row: the proposal's name, else the row's name.
export const ownerOf = (row) => row.proposal?.name || row.name || null

const dotted = (name) => (String(name).endsWith('.') ? String(name).toLowerCase() : `${String(name).toLowerCase()}.`)

// Whether the plan can write the row's owner: a proposal names one in a writable zone; a row
// name must be a FQDN under one of the forward `zones` (a short lease name never is).
// Without the zone list (not loaded), only the name is required.
export function ownerWritable(row, zones = null) {
  if (row.proposal?.name) return true
  if (!row.name) return false
  if (!zones?.length) return true
  const name = dotted(row.name)
  return zones.some((z) => {
    const zone = dotted(z)
    return name === zone || name.endsWith(`.${zone}`)
  })
}

// Observed addresses a selection may hold: a writable owner, an address not flagged past
// (`current: false`, a prefix the host left) unless still unknown, never a temporary one, and not already complete (an AAAA with its PTR); an AAAA
// without PTR gets only its PTR.
export function selectableAddresses(row, zones = null) {
  if (!ownerOf(row) || !ownerWritable(row, zones)) return []
  const aaaa = new Set(row.aaaa || [])
  const missing = new Set(row.ptr_missing || [])
  const ptr = new Set(row.ptr || [])
  return (row.observed || [])
    .filter((o) => o.class !== 'temporary' && (o.current !== false || o.class === 'unknown'))
    .filter((o) => !aaaa.has(o.address) || missing.has(o.address) || !ptr.has(o.address))
    .map((o) => o.address)
}

// The address a row's checkbox selects: the proposal, else the first selectable current one.
export function defaultAddress(row, zones = null) {
  const selectable = selectableAddresses(row, zones)
  if (row.proposal && selectable.includes(row.proposal.address)) return row.proposal.address
  const current = (row.observed || []).find((o) => o.current && selectable.includes(o.address))
  return current ? current.address : null
}

export const selectionKey = (hostKey, address) => `${hostKey}|${address}`

// reverse_zones of a 409 precondition_failed answer, or null for any other error.
export function missingReverseZones(err) {
  const zones = err?.status === 409 ? err.problem?.reverse_zones : null
  return Array.isArray(zones) && zones.length ? zones : null
}

// The body of POST /hosts/ipv6/reverse-zone/plan for an entry of `reverse_zones`: its placement
// (the primary and the copies of the host's forward zone) when the server gave one.
export function reverseZoneBody(z) {
  return {
    prefix: z.prefix,
    ...(z.view && z.view !== '_default' ? { view: z.view } : {}),
    ...(z.node_id ? { node_id: z.node_id } : {}),
    ...(Array.isArray(z.node_ids) ? { node_ids: z.node_ids } : {}),
  }
}
