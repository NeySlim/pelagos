// SPDX-License-Identifier: Apache-2.0
// PTR coverage, PTR changes added to record plans, orphan PTRs and consistency exceptions in the
// mock, with the shapes of services/ptr_service.py and services/exceptions_service.py.

const ADDRESS_TYPES = new Set(['A', 'AAAA'])
const isReverse = (zone) => zone.endsWith('.arpa.')

export function ptrHelpers(state, { reverseToIp, v6Nibbles, canonicalV6 }) {
  const canonical = (value) => {
    const v = String(value || '').trim().toLowerCase()
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every((p) => Number(p) <= 255)) return v
    if (v.includes(':') && /^[0-9a-f:]+$/.test(v) && v.split('::').length <= 2) return canonicalV6(v6Nibbles(v))
    return null
  }
  const ptrName = (ip) => (ip.includes(':') ? `${v6Nibbles(ip).split('').reverse().join('.')}.ip6.arpa.` : `${ip.split('.').reverse().join('.')}.in-addr.arpa.`)
  const servedZones = () => state.zones.filter((z) => ['primary', 'secondary'].includes(z.kind))
  const bestZone = (name, view, reverse) =>
    servedZones()
      .filter((z) => (z.view || '_default') === (view || '_default') && isReverse(z.name) === reverse && (name === z.name || name.endsWith(`.${z.name}`)))
      .sort((a, b) => b.name.length - a.name.length)[0] || null
  const rrset = (zone, name, rtype) => (state.records[zone] || []).find((r) => r.name === name && r.rtype === rtype) || null

  function coverage(body) {
    const view = body.reverse_view || body.view || '_default'
    const target = body.name ? String(body.name).toLowerCase().replace(/\.?$/, '.') : null
    return (body.addresses || []).map((raw) => {
      const ip = canonical(raw)
      const item = { ip: ip || String(raw), view, ptr_name: null, reverse_zone: null, covered: false, reason: null, current: [], points_here: false, conflict: false }
      if (!ip) return { ...item, reason: 'invalid' }
      item.ptr_name = ptrName(ip)
      const zone = bestZone(item.ptr_name, view, true)
      if (!zone) return { ...item, reason: 'no_reverse_zone' }
      const current = rrset(zone.name, item.ptr_name, 'PTR')?.rdata || []
      return { ...item, reverse_zone: zone.name, covered: true, current: [...current].sort(), points_here: Boolean(target && current.includes(target)), conflict: Boolean(target && current.length && !current.includes(target)) }
    })
  }

  // The PTR changes of record changes ({ op, before, after } RRsets), per reverse zone.
  function ptrChanges(normalized, ptr, view) {
    const sync = ptr.sync !== false
    const del = ptr.delete ?? sync
    const removals = new Map()
    const additions = new Map()
    for (const c of normalized) {
      const rtype = c.target.split('/').pop()
      if (!ADDRESS_TYPES.has(rtype)) continue
      const owner = (c.before || c.after).name
      const before = new Set((c.before?.rdata || []).map(canonical).filter(Boolean))
      const after = new Set((c.after?.rdata || []).map(canonical).filter(Boolean))
      const ttl = c.after?.ttl ?? c.before?.ttl ?? 3600
      if (c.op === 'delete') {
        if (del) for (const ip of before) removals.set(ip, [...(removals.get(ip) || []), owner])
        continue
      }
      if (!sync) continue
      for (const ip of before) if (!after.has(ip)) removals.set(ip, [...(removals.get(ip) || []), owner])
      for (const ip of after) additions.set(ip, [...(additions.get(ip) || []), { owner, ttl, fresh: !before.has(ip) }])
    }
    const out = []
    const replaced = []
    for (const ip of new Set([...removals.keys(), ...additions.keys()])) {
      const name = ptrName(ip)
      const zone = bestZone(name, view, true)
      if (!zone) continue
      const current = rrset(zone.name, name, 'PTR')
      const have = current?.rdata || []
      let want = have.filter((t) => !(removals.get(ip) || []).includes(t))
      let ttl = current?.ttl
      for (const add of additions.get(ip) || []) {
        if (want.includes(add.owner)) continue
        if (add.fresh) {
          const others = want.filter((t) => !(additions.get(ip) || []).some((a) => a.owner === t))
          if (others.length) replaced.push({ ip, targets: others })
          want = [...want.filter((t) => !others.includes(t)), add.owner]
        } else if (!want.length) want = [add.owner]
        ttl = ttl ?? add.ttl
      }
      if ([...want].sort().join() === [...have].sort().join()) continue
      const target = `${zone.name}/${name}/PTR`
      if (!want.length) out.push({ op: 'delete', target, before: current, after: null, node_ids: [] })
      else out.push({ op: current ? 'replace' : 'add', target, before: current, after: { name, rtype: 'PTR', ttl: ttl ?? 3600, rdata: want }, node_ids: [] })
    }
    return { changes: out, replaced }
  }

  function orphans() {
    const forward = new Map()
    for (const z of servedZones().filter((z) => !isReverse(z.name))) {
      for (const r of state.records[z.name] || []) {
        if (!ADDRESS_TYPES.has(r.rtype)) continue
        forward.set(r.name, [...(forward.get(r.name) || []), ...r.rdata.map(canonical).filter(Boolean)])
      }
    }
    const fwdZones = servedZones().filter((z) => !isReverse(z.name)).map((z) => z.name)
    const items = []
    for (const z of servedZones().filter((z) => isReverse(z.name))) {
      const records = state.records[z.name] || []
      const dhcid = new Set(records.filter((r) => r.rtype === 'DHCID').map((r) => r.name))
      for (const r of records.filter((x) => x.rtype === 'PTR')) {
        const ip = reverseToIp(r.name)
        if (!ip) continue
        const rtype = ip.includes(':') ? 'AAAA' : 'A'
        for (const target of r.rdata) {
          const addresses = forward.get(target) || []
          if (addresses.includes(ip)) continue
          const zone = fwdZones.filter((f) => target === f || target.endsWith(`.${f}`)).sort((a, b) => b.length - a.length)[0] || null
          const key = `${ip}|${target}`
          const exception = exceptions().find((e) => e.kind === 'ptr_mismatch' && e.key === key) || null
          const lease = (state.leases[rtype === 'A' ? 'v4' : 'v6'] || []).find((l) => l.ip_address === ip)
          // As the backend: an A is proposed only when a lease of the target's name holds the address.
          const active = lease && lease.state === 'default'
          const holder = String((active && lease.hostname) || '').toLowerCase().replace(/\.$/, '')
          const holds = Boolean(holder) && (holder.includes('.') ? `${holder}.` === target : target.split('.')[0] === holder)
          const sameFamily = addresses.some((a) => a.includes(':') === (rtype === 'AAAA'))
          const ddns = dhcid.has(r.name)
          const fix = !zone ? null : ddns && active ? 'wait' : !sameFamily && holds ? 'create_a' : 'delete'
          items.push({
            ip, name: r.name, target, rtype, zone: z.name, view: z.view || '_default',
            category: zone ? 'orphan' : 'external', target_zone: zone, target_addresses: addresses,
            ddns, fix, held: Boolean(active), stale: fix === 'delete' && !active,
            exception_key: key, excepted: Boolean(exception), exception,
            lease: lease ? { state: lease.state, hostname: lease.hostname, cltt: lease.cltt, expires_at: lease.expires_at } : null,
            last_seen: lease?.cltt ? { at: lease.cltt, source: 'lease' } : null,
          })
        }
      }
    }
    const counts = { orphan: 0, external: 0, excepted: 0, stale: 0 }
    for (const i of items) {
      counts[i.excepted ? 'excepted' : i.category] += 1
      if (i.stale && !i.excepted) counts.stale += 1
    }
    return { items, counts, errors: {} }
  }

  function exceptions() {
    if (!state.exceptions) state.exceptions = []
    return state.exceptions
  }

  return { canonical, ptrName, bestZone, rrset, coverage, ptrChanges, orphans, exceptions }
}
