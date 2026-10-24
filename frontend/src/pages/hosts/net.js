// SPDX-License-Identifier: Apache-2.0
// Address helpers for the create-host form: which subnet holds an address, and
// which known reverse zone (in-addr.arpa or ip6.arpa) covers it.

const isV6 = (ip) => String(ip).includes(':')

// The 32 hex nibbles of an IPv6 address, or null when it does not parse.
export function ipv6Nibbles(ip) {
  const text = String(ip || '').toLowerCase()
  if (!/^[0-9a-f:]+$/.test(text)) return null
  const halves = text.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - head.length - tail.length
  if ((halves.length === 2 && missing < 1) || (halves.length === 1 && missing !== 0)) return null
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail]
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups.map((g) => g.padStart(4, '0')).join('')
}

const toBig = (ip) => {
  if (isV6(ip)) {
    const nibbles = ipv6Nibbles(ip)
    return nibbles === null ? null : BigInt(`0x${nibbles}`)
  }
  return String(ip).split('.').reduce((acc, p) => acc * 256n + BigInt(Number(p)), 0n)
}

export function inPrefix(ip, prefix) {
  const [base, bits] = String(prefix).split('/')
  if (!base || bits === undefined || isV6(base) !== isV6(ip)) return false
  const width = isV6(base) ? 128n : 32n
  const host = width - BigInt(Number(bits))
  const a = toBig(base)
  const b = toBig(ip)
  if (a === null || b === null) return false
  return a >> host === b >> host
}

// Smallest subnet containing the address.
export function subnetFor(ip, subnets = []) {
  return (
    subnets
      .filter((s) => inPrefix(ip, s.subnet))
      .sort((a, b) => Number(b.subnet.split('/')[1]) - Number(a.subnet.split('/')[1]))[0] || null
  )
}

// Longest reverse zone that covers the address, among the zones read from BIND.
export function reverseZoneFor(ip, zoneNames = []) {
  if (isV6(ip)) {
    const nibbles = ipv6Nibbles(ip)
    if (!nibbles) return null
    for (let keep = 31; keep >= 1; keep -= 1) {
      const name = `${nibbles.slice(0, keep).split('').reverse().join('.')}.ip6.arpa.`
      if (zoneNames.includes(name)) return name
    }
    return null
  }
  const octets = String(ip).split('.')
  for (let keep = 3; keep >= 1; keep -= 1) {
    const name = `${octets.slice(0, keep).reverse().join('.')}.in-addr.arpa.`
    if (zoneNames.includes(name)) return name
  }
  return null
}
