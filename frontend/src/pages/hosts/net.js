// SPDX-License-Identifier: Apache-2.0
// IPv4 helpers for the create-host form: which subnet holds an address, and which
// known in-addr.arpa zone covers it.

const toInt = (ip) => ip.split('.').reduce((acc, p) => acc * 256 + Number(p), 0)

export function inPrefix(ip, prefix) {
  const [base, bits] = String(prefix).split('/')
  if (!base || bits === undefined || !base.includes('.')) return false
  const size = 2 ** (32 - Number(bits))
  const start = Math.floor(toInt(base) / size) * size
  const n = toInt(ip)
  return n >= start && n < start + size
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
  const octets = ip.split('.')
  for (let keep = 3; keep >= 1; keep -= 1) {
    const name = `${octets.slice(0, keep).reverse().join('.')}.in-addr.arpa.`
    if (zoneNames.includes(name)) return name
  }
  return null
}
