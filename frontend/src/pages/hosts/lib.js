// SPDX-License-Identifier: Apache-2.0
// What the hosts screens derive from a Host (architecture section 4): which parts
// of the join exist and which of them disagree.

const absolute = (name) => {
  const lower = String(name || '').toLowerCase()
  return !lower || lower.endsWith('.') ? lower : `${lower}.`
}

// Addresses a reservation holds (v4 ip_address, v6 ip_addresses).
export const reservedIps = (reservation) =>
  reservation ? (reservation.ip_address ? [reservation.ip_address] : reservation.ip_addresses || []) : []

// A lease of one family disagrees with a reservation of the same family that does not list its address.
function reservationMismatch(lease, reservation) {
  const reserved = reservedIps(reservation)
  if (!lease || !reserved.length || lease.lease_type === 'IA_PD') return false
  const v6 = lease.ip_address.includes(':')
  const sameFamily = reserved.filter((ip) => ip.includes(':') === v6)
  return sameFamily.length > 0 && !sameFamily.includes(lease.ip_address)
}

export function hostFacts(host) {
  const records = host.records || []
  const forward = records.filter((r) => r.rtype === 'A' || r.rtype === 'AAAA')
  const ptr = records.filter((r) => r.rtype === 'PTR')
  const name = absolute(host.hostname)
  const lease = host.lease
  const reservation = host.reservation
  return {
    hasLease: Boolean(lease),
    hasReservation: Boolean(reservation),
    hasForward: forward.length > 0,
    hasPtr: ptr.length > 0,
    ptrMismatch: Boolean(name) && ptr.some((r) => !r.rdata.map(absolute).includes(name)),
    forwardTypes: [...new Set(forward.map((r) => r.rtype))].sort(),
    reservationMismatch: reservationMismatch(lease, reservation),
    inconsistent: (host.alerts || []).length > 0,
  }
}
