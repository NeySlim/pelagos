// SPDX-License-Identifier: Apache-2.0
// What the hosts screens derive from a Host (architecture section 4): which parts
// of the join exist and which of them disagree.

const absolute = (name) => {
  const lower = String(name || '').toLowerCase()
  return !lower || lower.endsWith('.') ? lower : `${lower}.`
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
    reservationMismatch: Boolean(lease && reservation?.ip_address && reservation.ip_address !== lease.ip_address),
    inconsistent: (host.alerts || []).length > 0,
  }
}
