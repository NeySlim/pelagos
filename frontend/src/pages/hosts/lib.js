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

// Chips of the "Found in" column: one per part the host has. A missing record is drawn struck
// through only when the host's own inconsistency alerts expect it (an unmanaged zone or a client
// without DDNS raises none), and named AAAA for an IPv6 host.
export function presenceChips(host) {
  const f = hostFacts(host)
  const alerts = host.alerts || []
  const v6 = (host.ips || []).some((ip) => ip.includes(':')) && !(host.ips || []).some((ip) => !ip.includes(':'))
  const missingForward = alerts.find((a) => a.kind === 'lease_without_record' || a.kind === 'ipv6_missing_aaaa')
  const chips = []
  if (f.hasLease) chips.push({ key: 'lease', variant: 'purple' })
  if (f.hasReservation) chips.push({ key: 'reservation', variant: 'purple' })
  if (f.hasForward) chips.push({ key: 'forward', variant: 'primary', label: f.forwardTypes.join('/') })
  else if (missingForward) chips.push({ key: 'forward', absent: true, label: missingForward.details?.rtype || (v6 ? 'AAAA' : 'A') })
  if (f.hasPtr) chips.push({ key: 'ptr', variant: 'teal', label: 'PTR' })
  else if (alerts.some((a) => a.kind === 'ptr_mismatch')) chips.push({ key: 'ptr', absent: true, label: 'PTR' })
  return chips
}
