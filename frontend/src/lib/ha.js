// SPDX-License-Identifier: Apache-2.0
// Kea keeps in-touch true after the first heartbeat; an outage shows as communication-interrupted.
export function partnerLost(partner) {
  return !!partner && (partner.in_touch === false || partner.communication_interrupted === true)
}

// Service state from Kea's status-get dhcp-state: undefined when the server did not report it.
export function dhcpServiceState(status) {
  const st = status?.['dhcp-state']
  if (!st || typeof st !== 'object') return { enabled: undefined, userDisabled: undefined }
  const userDisabled = !!st['disabled-by-user']
  const globally = st['globally-disabled']
  return { enabled: typeof globally === 'boolean' ? !globally : !userDisabled, userDisabled }
}
