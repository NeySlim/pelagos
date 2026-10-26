// SPDX-License-Identifier: Apache-2.0
// A node's clock as the nodes table shows it: the offset against the node serving the page
// (measured on the last status exchange, within half its round trip) and the NTP state the
// node reports. Tones follow the alert thresholds (settings checks.clock_skew_*_seconds).

export const CLOCK_WARNING_SECONDS = 5
export const CLOCK_CRITICAL_SECONDS = 30

// The smallest skew the measurement allows: what the thresholds compare against.
export function skewFloor(clock) {
  const offset = Number(clock?.offset)
  if (clock?.offset === null || clock?.offset === undefined || Number.isNaN(offset)) return null
  return Math.max(0, Math.abs(offset) - Math.abs(Number(clock.uncertainty) || 0))
}

export function skewTone(clock, warning = CLOCK_WARNING_SECONDS, critical = CLOCK_CRITICAL_SECONDS) {
  const floor = skewFloor(clock)
  if (floor === null) return 'unknown'
  if (floor >= critical) return 'danger'
  if (floor >= warning) return 'warning'
  return 'success'
}

// "+0.012 s", "-42.0 s": three decimals under a second, one above.
export function formatOffset(offset) {
  const value = Number(offset)
  if (offset === null || offset === undefined || Number.isNaN(value)) return '-'
  const digits = Math.abs(value) < 1 ? 3 : 1
  return `${value >= 0 ? '+' : '-'}${Math.abs(value).toFixed(digits)} s`
}

// 'synced', 'unsynced' (NTP says so, or no time service runs) or 'unknown'.
export function ntpState(clock) {
  const ntp = clock?.ntp
  if (!ntp || typeof ntp !== 'object') return 'unknown'
  if (ntp.synchronized === false || ntp.ntp_enabled === false) return 'unsynced'
  if (ntp.synchronized === true) return 'synced'
  return 'unknown'
}
