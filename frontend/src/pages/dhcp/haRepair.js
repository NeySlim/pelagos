// SPDX-License-Identifier: Apache-2.0
// HA in `terminated` (architecture section 15, ha_terminated): which servers are stuck, what
// Kea measured before it stopped, and the probable cause the collector found.

export const SKEW_SHOWN_SECONDS = 5

// Servers (one entry per relationship) whose HA service terminated.
export function terminatedServers(items) {
  return (items || []).filter((h) => h && h.enabled !== false && h.state === 'terminated')
}

// The clock skews Kea measured with each partner (status-get `clock-skew`), worth showing.
export function keaSkews(items) {
  const out = []
  for (const h of terminatedServers(items)) {
    const skew = h.partner?.clock_skew
    if (typeof skew === 'number' && Math.abs(skew) >= SKEW_SHOWN_SECONDS) {
      out.push({ server: h.server_name, partner: h.partner?.server_name || null, seconds: Math.abs(skew) })
    }
  }
  return out
}

// Probable causes of the open ha_terminated alerts of `engine`, one per distinct cause: the
// alert's title carries it as a nested message (alert.ha_cause.*).
export function terminatedCauses(alerts, engine) {
  const seen = new Map()
  for (const a of alerts || []) {
    if (a?.kind !== 'ha_terminated' || a.state === 'resolved' || (engine && a.engine !== engine)) continue
    const cause = a.title_message?.params?.cause
    const code = a.details?.cause || 'unknown'
    if (!seen.has(code)) seen.set(code, { code, message: cause || null, title: a.title })
  }
  return [...seen.values()]
}
