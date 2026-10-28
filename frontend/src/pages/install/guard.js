// SPDX-License-Identifier: Apache-2.0
// The HA listener guard (GET /install/security/ha-guard) as the security page shows it.

export const ADOPT_FINDING = 'kea:kea_ha_guard_unmanaged:kea_ha_guard'

// State badge: set up by hand, differs from Pelagos, managed, or absent.
export function guardBadge(guard) {
  if (guard?.legacy) return { key: 'legacy', variant: 'warning' }
  if (guard?.managed && guard.differences?.length) return { key: 'drift', variant: 'warning' }
  if (guard?.managed) return { key: 'managed', variant: 'success' }
  return { key: 'absent', variant: 'secondary' }
}

// One address or prefix per line (commas and spaces separate too); the backend validates them.
export const parsePeers = (text) => [...new Set(String(text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean))]
