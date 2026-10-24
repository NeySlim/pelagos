// SPDX-License-Identifier: Apache-2.0
// Kea configuration file versus running configuration (architecture section 9): which files
// diverge, and the adopt plan to build for an engine ('v4', 'v6' or 'd2').
import { api } from '../../services/api'

export function divergedFiles(items) {
  return (items || []).filter((item) => item && item.diverged)
}

export function adoptCall(engine, source) {
  return engine === 'd2' ? api.d2.adoptPlan(source) : api.dhcp.adoptPlan(engine, source)
}

const ENGINES = { kea4: 'v4', kea6: 'v6', d2: 'd2' }

// The engine whose file an alert is about: config_divergence alerts with subject
// `<engine>:config-file` (kea4, kea6, d2); null for any other alert.
export function fileAlertEngine(alert) {
  if (!alert || alert.kind !== 'config_divergence') return null
  const match = /^(kea4|kea6|d2):config-file$/.exec(alert.subject || '')
  return match ? ENGINES[match[1]] : null
}
