// SPDX-License-Identifier: Apache-2.0
// Kea configuration file versus running configuration (architecture section 9): which files
// diverge, and the adopt plan to build for an engine ('v4', 'v6' or 'd2').
import { api } from '../../services/api'

export function divergedFiles(items) {
  return (items || []).filter((item) => item && item.diverged)
}

// `nodeId`: the node that holds the file; undefined for this node.
export function adoptCall(engine, source, nodeId) {
  return engine === 'd2' ? api.d2.adoptPlan(source, nodeId) : api.dhcp.adoptPlan(engine, source, nodeId)
}

const ENGINES = { kea4: 'v4', kea6: 'v6', d2: 'd2' }

// The engine whose file an alert is about: config_divergence alerts with subject
// `<engine>:config-file` (kea4, kea6, d2); null for any other alert.
export function fileAlertEngine(alert) {
  if (!alert || alert.kind !== 'config_divergence') return null
  const match = /^(kea4|kea6|d2):config-file$/.exec(alert.subject || '')
  return match ? ENGINES[match[1]] : null
}

// Where a diverged file is: 'here' (this node), 'other' (a peer builds the plan), or 'unknown'
// while the node list has not loaded (no adopt button then: the target node is not known).
export function adoptPlace(item, selfId) {
  if (!selfId) return 'unknown'
  return item?.node_id === selfId ? 'here' : 'other'
}

// Whether an `alerts` WebSocket message can change the file status of `engine`: only
// config_divergence alerts about that engine's file (pool alerts update every poll).
export function affectsFileStatus(message, engine) {
  const alert = message?.data
  if (!alert || typeof alert !== 'object') return false
  return fileAlertEngine(alert) === engine
}
