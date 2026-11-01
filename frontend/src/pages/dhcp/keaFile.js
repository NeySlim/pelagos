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

// Files whose Kea syntax warnings (an extra comma, with file, line and column) were found.
export function warnedFiles(items) {
  return (items || []).filter((item) => item && item.syntax_warnings?.length > 0)
}

// Files with comments and no include: the next Kea write copies the comments into user-context.
export function commentedFiles(items) {
  return (items || []).filter((item) => item && !item.includes && item.comments > 0)
}

// The engine a config_syntax_warning alert is about (subject `<engine>:config-syntax`), else null.
export function syntaxAlertEngine(alert) {
  if (!alert || alert.kind !== 'config_syntax_warning') return null
  const match = /^(kea4|kea6|d2):config-syntax$/.exec(alert.subject || '')
  return match ? ENGINES[match[1]] : null
}

// Where a diverged file is: 'here' (this node), 'other' (a peer builds the plan), or 'unknown'
// while the node list has not loaded (no adopt button then: the target node is not known).
export function adoptPlace(item, selfId) {
  if (!selfId) return 'unknown'
  return item?.node_id === selfId ? 'here' : 'other'
}

// Whether an `alerts` WebSocket message can change the file status of `engine`: only
// config_divergence and config_syntax_warning alerts about that engine's file (pool alerts update every poll).
export function affectsFileStatus(message, engine) {
  const alert = message?.data
  if (!alert || typeof alert !== 'object') return false
  return fileAlertEngine(alert) === engine || syntaxAlertEngine(alert) === engine
}

// The reconcile directions of a `<engine>:config-hash` config_divergence alert: one
// { family, source, target } per `details.reconcile` entry (two when both sides changed).
export function reconcileOptions(alert) {
  if (!alert || alert.kind !== 'config_divergence') return []
  const family = { kea4: 'v4', kea6: 'v6' }[alert.engine]
  if (!family) return []
  const seen = new Set()
  const out = []
  for (const r of alert.details?.reconcile || []) {
    const key = `${r?.source_node_id}>${r?.target_node_id}`
    if (!r?.source_node_id || !r?.target_node_id || r.source_node_id === r.target_node_id || seen.has(key)) continue
    seen.add(key)
    out.push({ family, source: r.source_node_id, target: r.target_node_id })
  }
  return out
}
