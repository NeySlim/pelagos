// SPDX-License-Identifier: Apache-2.0
// Pure helpers of Administration > Updates (architecture section 29): steps of a rollout, its
// actions, version order, reconnection errors, the order editor and the release notes.

// Steps of each rollout kind, in the order a node walks them (domain.updates.STEPS).
export const PELAGOS_STEPS = ['wait', 'fetch', 'verify', 'precheck', 'backup', 'install', 'version', 'restart', 'settle', 'health', 'convergence', 'audit', 'journal', 'permissions', 'ha']
export const ENGINE_STEPS = ['wait', 'precheck', 'ha_maintenance', 'install', 'version', 'restart', 'engine_checks', 'ha']
export const ACTIVE_STATES = ['running', 'failed']
export const FINAL_NODE_STATES = ['done', 'rolled_back', 'skipped']
// Unsigned releases, or signed by a key this cluster does not know, need the extra confirmation.
export const UNSIGNED_STATES = ['unsigned', 'unknown_key']

export const stepsOf = (kind) => (kind === 'engine_packages' ? ENGINE_STEPS : PELAGOS_STEPS)

export const isActive = (rollout) => Boolean(rollout) && ACTIVE_STATES.includes(rollout.state)

export const needsUnsignedConfirmation = (release) => Boolean(release) && UNSIGNED_STATES.includes(release.signature)

// Share of a node's steps behind it: 1 once done, the failed step counts as reached.
export function nodeProgress(node, kind) {
  if (!node) return 0
  if (node.state === 'done' || node.state === 'rolled_back') return 1
  if (node.state === 'pending' || node.state === 'skipped' || !node.step) return 0
  const steps = stepsOf(kind)
  const i = steps.indexOf(node.step)
  return i < 0 ? 0 : (i + (node.state === 'failed' ? 1 : 0.5)) / steps.length
}

// Overall progress of a rollout, from 0 to 1.
export function rolloutProgress(rollout) {
  const nodes = rollout?.nodes || []
  if (!nodes.length) return 0
  return nodes.reduce((sum, n) => sum + nodeProgress(n, rollout.kind), 0) / nodes.length
}

// What the actions of section 29 accept in the current state.
export function rolloutActions(rollout) {
  if (!rollout) return { resume: false, cancel: false, rollback: false }
  const active = isActive(rollout)
  const anyDone = (rollout.nodes || []).some((n) => n.state === 'done')
  return {
    resume: rollout.state === 'failed',
    cancel: active,
    rollback: rollout.kind !== 'rollback' && anyDone && (active || rollout.state === 'done'),
  }
}

// The node a rollout works on now (running or failed), else null.
export const currentNode = (rollout) => (rollout?.nodes || []).find((n) => n.state === 'running' || n.state === 'failed') || null

// Dotted numeric compare of the upstream part (0.2.10 > 0.2.9); a suffix counts as older.
export function compareVersions(a, b) {
  const split = (v) => {
    const [main, ...rest] = String(v ?? '').split(/[~+-]/)
    return { parts: main.split('.').map((x) => Number(x) || 0), pre: rest.length > 0 && /~/.test(String(v)) }
  }
  const x = split(a)
  const y = split(b)
  for (let i = 0; i < Math.max(x.parts.length, y.parts.length, 3); i++) {
    const d = (x.parts[i] || 0) - (y.parts[i] || 0)
    if (d) return d
  }
  if (x.pre !== y.pre) return x.pre ? -1 : 1
  return 0
}

// Nodes a release would update: those running an older version.
export const nodesBehind = (nodes, version) => (nodes || []).filter((n) => n.version && compareVersions(n.version, version) < 0)

// The most common previous version kept by the nodes, for the cluster rollback.
export function previousVersion(nodes) {
  const counts = new Map()
  for (const n of nodes || []) if (n.previous_kept) counts.set(n.previous_kept, (counts.get(n.previous_kept) || 0) + 1)
  let best = null
  for (const [v, c] of counts) if (!best || c > best[1]) best = [v, c]
  return best ? best[0] : null
}

// Moves one entry of the node order up (-1) or down (+1); out of range is a no-op.
export function moveItem(list, index, delta) {
  const to = index + delta
  if (index < 0 || index >= list.length || to < 0 || to >= list.length) return list
  const out = [...list]
  const [item] = out.splice(index, 1)
  out.splice(to, 0, item)
  return out
}

export const sameOrder = (a, b) => (a || []).length === (b || []).length && (a || []).every((x, i) => x === b[i])

// The node restarting under the page: no answer, or a proxy that cannot reach it.
export function isUnreachable(err) {
  if (!err) return false
  return err.status === 0 || err.code === 'network_error' || [502, 503, 504].includes(err.status)
}

// Minutes from seconds, rounded up, at least 1.
export const minutesOf = (seconds) => Math.max(1, Math.ceil((Number(seconds) || 0) / 60))

// Distinct packages and nodes of selected engine rows (keys `node_id|package`).
export function engineSelection(engines, keys) {
  const picked = (engines || []).filter((e) => keys.includes(engineKey(e)) && e.candidate)
  return { packages: [...new Set(picked.map((e) => e.package))], node_ids: [...new Set(picked.map((e) => e.node_id))] }
}

export const engineKey = (e) => `${e.node_id}|${e.package}`

// Rows a link from a security advisory preselects (?package=&node=): those with a candidate.
export function preselectedEngines(engines, packages, nodes) {
  if (!packages?.length) return []
  return (engines || [])
    .filter((e) => e.candidate && packages.includes(e.package) && (!nodes?.length || nodes.includes(e.node_id)))
    .map(engineKey)
}

// NOTES.md as blocks (headings, list items, code, paragraphs), rendered as text, never as HTML.
export function parseNotes(text) {
  const blocks = []
  let para = []
  let code = null
  const flush = () => {
    if (para.length) blocks.push({ type: 'p', text: para.join(' ') })
    para = []
  }
  for (const raw of String(text || '').split('\n')) {
    const line = raw.replace(/\s+$/, '')
    if (code) {
      if (/^```/.test(line)) {
        blocks.push({ type: 'code', text: code.join('\n') })
        code = null
      } else code.push(raw)
      continue
    }
    if (/^```/.test(line)) {
      flush()
      code = []
      continue
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line)
    const item = /^\s*[-*]\s+(.*)$/.exec(line)
    if (heading) {
      flush()
      blocks.push({ type: 'h', level: heading[1].length, text: heading[2] })
    } else if (item) {
      flush()
      blocks.push({ type: 'li', text: item[1] })
    } else if (/^ {4}|^\t/.test(raw) && !para.length) {
      const last = blocks[blocks.length - 1]
      if (last?.type === 'code') last.text += `\n${raw.replace(/^ {4}|^\t/, '')}`
      else blocks.push({ type: 'code', text: raw.replace(/^ {4}|^\t/, '') })
    } else if (!line.trim()) flush()
    else para.push(line.trim())
  }
  if (code) blocks.push({ type: 'code', text: code.join('\n') })
  flush()
  return blocks
}

// Settings form of the source tab: strings for the number fields, booleans kept.
export const SETTING_NUMBERS = { check_interval_hours: [1, 720], settle_seconds: [0, 3600], timeout_seconds: [30, 7200], pause_seconds: [0, 3600], keep_packages_count: [1, 10] }
export const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/

export function settingsForm(settings = {}) {
  const form = {
    source: settings.source || 'upload',
    github_repository: settings.github_repository || '',
    check_enabled: settings.check_enabled ?? true,
    auto_rollback_enabled: settings.auto_rollback_enabled ?? true,
  }
  for (const k of Object.keys(SETTING_NUMBERS)) form[k] = settings[k] === undefined || settings[k] === null ? '' : String(settings[k])
  return form
}

export function settingsErrors(form) {
  const errors = {}
  for (const [k, [min, max]] of Object.entries(SETTING_NUMBERS)) {
    const v = form[k]
    if (v === '') continue
    if (!/^\d+$/.test(v) || Number(v) < min || Number(v) > max) errors[k] = { code: 'range', min, max }
  }
  if (form.github_repository && !REPO_RE.test(form.github_repository)) errors.github_repository = { code: 'repository' }
  if (form.source === 'github' && !form.github_repository) errors.github_repository = { code: 'repositoryRequired' }
  return errors
}

// Only the fields that differ from the stored settings, numbers as numbers.
export function settingsChanges(form, settings = {}) {
  const base = settingsForm(settings)
  const out = {}
  for (const [k, v] of Object.entries(form)) {
    if (v === base[k]) continue
    out[k] = k in SETTING_NUMBERS ? Number(v) : v
  }
  return out
}
