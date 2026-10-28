// SPDX-License-Identifier: Apache-2.0
// Pure helpers of Administration > Backups: destination form <-> API body, local checks,
// settings changes, archive parts and the restore request (architecture section 23).

export const DESTINATION_TYPES = ['peer', 'mounted', 'sftp']
export const RECIPIENT_RE = /^age1[0-9a-z]{58}$/
export const IDENTITY_RE = /^AGE-SECRET-KEY-1[0-9A-Z]{58}$/
const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}=?$/
const HHMM = /^([01][0-9]|2[0-3]):[0-5][0-9]$/
const KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/
export const SFTP_TARGET = ['host', 'port', 'username']
// Settings the screen edits, by group; the others stay in Administration > Settings.
export const SETTING_GROUPS = {
  schedule: ['start_time', 'interval_hours', 'stagger_minutes'],
  retention: ['keep_daily_count', 'keep_weekly_count', 'keep_monthly_count', 'local_keep_count'],
  checks: ['include_leases_enabled', 'verify_enabled', 'test_restore_days', 'max_archive_mb'],
}

export function formFromDestination(d = {}) {
  const p = d.params || {}
  return {
    type: d.type || 'peer',
    name: d.name || '',
    enabled: d.enabled ?? true,
    nodeIds: p.node_ids || [],
    path: p.path || '',
    host: p.host || '',
    port: String(p.port ?? 22),
    username: p.username || '',
    fingerprint: p.host_key_fingerprint || '',
    customKeep: Boolean(d.keep),
    keep: { daily: String(d.keep?.daily ?? 7), weekly: String(d.keep?.weekly ?? 4), monthly: String(d.keep?.monthly ?? 6) },
    sshKey: '',
    keyStored: Boolean(d.secrets?.ssh_key),
    clearKey: false,
  }
}

export function destinationParams(form) {
  if (form.type === 'peer') return { node_ids: form.nodeIds }
  if (form.type === 'mounted') return { path: form.path.trim() }
  return {
    host: form.host.trim(),
    port: Number(form.port),
    username: form.username.trim(),
    path: form.path.trim() || '.',
    host_key_fingerprint: form.fingerprint.trim(),
  }
}

// The request body; the key goes only when typed (set) or cleared (null).
export function destinationBody(form, { editing = false } = {}) {
  const body = {
    name: form.name.trim(),
    enabled: form.enabled,
    params: destinationParams(form),
    keep: form.customKeep ? { daily: Number(form.keep.daily), weekly: Number(form.keep.weekly), monthly: Number(form.keep.monthly) } : null,
  }
  if (!editing) body.type = form.type
  if (form.type === 'sftp') {
    if (form.sshKey.trim()) body.secrets = { ssh_key: form.sshKey }
    else if (form.clearKey) body.secrets = { ssh_key: null }
  }
  return body
}

// Whether the SFTP server moved: a stored key never follows it unless typed again.
export function serverMoved(form, original) {
  if (!original || form.type !== 'sftp') return false
  const before = original.params || {}
  const now = destinationParams(form)
  return SFTP_TARGET.some((k) => String(before[k] ?? (k === 'port' ? 22 : '')) !== String(now[k]))
}

const isCount = (v, max) => /^\d+$/.test(String(v)) && Number(v) <= max

// {field: code} of what the server would refuse; codes are archives:errors.<code>.
export function destinationErrors(form, original = null) {
  const errors = {}
  if (!form.name.trim()) errors.name = 'required'
  if (form.type === 'mounted' && !form.path.trim().startsWith('/')) errors.path = 'absolutePath'
  if (form.type === 'mounted' && form.path.trim() === '/') errors.path = 'absolutePath'
  if (form.type === 'sftp') {
    if (!/^[A-Za-z0-9.:_-]{1,253}$/.test(form.host.trim()) || form.host.startsWith('-')) errors.host = 'host'
    if (!isCount(form.port, 65535) || Number(form.port) < 1) errors.port = 'port'
    if (!form.username.trim()) errors.username = 'required'
    if (/["'\\*?[\]\t]/.test(form.path)) errors.path = 'sftpPath'
    if (!FP_RE.test(form.fingerprint.trim())) errors.fingerprint = 'fingerprint'
    const typed = form.sshKey.trim()
    if (typed && !KEY_RE.test(typed)) errors.sshKey = 'privateKey'
    const stored = form.keyStored && !form.clearKey && !serverMoved(form, original)
    if (!typed && !stored && form.enabled) errors.sshKey = serverMoved(form, original) && form.keyStored ? 'keyAgain' : 'required'
  }
  if (form.customKeep) {
    for (const k of ['daily', 'weekly', 'monthly']) if (!isCount(form.keep[k], 1000)) errors[`keep.${k}`] = 'count'
  }
  return errors
}

// Server field errors (`params.host`, `secrets.ssh_key`...) mapped onto the form fields.
const SERVER_FIELDS = {
  'params.path': 'path', 'params.host': 'host', 'params.port': 'port', 'params.username': 'username',
  'params.host_key_fingerprint': 'fingerprint', 'secrets.ssh_key': 'sshKey', 'params.node_ids': 'nodeIds',
  'keep.daily': 'keep.daily', 'keep.weekly': 'keep.weekly', 'keep.monthly': 'keep.monthly', name: 'name',
}

export function serverFieldErrors(err) {
  const out = {}
  for (const e of err?.errors || []) out[SERVER_FIELDS[e.field] || e.field] = e.message
  return out
}

// Where a destination writes, for its card.
export function destinationTarget(d, nameOf = (id) => id) {
  const p = d.params || {}
  if (d.type === 'peer') return p.node_ids?.length ? p.node_ids.map(nameOf).join(', ') : null
  if (d.type === 'mounted') return p.path
  return `${p.username || '?'}@${p.host || '?'}:${p.port ?? 22}/${p.path || '.'}`
}

// The settings form: strings for the inputs, booleans kept.
export function settingsForm(settings = {}) {
  const out = {}
  for (const keys of Object.values(SETTING_GROUPS)) {
    for (const k of keys) out[k] = typeof settings[k] === 'boolean' ? settings[k] : String(settings[k] ?? '')
  }
  return out
}

const LIMITS = {
  interval_hours: [1, 168], stagger_minutes: [0, 720], keep_daily_count: [0, 366], keep_weekly_count: [0, 520],
  keep_monthly_count: [0, 240], local_keep_count: [1, 100], test_restore_days: [0, 365], max_archive_mb: [1, 65536],
}

export function settingsErrors(form) {
  const errors = {}
  if (!HHMM.test(form.start_time)) errors.start_time = 'time'
  for (const [k, [lo, hi]] of Object.entries(LIMITS)) {
    if (!/^\d+$/.test(form[k]) || Number(form[k]) < lo || Number(form[k]) > hi) errors[k] = { code: 'range', min: lo, max: hi }
  }
  return errors
}

// Only the values that changed, typed for the API.
export function settingsChanges(form, settings = {}) {
  const out = {}
  for (const [k, v] of Object.entries(form)) {
    const value = typeof v === 'boolean' ? v : k === 'start_time' ? v : Number(v)
    if (value !== settings[k]) out[k] = value
  }
  return out
}

// Kind of a restore part id: bind.zone:<view>/<zone>, pelagos.settings:<section>, kea4.config@<node>.
export function partInfo(id) {
  const [base, partner] = id.split('@')
  if (base.startsWith('bind.zone:')) {
    const rest = base.slice('bind.zone:'.length)
    const slash = rest.indexOf('/')
    return { kind: 'zone', view: rest.slice(0, slash), zone: rest.slice(slash + 1), partner: partner || null }
  }
  if (base.startsWith('pelagos.settings:')) return { kind: 'settings', section: base.slice('pelagos.settings:'.length), partner: null }
  return { kind: base, partner: partner || null }
}

// Whether a part has something to restore, from its diff_summary.
export function partChanged(part) {
  const s = part.diff_summary || {}
  if (s.error) return false
  if (Array.isArray(s.changed)) return s.changed.length > 0
  if (typeof s.changed === 'boolean') return s.changed
  if (s.entries !== undefined) return s.entries > 0
  return (s.add || 0) + (s.replace || 0) + (s.delete || 0) > 0
}

// "old=new" lines to the substitute map of the restore request.
export function parseSubstitute(text) {
  const out = {}
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^\s*([^=\s]+)\s*=\s*([^=\s]+)\s*$/)
    if (m) out[m[1]] = m[2]
  }
  return out
}

// The body shared by inspect and restore/plan.
export function restoreRequest({ target, identity, substitute, haTlsPlain }) {
  const body = {}
  if (target) body.target_node_id = target
  if (identity?.trim()) body.identity = identity.trim()
  const subs = parseSubstitute(substitute)
  if (Object.keys(subs).length) body.substitute = subs
  if (haTlsPlain) body.ha_tls = 'plain'
  return body
}

// restore/plan body: chosen parts, zone modes, user files only when asked twice.
export function restorePlanBody(request, chosen, modes, includeUserFiles) {
  const parts = chosen.map((id) => (modes[id] ? { id, mode: modes[id] } : id))
  const body = { ...request, parts }
  if (includeUserFiles) body.include_user_files = true
  return body
}

export function formatBytes(n) {
  if (n == null) return '-'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = Number(n)
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${i ? v.toFixed(1) : v} ${units[i]}`
}
