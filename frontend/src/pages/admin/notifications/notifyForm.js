// SPDX-License-Identifier: Apache-2.0
// Notification channels as the form edits them and as POST/PUT /admin/notifications/channels
// take them (architecture section 22). Secrets are write-only: typed values go once, `null`
// clears a stored one, and the API only ever answers which ones are set.

export const CHANNEL_TYPES = ['email', 'ntfy', 'gotify', 'matrix', 'webhook', 'home_assistant']
export const SEVERITIES = ['info', 'warning', 'critical']
export const ENGINES = ['bind', 'kea4', 'kea6', 'd2']
export const LANGUAGES = ['en', 'fr']
export const EMAIL_SECURITY = ['starttls', 'tls', 'none']
export const NTFY_AUTH = ['none', 'token', 'basic']
export const GOTIFY_DEFAULTS = { critical: 8, warning: 5, info: 2 }
// Monday 0, as the dispatcher counts days.
export const DAYS = [0, 1, 2, 3, 4, 5, 6]

// Secret names per type (cluster.toml [secrets] "notify/<channel id>/<name>").
export const SECRET_NAMES = {
  email: ['password'],
  ntfy: ['token', 'password'],
  gotify: ['token'],
  matrix: ['token'],
  webhook: ['hmac_secret'],
  home_assistant: ['webhook_id'],
}
// Secrets a channel cannot send without.
const REQUIRED_SECRETS = { gotify: ['token'], matrix: ['token'], home_assistant: ['webhook_id'] }

const URL_FIELD = { ntfy: 'url', gotify: 'url', matrix: 'homeserver', webhook: 'url', home_assistant: 'url' }
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/
const RESERVED_HEADERS = new Set(['host', 'content-length', 'content-type', 'transfer-encoding', 'connection'])
const ADDRESS = /^[^@\s<>,;]+@[^@\s<>,;]+$/
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/
const TOPIC = /^[-_A-Za-z0-9]{1,64}$/
const ROOM = /^![^\s/:]+(:\S+)?$/

export const DEFAULT_FILTERS = { severity_min: 'warning', kinds_include: [], kinds_exclude: ['ha_transition'], node_ids: [], engines: [] }
export const DEFAULT_SCHEDULE = { reminder_hours: 12, send_resolved: true, confirm_seconds: null, quiet: null }

// The server a channel's stored secrets belong to, normalized like the API does.
const TARGET_FIELD = { email: 'host', matrix: 'homeserver' }
export function channelTargetKey(type, params = {}) {
  return String(params[TARGET_FIELD[type] || 'url'] || '').trim().replace(/\/+$/, '').toLowerCase()
}

function browserZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

const headersToText = (headers) => Object.entries(headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')

// "Name: value" lines -> {name: value}; a line without a colon is reported by formErrors.
export function parseHeaders(text) {
  const out = {}
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue
    const i = line.indexOf(':')
    if (i < 0) continue
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}

// Form state from a channel the API returned, or a new channel of `type`.
export function formFromChannel(channel = {}, type = 'ntfy') {
  const p = channel.params || {}
  const f = { ...DEFAULT_FILTERS, ...(channel.filters || {}) }
  const s = { ...DEFAULT_SCHEDULE, ...(channel.schedule || {}) }
  const kind = channel.type || type
  const stored = { ...(channel.secrets || {}) }
  return {
    type: kind,
    name: channel.name || '',
    enabled: channel.enabled ?? true,
    language: channel.language || 'en',
    params: {
      url: p.url || '',
      topic: p.topic || '',
      username: p.username || '',
      homeserver: p.homeserver || '',
      room_id: p.room_id || '',
      host: p.host || '',
      port: p.port ?? (p.security === 'tls' ? 465 : 587),
      security: p.security || 'starttls',
      from: p.from || '',
      to: [...(p.to || [])],
      headers: headersToText(p.headers),
      priorities: { ...GOTIFY_DEFAULTS, ...(p.priorities || {}) },
      ca_pem: p.ca_pem || '',
    },
    // ntfy authenticates with a token (Bearer) or a username and password (Basic).
    ntfy_auth: stored.token ? 'token' : stored.password || p.username ? 'basic' : 'none',
    filters: {
      severity_min: f.severity_min,
      kinds_include: [...f.kinds_include],
      kinds_exclude: [...f.kinds_exclude],
      node_ids: [...f.node_ids],
      engines: [...f.engines],
    },
    schedule: {
      reminder_hours: s.reminder_hours,
      send_resolved: Boolean(s.send_resolved),
      confirm_seconds: s.confirm_seconds ?? '',
      quiet_enabled: Boolean(s.quiet),
      quiet: {
        start: s.quiet?.start || '22:00',
        end: s.quiet?.end || '07:00',
        timezone: s.quiet?.timezone || browserZone(),
        days: [...(s.quiet?.days || DAYS)],
        critical_passes: s.quiet?.critical_passes ?? true,
      },
    },
    secrets: Object.fromEntries((SECRET_NAMES[kind] || []).map((k) => [k, ''])),
    clear: {},
    stored,
    // Stored secrets never follow a saved channel to another server: they must be typed again.
    target: channel.id ? channelTargetKey(kind, p) : null,
  }
}

// Secrets the channel uses with its current settings (ntfy: the chosen authentication).
export function usedSecrets(form) {
  if (form.type === 'ntfy') return form.ntfy_auth === 'token' ? ['token'] : form.ntfy_auth === 'basic' ? ['password'] : []
  if (form.type === 'email') return ['password']
  return SECRET_NAMES[form.type] || []
}

// A secret is set after saving when typed now, or stored and neither cleared nor unused.
export function secretSet(form, name) {
  if (!usedSecrets(form).includes(name)) return false
  if (form.secrets[name]) return true
  return Boolean(form.stored[name]) && !form.clear[name]
}

const num = (v) => (v === '' || v === null || v === undefined ? NaN : Number(v))

function paramsBody(form) {
  const p = form.params
  const ca = p.ca_pem.trim() ? { ca_pem: p.ca_pem.trim() } : {}
  switch (form.type) {
    case 'email': {
      const out = { host: p.host.trim(), port: num(p.port), security: p.security, from: p.from.trim(), to: p.to.map((x) => x.trim()).filter(Boolean) }
      if (p.username.trim()) out.username = p.username.trim()
      return { ...out, ...ca }
    }
    case 'ntfy': {
      const out = { url: p.url.trim(), topic: p.topic.trim() }
      if (form.ntfy_auth === 'basic' && p.username.trim()) out.username = p.username.trim()
      return { ...out, ...ca }
    }
    case 'gotify':
      return { url: p.url.trim(), priorities: Object.fromEntries(SEVERITIES.map((s) => [s, num(p.priorities[s])])), ...ca }
    case 'matrix':
      return { homeserver: p.homeserver.trim(), room_id: p.room_id.trim(), ...ca }
    case 'webhook':
      return { url: p.url.trim(), headers: parseHeaders(p.headers), ...ca }
    case 'home_assistant':
      return { url: p.url.trim(), ...ca }
    default:
      return {}
  }
}

// The channel body without id and status; `secrets` carries typed values and null to clear,
// and a stored secret the settings no longer use (ntfy token after a switch to Basic) is cleared.
export function channelBody(form) {
  const s = form.schedule
  const body = {
    type: form.type,
    name: form.name.trim(),
    enabled: Boolean(form.enabled),
    language: form.language,
    params: paramsBody(form),
    filters: {
      severity_min: form.filters.severity_min,
      kinds_include: [...form.filters.kinds_include],
      kinds_exclude: [...form.filters.kinds_exclude],
      node_ids: [...form.filters.node_ids],
      engines: [...form.filters.engines],
    },
    schedule: {
      reminder_hours: num(s.reminder_hours),
      send_resolved: Boolean(s.send_resolved),
      confirm_seconds: s.confirm_seconds === '' || s.confirm_seconds === null ? null : num(s.confirm_seconds),
      quiet: s.quiet_enabled
        ? { start: s.quiet.start, end: s.quiet.end, timezone: s.quiet.timezone.trim(), days: [...s.quiet.days].sort(), critical_passes: Boolean(s.quiet.critical_passes) }
        : null,
    },
  }
  const used = usedSecrets(form)
  const secrets = {}
  for (const name of SECRET_NAMES[form.type] || []) {
    if (used.includes(name) && form.secrets[name]) secrets[name] = form.secrets[name]
    else if (form.stored[name] && (form.clear[name] || !used.includes(name))) secrets[name] = null
  }
  if (Object.keys(secrets).length) body.secrets = secrets
  return body
}

// POST /admin/notifications/test body: a saved channel by id, or the form as an unsaved channel
// whose `scope` names the channel whose stored secrets it may reuse.
export function testBody(form, channelId, { dirty = true } = {}) {
  if (channelId && !dirty) return { channel_id: channelId }
  const body = channelBody(form)
  if (channelId) body.scope = channelId
  return body
}

function urlProblem(value) {
  let u
  try {
    u = new URL(String(value || '').trim())
  } catch {
    return 'url'
  }
  if (!['http:', 'https:'].includes(u.protocol) || !u.hostname) return 'url'
  if (u.username || u.password) return 'urlCredentials'
  if (u.search || u.hash) return 'urlQuery'
  return null
}

const LOOPBACK = /^(localhost(\.localdomain)?|127(\.\d{1,3}){3}|::1|\[::1\])$/i

// Problems the server would also refuse: field path -> i18n key under `errors`.
export function formErrors(form) {
  const errors = {}
  const p = form.params
  if (!form.name.trim()) errors.name = 'required'
  const urlField = URL_FIELD[form.type]
  if (urlField) {
    const problem = urlProblem(p[urlField])
    if (problem) errors[`params.${urlField}`] = problem
  }
  if (form.type === 'email') {
    if (!p.host.trim()) errors['params.host'] = 'required'
    const port = num(p.port)
    if (!(Number.isInteger(port) && port >= 1 && port <= 65535)) errors['params.port'] = 'port'
    if (p.security === 'none' && p.host.trim() && !LOOPBACK.test(p.host.trim())) errors['params.security'] = 'loopbackOnly'
    if (!ADDRESS.test(p.from.trim())) errors['params.from'] = 'email'
    const to = p.to.map((x) => x.trim()).filter(Boolean)
    if (!to.length) errors['params.to'] = 'required'
    else if (to.some((x) => !ADDRESS.test(x))) errors['params.to'] = 'email'
    if (secretSet(form, 'password') && !p.username.trim()) errors['params.username'] = 'usernameWithPassword'
  }
  if (form.type === 'ntfy') {
    if (!TOPIC.test(p.topic.trim())) errors['params.topic'] = 'topic'
    if (form.ntfy_auth === 'basic' && !p.username.trim()) errors['params.username'] = 'required'
    if (form.ntfy_auth === 'token' && !secretSet(form, 'token')) errors['secrets.token'] = 'required'
    if (form.ntfy_auth === 'basic' && !secretSet(form, 'password')) errors['secrets.password'] = 'required'
  }
  if (form.type === 'gotify') {
    for (const s of SEVERITIES) {
      const v = num(p.priorities[s])
      if (!(Number.isInteger(v) && v >= 0 && v <= 10)) errors[`params.priorities.${s}`] = 'priority'
    }
  }
  if (form.type === 'matrix' && !ROOM.test(p.room_id.trim())) errors['params.room_id'] = 'room'
  if (form.type === 'webhook') {
    for (const line of p.headers.split('\n')) {
      if (!line.trim()) continue
      const i = line.indexOf(':')
      const name = i < 0 ? '' : line.slice(0, i).trim()
      if (!HEADER_NAME.test(name)) errors['params.headers'] = 'header'
      else if (RESERVED_HEADERS.has(name.toLowerCase()) || name.toLowerCase().startsWith('x-pelagos-')) errors['params.headers'] = 'headerReserved'
    }
  }
  for (const name of REQUIRED_SECRETS[form.type] || []) if (!secretSet(form, name)) errors[`secrets.${name}`] = 'required'
  if (form.target !== null && form.target !== undefined && channelTargetKey(form.type, form.params) !== form.target) {
    for (const name of usedSecrets(form)) {
      if (form.stored[name] && !form.clear[name] && !form.secrets[name]) errors[`secrets.${name}`] = 'reenter'
    }
  }
  if (form.type === 'home_assistant' && form.secrets.webhook_id && !/^[A-Za-z0-9_-]{1,128}$/.test(form.secrets.webhook_id)) errors['secrets.webhook_id'] = 'webhookId'
  const s = form.schedule
  const reminder = num(s.reminder_hours)
  if (!(reminder >= 0 && reminder <= 720)) errors['schedule.reminder_hours'] = 'hours'
  if (s.confirm_seconds !== '' && s.confirm_seconds !== null && !(num(s.confirm_seconds) >= 0 && num(s.confirm_seconds) <= 3600)) errors['schedule.confirm_seconds'] = 'seconds'
  if (s.quiet_enabled) {
    if (!TIME.test(s.quiet.start)) errors['schedule.quiet.start'] = 'time'
    if (!TIME.test(s.quiet.end)) errors['schedule.quiet.end'] = 'time'
    if (!s.quiet.timezone.trim()) errors['schedule.quiet.timezone'] = 'required'
    if (!s.quiet.days.length) errors['schedule.quiet.days'] = 'days'
  }
  return errors
}

// Advice shown without blocking: a secret over plain http.
export function formWarnings(form) {
  const warnings = {}
  const field = URL_FIELD[form.type]
  if (field && /^http:\/\//i.test(form.params[field].trim()) && (SECRET_NAMES[form.type] || []).some((n) => secretSet(form, n))) {
    warnings[`params.${field}`] = 'plainHttp'
  }
  if (form.type === 'email' && form.params.security === 'none') warnings['params.security'] = 'noTls'
  return warnings
}

// Server field errors ("params.to.0", "params.headers.X-Foo") mapped onto the form fields.
export function serverFieldErrors(errors = []) {
  const out = {}
  for (const e of errors) {
    if (!e?.field) continue
    let field = e.field
    if (/^params\.to\.\d+$/.test(field)) field = 'params.to'
    if (field.startsWith('params.headers.')) field = 'params.headers'
    out[field] = e.message || 'invalid'
  }
  return out
}

// Where a channel sends, for its card: host, topic, room or masked webhook URL.
export function channelTarget(channel) {
  const p = channel?.params || {}
  const host = (url) => {
    try {
      return new URL(url).host
    } catch {
      return url || ''
    }
  }
  switch (channel?.type) {
    case 'email':
      return `${(p.to || []).join(', ')} (${p.host || ''})`
    case 'ntfy':
      return `${host(p.url)}/${p.topic || ''}`
    case 'matrix':
      return `${p.room_id || ''} (${host(p.homeserver)})`
    default:
      return host(p.url)
  }
}

// Mute end presets, at most 24 hours ahead as the API requires.
export const MUTE_PRESETS = [1, 2, 4, 8, 24]
export const MUTE_MAX_HOURS = 24

export function muteUntil(hours, now = Date.now()) {
  return new Date(now + Math.min(MUTE_MAX_HOURS, hours) * 3600000).toISOString()
}

// History entries that concern one alert: the server filters by alert_id when it can; entries
// are checked here too, so an older server answering the whole page still gives the right list.
export function notificationsOfAlert(items, alertId) {
  return (items || []).filter((h) => h.result === 'ok' && (h.events || []).some((e) => e.alert_id === alertId))
}
