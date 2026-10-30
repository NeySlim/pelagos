// SPDX-License-Identifier: Apache-2.0
// Certificate sources as the form edits them and as PUT /admin/certificates/... takes them,
// and the expiry level of a certificate (thresholds of cluster.toml [settings]).

export const SOURCES = ['self_signed', 'manual', 'acme', 'ucm']
export const AUTOMATIC = ['acme', 'ucm']
export const ACME_PROFILES = ['letsencrypt', 'letsencrypt-staging', 'private', 'custom']
export const KEY_TYPES = ['ec-p256', 'rsa-3072']
export const SECRET_FIELDS = ['eab_hmac', 'dns_api_token', 'ucm_api_key']

const DAY = 86400000

// Form state from a source the API returned (or nothing: a new automatic source).
export function formFromSource(src = {}, { cluster = false } = {}) {
  const acme = src.acme || {}
  const dns = acme.dns || {}
  const ucm = src.ucm || {}
  return {
    source: src.source && src.source !== 'inherit' ? src.source : cluster ? 'acme' : 'self_signed',
    names: [...(src.names || [])],
    key_type: src.key_type || 'ec-p256',
    mode: src.mode || 'node',
    cluster_name: src.cluster_name || '',
    node_ids: src.node_ids || 'all',
    acme: {
      profile: acme.profile || 'letsencrypt-staging',
      directory_url: acme.directory_url || '',
      trust_root: acme.trust_root || '',
      email: acme.email || '',
      eab_kid: acme.eab_kid || '',
      challenge: acme.challenge || 'dns-01',
      http_port: acme.http_port || 8080,
      dns: {
        method: dns.method || 'pelagos',
        server: dns.server || '',
        provider: dns.provider || 'hetzner',
        delegation_zone: dns.delegation_zone || '',
      },
    },
    ucm: {
      url: ucm.url || '',
      trust_root: ucm.trust_root || '',
      ca_id: ucm.ca_id ?? '',
      template_id: ucm.template_id ?? '',
      validity_days: ucm.validity_days || 365,
      revoke_old: Boolean(ucm.revoke_old),
    },
    // Typed secrets only; `stored` says which ones the server already holds.
    secrets: Object.fromEntries(SECRET_FIELDS.map((k) => [k, ''])),
    stored: { ...(src.secrets || {}) },
  }
}

const clean = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== '' && v !== null && v !== undefined))

// The PUT body: only what the chosen source uses; a secret goes only when typed.
export function sourceBody(form, { cluster = false, apply = false } = {}) {
  if (form.source === 'inherit') return { source: 'inherit' }
  const body ={ source: form.source, names: form.names, key_type: form.key_type, mode: form.mode }
  if (form.mode === 'cluster') body.cluster_name = form.cluster_name
  if (cluster) body.node_ids = form.node_ids
  if (form.source === 'acme') {
    const a = form.acme
    const acme = clean({ profile: a.profile, email: a.email, eab_kid: a.eab_kid, challenge: a.challenge })
    if (a.profile === 'private' || a.profile === 'custom') Object.assign(acme, clean({ directory_url: a.directory_url, trust_root: a.trust_root }))
    if (a.challenge === 'http-01') acme.http_port = Number(a.http_port)
    else acme.dns = clean({ method: a.dns.method, server: a.dns.method === 'pelagos' ? a.dns.server : '', provider: a.dns.method === 'provider' ? a.dns.provider : '', delegation_zone: a.dns.delegation_zone })
    body.acme = acme
  }
  if (form.source === 'ucm') {
    const u = form.ucm
    body.ucm = clean({ url: u.url, trust_root: u.trust_root, ca_id: u.ca_id, template_id: u.template_id })
    body.ucm.validity_days = Number(u.validity_days)
    body.ucm.revoke_old = Boolean(u.revoke_old)
  }
  const used = form.source === 'acme' ? ['eab_hmac', 'dns_api_token'] : form.source === 'ucm' ? ['ucm_api_key'] : []
  const secrets = Object.fromEntries(used.filter((k) => form.secrets[k]).map((k) => [k, form.secrets[k]]))
  if (Object.keys(secrets).length) body.secrets = secrets
  if (apply) body.apply = true
  return body
}

// Problems the server would also refuse, shown before sending: field path -> i18n key.
export function formErrors(form) {
  const errors = {}
  const https = (v) => /^https:\/\/\S+$/i.test(String(v || '').trim())
  if (form.mode === 'cluster' && !form.cluster_name.trim()) errors.cluster_name = 'required'
  if (form.source === 'acme') {
    const a = form.acme
    if ((a.profile === 'private' || a.profile === 'custom') && !https(a.directory_url)) errors['acme.directory_url'] = 'https'
    if (a.email && !a.email.includes('@')) errors['acme.email'] = 'email'
    if (a.challenge === 'http-01' && !(Number(a.http_port) >= 1 && Number(a.http_port) <= 65535)) errors['acme.http_port'] = 'port'
    if (a.challenge === 'dns-01' && a.dns.method === 'provider' && !form.secrets.dns_api_token && !form.stored.dns_api_token) errors['secrets.dns_api_token'] = 'required'
    if (a.eab_kid && !form.secrets.eab_hmac && !form.stored.eab_hmac) errors['secrets.eab_hmac'] = 'required'
  }
  if (form.source === 'ucm') {
    if (!https(form.ucm.url)) errors['ucm.url'] = 'https'
    if (form.ucm.ca_id === '' || form.ucm.ca_id === null) errors['ucm.ca_id'] = 'required'
    if (!form.secrets.ucm_api_key && !form.stored.ucm_api_key) errors['secrets.ucm_api_key'] = 'required'
    const days = Number(form.ucm.validity_days)
    if (!(days >= 1 && days <= 3650)) errors['ucm.validity_days'] = 'days'
  }
  return errors
}

// 'expired', 'critical', 'warning' or 'ok' with the days left, from cluster.toml thresholds;
// a short-lived certificate uses a third and a tenth of its lifetime, like the collector.
export function expiryLevel(cert, thresholds = {}, now = Date.now()) {
  if (!cert?.not_after) return { level: 'unknown', days: null }
  const end = Date.parse(cert.not_after)
  const start = Date.parse(cert.not_before || cert.not_after)
  const lifetime = Math.max(0, end - start)
  const left = end - now
  const warn = Math.min((thresholds.warning_days ?? 30) * DAY, lifetime / 3)
  const crit = Math.min((thresholds.critical_days ?? 7) * DAY, lifetime / 10)
  const days = Math.floor(left / DAY)
  if (left <= 0) return { level: 'expired', days: 0 }
  if (left <= crit) return { level: 'critical', days }
  if (left <= warn) return { level: 'warning', days }
  return { level: 'ok', days }
}

export const LEVEL_BADGE = { ok: 'success', warning: 'warning', critical: 'danger', expired: 'danger', unknown: 'secondary' }

// Worst level per check id, in the order the server listed them.
export function checkRows(report) {
  const rank = { ok: 0, warning: 1, error: 2 }
  const rows = []
  for (const c of report?.checks || []) {
    const row = rows.find((r) => r.id === c.id)
    if (!row) rows.push({ ...c })
    else if (rank[c.level] > rank[row.level]) Object.assign(row, c)
  }
  return rows
}

// Text of one check: the server's English with its parameters, for the fallback.
export function checkText(check) {
  return String(check?.message || '').replace(/\{(\w+)\}/g, (_m, k) => {
    const v = check.params?.[k]
    return Array.isArray(v) ? v.join(', ') : String(v ?? '')
  })
}

// Interpolation values of a check: lists joined like the server's English text.
export function checkParams(check) {
  return Object.fromEntries(Object.entries(check?.params || {}).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v]))
}

export async function fileBase64(file) {
  const buf = await file.arrayBuffer()
  let binary = ''
  const bytes = new Uint8Array(buf)
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

// The source every node uses on its own when no common source is set (same ACME or UCM settings,
// names aside), to offer adopting it as the common source; null otherwise. Secrets stay behind:
// the common source asks for them again.
export function commonNodeSource(nodes = []) {
  if (nodes.length < 2) return null
  const shared = (src) => {
    if (!src || !['acme', 'ucm'].includes(src.source)) return null
    const { names: _names, ...rest } = sourceBody(formFromSource(src))
    return JSON.stringify(rest)
  }
  const keys = nodes.map((n) => (n.inherited ? null : shared(n.source)))
  if (keys.some((k) => k === null) || new Set(keys).size !== 1) return null
  const { secrets: _secrets, names: _names, ...src } = nodes[0].source
  return src
}
