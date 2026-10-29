// SPDX-License-Identifier: Apache-2.0
// Administration > IPv6 sources (architecture section 27): the source form, the PUT body that
// replaces the source list whole, the test body and the watched prefix list.

const MAC_RE = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i
export const SECRET_NAMES = ['api_key', 'api_secret']

export function formFromSource(source = {}) {
  return {
    id: source.id || null,
    type: source.type || 'opnsense',
    name: source.name || '',
    url: source.url || '',
    verify_tls: source.verify_tls !== false,
    allow_http: source.allow_http === true,
    ca_pem: source.ca_pem || '',
    enabled: source.enabled !== false,
    exclude_macs: (source.exclude_macs || []).join('\n'),
    secrets: { api_key: '', api_secret: '' },
    stored: { api_key: Boolean(source.secrets?.api_key), api_secret: Boolean(source.secrets?.api_secret) },
    originalUrl: source.url || '',
  }
}

export const splitList = (text) => String(text || '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

// The fields of a source as the API stores it, without secrets.
export function sourceFields(form) {
  return {
    ...(form.id ? { id: form.id } : {}),
    type: form.type,
    name: form.name.trim(),
    url: form.url.trim(),
    verify_tls: form.verify_tls,
    allow_http: form.allow_http,
    ca_pem: form.ca_pem.trim() || null,
    enabled: form.enabled,
    exclude_macs: splitList(form.exclude_macs).map((m) => m.toLowerCase().replace(/-/g, ':')),
  }
}

// A stored key never follows a source to another URL: the server clears it unless it is given again.
export const urlChanged = (form) => Boolean(form.id) && form.url.trim() !== form.originalUrl

// Field -> error code, checked before any request.
export function formErrors(form) {
  const errors = {}
  if (!form.name.trim()) errors.name = 'required'
  const url = form.url.trim()
  if (!url) errors.url = 'required'
  else if (!/^https?:\/\/[^\s/]+(\/\S*)?$/i.test(url)) errors.url = 'url'
  else if (url.toLowerCase().startsWith('http:') && !form.allow_http) errors.url = 'http'
  const bad = splitList(form.exclude_macs).find((m) => !MAC_RE.test(m))
  if (bad) errors.exclude_macs = 'mac'
  if (form.ca_pem.trim() && !form.ca_pem.includes('-----BEGIN CERTIFICATE-----')) errors.ca_pem = 'pem'
  const willHave = (n) => Boolean(form.secrets[n]) || (form.stored[n] && !urlChanged(form))
  for (const n of SECRET_NAMES) if (!willHave(n)) errors[`secrets.${n}`] = 'secret'
  return errors
}

// The secrets typed in the form; an empty field keeps the stored one.
export function typedSecrets(form) {
  return Object.fromEntries(SECRET_NAMES.filter((n) => form.secrets[n]).map((n) => [n, form.secrets[n]]))
}

const stored = (s) => sourceFields(formFromSource(s))

// The stored source list with `form` added or replaced; the others keep their stored secrets.
export function sourcesBody(sources, form) {
  const secrets = typedSecrets(form)
  const edited = { ...sourceFields(form), ...(Object.keys(secrets).length ? { secrets } : {}) }
  const list = form.id ? sources.map((s) => (s.id === form.id ? edited : stored(s))) : [...sources.map(stored), edited]
  return { sources: list }
}

export function removeBody(sources, id) {
  return { sources: sources.filter((s) => s.id !== id).map(stored) }
}

export function toggleBody(sources, id, enabled) {
  return { sources: sources.map((s) => ({ ...stored(s), ...(s.id === id ? { enabled } : {}) })) }
}

// An unsaved source for POST /admin/ipv6/sources/test: `scope` reuses the stored secrets while
// the URL is unchanged, typed ones win.
export function testBody(form) {
  const { id, ...fields } = sourceFields(form)
  const secrets = typedSecrets(form)
  return { ...fields, ...(id ? { scope: id } : {}), ...(Object.keys(secrets).length ? { secrets } : {}) }
}

// 'format' | 'scope' | null for one watched prefix typed by hand (ULA is allowed, it is opt-in).
export function prefixProblem(value) {
  const m = String(value).trim().match(/^([0-9a-f:]+)\/(\d{1,3})$/i)
  if (!m || !m[1].includes(':') || (m[1].match(/::/g) || []).length > 1) return 'format'
  const len = Number(m[2])
  if (len < 1 || len > 128) return 'format'
  const head = m[1].toLowerCase()
  if (/^fe[89ab]/.test(head) || head.startsWith('ff')) return 'scope'
  return null
}

// API field errors ("sources[0].url") -> form field errors of the edited source.
export function serverFieldErrors(errors = [], index) {
  const out = {}
  for (const e of errors || []) {
    const m = String(e.field || '').match(/^sources\[(\d+)\]\.(.+)$/) || String(e.field || '').match(/^source\.(.+)$/)
    if (!m) continue
    if (m.length === 3 && Number(m[1]) !== index) continue
    out[m[m.length - 1]] = e.message
  }
  return out
}
