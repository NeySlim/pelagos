// SPDX-License-Identifier: Apache-2.0
// Runtime operation forms: the input kind of each typed parameter, the request params built
// from the form values, and whether an operation may run where and how it is set up.

const KINDS = {
  clean: 'bool',
  remove: 'bool',
  'max-period': 'int',
  'subnet-id': 'int',
  count: 'int',
  scopes: 'list',
}

export function paramKind(spec, name) {
  if (spec?.choices?.[name]) return 'choice'
  return KINDS[name] || 'text'
}

// Empty fields are left out; integers and booleans go typed, as the server checks them.
export function buildParams(spec, values) {
  const out = {}
  const errors = {}
  for (const name of spec?.params || []) {
    const kind = paramKind(spec, name)
    const raw = values?.[name]
    if (kind === 'bool') {
      if (raw !== undefined) out[name] = Boolean(raw)
      continue
    }
    if (kind === 'list') {
      if (Array.isArray(raw) && raw.length) out[name] = raw
      continue
    }
    const text = raw === undefined || raw === null ? '' : String(raw).trim()
    if (text === '') continue
    if (kind === 'int') {
      if (!/^\d+$/.test(text)) {
        errors[name] = 'int'
        continue
      }
      out[name] = Number(text)
      continue
    }
    out[name] = text
  }
  for (const name of spec?.required || []) {
    const kind = paramKind(spec, name)
    if (out[name] === undefined && kind !== 'bool') errors[name] = errors[name] || 'required'
    if (kind === 'bool' && out[name] === undefined) out[name] = false
  }
  return { params: out, errors }
}

// Changes run on this node only; a confirmed operation needs the box ticked.
export function runBlocker(spec, { isLocal, confirmed, allowed }) {
  if (!spec) return 'none'
  if (!allowed) return 'permission'
  if (spec.available === false) return 'unavailable'
  if (spec.write && !isLocal) return 'remote'
  if (spec.confirm && !confirmed) return 'confirm'
  return null
}

export function groupOps(operations, hasPermission, query = '') {
  const q = query.trim().toLowerCase()
  const visible = (operations || []).filter((o) => !q || o.name.includes(q))
  return {
    reads: visible.filter((o) => !o.write),
    changes: visible.filter((o) => o.write),
    allowed: (o) => hasPermission(o.permission),
  }
}
