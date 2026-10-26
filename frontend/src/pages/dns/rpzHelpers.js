// SPDX-License-Identifier: Apache-2.0
// Pure helpers of the RPZ subscription screens: sizes, selections turned into request bodies, status summaries.

export const LEVELS = ['light', 'normal', 'strict']
export const ACTIONS = ['nxdomain', 'nodata', 'redirect', 'passthru']

export const formatCount = (n) => (n === null || n === undefined ? '' : new Intl.NumberFormat('en-US').format(n).replace(/,/g, ' '))

export function formatMb(mb) {
  if (mb === null || mb === undefined) return ''
  return mb >= 1000 ? `${(mb / 1000).toFixed(1)} GB` : `${Math.round(mb)} MB`
}

export function formatBytes(bytes) {
  if (!bytes) return ''
  return bytes >= 1e6 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.round(bytes / 1e3)} kB`
}

// Epoch seconds as a local date and time; empty when unknown.
export function formatEpoch(seconds) {
  if (!seconds) return ''
  const d = new Date(seconds * 1000)
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export const estimatedMb = (entries, bytesPerEntry = 800) => Math.round((entries * bytesPerEntry) / 1e5) / 10

// The levels a category defines, plus "custom" when it has several lists to pick from.
export function levelsOf(category) {
  const defined = LEVELS.filter((l) => category.levels?.[l])
  return category.lists?.length > 1 ? [...defined, 'custom'] : defined
}

export function defaultSelection(category) {
  const levels = levelsOf(category)
  return {
    enabled: true,
    level: levels.includes('normal') ? 'normal' : levels[0],
    lists: [],
    addons: [],
    urls: [],
    action: 'nxdomain',
    redirect: '',
    interval_hours: 24,
    nodes: [],
  }
}

// What a selection stands for: list ids of the level (or the picked ones) and the chosen add-ons.
export function selectedLists(category, form) {
  const base = form.level === 'custom' ? form.lists || [] : category.levels?.[form.level]?.lists || []
  return [...base, ...(form.addons || [])]
}

export function selectionEntries(catalog, category, form) {
  return selectedLists(category, form).reduce((n, id) => n + (catalog.lists[id]?.entries || 0), 0)
}

// Request body of PUT /dns/rpz/categories/{id}.
export function categoryBody(form) {
  const body = {
    enabled: form.enabled,
    level: form.level,
    addons: form.addons || [],
    urls: (form.urls || []).map((url) => ({ url, format: 'auto' })),
    action: form.action,
    interval_hours: Number(form.interval_hours) || 24,
  }
  if (form.level === 'custom') body.lists = form.lists || []
  if (form.action === 'redirect') body.redirect = form.redirect
  if (form.nodes?.length) body.nodes = form.nodes
  return body
}

export function formFromSelection(category, selection) {
  if (!selection) return { ...defaultSelection(category), enabled: false }
  return {
    ...defaultSelection(category),
    ...selection,
    urls: (selection.urls || []).map((u) => u.url),
    nodes: selection.nodes || [],
    redirect: selection.redirect || '',
  }
}

export const sameForm = (a, b) => JSON.stringify(categoryBody(a)) === JSON.stringify(categoryBody(b))

export const validUrl = (value) => /^https?:\/\/[^\s/]+(\/\S*)?$/.test(value)

export const validDomain = (value) => /^([a-z0-9_-]{1,63}\.)*[a-z0-9_-]{1,63}$/i.test(String(value).trim().replace(/^\*\./, '').replace(/\.$/, ''))

export const validNetwork = (value) => /^[0-9a-f.:]+(\/\d{1,3})?$/i.test(String(value).trim())

// Worst of the per-node statuses of a subscription, for one badge.
const RANK = { error: 3, rejected: 3, waiting_config: 2, ok: 0 }
export function worstStatus(statusByNode) {
  const rows = Object.values(statusByNode || {})
  if (!rows.length || rows.every((r) => !r)) return { status: 'pending', error: '' }
  let worst = { status: 'ok', error: '' }
  for (const row of rows) {
    const status = row ? row.status || 'ok' : 'pending'
    if ((RANK[status] ?? 1) > (RANK[worst.status] ?? 1)) worst = { status, error: row?.error || '' }
  }
  return worst
}

// The row of the node that was updated last, for entries, size and dates.
export function latestStatus(statusByNode) {
  return Object.values(statusByNode || {})
    .filter(Boolean)
    .sort((a, b) => (b.ok_at || 0) - (a.ok_at || 0))[0] || null
}

export const STATUS_VARIANT = { ok: 'success', pending: 'gray', waiting_config: 'warning', error: 'danger', rejected: 'danger' }
export const LEVEL_VARIANT = { ok: 'success', caution: 'warning', high: 'danger' }
