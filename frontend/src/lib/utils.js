// SPDX-License-Identifier: Apache-2.0
import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import i18n from '../i18n'

export function cn(...inputs) {
  return twMerge(clsx(inputs))
}

export function safeJsonParse(json, fallback = []) {
  if (!json) return fallback
  try {
    const parsed = JSON.parse(json)
    return parsed ?? fallback
  } catch {
    return fallback
  }
}

/**
 * Extract data from an API response: a given key, else the whole object.
 * Pelagos lists arrive as { items: [...] }.
 */
export function extractData(obj, key, fallback = null) {
  if (!obj) return fallback
  if (key !== undefined) return obj?.[key] ?? fallback
  return obj?.items ?? obj?.data ?? obj ?? fallback
}

/**
 * Format a date in the browser's time zone and the app language (not the browser locale).
 * fmt: 'short' (default) | 'long' | 'iso'; options override Intl options.
 */
export function formatDate(date, options = {}) {
  if (!date) return '-'
  try {
    const d = new Date(date)
    if (Number.isNaN(d.getTime())) return '-'
    const fmt = options.format || 'short'
    if (fmt === 'iso') return d.toISOString().replace('T', ' ').slice(0, 16)
    const { format: _format, ...rest } = options
    const base = fmt === 'long'
      ? { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' }
      : { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
    return new Intl.DateTimeFormat(i18n.language || undefined, { ...base, ...rest }).format(d)
  } catch {
    return '-'
  }
}

/**
 * Relative time: just now, Xm ago, Xh Ym ago, Xd Yh ago, else a formatted date.
 * Strings come from common:time.* in the app language; `t` is accepted for old callers.
 */
// eslint-disable-next-line no-unused-vars
export function formatRelativeTime(date, t) {
  if (!date) return '-'
  const then = new Date(date)
  const diffMs = Date.now() - then.getTime()
  if (Number.isNaN(diffMs) || diffMs < 0) return formatDate(date)
  const diffSecs = Math.floor(diffMs / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)
  const remainMins = diffMins % 60
  const remainHours = diffHours % 24
  const tr = (key, fallback, vars) => i18n.t(`common:${key}`, { ...vars, defaultValue: fallback })
  if (diffSecs < 60) return tr('time.justNow', 'just now')
  if (diffMins < 60) return tr('time.minutesAgo', `${diffMins}m ago`, { count: diffMins })
  if (diffHours < 24) {
    return remainMins > 0
      ? tr('time.hoursMinutesAgo', `${diffHours}h ${remainMins}m ago`, { hours: diffHours, minutes: remainMins })
      : tr('time.hoursAgo', `${diffHours}h ago`, { count: diffHours })
  }
  if (diffDays < 7) {
    return remainHours > 0
      ? tr('time.daysHoursAgo', `${diffDays}d ${remainHours}h ago`, { days: diffDays, hours: remainHours })
      : tr('time.daysAgo', `${diffDays}d ago`, { count: diffDays })
  }
  return formatDate(date)
}

// A non-empty pool never reads 0%, a pool that is not full never reads 100%.
// A size in bytes with decimal units in the app language (1,5 Go in French, 1.5 GB in English).
export function formatSize(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes))) return ''
  const n = Number(bytes)
  const [value, unit] = n >= 1e9 ? [n / 1e9, 'GB'] : n >= 1e6 ? [n / 1e6, 'MB'] : n >= 1e3 ? [n / 1e3, 'kB'] : [n, 'B']
  const digits = unit === 'B' || unit === 'kB' || (unit === 'MB' && value >= 10) ? 0 : 1
  const text = new Intl.NumberFormat(i18n.language || 'en', { maximumFractionDigits: digits }).format(value)
  return i18n.t(`common:units.${unit}`, { value: text, defaultValue: `${text} ${unit}` })
}

export function formatPercent(percent) {
  const p = Number(percent) || 0
  if (p > 0 && p < 1) return '<1%'
  if (p > 99 && p < 100) return '>99%'
  return `${Math.round(Math.max(0, Math.min(100, p)))}%`
}

export function exportToCSV(data, columns, filename = 'export') {
  if (!data || data.length === 0) return
  const headers = columns.map((col) => col.header || col.key)
  const rows = data.map((row) =>
    columns
      .map((col) => {
        let value = col.accessor ? col.accessor(row) : row[col.key]
        if (value === null || value === undefined) value = ''
        value = String(value)
        if (value.includes(',') || value.includes('"') || value.includes('\n')) {
          value = `"${value.replace(/"/g, '""')}"`
        }
        return value
      })
      .join(','),
  )
  const csv = [headers.join(','), ...rows].join('\n')
  downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8;' }), `${filename}-${today()}.csv`)
}

export function exportToJSON(data, filename = 'export') {
  if (!data || (Array.isArray(data) && data.length === 0)) return
  const json = JSON.stringify(data, null, 2)
  downloadBlob(new Blob([json], { type: 'application/json' }), `${filename}-${today()}.json`)
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function today() {
  return new Date().toISOString().split('T')[0]
}
