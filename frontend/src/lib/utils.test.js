// SPDX-License-Identifier: Apache-2.0
// Dates and relative times follow the app language, not the browser locale; percents never
// round a used pool to 0%.
import { describe, it, expect, afterEach } from 'vitest'
import i18n from '../i18n'
import { formatDate, formatRelativeTime, formatPercent } from './utils'

const ago = (ms) => new Date(Date.now() - ms).toISOString()

describe('formatRelativeTime and formatDate', () => {
  afterEach(() => i18n.changeLanguage('en'))

  it('speak the app language without a t function', async () => {
    expect(formatRelativeTime(ago(5000))).toBe('just now')
    expect(formatRelativeTime(ago(3 * 60000))).toBe('3 min ago')
    await i18n.changeLanguage('fr')
    expect(formatRelativeTime(ago(5000))).toBe("à l'instant")
    expect(formatRelativeTime(ago(3 * 60000))).toBe('il y a 3 min')
    expect(formatRelativeTime(ago((60 + 55) * 60000))).toBe('il y a 1 h 55 min')
  })

  it('format dates with the app language', async () => {
    const d = '2026-10-24T18:14:00Z'
    await i18n.changeLanguage('fr')
    expect(formatDate(d)).toBe(new Intl.DateTimeFormat('fr', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(d)))
    expect(formatDate(d)).toMatch(/oct\./)
  })

  it('sets <html lang> when the language changes', async () => {
    await i18n.changeLanguage('fr')
    expect(document.documentElement.lang).toBe('fr')
    await i18n.changeLanguage('en')
    expect(document.documentElement.lang).toBe('en')
  })
})

describe('formatPercent', () => {
  it.each([
    [0, '0%'],
    [0.39, '<1%'],
    [0.29, '<1%'],
    [12.4, '12%'],
    [99.6, '>99%'],
    [100, '100%'],
    [150, '100%'],
  ])('%s -> %s', (value, text) => expect(formatPercent(value)).toBe(text))
})

describe('plural forms', () => {
  it('pick the singular for one', () => {
    expect(i18n.t('dashboard:tiles.d2.errors', { count: 1 })).toBe('1 error')
    expect(i18n.t('dashboard:tiles.d2.errors', { count: 2 })).toBe('2 errors')
    expect(i18n.t('common:diff.lines', { count: 1 })).toBe('1 line')
    expect(i18n.getFixedT('fr')('common:diff.lines', { count: 1 })).toBe('1 ligne')
    expect(i18n.getFixedT('fr')('common:diff.lines', { count: 3 })).toBe('3 lignes')
  })
})
