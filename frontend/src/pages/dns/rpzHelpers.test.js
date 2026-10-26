// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import catalog from '../../../../backend/pelagos/rpz/catalog.json'
import { resources, languages } from '../../i18n'
import {
  categoryBody,
  defaultSelection,
  estimatedMb,
  formFromSelection,
  formatBytes,
  formatCount,
  formatMb,
  latestStatus,
  levelsOf,
  sameForm,
  selectedLists,
  selectionEntries,
  validDomain,
  validNetwork,
  validUrl,
  worstStatus,
} from './rpzHelpers'

const view = (id) => {
  const c = catalog.categories[id]
  const levels = Object.fromEntries(
    Object.entries(c.levels).map(([level, lists]) => [level, { lists, entries: lists.reduce((n, i) => n + catalog.lists[i].entries, 0) }]),
  )
  return { levels, lists: c.lists, addons: c.addons || [] }
}

describe('rpz helpers', () => {
  it('formats counts and sizes', () => {
    expect(formatCount(118000)).toBe('118 000')
    expect(formatMb(94.4)).toBe('94 MB')
    expect(formatMb(1520)).toBe('1.5 GB')
    expect(formatBytes(7_300_000)).toBe('7.3 MB')
    expect(formatBytes(48_000)).toBe('48 kB')
    expect(estimatedMb(118000, 800)).toBe(94.4)
  })

  it('offers the levels a category defines, and custom when it has several lists', () => {
    expect(levelsOf(view('ads'))).toEqual(['light', 'normal', 'strict', 'custom'])
    expect(levelsOf(view('social'))).toEqual(['normal'])
  })

  it('turns a level and add-ons into lists and a size', () => {
    const ads = view('ads')
    const form = { ...defaultSelection(ads), level: 'light', addons: ['hagezi-popupads'] }
    expect(selectedLists(ads, form)).toEqual(['oisd-small', 'hagezi-popupads'])
    expect(selectionEntries(catalog, ads, form)).toBe(catalog.lists['oisd-small'].entries + catalog.lists['hagezi-popupads'].entries)
    const custom = { ...form, level: 'custom', lists: ['hagezi-pro'] }
    expect(selectedLists(ads, custom)).toEqual(['hagezi-pro', 'hagezi-popupads'])
  })

  it('builds the request body and detects changes', () => {
    const ads = view('ads')
    const form = { ...defaultSelection(ads), level: 'strict', action: 'redirect', redirect: '192.0.2.80', urls: ['https://lists.example.com/a.txt'], nodes: ['n1'] }
    expect(categoryBody(form)).toEqual({
      enabled: true, level: 'strict', addons: [], urls: [{ url: 'https://lists.example.com/a.txt', format: 'auto' }],
      action: 'redirect', interval_hours: 24, redirect: '192.0.2.80', nodes: ['n1'],
    })
    const saved = { enabled: true, level: 'strict', addons: [], urls: [{ url: 'https://lists.example.com/a.txt' }], action: 'redirect', redirect: '192.0.2.80', interval_hours: 24, nodes: ['n1'] }
    expect(sameForm(formFromSelection(ads, saved), form)).toBe(true)
    expect(sameForm({ ...form, level: 'light' }, form)).toBe(false)
    expect(formFromSelection(ads, undefined).enabled).toBe(false)
  })

  it('validates what the forms accept', () => {
    expect(validUrl('https://lists.example.com/list.txt')).toBe(true)
    expect(validUrl('ftp://lists.example.com/list.txt')).toBe(false)
    expect(validDomain('*.shop.example.com.')).toBe(true)
    expect(validDomain('not a domain')).toBe(false)
    expect(validNetwork('192.0.2.0/24')).toBe(true)
    expect(validNetwork('2001:db8::1')).toBe(true)
    expect(validNetwork('hello')).toBe(false)
  })

  it('summarizes the status of a subscription over the nodes', () => {
    expect(worstStatus({})).toEqual({ status: 'pending', error: '' })
    expect(worstStatus({ a: { status: 'ok' }, b: null }).status).toBe('pending')
    expect(worstStatus({ a: { status: 'ok' }, b: { status: 'rejected', error: 'shrank by 70%' } })).toEqual({ status: 'rejected', error: 'shrank by 70%' })
    expect(latestStatus({ a: { ok_at: 10, entries: 1 }, b: { ok_at: 20, entries: 2 }, c: null }).entries).toBe(2)
  })
})

describe('rpz catalog in the interface', () => {
  it.each(languages.map((l) => l.code))('%s names and describes every category', (lang) => {
    for (const id of Object.keys(catalog.categories)) {
      expect(resources[lang].dns.rpzsub.categories[id]?.name, `${lang} ${id}`).toBeTruthy()
      expect(resources[lang].dns.rpzsub.categories[id]?.description, `${lang} ${id}`).toBeTruthy()
    }
  })

  it('has no em dash in the catalog or the texts', () => {
    expect(JSON.stringify(catalog)).not.toContain('—')
    for (const lang of languages.map((l) => l.code)) expect(JSON.stringify(resources[lang].dns.rpzsub)).not.toContain('—')
  })
})
