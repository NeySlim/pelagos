// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  stepsFor, suggestMode, engineChoices, defaultEngines, initialState, setMode, toggleEngine,
  validateStep, canGoNext, next, prev, buildRequest, needsSeries,
} from './wizard'

const engine = (installed) => ({ installed, version: installed ? '1' : null })
const bare = { engines: { bind: engine(false), kea4: engine(false), kea6: engine(false), d2: engine(false) } }
const full = { engines: { bind: engine(true), kea4: engine(true), kea6: engine(true), d2: engine(true) } }
const dnsOnly = { engines: { bind: engine(true), kea4: engine(false), kea6: engine(false), d2: engine(false) } }

describe('install wizard steps', () => {
  it('install has a package step, import does not', () => {
    expect(stepsFor('install')).toEqual(['mode', 'engines', 'source', 'review'])
    expect(stepsFor('import')).toEqual(['mode', 'engines', 'review'])
  })

  it('suggests install on a bare node and import when something is installed', () => {
    expect(suggestMode(bare)).toBe('install')
    expect(suggestMode(dnsOnly)).toBe('import')
    expect(suggestMode(full)).toBe('import')
    expect(suggestMode(undefined)).toBe('install')
  })

  it('offers missing engines to install and installed ones to import', () => {
    const install = engineChoices('install', dnsOnly)
    expect(install.find((c) => c.engine === 'bind')).toMatchObject({ selectable: false, reason: 'installed' })
    expect(install.find((c) => c.engine === 'kea4')).toMatchObject({ selectable: true, reason: null })
    const imp = engineChoices('import', dnsOnly)
    expect(imp.filter((c) => c.selectable).map((c) => c.engine)).toEqual(['bind'])
    expect(imp.find((c) => c.engine === 'd2').reason).toBe('notInstalled')
  })

  it('keeps DHCPv6 out when the module is disabled and opt-in for a fresh install', () => {
    expect(engineChoices('install', bare, { dhcpv6: false }).find((c) => c.engine === 'kea6')).toMatchObject({ selectable: false, reason: 'module' })
    expect(defaultEngines('install', bare)).toEqual(['bind', 'kea4', 'd2'])
    expect(defaultEngines('import', full)).toEqual(['bind', 'kea4', 'kea6', 'd2'])
    expect(defaultEngines('import', full, { dhcpv6: false })).toEqual(['bind', 'kea4', 'd2'])
  })

  it('starts on the mode step with defaults for the suggested mode', () => {
    expect(initialState(bare)).toEqual({ mode: 'install', step: 'mode', engines: ['bind', 'kea4', 'd2'], source: 'distro', iscSeries: '3.2' })
    expect(initialState(dnsOnly).engines).toEqual(['bind'])
  })

  it('resets the engines when the mode changes', () => {
    const s = setMode(initialState(dnsOnly), 'install', dnsOnly)
    expect(s.mode).toBe('install')
    expect(s.engines).toEqual(['kea4', 'd2'])
  })

  it('toggles engines and keeps them in canonical order', () => {
    let s = { ...initialState(bare), engines: [] }
    s = toggleEngine(s, 'd2')
    s = toggleEngine(s, 'bind')
    expect(s.engines).toEqual(['bind', 'd2'])
    expect(toggleEngine(s, 'bind').engines).toEqual(['d2'])
  })

  it('validates the engines step', () => {
    const base = { ...initialState(bare), step: 'engines' }
    expect(validateStep({ ...base, engines: [] }, bare)).toBe('noEngine')
    expect(validateStep({ ...base, engines: ['d2'] }, bare)).toBe('d2NeedsKea')
    expect(validateStep({ ...base, engines: ['d2', 'kea6'] }, bare)).toBe(null)
    // D2 alone is fine when Kea is already there.
    const keaThere = { engines: { ...bare.engines, kea4: engine(true) } }
    expect(validateStep({ ...base, engines: ['d2'] }, keaThere)).toBe(null)
    expect(validateStep({ ...base, mode: 'import', engines: ['bind'] }, bare)).toBe('notSelectable')
  })

  it('validates the package source and the ISC series', () => {
    const base = { ...initialState(bare), step: 'source' }
    expect(validateStep({ ...base, source: 'ppa' }, bare)).toBe('source')
    expect(validateStep({ ...base, source: 'isc', iscSeries: '9.9' }, bare)).toBe('series')
    expect(validateStep({ ...base, source: 'isc', iscSeries: '3.0' }, bare)).toBe(null)
    expect(validateStep({ ...base, source: 'distro', iscSeries: '9.9' }, bare)).toBe(null)
  })

  it('walks forward only when the step is valid and stops at review', () => {
    let s = initialState(bare)
    s = next(s, bare)
    expect(s.step).toBe('engines')
    const blocked = next({ ...s, engines: [] }, bare)
    expect(blocked.step).toBe('engines')
    s = next(s, bare)
    expect(s.step).toBe('source')
    s = next(s, bare)
    expect(s.step).toBe('review')
    expect(canGoNext(s, bare)).toBe(false)
    expect(next(s, bare)).toBe(s)
    expect(prev(s).step).toBe('source')
    expect(prev(initialState(bare)).step).toBe('mode')
  })

  it('import goes from engines straight to review', () => {
    let s = initialState(full)
    s = next(next(s, full), full)
    expect(s.step).toBe('review')
    expect(prev(s).step).toBe('engines')
  })

  it('builds the request bodies of section 17', () => {
    expect(buildRequest({ mode: 'import', engines: ['bind', 'kea4'] })).toEqual({ kind: 'import', body: { engines: ['bind', 'kea4'] } })
    expect(buildRequest({ mode: 'install', engines: ['bind'], source: 'distro', iscSeries: '3.2' })).toEqual({ kind: 'install', body: { engines: ['bind'], source: 'distro' } })
    expect(buildRequest({ mode: 'install', engines: ['kea4'], source: 'isc', iscSeries: '3.0' })).toEqual({ kind: 'install', body: { engines: ['kea4'], source: 'isc', isc_series: '3.0' } })
    // The series only applies to Kea.
    expect(needsSeries({ engines: ['bind'], source: 'isc' })).toBe(false)
    expect(buildRequest({ mode: 'install', engines: ['bind'], source: 'isc', iscSeries: '3.2' }).body).not.toHaveProperty('isc_series')
  })
})
