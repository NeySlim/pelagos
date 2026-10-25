// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { resources, languages } from '../../i18n'
import { paramKind, buildParams, runBlocker, groupOps } from './opsForm'

const nta = { name: 'nta-add', write: true, params: ['name', 'lifetime', 'view'], required: ['name'], choices: {} }
const sync = { name: 'ha-sync', write: true, params: ['server-name', 'max-period'], required: [], choices: {} }
const reclaim = { name: 'leases-reclaim', write: true, params: ['remove'], required: ['remove'], choices: {} }
const querylog = { name: 'querylog', write: true, params: ['mode'], required: ['mode'], choices: { mode: ['on', 'off'] } }

describe('opsForm', () => {
  it('knows each parameter kind', () => {
    expect(paramKind(querylog, 'mode')).toBe('choice')
    expect(paramKind(sync, 'max-period')).toBe('int')
    expect(paramKind(reclaim, 'remove')).toBe('bool')
    expect(paramKind({ choices: {} }, 'scopes')).toBe('list')
    expect(paramKind(nta, 'name')).toBe('text')
  })

  it('builds typed params and reports missing or malformed fields', () => {
    expect(buildParams(nta, { name: ' bad.example ', lifetime: '', view: undefined })).toEqual({ params: { name: 'bad.example' }, errors: {} })
    expect(buildParams(nta, {}).errors).toEqual({ name: 'required' })
    expect(buildParams(sync, { 'max-period': '30', 'server-name': 'ns2' }).params).toEqual({ 'max-period': 30, 'server-name': 'ns2' })
    expect(buildParams(sync, { 'max-period': 'soon' }).errors).toEqual({ 'max-period': 'int' })
    expect(buildParams(reclaim, {}).params).toEqual({ remove: false })
    expect(buildParams(reclaim, { remove: true }).params).toEqual({ remove: true })
    expect(buildParams({ params: ['scopes'], required: ['scopes'], choices: {} }, { scopes: [] }).errors).toEqual({ scopes: 'required' })
  })

  it('blocks what cannot run', () => {
    const local = { isLocal: true, confirmed: false, allowed: true }
    expect(runBlocker(null, local)).toBe('none')
    expect(runBlocker(nta, { ...local, allowed: false })).toBe('permission')
    expect(runBlocker({ ...nta, available: false }, local)).toBe('unavailable')
    expect(runBlocker(nta, { ...local, isLocal: false })).toBe(null)
    expect(runBlocker({ ...nta, write: false }, { ...local, isLocal: false })).toBe(null)
    expect(runBlocker({ ...nta, confirm: true }, local)).toBe('confirm')
    expect(runBlocker({ ...nta, confirm: true }, { ...local, confirmed: true })).toBe(null)
  })

  it('splits reads and changes and filters by name', () => {
    const ops = [{ name: 'status', write: false, permission: 'read:dns' }, nta, querylog]
    const g = groupOps(ops, (p) => p === 'read:dns', 'nta')
    expect(g.reads).toEqual([])
    expect(g.changes.map((o) => o.name)).toEqual(['nta-add'])
    expect(g.allowed(ops[0])).toBe(true)
  })

  it('has a help text in every language for each allow-listed operation', () => {
    // The allow-lists live in the backend ops service; every _op("name", ...) is offered.
    const source = readFileSync(resolve(__dirname, '../../../../backend/pelagos/services/ops_service.py'), 'utf8')
    const names = [...source.matchAll(/_op\(\s*"([a-z0-9-]+)"/g)].map((m) => m[1])
    expect(names.length).toBeGreaterThan(50)
    for (const { code: lang } of languages) {
      const help = resources[lang].advanced.ops.help
      expect(names.filter((n) => !help[n]), lang).toEqual([])
    }
  })
})
