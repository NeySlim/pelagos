// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { resources, languages } from '../../../i18n'
import {
  destinationBody, destinationErrors, formFromDestination, partChanged, partInfo, restorePlanBody, restoreRequest,
  serverFieldErrors, settingsChanges, settingsErrors, settingsForm, formatBytes,
} from './archivesForm'

const FP = `SHA256:${'A'.repeat(43)}`
const SFTP = { id: 'd1', type: 'sftp', name: 'Off site', enabled: true, params: { host: 'backup.example.lan', port: 22, username: 'pelagos', path: 'archives', host_key_fingerprint: FP }, keep: null, secrets: { ssh_key: true } }

describe('archive destination form', () => {
  it('sends the key only when typed or cleared, and the type only on create', () => {
    const form = formFromDestination(SFTP)
    expect(destinationErrors(form, SFTP)).toEqual({})
    const body = destinationBody(form, { editing: true })
    expect(body).not.toHaveProperty('secrets')
    expect(body).not.toHaveProperty('type')
    expect(body.params).toEqual({ host: 'backup.example.lan', port: 22, username: 'pelagos', path: 'archives', host_key_fingerprint: FP })
    expect(destinationBody({ ...form, clearKey: true }, { editing: true }).secrets).toEqual({ ssh_key: null })
    expect(destinationBody({ ...form, sshKey: 'k' }).secrets).toEqual({ ssh_key: 'k' })
    expect(destinationBody(formFromDestination({ type: 'peer', name: 'p' })).type).toBe('peer')
  })

  it('asks for the key again when the server moves, and checks the fields', () => {
    const moved = { ...formFromDestination(SFTP), host: 'other.example.lan' }
    expect(destinationErrors(moved, SFTP).sshKey).toBe('keyAgain')
    const fresh = { ...formFromDestination({ type: 'sftp' }), name: 'x', host: 'h', username: 'u', fingerprint: 'nope', sshKey: 'not a key' }
    expect(destinationErrors(fresh)).toMatchObject({ fingerprint: 'fingerprint', sshKey: 'privateKey' })
    expect(destinationErrors({ ...formFromDestination({ type: 'mounted', name: 'n' }), path: 'rel' })).toEqual({ path: 'absolutePath' })
    const keep = { ...formFromDestination({ type: 'peer', name: 'p' }), customKeep: true, keep: { daily: '3', weekly: 'x', monthly: '1' } }
    expect(destinationErrors(keep)).toEqual({ 'keep.weekly': 'count' })
    expect(destinationBody({ ...keep, keep: { daily: '3', weekly: '0', monthly: '1' } }).keep).toEqual({ daily: 3, weekly: 0, monthly: 1 })
    expect(serverFieldErrors({ errors: [{ field: 'params.host_key_fingerprint', message: 'bad' }] })).toEqual({ fingerprint: 'bad' })
  })
})

describe('archive settings form', () => {
  const settings = { schedule_enabled: false, start_time: '03:15', interval_hours: 24, stagger_minutes: 15, keep_daily_count: 7, keep_weekly_count: 4, keep_monthly_count: 6, local_keep_count: 3, include_leases_enabled: true, verify_enabled: true, test_restore_days: 7, max_archive_mb: 512 }
  it('sends only the changed values, typed', () => {
    const form = settingsForm(settings)
    expect(settingsChanges(form, settings)).toEqual({})
    expect(settingsChanges({ ...form, interval_hours: '12', verify_enabled: false }, settings)).toEqual({ interval_hours: 12, verify_enabled: false })
    expect(settingsErrors({ ...form, start_time: '3h', local_keep_count: '0' })).toEqual({ start_time: 'time', local_keep_count: { code: 'range', min: 1, max: 100 } })
  })
})

describe('restore helpers', () => {
  it('reads part ids and their difference', () => {
    expect(partInfo('bind.zone:_default/example.lan')).toEqual({ kind: 'zone', view: '_default', zone: 'example.lan', partner: null })
    expect(partInfo('kea4.config@n2')).toEqual({ kind: 'kea4.config', partner: 'n2' })
    expect(partInfo('pelagos.settings:users').section).toBe('users')
    expect(partChanged({ diff_summary: { changed: [] } })).toBe(false)
    expect(partChanged({ diff_summary: { add: 1 } })).toBe(true)
    expect(partChanged({ diff_summary: { entries: 0 } })).toBe(false)
    expect(partChanged({ diff_summary: { error: 'x', changed: true } })).toBe(false)
  })

  it('builds the inspect and plan bodies', () => {
    const request = restoreRequest({ target: 'n2', identity: ' AGE-SECRET-KEY-1X ', substitute: '192.0.2.12=192.0.2.14\nbad line\nns2 = ns4', haTlsPlain: true })
    expect(request).toEqual({ target_node_id: 'n2', identity: 'AGE-SECRET-KEY-1X', substitute: { '192.0.2.12': '192.0.2.14', ns2: 'ns4' }, ha_tls: 'plain' })
    expect(restorePlanBody({ target_node_id: 'n1' }, ['bind.zone:_default/a', 'kea4.config'], { 'bind.zone:_default/a': 'replace' }, false))
      .toEqual({ target_node_id: 'n1', parts: [{ id: 'bind.zone:_default/a', mode: 'replace' }, 'kea4.config'] })
    expect(restorePlanBody({}, ['bind.user_files'], {}, true).include_user_files).toBe(true)
    expect(formatBytes(1843200)).toBe('1.8 MiB')
  })
})

// Every literal key the archives screen passes to t() resolves in each language.
const sources = import.meta.glob(['./*.jsx', '!./*.test.*'], { eager: true, query: '?raw', import: 'default' })
describe('archives i18n', () => {
  it('resolves every literal key', () => {
    expect(Object.keys(sources)).toHaveLength(3)
    const resolve = (lang, key) => {
      const get = (path) => path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), resources[lang].archives)
      return get(key) ?? get(`${key}_other`)
    }
    for (const text of Object.values(sources)) {
      for (const m of text.matchAll(/\bt\(\s*'([A-Za-z0-9_.-]+)'/g)) {
        for (const { code } of languages) expect(resolve(code, m[1]), `${code}: ${m[1]}`).toBeTruthy()
      }
    }
  })
})
