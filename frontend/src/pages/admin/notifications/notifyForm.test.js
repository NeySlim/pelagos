// SPDX-License-Identifier: Apache-2.0
// Channel forms: the body carries only what the type uses, secrets are write-only (typed, null
// to clear, never echoed), client checks match the transports' validation, and every literal
// notifications key of these pages exists in both languages.
import { describe, it, expect } from 'vitest'
import { resources, languages } from '../../../i18n'
import { channelBody, formErrors, formFromChannel, formWarnings, muteUntil, notificationsOfAlert, parseHeaders, serverFieldErrors, testBody } from './notifyForm'

const NTFY = {
  id: 'ch-ntfy', type: 'ntfy', name: 'Phone', enabled: true, language: 'fr',
  params: { url: 'https://ntfy.example.lan', topic: 'pelagos' },
  filters: { severity_min: 'critical', kinds_include: [], kinds_exclude: ['ha_transition'], node_ids: [], engines: ['kea4'] },
  schedule: { reminder_hours: 6, send_resolved: false, confirm_seconds: null, quiet: { start: '22:00', end: '07:00', timezone: 'Europe/Paris', days: [5, 6], critical_passes: false } },
  secrets: { token: true, password: false },
  status: { state: 'ok' },
}

describe('notification channel form', () => {
  it('round-trips a stored ntfy channel without sending its secret', () => {
    const form = formFromChannel(NTFY)
    expect(form.ntfy_auth).toBe('token')
    expect(formErrors(form)).toEqual({})
    const body = channelBody(form)
    expect(body).toEqual({
      type: 'ntfy', name: 'Phone', enabled: true, language: 'fr',
      params: { url: 'https://ntfy.example.lan', topic: 'pelagos' },
      filters: NTFY.filters,
      schedule: NTFY.schedule,
    })
    expect(body).not.toHaveProperty('secrets')
    expect(body).not.toHaveProperty('status')
  })

  it('sends a typed secret, clears a stored one, and drops the token when ntfy switches to Basic', () => {
    const form = formFromChannel(NTFY)
    form.secrets.token = 'tk_new'
    expect(channelBody(form).secrets).toEqual({ token: 'tk_new' })
    form.secrets.token = ''
    form.ntfy_auth = 'basic'
    form.params.username = 'pelagos'
    expect(formErrors(form)['secrets.password']).toBe('required')
    form.secrets.password = 'pw'
    expect(formErrors(form)).toEqual({})
    const body = channelBody(form)
    expect(body.secrets).toEqual({ token: null, password: 'pw' })
    expect(body.params.username).toBe('pelagos')
  })

  it('checks each type like the transports', () => {
    const email = formFromChannel({}, 'email')
    email.name = 'Mail'
    email.params.host = 'smtp.example.lan'
    email.params.security = 'none'
    email.params.from = 'nope'
    email.params.to = ['ops@example.lan', 'bad']
    email.secrets.password = 'x'
    expect(formErrors(email)).toMatchObject({ 'params.security': 'loopbackOnly', 'params.from': 'email', 'params.to': 'email', 'params.username': 'usernameWithPassword' })
    email.params.host = '127.0.0.1'
    expect(formErrors(email)['params.security']).toBeUndefined()
    expect(formWarnings(email)['params.security']).toBe('noTls')

    const matrix = formFromChannel({ name: 'Room', params: { homeserver: 'https://m.example.lan', room_id: '#alias:example.lan' } }, 'matrix')
    expect(formErrors(matrix)).toMatchObject({ 'params.room_id': 'room', 'secrets.token': 'required' })

    const hook = formFromChannel({ name: 'Hook', params: { url: 'https://u:p@hooks.example.lan/x?y=1' } }, 'webhook')
    expect(formErrors(hook)['params.url']).toBe('urlCredentials')
    hook.params.url = 'http://hooks.example.lan/x'
    hook.params.headers = 'X-Team: dns\nX-Pelagos-Signature: forged'
    expect(formErrors(hook)['params.headers']).toBe('headerReserved')
    hook.params.headers = 'X-Team: dns'
    hook.secrets.hmac_secret = 's'
    expect(formErrors(hook)).toEqual({})
    expect(formWarnings(hook)['params.url']).toBe('plainHttp')
    expect(channelBody(hook).params.headers).toEqual({ 'X-Team': 'dns' })

    const gotify = formFromChannel({ name: 'G', params: { url: 'https://g.example.lan' }, secrets: { token: true } }, 'gotify')
    gotify.params.priorities.critical = 11
    expect(formErrors(gotify)).toEqual({ 'params.priorities.critical': 'priority' })

    const ha = formFromChannel({ name: 'HA', params: { url: 'https://ha.example.lan:8123' } }, 'home_assistant')
    expect(formErrors(ha)['secrets.webhook_id']).toBe('required')
    ha.secrets.webhook_id = 'bad id'
    expect(formErrors(ha)['secrets.webhook_id']).toBe('webhookId')
  })

  it('asks for a stored secret again when the channel moves to another server', () => {
    const form = formFromChannel(NTFY)
    form.params.url = 'https://ntfy.example.lan/'
    expect(formErrors(form)).toEqual({})
    form.params.url = 'https://other.example.lan'
    expect(formErrors(form)['secrets.token']).toBe('reenter')
    form.clear.token = true
    form.ntfy_auth = 'none'
    expect(formErrors(form)).toEqual({})
    expect(channelBody(form).secrets).toEqual({ token: null })
  })

  it('checks quiet hours and builds the schedule', () => {
    const form = formFromChannel(NTFY)
    form.schedule.quiet.start = '25:00'
    form.schedule.quiet.days = []
    expect(formErrors(form)).toMatchObject({ 'schedule.quiet.start': 'time', 'schedule.quiet.days': 'days' })
    form.schedule.quiet_enabled = false
    form.schedule.confirm_seconds = '0'
    const body = channelBody(form)
    expect(body.schedule.quiet).toBeNull()
    expect(body.schedule.confirm_seconds).toBe(0)
  })

  it('tests a saved channel by id, an edited one as unsaved with its scope', () => {
    const form = formFromChannel(NTFY)
    expect(testBody(form, 'ch-ntfy', { dirty: false })).toEqual({ channel_id: 'ch-ntfy' })
    const body = testBody(form, 'ch-ntfy')
    expect(body.scope).toBe('ch-ntfy')
    expect(body.type).toBe('ntfy')
    expect(testBody(formFromChannel({}, 'gotify'))).not.toHaveProperty('scope')
  })

  it('maps server field errors, parses headers, bounds the mute', () => {
    expect(serverFieldErrors([{ field: 'params.to.1', message: 'e-mail address expected' }, { field: 'params.headers.X-A', message: 'set by Pelagos' }])).toEqual({
      'params.to': 'e-mail address expected', 'params.headers': 'set by Pelagos',
    })
    expect(parseHeaders('A: 1\n\nB:2:3')).toEqual({ A: '1', B: '2:3' })
    const now = Date.parse('2026-10-28T10:00:00Z')
    expect(muteUntil(48, now)).toBe('2026-10-29T10:00:00.000Z')
  })

  it('keeps the sent batches that carry an alert', () => {
    const items = [
      { result: 'ok', channel_id: 'a', events: [{ alert_id: 'X' }] },
      { result: 'failed', channel_id: 'b', events: [{ alert_id: 'X' }] },
      { result: 'ok', channel_id: 'c', events: [{ event: 'test' }] },
    ]
    expect(notificationsOfAlert(items, 'X').map((h) => h.channel_id)).toEqual(['a'])
  })
})

describe('notifications i18n', () => {
  const sources = import.meta.glob(['./*.jsx'], { eager: true, query: '?raw', import: 'default' })
  const node = (lang, ns, key) => key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), resources[lang][ns])
  const resolve = (lang, ns, key) => node(lang, ns, key) ?? node(lang, ns, `${key}_other`)
  const flat = (obj, prefix = '') => Object.entries(obj).flatMap(([k, v]) => (v && typeof v === 'object' ? flat(v, `${prefix}${k}.`) : [`${prefix}${k}`]))

  it('has the same keys in every language', () => {
    const en = flat(resources.en.notifications).sort()
    for (const { code } of languages) expect(flat(resources[code].notifications).sort()).toEqual(en)
  })

  it('resolves every literal key of the notification pages in every language', () => {
    let count = 0
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/\bt\(\s*'([A-Za-z0-9_.:-]+)'/g)) {
        const [ns, key] = m[1].includes(':') ? m[1].split(':') : ['notifications', m[1]]
        for (const { code } of languages) expect(resolve(code, ns, key), `${file}: ${code} ${ns}:${key}`).toBeTypeOf('string')
        count += 1
      }
    }
    expect(count).toBeGreaterThan(100)
  })

  it('names every type, error and warning key the form can produce', () => {
    for (const { code } of languages) {
      for (const k of ['email', 'ntfy', 'gotify', 'matrix', 'webhook', 'home_assistant']) {
        expect(node(code, 'notifications', `types.${k}`)).toBeTypeOf('string')
        expect(node(code, 'notifications', `typeHelp.${k}`)).toBeTypeOf('string')
        expect(node(code, 'notifications', `placeholders.name.${k}`)).toBeTypeOf('string')
      }
      for (const k of ['required', 'url', 'urlCredentials', 'urlQuery', 'port', 'loopbackOnly', 'email', 'usernameWithPassword', 'topic', 'priority', 'room', 'header', 'headerReserved', 'webhookId', 'reenter', 'hours', 'seconds', 'time', 'days']) {
        expect(node(code, 'notifications', `errors.${k}`), k).toBeTypeOf('string')
      }
      for (const k of ['plainHttp', 'noTls']) expect(node(code, 'notifications', `warnings.${k}`)).toBeTypeOf('string')
    }
  })
})
