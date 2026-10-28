// SPDX-License-Identifier: Apache-2.0
// One notification channel: the fields of its type, filters, grouping and reminders, quiet
// hours and language. Secrets are typed here and sent once; the form only shows whether one is
// stored and can clear it. "Send a test" sends a real message from this node, before saving.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PaperPlaneTilt, Trash } from '@phosphor-icons/react'
import { FormModal, Input, Textarea, Select, TagsInput, ToggleSwitch, Button, Badge, MultiSelectFilter } from '../../../components'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { useNotification } from '../../../contexts/NotificationContext'
import { KINDS } from '../../alerts/lib'
import {
  CHANNEL_TYPES, DAYS, EMAIL_SECURITY, ENGINES, LANGUAGES, NTFY_AUTH, SEVERITIES,
  channelBody, formErrors, formFromChannel, formWarnings, serverFieldErrors, testBody, usedSecrets,
} from './notifyForm'

const setPath = (obj, path, value) => {
  const [head, ...rest] = path.split('.')
  return { ...obj, [head]: rest.length ? setPath(obj[head] || {}, rest.join('.'), value) : value }
}

// Toggle buttons for a small set of values (nodes, engines, days).
function Chips({ label, options, value, onChange, testId, error, help }) {
  const toggle = (v) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v])
  return (
    <div className="space-y-1" data-testid={testId}>
      <span className="block text-xs font-medium text-text-secondary">{label}</span>
      <div className="flex flex-wrap gap-1.5">
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            aria-pressed={value.includes(o.value)}
            onClick={() => toggle(o.value)}
            data-value={o.value}
            className={`px-2 py-0.5 rounded-md border text-xs transition-colors ${value.includes(o.value) ? 'border-accent-primary bg-accent-primary-op15 text-text-primary' : 'border-border text-text-secondary hover:bg-bg-tertiary'}`}
          >
            {o.label}
          </button>
        ))}
      </div>
      {help && !error && <p className="text-2xs text-text-tertiary">{help}</p>}
      {error && <p className="text-2xs status-danger-text">{error}</p>}
    </div>
  )
}

// A write-only secret: typed value, "stored" badge, and a clear button for a stored one.
function SecretInput({ form, name, label, onType, onClear, error }) {
  const { t } = useTranslation('notifications')
  const stored = Boolean(form.stored[name]) && !form.clear[name]
  return (
    <div className="space-y-1">
      <Input
        label={label}
        type="password"
        noAutofill
        hasExistingValue={stored}
        value={form.secrets[name]}
        onChange={(e) => onType(e.target.value)}
        error={error}
        helperText={form.clear[name] ? t('secrets.cleared') : undefined}
        data-testid={`notify-secret-${name}`}
      />
      {form.stored[name] && !form.secrets[name] && (
        <Button size="xs" variant="ghost" onClick={onClear} data-testid={`notify-secret-clear-${name}`}>
          <Trash size={12} />
          {form.clear[name] ? t('secrets.undoClear') : t('secrets.clear')}
        </Button>
      )}
    </div>
  )
}

export default function ChannelDialog({ open, onClose, channel, nodes = [], onSaved }) {
  const { t } = useTranslation(['notifications', 'common', 'dashboard'])
  const { showError } = useNotification()
  const editing = Boolean(channel?.id)
  const [form, setForm] = useState(() => formFromChannel(channel || {}))
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)
  const [test, setTest] = useState(null)
  const [dirty, setDirty] = useState(false)
  const set = (path) => (value) => {
    setDirty(true)
    setForm((f) => setPath(f, path, value))
  }
  const ev = (path) => (e) => set(path)(e.target.value)
  const err = (path) => (errors[path] ? t(`errors.${errors[path]}`, { defaultValue: errors[path] }) : undefined)
  const warnings = formWarnings(form)
  const warn = (path) => (warnings[path] ? t(`warnings.${warnings[path]}`) : undefined)
  const p = form.params
  const s = form.schedule

  const changeType = (type) => {
    setDirty(true)
    setForm((f) => ({ ...formFromChannel({ name: f.name, language: f.language, filters: f.filters }, type), schedule: f.schedule, enabled: f.enabled }))
    setErrors({})
    setTest(null)
  }

  const check = () => {
    const local = formErrors(form)
    setErrors(local)
    return Object.keys(local).length === 0
  }

  const save = async () => {
    if (!check()) return
    setBusy(true)
    try {
      const body = channelBody(form)
      const out = editing ? await api.notifications.updateChannel(channel.id, body) : await api.notifications.createChannel(body)
      onSaved?.(out)
    } catch (e) {
      const fields = serverFieldErrors(e?.errors)
      if (Object.keys(fields).length) setErrors(fields)
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const sendTest = async () => {
    if (!check()) return
    setTest({ running: true })
    const out = await api.notifications.test(testBody(form, channel?.id, { dirty })).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setTest(out)
  }

  const used = usedSecrets(form)
  const option = (value, label) => ({ value, label })
  const footer = (
    <div className="ui-modal-footer flex flex-wrap items-center justify-end gap-2 p-4 border-t border-border">
      <Button variant="secondary" onClick={sendTest} loading={test?.running} data-testid="notify-dialog-test">
        <PaperPlaneTilt size={14} />
        {t('actions.test')}
      </Button>
      <span className="flex-1" />
      <Button variant="secondary" onClick={onClose}>{t('common:actions.cancel')}</Button>
      <Button loading={busy} onClick={save} data-testid="notify-dialog-save">{t('actions.save')}</Button>
    </div>
  )

  return (
    <FormModal open={open} onClose={onClose} title={editing ? t('dialog.editTitle', { name: channel.name }) : t('dialog.newTitle')} size="lg" footer={footer} testId="notify-channel-dialog">
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {editing ? (
            <div className="space-y-1">
              <span className="block text-xs font-medium text-text-secondary">{t('dialog.type')}</span>
              <Badge variant="info">{t(`types.${form.type}`)}</Badge>
            </div>
          ) : (
            <Select label={t('dialog.type')} value={form.type} onChange={changeType} options={CHANNEL_TYPES.map((x) => option(x, t(`types.${x}`)))} id="notify-type" />
          )}
          <Input label={t('dialog.name')} value={form.name} onChange={ev('name')} error={err('name')} placeholder={t(`placeholders.name.${form.type}`)} data-testid="notify-name" />
          <Select label={t('dialog.language')} value={form.language} onChange={set('language')} options={LANGUAGES.map((l) => option(l, t(`languages.${l}`)))} />
        </div>
        <p className="text-xs text-text-secondary">{t(`typeHelp.${form.type}`)}</p>

        <section className="space-y-3 border-t border-border-op50 pt-3" data-testid="notify-params" data-type={form.type}>
          {form.type === 'email' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <Input label={t('fields.host')} value={p.host} onChange={ev('params.host')} error={err('params.host')} placeholder="smtp.example.lan" data-testid="notify-host" />
              <Select label={t('fields.security')} value={p.security} onChange={(v) => { set('params.security')(v); if (v === 'tls' && Number(p.port) === 587) set('params.port')(465); if (v === 'starttls' && Number(p.port) === 465) set('params.port')(587) }} options={EMAIL_SECURITY.map((x) => option(x, t(`security.${x}`)))} error={err('params.security')} />
              <Input label={t('fields.port')} type="number" value={p.port} onChange={ev('params.port')} error={err('params.port')} />
              <Input label={t('fields.username')} value={p.username} onChange={ev('params.username')} error={err('params.username')} helperText={t('fields.optional')} />
              <SecretInput form={form} name="password" label={t('fields.password')} onType={set('secrets.password')} onClear={() => set('clear.password')(!form.clear.password)} error={err('secrets.password')} />
              <Input label={t('fields.from')} value={p.from} onChange={ev('params.from')} error={err('params.from')} placeholder="pelagos@example.lan" data-testid="notify-from" />
              <div className="md:col-span-3">
                <TagsInput label={t('fields.to')} value={p.to} onChange={set('params.to')} helperText={err('params.to') || t('fields.toHelp')} placeholder="ops@example.lan" />
              </div>
              {warn('params.security') && <p className="md:col-span-3 text-xs status-warning-text">{warn('params.security')}</p>}
            </div>
          )}

          {form.type === 'ntfy' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input label={t('fields.serverUrl')} value={p.url} onChange={ev('params.url')} error={err('params.url')} helperText={warn('params.url')} placeholder="https://ntfy.example.lan" data-testid="notify-url" />
              <Input label={t('fields.topic')} value={p.topic} onChange={ev('params.topic')} error={err('params.topic')} placeholder="pelagos" data-testid="notify-topic" />
              <Select label={t('fields.auth')} value={form.ntfy_auth} onChange={set('ntfy_auth')} options={NTFY_AUTH.map((x) => option(x, t(`ntfyAuth.${x}`)))} />
              {form.ntfy_auth === 'token' && <SecretInput form={form} name="token" label={t('fields.accessToken')} onType={set('secrets.token')} onClear={() => set('clear.token')(!form.clear.token)} error={err('secrets.token')} />}
              {form.ntfy_auth === 'basic' && (
                <>
                  <Input label={t('fields.username')} value={p.username} onChange={ev('params.username')} error={err('params.username')} />
                  <SecretInput form={form} name="password" label={t('fields.password')} onType={set('secrets.password')} onClear={() => set('clear.password')(!form.clear.password)} error={err('secrets.password')} />
                </>
              )}
            </div>
          )}

          {form.type === 'gotify' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input label={t('fields.serverUrl')} value={p.url} onChange={ev('params.url')} error={err('params.url')} helperText={warn('params.url')} placeholder="https://gotify.example.lan" data-testid="notify-url" />
              <SecretInput form={form} name="token" label={t('fields.appToken')} onType={set('secrets.token')} onClear={() => set('clear.token')(!form.clear.token)} error={err('secrets.token')} />
              <div className="md:col-span-2 grid grid-cols-3 gap-3">
                {[...SEVERITIES].reverse().map((sev) => (
                  <Input key={sev} label={t('fields.priority', { severity: t(`severity.${sev}`) })} type="number" min={0} max={10} value={p.priorities[sev]} onChange={ev(`params.priorities.${sev}`)} error={err(`params.priorities.${sev}`)} />
                ))}
              </div>
            </div>
          )}

          {form.type === 'matrix' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input label={t('fields.homeserver')} value={p.homeserver} onChange={ev('params.homeserver')} error={err('params.homeserver')} helperText={warn('params.homeserver')} placeholder="https://matrix.example.lan" data-testid="notify-url" />
              <Input label={t('fields.roomId')} value={p.room_id} onChange={ev('params.room_id')} error={err('params.room_id')} helperText={t('fields.roomIdHelp')} placeholder="!abcdef:example.lan" data-testid="notify-room" />
              <SecretInput form={form} name="token" label={t('fields.botToken')} onType={set('secrets.token')} onClear={() => set('clear.token')(!form.clear.token)} error={err('secrets.token')} />
            </div>
          )}

          {form.type === 'webhook' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input label={t('fields.webhookUrl')} value={p.url} onChange={ev('params.url')} error={err('params.url')} helperText={warn('params.url')} placeholder="https://hooks.example.lan/pelagos" data-testid="notify-url" />
              <SecretInput form={form} name="hmac_secret" label={t('fields.hmacSecret')} onType={set('secrets.hmac_secret')} onClear={() => set('clear.hmac_secret')(!form.clear.hmac_secret)} error={err('secrets.hmac_secret')} />
              <div className="md:col-span-2">
                <Textarea label={t('fields.headers')} helperText={err('params.headers') || t('fields.headersHelp')} rows={3} value={p.headers} onChange={ev('params.headers')} className="font-mono text-xs" placeholder="X-Team: dns" />
              </div>
              <p className="md:col-span-2 text-2xs text-text-tertiary">{t('fields.hmacHelp')}</p>
            </div>
          )}

          {form.type === 'home_assistant' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input label={t('fields.haUrl')} value={p.url} onChange={ev('params.url')} error={err('params.url')} helperText={warn('params.url')} placeholder="https://homeassistant.example.lan:8123" data-testid="notify-url" />
              <SecretInput form={form} name="webhook_id" label={t('fields.webhookId')} onType={set('secrets.webhook_id')} onClear={() => set('clear.webhook_id')(!form.clear.webhook_id)} error={err('secrets.webhook_id')} />
              <p className="md:col-span-2 text-2xs text-text-tertiary">{t('fields.haHelp')}</p>
            </div>
          )}

          <details className="text-xs">
            <summary className="cursor-pointer text-text-secondary">{t('fields.caPem')}</summary>
            <Textarea helperText={t('fields.caPemHelp')} rows={4} value={p.ca_pem} onChange={ev('params.ca_pem')} className="font-mono text-xs mt-2" />
          </details>
        </section>

        <section className="space-y-3 border-t border-border-op50 pt-3" data-testid="notify-filters">
          <h4 className="text-xs font-semibold text-text-primary">{t('dialog.filters')}</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Select label={t('fields.severityMin')} value={form.filters.severity_min} onChange={set('filters.severity_min')} options={SEVERITIES.map((x) => option(x, t(`severity.${x}`)))} />
            <Chips label={t('fields.engines')} help={t('fields.allWhenEmpty')} options={ENGINES.map((x) => option(x, x))} value={form.filters.engines} onChange={set('filters.engines')} testId="notify-engines" />
            <div className="space-y-1">
              <span className="block text-xs font-medium text-text-secondary">{t('fields.kindsInclude')}</span>
              <MultiSelectFilter searchable options={KINDS.map((k) => option(k, t(`dashboard:kinds.${k}`, { defaultValue: k })))} value={form.filters.kinds_include} onChange={set('filters.kinds_include')} placeholder={t('fields.allKinds')} />
            </div>
            <div className="space-y-1">
              <span className="block text-xs font-medium text-text-secondary">{t('fields.kindsExclude')}</span>
              <MultiSelectFilter searchable options={KINDS.map((k) => option(k, t(`dashboard:kinds.${k}`, { defaultValue: k })))} value={form.filters.kinds_exclude} onChange={set('filters.kinds_exclude')} placeholder={t('fields.noKind')} />
            </div>
            {nodes.length > 1 && (
              <Chips label={t('fields.nodes')} help={t('fields.allWhenEmpty')} options={nodes.map((n) => option(n.id, n.name))} value={form.filters.node_ids} onChange={set('filters.node_ids')} testId="notify-nodes" />
            )}
          </div>
        </section>

        <section className="space-y-3 border-t border-border-op50 pt-3" data-testid="notify-schedule">
          <h4 className="text-xs font-semibold text-text-primary">{t('dialog.schedule')}</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Input label={t('fields.reminder')} type="number" min={0} value={s.reminder_hours} onChange={ev('schedule.reminder_hours')} error={err('schedule.reminder_hours')} helperText={t('fields.reminderHelp')} />
            <Input label={t('fields.confirm')} type="number" min={0} value={s.confirm_seconds} onChange={ev('schedule.confirm_seconds')} error={err('schedule.confirm_seconds')} helperText={t('fields.confirmHelp')} placeholder={t('fields.confirmDefault')} />
            <ToggleSwitch checked={s.send_resolved} onChange={set('schedule.send_resolved')} label={t('fields.sendResolved')} />
          </div>
          <ToggleSwitch checked={s.quiet_enabled} onChange={set('schedule.quiet_enabled')} label={t('fields.quiet')} description={t('fields.quietHelp')} />
          {s.quiet_enabled && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pl-2 border-l-2 border-border-op50" data-testid="notify-quiet">
              <Input label={t('fields.quietStart')} type="time" value={s.quiet.start} onChange={ev('schedule.quiet.start')} error={err('schedule.quiet.start')} data-testid="notify-quiet-start" />
              <Input label={t('fields.quietEnd')} type="time" value={s.quiet.end} onChange={ev('schedule.quiet.end')} error={err('schedule.quiet.end')} data-testid="notify-quiet-end" />
              <Input label={t('fields.timezone')} value={s.quiet.timezone} onChange={ev('schedule.quiet.timezone')} error={err('schedule.quiet.timezone')} placeholder="Europe/Paris" />
              <div className="md:col-span-3">
                <Chips label={t('fields.days')} options={DAYS.map((d) => option(d, t(`days.${d}`)))} value={s.quiet.days} onChange={set('schedule.quiet.days')} error={err('schedule.quiet.days')} testId="notify-quiet-days" />
              </div>
              <div className="md:col-span-3">
                <ToggleSwitch checked={s.quiet.critical_passes} onChange={set('schedule.quiet.critical_passes')} label={t('fields.criticalPasses')} />
              </div>
            </div>
          )}
          <ToggleSwitch checked={form.enabled} onChange={set('enabled')} label={t('fields.enabled')} />
        </section>

        {test && !test.running && (
          <p className={test.ok ? 'text-xs status-success-text' : 'text-xs status-danger-text'} role="status" data-testid="notify-test-result" data-ok={String(Boolean(test.ok))}>
            {test.ok
              ? t('test.ok', { node: test.node_id || '-', ms: test.duration_ms ?? '-', status: test.status ?? '-' })
              : t('test.failed', { error: test.error || '-', status: test.status ?? '-' })}
          </p>
        )}
        {used.length === 0 && form.type === 'ntfy' && <p className="text-2xs text-text-tertiary">{t('fields.ntfyOpen')}</p>}
        {Object.keys(errors).length > 0 && <Badge variant="danger">{t('errors.fix')}</Badge>}
      </div>
    </FormModal>
  )
}
