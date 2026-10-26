// SPDX-License-Identifier: Apache-2.0
// Cluster settings ([settings] of cluster.toml): one form per domain, built from the server's
// schema (types, bounds, units, defaults, pairs), validated as typed, saved as a partial PUT.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { Gear, FloppyDisk, ArrowCounterClockwise, Plus, Trash, MagnifyingGlass } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Input, ToggleSwitch, TagsInput, LoadingSpinner } from '../../components'
import { useApi } from '../../hooks'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { parseNumber } from './settingsForm'
import { sectionsOf, validateSettings, getPath, setPath, durationParts, matchesQuery, viewKeyRows, rowsToViewKeys } from './settingsSchema'

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)
const testId = (key) => `setting-${key.replace(/\./g, '-')}`

function useLabels() {
  const { t } = useTranslation('admin')
  return {
    label: (spec) => t(`settings.fields.${spec.key}`, { defaultValue: spec.key }),
    help: (spec) => t(`settings.help.${spec.key}`, { defaultValue: '' }),
    unit: (spec) => (spec.unit ? t(`settings.units.${spec.unit}`, { defaultValue: spec.unit }) : ''),
    error: (err) => (err ? t(`settings.errors.${err.code}`, { ...(err.params || {}), other: err.params?.other ? t(`settings.fields.${err.params.other}`, { defaultValue: err.params.other }) : undefined }) : undefined),
  }
}

function shown(spec, value, t) {
  if (spec.type === 'boolean') return value ? t('settings.on') : t('settings.off')
  if (Array.isArray(value)) return value.length ? value.join(', ') : t('settings.none')
  if (value && typeof value === 'object') return Object.keys(value).length ? Object.keys(value).join(', ') : t('settings.none')
  return value === '' ? t('settings.none') : String(value)
}

function ViewKeysEditor({ spec, value, onChange, error }) {
  const { t } = useTranslation('admin')
  const labels = useLabels()
  const [rows, setRows] = useState(() => viewKeyRows(value))
  useEffect(() => {
    if (!same(rowsToViewKeys(rows), value || {})) setRows(viewKeyRows(value))
    // Rows follow the value only when it changes from outside (cancel, reset, save).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value])
  const update = (next) => {
    setRows(next)
    onChange(rowsToViewKeys(next))
  }
  return (
    <div className="space-y-2 md:col-span-2" data-testid={testId(spec.key)}>
      <span className="block text-xs font-medium text-text-secondary">{labels.label(spec)}</span>
      {rows.length === 0 && <p className="text-xs text-text-tertiary">{t('settings.viewKeys.empty')}</p>}
      {rows.map((row, i) => (
        <div key={i} className="grid grid-cols-1 sm:grid-cols-[1fr_1fr_1fr_auto] gap-2 items-end">
          <Input label={t('settings.viewKeys.view')} value={row.view} onChange={(e) => update(rows.map((r, j) => (j === i ? { ...r, view: e.target.value } : r)))} data-testid="view-key-view" />
          <Input label={t('settings.viewKeys.admin')} value={row.admin} onChange={(e) => update(rows.map((r, j) => (j === i ? { ...r, admin: e.target.value } : r)))} data-testid="view-key-admin" />
          <Input label={t('settings.viewKeys.read')} value={row.read} onChange={(e) => update(rows.map((r, j) => (j === i ? { ...r, read: e.target.value } : r)))} data-testid="view-key-read" />
          <Button variant="ghost" size="sm" onClick={() => update(rows.filter((_, j) => j !== i))} aria-label={t('settings.viewKeys.remove')}>
            <Trash size={14} />
          </Button>
        </div>
      ))}
      <Button variant="secondary" size="xs" onClick={() => update([...rows, { view: '', admin: '', read: '' }])} data-testid="view-key-add">
        <Plus size={12} />
        {t('settings.viewKeys.add')}
      </Button>
      {labels.help(spec) && <p className="text-2xs text-text-tertiary">{labels.help(spec)}</p>}
      {error && <p className="text-xs status-danger-text" role="alert">{error}</p>}
    </div>
  )
}

function Field({ spec, value, saved, onChange, error }) {
  const { t } = useTranslation('admin')
  const labels = useLabels()
  if (spec.type === 'map') return <ViewKeysEditor spec={spec} value={value} onChange={onChange} error={error} />
  const unit = labels.unit(spec)
  const label = unit ? `${labels.label(spec)} (${unit})` : labels.label(spec)
  const duration = durationParts(value, spec.unit)
  const hints = [
    labels.help(spec),
    duration ? t(`settings.duration.${duration[1]}`, { count: duration[0] }) : '',
    t('settings.default', { value: shown(spec, spec.default, t) }),
  ].filter(Boolean)
  const changed = !same(value, saved)
  const atDefault = same(value, spec.default)
  const reset = !atDefault && (
    <button type="button" className="text-2xs text-accent-primary hover:underline" onClick={() => onChange(structuredClone(spec.default))} data-testid={`${testId(spec.key)}-reset`}>
      {t('settings.reset')}
    </button>
  )
  let control
  switch (spec.type) {
    case 'boolean':
      control = <ToggleSwitch checked={Boolean(value)} onChange={onChange} label={labels.label(spec)} description={hints.join(' · ')} />
      break
    case 'integer':
    case 'number':
      control = (
        <Input
          label={label}
          type="number"
          inputMode={spec.type === 'integer' ? 'numeric' : 'decimal'}
          min={spec.min}
          max={spec.max}
          step={spec.type === 'integer' ? 1 : 'any'}
          value={value ?? ''}
          onChange={(e) => onChange(parseNumber(spec.type, e.target.value) ?? e.target.value)}
          error={error}
          helperText={error ? undefined : hints.join(' · ')}
          data-testid={testId(spec.key)}
        />
      )
      break
    case 'list':
      control = (
        <div>
          <TagsInput label={label} value={value || []} onChange={onChange} helperText={hints.join(' · ')} />
          {error && <p className="mt-1 text-xs status-danger-text" role="alert">{error}</p>}
        </div>
      )
      break
    default:
      control = <Input label={label} value={value ?? ''} onChange={(e) => onChange(e.target.value)} error={error} helperText={error ? undefined : hints.join(' · ')} data-testid={testId(spec.key)} />
  }
  return (
    <div className={cn('relative space-y-1 rounded-md', changed && 'ring-1 ring-accent-primary/40 p-1 -m-1')} data-setting={spec.key} data-testid={`${testId(spec.key)}-field`}>
      {control}
      {reset}
    </div>
  )
}

export default function SettingsPage() {
  const { t } = useTranslation(['admin', 'common'])
  const labels = useLabels()
  const { showSuccess, showError } = useNotification()
  const [params, setParams] = useSearchParams()
  const schemaQ = useApi(() => api.admin.settingsSchema(), [])
  const settingsQ = useApi(() => api.admin.settings(), [])
  const [draft, setDraft] = useState(null)
  const [serverErrors, setServerErrors] = useState({})
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const schema = schemaQ.data
  useEffect(() => {
    if (settingsQ.data) setDraft(structuredClone(settingsQ.data))
  }, [settingsQ.data])

  const sections = useMemo(() => sectionsOf(schema), [schema])
  const active = sections.some((s) => s.id === params.get('section')) ? params.get('section') : sections[0]?.id
  const errors = useMemo(() => (schema && draft ? validateSettings(schema, draft) : {}), [schema, draft])
  // Only what changed, per setting; a map (view keys) is sent whole so a removed entry goes.
  const patch = useMemo(() => {
    if (!schema || !draft || !settingsQ.data) return null
    let out = null
    for (const spec of schema.settings) {
      const value = getPath(draft, spec.key)
      if (value !== undefined && !same(value, getPath(settingsQ.data, spec.key))) out = setPath(out || {}, spec.key, value)
    }
    return out
  }, [schema, draft, settingsQ.data])
  const changes = useMemo(() => (schema && patch ? schema.settings.filter((s) => getPath(patch, s.key) !== undefined).length : 0), [schema, patch])
  const invalid = Object.keys(errors).length > 0

  const setValue = (key, value) => {
    setDraft((d) => setPath(d, key, value))
    setServerErrors((e) => (e[key] ? Object.fromEntries(Object.entries(e).filter(([k]) => k !== key)) : e))
  }

  const save = async () => {
    setBusy(true)
    try {
      const merged = await api.admin.updateSettings(patch)
      setServerErrors({})
      settingsQ.setData(merged)
      showSuccess(t('settings.saved'))
    } catch (err) {
      setServerErrors(Object.fromEntries((err?.errors || []).filter((e) => e.field).map((e) => [e.field, e.message])))
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const visible = (section) =>
    section.groups
      .map((g) => ({ ...g, fields: g.fields.filter((f) => matchesQuery(f, [labels.label(f), labels.help(f)], query)) }))
      .filter((g) => g.fields.length)
  const shownSections = query ? sections.map((s) => ({ ...s, groups: visible(s) })).filter((s) => s.groups.length) : sections.filter((s) => s.id === active)
  const loadError = schemaQ.error || settingsQ.error

  return (
    <PageLayout
      icon={Gear}
      title={t('pages.settings.title')}
      subtitle={t('pages.settings.subtitle')}
      testId="page-admin-settings"
      actions={
        <>
          {changes > 0 && <span className="text-xs text-text-secondary self-center" data-testid="settings-changes">{t('settings.changed', { count: changes })}</span>}
          <Button variant="secondary" size="sm" disabled={!patch} onClick={() => { setDraft(structuredClone(settingsQ.data)); setServerErrors({}) }} data-testid="settings-cancel">
            <ArrowCounterClockwise size={14} />
            {t('common:actions.cancel')}
          </Button>
          <Button size="sm" disabled={!patch || invalid} loading={busy} onClick={save} data-testid="settings-save" title={invalid ? t('settings.invalidCount') : undefined}>
            <FloppyDisk size={14} />
            {t('common:actions.save')}
          </Button>
        </>
      }
    >
      {!draft || !schema ? (
        loadError ? <p className="text-sm status-danger-text" role="alert">{t('settings.loadError')}: {errorMessage(loadError)}</p> : <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : (
        <div className="space-y-4 max-w-5xl">
          <div className="flex flex-col gap-3 md:flex-row md:items-center">
            <div className="flex flex-wrap gap-1" role="tablist" aria-label={t('pages.settings.title')}>
              {sections.map((s) => {
                const bad = Object.keys(errors).some((k) => k.startsWith(`${s.id}.`))
                return (
                  <button
                    key={s.id}
                    type="button"
                    role="tab"
                    aria-selected={!query && s.id === active}
                    onClick={() => { setQuery(''); setParams((p) => { const n = new URLSearchParams(p); n.set('section', s.id); return n }, { replace: true }) }}
                    className={cn('rounded-md px-3 py-1.5 text-xs font-medium transition-colors', !query && s.id === active ? 'bg-accent-primary/15 text-accent-primary' : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary', bad && 'status-danger-text')}
                    data-testid={`settings-tab-${s.id}`}
                  >
                    {t(`settings.sections.${s.id}.title`, { defaultValue: s.id })}
                  </button>
                )
              })}
            </div>
            <div className="md:ml-auto md:w-64">
              <Input icon={<MagnifyingGlass size={14} />} placeholder={t('settings.search')} aria-label={t('settings.search')} value={query} onChange={(e) => setQuery(e.target.value)} data-testid="settings-search" />
            </div>
          </div>
          {query && shownSections.length === 0 && <p className="text-sm text-text-secondary" data-testid="settings-no-match">{t('settings.noMatch', { query })}</p>}
          {shownSections.map((section) => (
            <Card key={section.id} className="p-4 space-y-4" hover={false} data-testid={`settings-${section.id}`}>
              <div>
                <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t(`settings.sections.${section.id}.title`, { defaultValue: section.id })}</h3>
                <p className="text-xs text-text-secondary">{t(`settings.sections.${section.id}.help`, { defaultValue: '' })}</p>
              </div>
              {section.groups.map((group) => (
                <div key={group.id || '_'} className="space-y-3" data-testid={group.id ? `settings-group-${section.id}-${group.id}` : undefined}>
                  {group.id && <h4 className="text-xs font-semibold uppercase tracking-wide text-text-tertiary">{t(`settings.groups.${group.id}`, { defaultValue: group.id })}</h4>}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-3">
                    {group.fields.map((spec) => (
                      <Field
                        key={spec.key}
                        spec={spec}
                        value={getPath(draft, spec.key)}
                        saved={getPath(settingsQ.data, spec.key)}
                        onChange={(v) => setValue(spec.key, v)}
                        error={labels.error(errors[spec.key]) || serverErrors[spec.key]}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </Card>
          ))}
        </div>
      )}
    </PageLayout>
  )
}
