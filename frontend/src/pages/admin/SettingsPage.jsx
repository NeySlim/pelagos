// SPDX-License-Identifier: Apache-2.0
// Cluster settings ([settings] of cluster.toml): every key the server returns,
// grouped in sections, typed from its value, saved as a partial PUT.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Gear, FloppyDisk, ArrowCounterClockwise } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Input, ToggleSwitch, TagsInput, LoadingSpinner } from '../../components'
import { useApi } from '../../hooks'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { describeSettings, diffPatch, getIn, setIn, parseNumber } from './settingsForm'

const humanize = (key) => key.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())

function Field({ field, value, onChange, error }) {
  const { t } = useTranslation('admin')
  const label = t(`settings.fields.${field.path.join('.')}`, { defaultValue: humanize(field.key) })
  const testId = `setting-${field.path.join('-')}`
  switch (field.type) {
    case 'boolean':
      return <ToggleSwitch checked={Boolean(value)} onChange={onChange} label={label} />
    case 'integer':
    case 'number':
      return <Input label={label} type="number" value={value ?? ''} onChange={(e) => onChange(parseNumber(field.type, e.target.value) ?? e.target.value)} error={error} data-testid={testId} />
    case 'list':
      return <TagsInput label={label} value={value || []} onChange={onChange} />
    case 'string':
      return <Input label={label} value={value ?? ''} onChange={(e) => onChange(e.target.value)} data-testid={testId} />
    default:
      return (
        <div className="space-y-1">
          <span className="block text-xs font-medium text-text-secondary">{label}</span>
          <pre className="text-xs font-mono rounded-md border border-border bg-bg-primary p-2 overflow-auto">{JSON.stringify(value, null, 2)}</pre>
        </div>
      )
  }
}

export default function SettingsPage() {
  const { t } = useTranslation(['admin', 'common'])
  const { showSuccess, showError } = useNotification()
  const settingsQ = useApi(() => api.admin.settings(), [])
  const [draft, setDraft] = useState(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (settingsQ.data) setDraft(JSON.parse(JSON.stringify(settingsQ.data)))
  }, [settingsQ.data])
  const sections = useMemo(() => describeSettings(settingsQ.data), [settingsQ.data])
  const invalid = useMemo(
    () => sections.flatMap((s) => s.fields).filter((f) => (f.type === 'integer' || f.type === 'number') && typeof getIn(draft, f.path) !== 'number').map((f) => f.path.join('.')),
    [sections, draft],
  )
  const patch = useMemo(() => (draft && settingsQ.data ? diffPatch(settingsQ.data, draft) : null), [draft, settingsQ.data])

  const save = async () => {
    setBusy(true)
    try {
      const merged = await api.admin.updateSettings(patch)
      settingsQ.setData(merged)
      showSuccess(t('settings.saved'))
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <PageLayout
      icon={Gear}
      title={t('pages.settings.title')}
      subtitle={t('pages.settings.subtitle')}
      testId="page-admin-settings"
      actions={
        <>
          <Button variant="secondary" size="sm" disabled={!patch} onClick={() => setDraft(JSON.parse(JSON.stringify(settingsQ.data)))}>
            <ArrowCounterClockwise size={14} />
            {t('common:actions.cancel')}
          </Button>
          <Button size="sm" disabled={!patch || invalid.length > 0} loading={busy} onClick={save} data-testid="settings-save">
            <FloppyDisk size={14} />
            {t('common:actions.save')}
          </Button>
        </>
      }
    >
      {!draft ? (
        settingsQ.error ? <p className="text-sm status-danger-text" role="alert">{errorMessage(settingsQ.error)}</p> : <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : (
        <div className="space-y-4 max-w-4xl">
          {sections.map((section) => (
            <Card key={section.id} className="p-4 space-y-3" hover={false} data-testid={`settings-${section.id}`}>
              <div>
                <h3 className="text-sm font-semibold text-text-primary">{t(`settings.sections.${section.id}.title`, { defaultValue: humanize(section.id) })}</h3>
                <p className="text-xs text-text-secondary">{t(`settings.sections.${section.id}.help`, { defaultValue: '' })}</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {section.fields.map((field) => (
                  <Field
                    key={field.path.join('.')}
                    field={field}
                    value={getIn(draft, field.path)}
                    onChange={(v) => setDraft((d) => setIn(d, field.path, v))}
                    error={invalid.includes(field.path.join('.')) ? t('settings.number') : undefined}
                  />
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}
    </PageLayout>
  )
}
