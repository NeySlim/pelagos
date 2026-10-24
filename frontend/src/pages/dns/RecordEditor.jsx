// SPDX-License-Identifier: Apache-2.0
// Record editor: a FormModal with live before/after preview, then the server's
// plan in PlanPreview (diff, preconditions, apply with the UPDATE response code,
// rollback). Adding to an existing RRset turns into a replace with merged rdata.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Modal } from '../../components/Modal'
import { PlanPreview } from '../../components/PlanPreview'
import { DiffView } from '../../components/DiffView'
import { Input } from '../../components/Input'
import { Textarea } from '../../components/Textarea'
import { Select } from '../../components/ui/Select'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { EDITABLE_TYPES, absZone, buildChanges, localDiff, relativeName, validateForm } from './records'

const DEFAULT_TTL = 3600

function initialForm(mode, rrset, defaults) {
  if (rrset) {
    return { owner: relativeName(rrset.name, defaults.zone), rtype: rrset.rtype, ttl: String(rrset.ttl), rdata: (rrset.rdata || []).join('\n') }
  }
  return { owner: defaults.owner || '', rtype: defaults.rtype || 'A', ttl: String(defaults.ttl ?? DEFAULT_TTL), rdata: '' }
}

export function RecordEditor({
  open,
  onClose,
  zone,
  view,
  mode = 'add',
  rrset = null,
  defaults = {},
  onApplied,
  planFn = (z, changes, v) => api.dns.recordsPlan(z, changes, v),
  lookupFn = (z, params) => api.dns.records(z, params),
}) {
  const { t } = useTranslation(['dns', 'common'])
  const zoneName = absZone(zone)
  const [form, setForm] = useState(() => initialForm(mode, rrset, { ...defaults, zone: zoneName }))
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [plan, setPlan] = useState(null)

  useEffect(() => {
    if (open) {
      setForm(initialForm(mode, rrset, { ...defaults, zone: zoneName }))
      setTouched(false)
      setError(null)
      setPlan(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, mode, rrset, zoneName])

  const { errors, rrset: after } = useMemo(() => validateForm(form, zoneName), [form, zoneName])
  const hasErrors = mode !== 'delete' && Object.keys(errors).length > 0
  const preview = useMemo(
    () => (mode === 'delete' ? localDiff(rrset, null, zoneName) : hasErrors ? '' : localDiff(rrset, after, zoneName)),
    [mode, rrset, after, hasErrors, zoneName],
  )
  const unchanged = mode === 'edit' && !hasErrors && preview === ''

  const set = (field) => (e) => {
    const value = e?.target ? e.target.value : e
    setForm((f) => ({ ...f, [field]: value }))
  }
  const fieldError = (field) => (touched && errors[field] ? t(`editor.errors.${errors[field]}`) : undefined)

  const submit = async () => {
    setTouched(true)
    if (hasErrors || unchanged) return
    setBusy(true)
    setError(null)
    try {
      let before = rrset
      let next = after
      if (mode === 'add') {
        // An existing RRset of that name and type gets the new values added to it.
        const found = await lookupFn(zoneName, { name: after.name, type: after.rtype, ...(view ? { view } : {}) })
        before = (found?.items || []).find((r) => r.name === after.name && r.rtype === after.rtype) || null
        if (before) next = { ...after, rdata: [...new Set([...(before.rdata || []), ...after.rdata])] }
      }
      const changes = buildChanges({ zone: zoneName, mode, before, after: next })
      setPlan(await planFn(zoneName, changes, view))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  const title = t(`editor.title.${mode}`)

  if (plan) {
    return (
      <Modal open={open} onClose={onClose} title={title} size="lg">
        <div className="p-4" data-testid="record-editor-plan">
          <PlanPreview plan={plan} onClose={onClose} onApplied={onApplied} onRolledBack={onApplied} />
        </div>
      </Modal>
    )
  }

  return (
    <FormModal
      open={open}
      onClose={onClose}
      title={title}
      size="lg"
      onSubmit={submit}
      loading={busy}
      disabled={unchanged}
      variant={mode === 'delete' ? 'danger' : 'primary'}
      submitLabel={t('editor.buildPlan')}
      testId="record-editor"
    >
      {mode === 'delete' ? (
        <p className="text-sm text-text-secondary">{t('editor.deleteBody', { name: rrset?.name, type: rrset?.rtype })}</p>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-[1fr_9rem_8rem] gap-3">
            <Input
              label={t('editor.owner')}
              value={form.owner}
              onChange={set('owner')}
              placeholder="@"
              helperText={t('editor.ownerHelp', { zone: zoneName })}
              error={fieldError('owner')}
              data-testid="record-owner"
              autoFocus
            />
            <Select
              label={t('editor.type')}
              value={form.rtype}
              onChange={set('rtype')}
              options={EDITABLE_TYPES.map((x) => ({ value: x, label: x }))}
              disabled={mode === 'edit'}
              error={fieldError('rtype')}
            />
            <Input label={t('editor.ttl')} type="number" min={0} value={form.ttl} onChange={set('ttl')} error={fieldError('ttl')} data-testid="record-ttl" />
          </div>
          <Textarea
            label={t('editor.rdata')}
            value={form.rdata}
            onChange={set('rdata')}
            rows={4}
            placeholder={t(`editor.placeholder.${form.rtype}`, { defaultValue: '' })}
            helperText={t('editor.rdataHelp')}
            error={fieldError('rdata')}
            className="font-mono"
            data-testid="record-rdata"
          />
        </>
      )}
      <div>
        <p className="text-xs font-medium text-text-secondary mb-1">{t('editor.preview')}</p>
        {mode !== 'delete' && hasErrors ? (
          <p className="text-xs text-text-tertiary italic" data-testid="record-preview-pending">
            {t('editor.previewPending')}
          </p>
        ) : unchanged ? (
          <p className="text-xs text-text-tertiary italic" data-testid="record-preview-unchanged">
            {t('editor.unchanged')}
          </p>
        ) : (
          <div data-testid="record-preview">
            <DiffView diff={preview} maxHeight={200} />
          </div>
        )}
      </div>
      {error && (
        <div className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text" role="alert" data-testid="record-editor-error">
          <div className="font-medium">{errorMessage(error)}</div>
          {error.errors?.length > 0 && (
            <ul className="list-disc ml-4 font-mono text-2xs">
              {error.errors.map((e, i) => (
                <li key={i}>
                  {e.field ? `${e.field}: ` : ''}
                  {e.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </FormModal>
  )
}

export default RecordEditor
