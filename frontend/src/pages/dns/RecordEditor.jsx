// SPDX-License-Identifier: Apache-2.0
// Record editor: a FormModal with live before/after preview, then the server's
// plan in PlanPreview (diff, preconditions, apply with the UPDATE response code,
// rollback). Adding to an existing RRset turns into a replace with merged rdata. For A/AAAA, the
// PTR option adds the reverse records to the same plan (POST /dns/ptr/coverage says if it can).
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Modal } from '../../components/Modal'
import { PlanPreview } from '../../components/PlanPreview'
import { DiffView } from '../../components/DiffView'
import { Input } from '../../components/Input'
import { Textarea } from '../../components/Textarea'
import { Select } from '../../components/ui/Select'
import { api } from '../../services/api'
import { errorItemText, errorMessage } from '../../services/apiClient'
import { EDITABLE_TYPES, absZone, buildChanges, isAddressType, localDiff, ptrOption, relativeName, validateForm } from './records'

const DEFAULT_TTL = 3600
const COVERAGE_DELAY_MS = 300

// The PTR checkbox, with why it is off and what the plan will replace.
function PtrOption({ mode, option, checked, onChange, loading }) {
  const { t } = useTranslation('dns')
  const disabled = loading || !option.enabled
  return (
    <div className="rounded-lg border border-border px-3 py-2 space-y-1" data-testid="record-ptr">
      <label className={`flex items-start gap-2 text-sm text-text-primary ${disabled ? 'opacity-70' : 'cursor-pointer'}`}>
        <input
          type="checkbox"
          className="mt-1 accent-[var(--accent-pro)]"
          checked={Boolean(checked) && option.enabled}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
          data-testid="record-ptr-sync"
        />
        <span>
          {t(mode === 'delete' ? 'editor.ptr.deleteLabel' : 'editor.ptr.label')}
          <span className="block text-xs text-text-secondary" data-testid="record-ptr-help">
            {loading
              ? t('editor.ptr.checking')
              : option.enabled
                ? t('editor.ptr.in', { zones: option.zones.join(', ') })
                : option.reason
                  ? t(`editor.ptr.reasons.${option.reason}`, { defaultValue: option.reason })
                  : ''}
          </span>
        </span>
      </label>
      {checked && option.enabled && option.conflicts.map((c) => (
        <p key={c.ip} className="text-xs status-warning-text" data-testid="record-ptr-conflict">
          {t('editor.ptr.conflict', { ip: c.ip, targets: c.current.join(', ') })}
        </p>
      ))}
      {!(checked && option.enabled) && !loading && option.stays.length > 0 && (
        <p className="text-xs status-warning-text" data-testid="record-ptr-stays">
          {t('editor.ptr.stays', { addresses: option.stays.join(', ') })}
        </p>
      )}
      {checked && option.enabled && option.uncovered.length > 0 && (
        <p className="text-xs text-text-tertiary" data-testid="record-ptr-uncovered">
          {t('editor.ptr.uncovered', { addresses: option.uncovered.join(', ') })}
        </p>
      )}
    </div>
  )
}

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
  // Called on close when the plan stayed applied: (plan, result), for the toast that offers its rollback.
  onCommitted,
  planFn = (z, changes, v, ptr) => api.dns.recordsPlan(z, changes, v, ptr),
  lookupFn = (z, params) => api.dns.records(z, params),
  coverageFn = (body) => api.dns.ptrCoverage(body),
}) {
  const { t } = useTranslation(['dns', 'common'])
  const zoneName = absZone(zone)
  const [form, setForm] = useState(() => initialForm(mode, rrset, { ...defaults, zone: zoneName }))
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [plan, setPlan] = useState(null)
  const lastChanges = useRef(null)
  const lastPtr = useRef(undefined)
  const outcome = useRef(null)
  // null follows the coverage (checked when a reverse zone covers the address); a click decides.
  const [ptrChecked, setPtrChecked] = useState(null)
  const [coverage, setCoverage] = useState(null)
  const [coverageLoading, setCoverageLoading] = useState(false)

  useEffect(() => {
    if (open) {
      setForm(initialForm(mode, rrset, { ...defaults, zone: zoneName }))
      setTouched(false)
      setError(null)
      setPlan(null)
      setPtrChecked(null)
      setCoverage(null)
      outcome.current = null
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

  // Addresses whose PTR the option would write (or, on delete, remove), looked up after a pause.
  const ptrSubject = mode === 'delete' ? rrset : hasErrors ? null : after
  const subjectAddresses = ptrSubject && isAddressType(ptrSubject.rtype) ? ptrSubject.rdata || [] : []
  // An edit also looks up the addresses it removes: their PTR goes with the option.
  const removedAddresses = mode === 'edit' && rrset && isAddressType(rrset.rtype) && subjectAddresses.length
    ? (rrset.rdata || []).filter((ip) => !subjectAddresses.includes(ip))
    : []
  const ptrAddresses = [...subjectAddresses, ...removedAddresses]
  const ptrKey = ptrAddresses.length ? `${ptrSubject.name}|${ptrAddresses.join(',')}` : ''
  const lookupCoverage = async () => {
    try {
      const res = await coverageFn({ addresses: ptrAddresses, name: ptrSubject.name, ...(view ? { view } : {}) })
      return res?.items || []
    } catch {
      return ptrAddresses.map((ip) => ({ ip, covered: false, reason: 'unavailable' }))
    }
  }
  useEffect(() => {
    if (!open || !ptrKey) return undefined
    let live = true
    setCoverageLoading(true)
    const timer = setTimeout(async () => {
      const items = await lookupCoverage()
      if (live) {
        setCoverage({ key: ptrKey, items })
        setCoverageLoading(false)
      }
    }, COVERAGE_DELAY_MS)
    return () => {
      live = false
      clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, ptrKey, view])
  // Coverage of other addresses than the form's is stale: never shown, never used.
  const currentCoverage = coverage?.key === ptrKey ? coverage.items : null
  const ptr = useMemo(
    () => ptrOption({ mode, before: rrset, after: subjectAddresses, coverage: currentCoverage }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [mode, rrset, currentCoverage, ptrKey],
  )

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
      // Submitted before the lookup answered: look the coverage up now, so the option is never lost.
      let option = ptr
      if (ptrKey && ptrChecked !== false && !currentCoverage) {
        option = ptrOption({ mode, before: rrset, after: subjectAddresses, coverage: await lookupCoverage() })
      }
      const ptrOn = Boolean(ptrKey) && ptrChecked !== false && option.enabled
      // A rename deletes the old RRset: its PTR goes with it when the option is on.
      const ptrBody = ptrOn ? (mode === 'delete' ? { sync: false, delete: true } : { sync: true, delete: true }) : undefined
      lastChanges.current = changes
      lastPtr.current = ptrBody
      setPlan(await planFn(zoneName, changes, view, ptrBody))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  // Same changes, same zone: the server builds a fresh plan when the old one expired.
  const recompute = async () => {
    const fresh = await planFn(zoneName, lastChanges.current, view, lastPtr.current)
    setPlan(fresh)
    return fresh
  }

  const title = t(`editor.title.${mode}`)

  if (plan) {
    const close = () => {
      const done = outcome.current
      outcome.current = null
      onClose?.()
      if (done) onCommitted?.(done.plan, done.result)
    }
    const applied = (res) => {
      outcome.current = res?.state === 'applied' ? { plan, result: res } : null
      onApplied?.(res)
    }
    const rolledBack = (res) => {
      outcome.current = null
      onApplied?.(res)
    }
    return (
      <Modal open={open} onClose={close} title={title} size="lg">
        <div className="p-4" data-testid="record-editor-plan">
          <PlanPreview plan={plan} onClose={close} onApplied={applied} onRolledBack={rolledBack} onRecompute={recompute} />
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
            <Input label={t('editor.ttl')} type="number" value={form.ttl} onChange={set('ttl')} error={fieldError('ttl')} data-testid="record-ttl" />
          </div>
          <Textarea
            label={t('editor.rdata')}
            value={form.rdata}
            onChange={set('rdata')}
            rows={4}
            placeholder={t(`editor.placeholder.${form.rtype}`, { defaultValue: '' })}
            helperText={t('editor.rdataHelp')}
            error={fieldError('rdata')}
            data-testid="record-rdata"
          />
        </>
      )}
      {ptrKey && (
        <PtrOption mode={mode} option={ptr} checked={ptrChecked ?? true} onChange={setPtrChecked} loading={coverageLoading && !currentCoverage} />
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
                  {errorItemText(e)}
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
