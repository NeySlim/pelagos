// SPDX-License-Identifier: Apache-2.0
// Dialogs of the IPv6 plans (architecture section 27, Plans): the reverse zones a selection
// lacks (409 precondition_failed `reverse_zones`) and the replacement of a prefix.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { Modal } from '../../components/Modal'
import { useNodeNames } from '../../hooks/useNodeNames'
import { errorItemText, errorMessage } from '../../services/apiClient'
import { missingReverseZones, prefixSwapErrors } from './ipv6'

// The ip6.arpa zones to create before the AAAA and PTR plan; each button builds its zone plan.
export function ReverseZoneList({ zones, canCreate, building, onCreate }) {
  const { t } = useTranslation(['ipv6'])
  const nameOf = useNodeNames()
  return (
    <ul className="space-y-2" data-testid="ipv6-reverse-zones">
      {zones.map((z) => (
        <li key={`${z.view}|${z.zone}`} className="flex flex-wrap items-center gap-2 text-xs" data-zone={z.zone}>
          <span className="min-w-0 flex-1">
            <span className="block font-mono break-all text-text-primary">{z.zone}</span>
            <span className="block text-text-secondary">
              {t('plans.reverse.prefix', { prefix: z.prefix })}
              {z.view && z.view !== '_default' ? ` · ${t('plans.reverse.view', { view: z.view })}` : ''}
            </span>
            {z.node_id && (
              <span className="block text-text-tertiary" data-testid="ipv6-reverse-nodes">
                {z.node_ids?.length
                  ? t('plans.reverse.nodes', { primary: nameOf(z.node_id), copies: z.node_ids.map(nameOf).join(', ') })
                  : t('plans.reverse.nodesAlone', { primary: nameOf(z.node_id) })}
              </span>
            )}
          </span>
          {canCreate && (
            <Button size="xs" variant="secondary" disabled={building} onClick={() => onCreate(z)} data-testid="ipv6-reverse-create">
              <Plus size={12} />
              {t('plans.reverse.create')}
            </Button>
          )}
        </li>
      ))}
    </ul>
  )
}

export function ReverseZonesDialog({ zones, onClose, canCreate, building, onCreate }) {
  const { t } = useTranslation(['ipv6'])
  return (
    <Modal open={Boolean(zones?.length)} onClose={onClose} title={t('plans.reverse.title')}>
      <div className="space-y-3" data-testid="ipv6-reverse-dialog">
        <p className="text-sm text-text-secondary">{t('plans.reverse.body')}</p>
        <ReverseZoneList zones={zones || []} canCreate={canCreate} building={building} onCreate={onCreate} />
        {!canCreate && <p className="text-xs status-warning-text">{t('plans.reverse.noPermission')}</p>}
        <p className="text-2xs text-text-tertiary">{t('plans.reverse.then')}</p>
      </div>
    </Modal>
  )
}

// Old and new prefix (same length), optional zones; build(body) returns the plan or throws.
export function ReplacePrefixDialog({ open, initial, onClose, build, onMissingZones }) {
  const { t } = useTranslation(['ipv6', 'common'])
  const [form, setForm] = useState({ old_prefix: '', new_prefix: '', zones: '' })
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [serverErrors, setServerErrors] = useState({})

  useEffect(() => {
    if (!open) return
    setForm({ old_prefix: initial?.old_prefix || '', new_prefix: initial?.new_prefix || '', zones: '' })
    setTouched(false)
    setError(null)
    setServerErrors({})
  }, [open, initial?.old_prefix, initial?.new_prefix])

  const local = prefixSwapErrors(form.old_prefix, form.new_prefix)
  const fieldError = (field) => (touched && local[field] ? t(`plans.replace.errors.${local[field]}`) : serverErrors[field])
  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e.target.value }))

  const submit = async () => {
    setTouched(true)
    if (Object.keys(local).length) return
    const zones = form.zones.split(/[\s,]+/).map((z) => z.trim()).filter(Boolean)
    setBusy(true)
    setError(null)
    setServerErrors({})
    try {
      await build({ old_prefix: form.old_prefix.trim(), new_prefix: form.new_prefix.trim(), ...(zones.length ? { zones } : {}) })
      onClose()
    } catch (err) {
      const missing = missingReverseZones(err)
      if (missing) {
        onMissingZones(missing)
        onClose()
        return
      }
      const byField = Object.fromEntries((err?.errors || []).map((e) => [e.field, errorItemText(e)]))
      setServerErrors(byField)
      if (!Object.keys(byField).length) setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('plans.replace.title')} onSubmit={submit} loading={busy} submitLabel={t('plans.replace.submit')} testId="ipv6-replace-dialog">
      <p className="text-sm text-text-secondary">{t('plans.replace.body')}</p>
      <Input label={t('plans.replace.old')} value={form.old_prefix} onChange={set('old_prefix')} placeholder="2001:db8::/64" error={fieldError('old_prefix')} data-testid="ipv6-replace-old" autoFocus />
      <Input label={t('plans.replace.new')} value={form.new_prefix} onChange={set('new_prefix')} placeholder="2001:db8:1::/64" error={fieldError('new_prefix')} data-testid="ipv6-replace-new" />
      <Input label={t('plans.replace.zones')} value={form.zones} onChange={set('zones')} placeholder="example.lan." helperText={t('plans.replace.zonesHelp')} error={serverErrors.zones} data-testid="ipv6-replace-zones" />
      {error && (
        <p className="text-xs status-danger-text" role="alert" data-testid="ipv6-replace-error">
          {error}
        </p>
      )}
    </FormModal>
  )
}
