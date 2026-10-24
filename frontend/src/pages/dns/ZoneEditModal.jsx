// SPDX-License-Identifier: Apache-2.0
// Edit a zone Pelagos manages (zones.conf statement or rndc addzone zone): primaries,
// notify targets, transfer and update rules, forwarding, DNSSEC policy and notes. The
// change goes through POST /dns/zones/plan as a replace; the plan preview follows.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Textarea } from '../../components/Textarea'
import { Input } from '../../components/Input'
import { Select } from '../../components/ui/Select'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import { zoneEditChange, zoneEditDiff, zoneForm } from './zoneTools'

const LISTS = [
  ['primaries', 'zones.primaries', ['secondary', 'stub', 'mirror', 'redirect']],
  ['also_notify', 'detail.alsoNotify', ['primary', 'secondary']],
  ['allow_transfer', 'detail.allowTransfer', ['primary', 'secondary', 'mirror']],
  ['update_policy', 'detail.updatePolicy', ['primary']],
  ['allow_update', 'detail.allowUpdate', ['primary']],
  ['forwarders', 'resolver.forwarders', ['forward', 'primary', 'secondary']],
]

export function ZoneEditModal({ zone, open, onClose, onPlan }) {
  const { t } = useTranslation(['dns', 'common'])
  const [form, setForm] = useState(() => zoneForm(zone))
  const [busy, setBusy] = useState(false)
  const policies = useApi(() => api.dns.dnssecPolicies().catch(() => ({ items: [], builtin: ['default', 'insecure', 'none'] })), [])
  const changed = zoneEditDiff(zone, form)
  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e?.target ? e.target.value : e }))
  const policyOptions = useMemo(() => {
    const names = [...(policies.data?.builtin || []), ...(policies.data?.items || []).map((p) => p.name)]
    return [{ value: '', label: '-' }, ...[...new Set(names)].map((n) => ({ value: n, label: n }))]
  }, [policies.data])

  const submit = async () => {
    if (!changed.length) return
    setBusy(true)
    try {
      await onPlan(zoneEditChange(zone, form))
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('detail.editTitle', { zone: zone.name })} onSubmit={submit} loading={busy} disabled={!changed.length} submitLabel={changed.length ? t('editor.buildPlan') : t('detail.noChange')} size="lg" testId="zone-edit">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {LISTS.filter(([, , kinds]) => kinds.includes(zone.kind)).map(([field, label]) => (
          <Textarea key={field} label={t(label)} value={form[field]} onChange={set(field)} rows={3} helperText={t('detail.listHelp')} className="font-mono" data-testid={`zone-edit-${field}`} />
        ))}
      </div>
      {['forward', 'primary', 'secondary'].includes(zone.kind) && (
        <Select label={t('resolver.forward')} value={form.forward} onChange={set('forward')} options={[{ value: '', label: t('resolver.forwardDefault') }, { value: 'first', label: 'first' }, { value: 'only', label: 'only' }]} />
      )}
      {['primary', 'secondary'].includes(zone.kind) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Select label={t('detail.dnssecPolicy')} value={form.dnssec_policy} onChange={set('dnssec_policy')} options={policyOptions} />
          <Select
            label={t('detail.inlineSigning')}
            value={form.inline_signing === null ? '' : form.inline_signing ? 'yes' : 'no'}
            onChange={(v) => setForm((f) => ({ ...f, inline_signing: v === '' ? null : v === 'yes' }))}
            options={[{ value: '', label: t('detail.inlineDefault') }, { value: 'yes', label: t('common:common.yes') }, { value: 'no', label: t('common:common.no') }]}
          />
        </div>
      )}
      <Input label={t('detail.notes')} value={form.notes} onChange={set('notes')} />
    </FormModal>
  )
}
