// SPDX-License-Identifier: Apache-2.0
// Subnet add/replace form. Fields the form does not show (raw, ddns, reservations,
// pool user-context) are carried over from the subnet as read.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { api } from '../../services/api'
import { NativeSelect, TextArea } from './ui'
import {
  noteOf, fieldErrors, isPool, isPrefix, optionsToText, splitLines, splitList, subnetKey, textToOptions, withNote,
} from './lib'

function pdPoolsToText(pdPools = []) {
  return pdPools.map((p) => `${p.prefix}/${p.prefix_len} ${p.delegated_len}`).join('\n')
}

// "2001:db8:8000::/48 56" lines; existing pd-pools keep their other fields.
function textToPdPools(text, previous = []) {
  return splitLines(text).map((line) => {
    const [prefixPart, delegated] = line.split(/\s+/)
    const [prefix, len] = prefixPart.split('/')
    const prev = previous.find((p) => p.prefix === prefix && p.prefix_len === Number(len))
    return {
      excluded_prefix: null, excluded_prefix_len: null, client_classes: [], options: [], user_context: {}, raw: {},
      ...(prev || {}),
      prefix,
      prefix_len: Number(len),
      delegated_len: Number(delegated),
    }
  })
}

export function SubnetForm({ family, subnet, existing, sharedNetworks, onClose, flow }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !subnet
  const nextId = Math.max(0, ...existing.map((s) => Number(s.id) || 0)) + 1
  const [form, setForm] = useState(() => ({
    id: String(subnet?.id ?? nextId),
    subnet: subnet?.subnet || '',
    shared_network: subnet?.shared_network || '',
    pools: (subnet?.pools || []).map((p) => p.pool).join('\n'),
    pd_pools: pdPoolsToText(subnet?.pd_pools),
    options: optionsToText(subnet?.options),
    valid_lifetime: subnet?.valid_lifetime ?? '',
    preferred_lifetime: subnet?.preferred_lifetime ?? '',
    interface: subnet?.interface || '',
    relay: (subnet?.relay || []).join(', '),
    client_classes: (subnet?.client_classes || []).join(', '),
    note: noteOf(subnet?.user_context),
  }))
  const [errors, setErrors] = useState({})
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value?.target ? value.target.value : value }))

  const validate = () => {
    const e = {}
    if (!/^\d+$/.test(form.id) || Number(form.id) < 1) e.id = t('form.positiveInteger')
    else if (isNew && existing.some((s) => String(s.id) === form.id)) e.id = t('form.idTaken')
    if (!isPrefix(form.subnet, family)) e.subnet = t('form.badPrefix')
    const badPool = splitLines(form.pools).find((p) => !isPool(p, family))
    if (badPool) e.pools = t('form.badPool', { value: badPool })
    if (family === 'v6') {
      const badPd = splitLines(form.pd_pools).find((line) => {
        const [prefix, delegated] = line.split(/\s+/)
        return !isPrefix(prefix, 'v6') || !/^\d+$/.test(delegated || '')
      })
      if (badPd) e.pd_pools = t('form.badPdPool', { value: badPd })
    }
    for (const key of ['valid_lifetime', 'preferred_lifetime']) {
      if (form[key] !== '' && !/^\d+$/.test(String(form[key]))) e[key] = t('form.positiveInteger')
    }
    return e
  }

  const submit = async () => {
    const e = validate()
    setErrors(e)
    if (Object.keys(e).length) return
    const prevPools = subnet?.pools || []
    const after = {
      ...(subnet || { family, reservations: [], ddns: {}, raw: {}, user_context: {} }),
      id: Number(form.id),
      subnet: form.subnet.trim(),
      family,
      shared_network: form.shared_network || null,
      pools: splitLines(form.pools).map(
        (pool) => prevPools.find((p) => p.pool === pool) || { pool, client_classes: [], options: [], user_context: {}, raw: {} },
      ),
      pd_pools: family === 'v6' ? textToPdPools(form.pd_pools, subnet?.pd_pools) : [],
      options: textToOptions(form.options, family, subnet?.options),
      valid_lifetime: form.valid_lifetime === '' ? null : Number(form.valid_lifetime),
      preferred_lifetime:
        family === 'v6' ? (form.preferred_lifetime === '' ? null : Number(form.preferred_lifetime)) : subnet?.preferred_lifetime ?? null,
      interface: form.interface.trim() || null,
      relay: splitList(form.relay),
      client_classes: splitList(form.client_classes),
      user_context: withNote(subnet?.user_context, form.note.trim()),
    }
    const change = { op: isNew ? 'add' : 'replace', target: `${subnetKey(family)}/${after.id}`, before: subnet || null, after }
    try {
      const plan = await flow.build(() => api.dhcp.subnetPlan(family, change), { rethrow: true })
      if (plan) onClose()
    } catch (err) {
      setErrors({ ...fieldErrors(err), _form: err.message })
    }
  }

  return (
    <FormModal
      open
      onClose={onClose}
      title={isNew ? t('subnets.createTitle') : t('subnets.editTitle', { subnet: subnet.subnet })}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      size="lg"
      testId="subnet-form"
    >
      <div className="grid gap-3 sm:grid-cols-[120px_1fr_1fr]">
        <Input label={t('fields.id')} value={form.id} onChange={set('id')} disabled={!isNew} error={errors.id} data-testid="subnet-id" />
        <Input
          label={t('fields.subnet')}
          value={form.subnet}
          onChange={set('subnet')}
          placeholder={family === 'v6' ? '2001:db8:1::/64' : '192.0.2.0/24'}
          error={errors.subnet}
          required
          data-testid="subnet-prefix"
        />
        <NativeSelect
          label={t('fields.sharedNetwork')}
          value={form.shared_network}
          onChange={set('shared_network')}
          options={[{ value: '', label: t('subnets.noSharedNetwork') }, ...sharedNetworks.map((n) => ({ value: n.name, label: n.name }))]}
        />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <TextArea
          label={t('fields.pools')}
          hint={t('form.onePerLine')}
          value={form.pools}
          onChange={set('pools')}
          placeholder={family === 'v6' ? '2001:db8:1::1000 - 2001:db8:1::1fff' : '192.0.2.100 - 192.0.2.199'}
          error={errors.pools}
          testId="subnet-pools"
        />
        {family === 'v6' ? (
          <TextArea
            label={t('fields.pdPools')}
            hint={t('form.pdPoolHint')}
            value={form.pd_pools}
            onChange={set('pd_pools')}
            placeholder="2001:db8:8000::/48 56"
            error={errors.pd_pools}
            testId="subnet-pd-pools"
          />
        ) : (
          <TextArea label={t('fields.options')} hint={t('form.optionHint')} value={form.options} onChange={set('options')} placeholder="routers = 192.0.2.1" />
        )}
      </div>
      {family === 'v6' && (
        <TextArea label={t('fields.options')} hint={t('form.optionHint')} value={form.options} onChange={set('options')} placeholder="dns-servers = 2001:db8::53" />
      )}
      <div className="grid gap-3 sm:grid-cols-3">
        <Input label={t('fields.validLifetimeSeconds')} value={form.valid_lifetime} onChange={set('valid_lifetime')} error={errors.valid_lifetime} />
        {family === 'v6' && (
          <Input label={t('fields.preferredLifetimeSeconds')} value={form.preferred_lifetime} onChange={set('preferred_lifetime')} error={errors.preferred_lifetime} />
        )}
        <Input label={t('fields.interface')} value={form.interface} onChange={set('interface')} placeholder="eth1" />
        <Input label={t('fields.relay')} value={form.relay} onChange={set('relay')} helperText={t('form.commaSeparated')} />
        <Input label={t('fields.clientClasses')} value={form.client_classes} onChange={set('client_classes')} helperText={t('form.commaSeparated')} />
      </div>
      <Input label={t('fields.note')} value={form.note} onChange={set('note')} helperText={t('form.noteHint')} />
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
