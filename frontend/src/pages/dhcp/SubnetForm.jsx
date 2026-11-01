// SPDX-License-Identifier: Apache-2.0
// Subnet add/replace form. Fields the form does not show (raw, ddns, reservations,
// pool user-context) are carried over from the subnet as read.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { api } from '../../services/api'
import { NativeSelect, OptionRows, PoolRows, TextArea } from './ui'
import {
  noteOf, effectiveBounds, fieldErrors, firstBadPool, poolErrorRow, isPrefix, isUnchanged, optionRowsOf, optionRowsToText, splitLines, splitList, subnetKey,
  textToOptions, withNote,
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

// Row errors come as { index: message }; a server error on the whole list is a string.
const rowErrors = (value) => (value && typeof value === 'object' ? value : {})

export function SubnetForm({ family, subnet, existing, sharedNetworks, onClose, flow }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !subnet
  const nextId = Math.max(0, ...existing.map((s) => Number(s.id) || 0)) + 1
  const [form, setForm] = useState(() => ({
    id: String(subnet?.id ?? nextId),
    subnet: subnet?.subnet || '',
    shared_network: subnet?.shared_network || '',
    pools: subnet ? subnet.pools.map((p) => p.pool) : [''],
    pd_pools: pdPoolsToText(subnet?.pd_pools),
    options: optionRowsOf(subnet?.options),
    valid_lifetime: subnet?.valid_lifetime ?? '',
    min_valid_lifetime: subnet?.min_valid_lifetime ?? '',
    max_valid_lifetime: subnet?.max_valid_lifetime ?? '',
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
    const badPool = firstBadPool(form.pools, family)
    if (badPool) e.pools = { [badPool.index]: t('form.badPool', { value: badPool.value }) }
    const badOption = form.options.findIndex((r) => r.value.trim() && !r.key.trim())
    if (badOption >= 0) e.options = { [badOption]: t('form.optionKeyRequired') }
    if (family === 'v6') {
      const badPd = splitLines(form.pd_pools).find((line) => {
        const [prefix, delegated] = line.split(/\s+/)
        return !isPrefix(prefix, 'v6') || !/^\d+$/.test(delegated || '')
      })
      if (badPd) e.pd_pools = t('form.badPdPool', { value: badPd })
    }
    for (const key of ['valid_lifetime', 'min_valid_lifetime', 'max_valid_lifetime', 'preferred_lifetime']) {
      if (form[key] !== '' && !/^\d+$/.test(String(form[key]))) e[key] = t('form.positiveInteger')
    }
    const { min, def, max } = bounds
    if (!e.min_valid_lifetime && min !== null && def !== null && min > def) e.min_valid_lifetime = t('form.lifetimeOrder')
    if (!e.max_valid_lifetime && max !== null && def !== null && max < def) e.max_valid_lifetime = t('form.lifetimeOrder')
    if (!e.max_valid_lifetime && max !== null && min !== null && max < min) e.max_valid_lifetime = t('form.lifetimeOrder')
    return e
  }

  const num = (v) => (v === '' ? null : Number(v))
  const bounds = effectiveBounds(subnet, { min: num(form.min_valid_lifetime), def: num(form.valid_lifetime), max: num(form.max_valid_lifetime) })
  const prevPools = subnet?.pools || []
  const after = {
    ...(subnet || { family, reservations: [], ddns: {}, raw: {}, user_context: {} }),
    id: Number(form.id),
    subnet: form.subnet.trim(),
    family,
    shared_network: form.shared_network || null,
    pools: form.pools
      .map((p) => p.trim())
      .filter(Boolean)
      .map((pool) => prevPools.find((p) => p.pool === pool) || { pool, client_classes: [], options: [], user_context: {}, raw: {} }),
    pd_pools: family === 'v6' ? textToPdPools(form.pd_pools, subnet?.pd_pools) : [],
    options: textToOptions(optionRowsToText(form.options), family, subnet?.options),
    valid_lifetime: bounds.def,
    min_valid_lifetime: bounds.min,
    max_valid_lifetime: bounds.max,
    preferred_lifetime: family === 'v6' ? num(form.preferred_lifetime) : subnet?.preferred_lifetime ?? null,
    interface: form.interface.trim() || null,
    relay: splitList(form.relay),
    client_classes: splitList(form.client_classes),
    user_context: withNote(subnet?.user_context, form.note.trim()),
  }
  const unchanged = isUnchanged(subnet, after)

  const submit = async () => {
    const e = validate()
    setErrors(e)
    if (Object.keys(e).length) return
    const change = { op: isNew ? 'add' : 'replace', target: `${subnetKey(family)}/${after.id}`, before: subnet || null, after }
    try {
      const plan = await flow.build(() => api.dhcp.subnetPlan(family, change), { rethrow: true, unchanged })
      if (plan) onClose()
    } catch (err) {
      const mapped = fieldErrors(err)
      // A pool error from the server lands on its row; the rest stays on the field.
      const rowErr = {}
      for (const e of err?.errors || []) {
        const row = poolErrorRow(e.field)
        if (row !== null) rowErr[row] = e.message
      }
      if (Object.keys(rowErr).length) mapped.pools = rowErr
      setErrors({ ...mapped, _form: err.message })
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
      disabled={unchanged}
      size="lg"
      testId="subnet-form"
    >
      <div className="grid gap-3 sm:grid-cols-[120px_1fr_1fr]">
        <Input
          label={t('fields.id')}
          value={form.id}
          onChange={set('id')}
          disabled={!isNew}
          error={errors.id}
          helperText={isNew ? undefined : t('form.idLocked')}
          data-testid="subnet-id"
        />
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
      <div className={family === 'v6' ? 'grid gap-3 sm:grid-cols-2' : undefined}>
        <PoolRows
          label={t('fields.pools')}
          rows={form.pools}
          onChange={set('pools')}
          placeholder={family === 'v6' ? '2001:db8:1::1000 - 2001:db8:1::1fff' : '192.0.2.100 - 192.0.2.199'}
          errors={rowErrors(errors.pools)}
          addLabel={t('form.addPool')}
          removeLabel={t('form.removePool')}
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
        ) : null}
      </div>
      <OptionRows
        label={t('fields.options')}
        rows={form.options}
        onChange={set('options')}
        keyLabel={t('form.optionName')}
        valueLabel={t('fields.data')}
        keyPlaceholder={family === 'v6' ? 'dns-servers' : 'routers'}
        valuePlaceholder={family === 'v6' ? '2001:db8::53' : '192.0.2.1'}
        errors={rowErrors(errors.options)}
        addLabel={t('form.addOption')}
        removeLabel={t('form.removeOption')}
        testId="subnet-options"
      />
      <div className="grid gap-3 sm:grid-cols-3">
        <Input label={t('fields.validLifetimeSeconds')} value={form.valid_lifetime} onChange={set('valid_lifetime')} error={errors.valid_lifetime} data-testid="subnet-valid-lifetime" />
        <Input label={t('fields.minValidLifetimeSeconds')} value={form.min_valid_lifetime} onChange={set('min_valid_lifetime')} error={errors.min_valid_lifetime} data-testid="subnet-min-lifetime" />
        <Input label={t('fields.maxValidLifetimeSeconds')} value={form.max_valid_lifetime} onChange={set('max_valid_lifetime')} error={errors.max_valid_lifetime} data-testid="subnet-max-lifetime" />
        {family === 'v6' && (
          <Input label={t('fields.preferredLifetimeSeconds')} value={form.preferred_lifetime} onChange={set('preferred_lifetime')} error={errors.preferred_lifetime} />
        )}
        <Input label={t('fields.interface')} value={form.interface} onChange={set('interface')} placeholder="eth1" />
        <Input label={t('fields.relay')} value={form.relay} onChange={set('relay')} helperText={t('form.commaSeparated')} />
        <Input label={t('fields.clientClasses')} value={form.client_classes} onChange={set('client_classes')} helperText={t('form.commaSeparated')} />
      </div>
      <Input label={t('fields.note')} value={form.note} onChange={set('note')} helperText={t('form.noteHint')} />
      {[errors.pools, errors.options].filter((v) => typeof v === 'string').map((v) => (
        <p key={v} className="text-xs status-danger-text">{v}</p>
      ))}
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
