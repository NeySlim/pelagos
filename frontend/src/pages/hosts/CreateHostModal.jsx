// SPDX-License-Identifier: Apache-2.0
// Create-host form: POST /hosts/plan with the A or AAAA record, the PTR in the
// reverse zone and, when asked, a DHCP reservation; the answer is one `host` plan.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { api } from '../../services/api'
import { Checkbox, NativeSelect } from '../dhcp/ui'
import { fieldErrors, isIPv4, isIPv6, isMac } from '../dhcp/lib'
import { DEFAULT_VIEW, recordZoneNamesIn, reverseZoneFor, subnetFor, zoneViews } from './net'

export function CreateHostModal({ subnets, subnets6 = [], zones, flow, onClose, initial = {} }) {
  const { t } = useTranslation(['hosts', 'dhcp', 'common'])
  // The view pickers only show when BIND has views beyond the default one.
  const views = useMemo(() => zoneViews(zones), [zones])
  const hasViews = views.some((v) => v !== DEFAULT_VIEW)
  const initialView = initial.view || DEFAULT_VIEW
  const forwardIn = (view) => recordZoneNamesIn(zones, view).filter((z) => !z.endsWith('.arpa.'))
  const [form, setForm] = useState({
    hostname: initial.hostname || '',
    view: initialView,
    reverse_view: '',
    zone: initial.zone || forwardIn(initialView)[0] || '',
    ip: initial.ip || '',
    reverse_zone: '',
    ttl: '3600',
    reservation: Boolean(initial.mac),
    mac: initial.mac || '',
    subnet_id: '',
    notes: '',
  })
  const [errors, setErrors] = useState({})
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value?.target ? value.target.value : value }))
  // A new view offers its own zones: keep the zone when that view serves it too.
  const setView = (view) =>
    setForm((f) => {
      const names = forwardIn(view)
      return { ...f, view, zone: names.includes(f.zone) ? f.zone : names[0] || '' }
    })
  const forwardZones = forwardIn(form.view)
  // An empty reverse_view follows the view, as the backend does.
  const reverseNames = recordZoneNamesIn(zones, form.reverse_view || form.view).filter((z) => z.endsWith('.arpa.'))

  const ip = form.ip.trim()
  const validIp = isIPv4(ip) || isIPv6(ip)
  // The subnet list follows the family of the address typed.
  const familySubnets = isIPv6(ip) ? subnets6 : subnets
  const autoReverse = validIp ? reverseZoneFor(ip, reverseNames) : null
  const autoSubnet = validIp ? subnetFor(ip, familySubnets) : null

  const validate = () => {
    const e = {}
    if (!/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?$/.test(form.hostname.trim())) e.hostname = t('dhcp:form.badHostname')
    if (!form.zone.trim()) e.zone = t('dhcp:form.required')
    if (!validIp) e.ip = t('dhcp:form.badIp')
    if (!/^\d+$/.test(form.ttl)) e.ttl = t('dhcp:form.positiveInteger')
    if (form.reservation && !isMac(form.mac.trim())) e.mac = t('dhcp:form.badMac')
    return e
  }

  const submit = async () => {
    const e = validate()
    setErrors(e)
    if (Object.keys(e).length) return
    const subnetId = form.subnet_id || (autoSubnet ? String(autoSubnet.id) : '')
    const body = {
      hostname: form.hostname.trim(),
      ip,
      zone: form.zone.trim(),
      ttl: Number(form.ttl),
      reservation: form.reservation,
      ...(form.view !== DEFAULT_VIEW ? { view: form.view } : {}),
      ...(form.reverse_view ? { reverse_view: form.reverse_view } : {}),
      ...(form.reverse_zone.trim() || autoReverse ? { reverse_zone: form.reverse_zone.trim() || autoReverse } : {}),
      ...(form.reservation ? { mac: form.mac.trim().toLowerCase(), ...(subnetId ? { subnet_id: Number(subnetId) } : {}) } : {}),
      ...(form.notes.trim() ? { notes: form.notes.trim() } : {}),
    }
    try {
      const plan = await flow.build(() => api.hosts.plan(body), { rethrow: true })
      if (plan) onClose()
    } catch (err) {
      setErrors({ ...fieldErrors(err), _form: err.message })
    }
  }

  return (
    <FormModal
      open
      onClose={onClose}
      title={t('create.title')}
      onSubmit={submit}
      submitLabel={t('dhcp:form.preview')}
      loading={flow.building}
      testId="host-form"
    >
      {hasViews && (
        <div className="grid gap-3 sm:grid-cols-2">
          <NativeSelect label={t('fields.view')} value={form.view} onChange={setView} options={views.map((v) => ({ value: v, label: v }))} testId="host-view" />
          <NativeSelect
            label={t('fields.reverseView')}
            value={form.reverse_view}
            onChange={set('reverse_view')}
            options={[{ value: '', label: t('create.reverseViewSame', { view: form.view }) }, ...views.map((v) => ({ value: v, label: v }))]}
            testId="host-reverse-view"
          />
        </div>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <Input label={t('dhcp:fields.hostname')} value={form.hostname} onChange={set('hostname')} error={errors.hostname} placeholder="printer2" required data-testid="host-hostname" />
        {forwardZones.length ? (
          <NativeSelect label={t('fields.zone')} value={form.zone} onChange={set('zone')} options={forwardZones.map((z) => ({ value: z, label: z }))} testId="host-zone" />
        ) : (
          <Input label={t('fields.zone')} value={form.zone} onChange={set('zone')} error={errors.zone} placeholder="example.lan" data-testid="host-zone" />
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-[1fr_1fr_100px]">
        <Input label={t('dhcp:fields.ipAddress')} value={form.ip} onChange={set('ip')} error={errors.ip} placeholder="192.0.2.42" required data-testid="host-ip" />
        <Input
          label={t('fields.reverseZone')}
          value={form.reverse_zone}
          onChange={set('reverse_zone')}
          placeholder={autoReverse || '2.0.192.in-addr.arpa'}
          helperText={autoReverse ? t('create.reverseAuto', { zone: autoReverse }) : validIp ? t('create.reverseNone') : t('create.reverseFromAddress')}
        />
        <Input label={t('fields.ttl')} value={form.ttl} onChange={set('ttl')} error={errors.ttl} />
      </div>
      <Checkbox label={t('create.withReservation')} checked={form.reservation} onChange={set('reservation')} testId="host-reservation-toggle" />
      {form.reservation && (
        <div className="grid gap-3 sm:grid-cols-2">
          <Input label={t('dhcp:fields.mac')} value={form.mac} onChange={set('mac')} error={errors.mac} placeholder="02:00:5e:00:00:01" data-testid="host-mac" />
          <NativeSelect
            label={t('dhcp:fields.subnet')}
            value={form.subnet_id}
            onChange={set('subnet_id')}
            options={[
              { value: '', label: autoSubnet ? t('create.subnetAuto', { subnet: autoSubnet.subnet }) : t('create.subnetPick') },
              ...familySubnets.map((s) => ({ value: String(s.id), label: `${s.id}: ${s.subnet}` })),
            ]}
            testId="host-subnet"
          />
        </div>
      )}
      <Input label={t('dhcp:fields.note')} value={form.notes} onChange={set('notes')} helperText={t('create.notesHint')} />
      {errors._form && (
        <p className="text-xs status-danger-text" data-testid="host-form-error">
          {errors._form}
        </p>
      )}
    </FormModal>
  )
}
