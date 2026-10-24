// SPDX-License-Identifier: Apache-2.0
// Host reservations: paginated, by subnet and search; the reservation plan form.
// ?new=1&mac=&ip=&hostname=&subnet_id= opens the form prefilled (host card action).
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { BookmarkSimple, Plus } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { useApi, usePaginatedApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, ClassChips, NativeSelect, RowActions, TextArea } from './ui'
import { usePlanFlow } from './hooks'
import {
  NOTE_KEY, OWNER_KEY, fieldErrors, isIP, isMac, isPrefix, reservationTarget, splitList, withNote,
} from './lib'

const ID_TYPES = ['hw-address', 'duid', 'client-id', 'circuit-id', 'flex-id']

export default function ReservationsPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const [params, setParams] = useSearchParams()
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.reservations')
  const [q, setQ] = useState(params.get('q') || '')
  const [subnetId, setSubnetId] = useState(params.get('subnet_id') && !params.get('new') ? params.get('subnet_id') : '')
  const [editing, setEditing] = useState(null)

  const list = usePaginatedApi(({ family: _family, ...query }) => api.dhcp.reservations(family, query), {
    perPage: 50,
    filters: { q, subnet_id: subnetId, family },
  })
  const subnets = useApi(() => api.dhcp.subnets(family), [family])
  const classes = useApi(() => api.dhcp.clientClasses(family), [family])
  const flow = usePlanFlow({ onApplied: list.refetch })

  // Prefill from a cross action, once, then drop the parameters from the URL.
  useEffect(() => {
    if (params.get('new') !== '1' || !canWrite) return
    setEditing({
      reservation: null,
      prefill: { identifier: params.get('mac') || '', ip: params.get('ip') || '', hostname: params.get('hostname') || '', subnet_id: params.get('subnet_id') || '' },
    })
    setParams({}, { replace: true })
  }, [params, setParams, canWrite])

  const remove = (r) =>
    flow.build(() => api.dhcp.reservationPlan(family, { op: 'delete', target: reservationTarget(family, r), before: r, after: null }))

  const columns = [
    {
      key: 'identifier',
      label: t('fields.identifier'),
      render: (r) => (
        <span className="inline-flex items-center gap-1.5">
          <Badge variant="outline" size="sm">{r.id_type}</Badge>
          <span className="font-mono text-xs">{r.identifier}</span>
        </span>
      ),
    },
    {
      key: 'ip',
      label: family === 'v6' ? t('fields.addressesAndPrefixes') : t('fields.ipAddress'),
      mono: true,
      render: (r) => (family === 'v6' ? [...(r.ip_addresses || []), ...(r.prefixes || [])].join(', ') || '-' : r.ip_address || '-'),
    },
    { key: 'hostname', label: t('fields.hostname'), truncate: true },
    { key: 'subnet_id', label: t('fields.subnetId'), mono: true, width: 70, render: (r) => r.subnet_id ?? t('reservations.global') },
    { key: 'client_classes', label: t('fields.clientClasses'), render: (r) => <ClassChips classes={r.client_classes} /> },
    { key: 'owner', label: t('userContext.owner'), render: (r) => r.user_context?.[OWNER_KEY] || '' },
    { key: 'note', label: t('fields.note'), truncate: true, render: (r) => r.user_context?.[NOTE_KEY] || '' },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (r) => (
            <RowActions editLabel={t('common:actions.edit')} deleteLabel={t('common:actions.delete')} onEdit={() => setEditing({ reservation: r })} onDelete={() => remove(r)} />
          ),
        }]
      : []),
  ]

  const subnetOptions = (subnets.data?.items || []).map((s) => ({ value: String(s.id), label: `${s.id}: ${s.subnet}` }))

  return (
    <AreaPage
      ns="dhcp"
      page="reservations"
      icon={BookmarkSimple}
      family={family}
      onRefresh={list.refetch}
      loading={list.loading}
      actions={
        canWrite && (
          <Button size="sm" onClick={() => setEditing({ reservation: null })} data-testid="reservation-create">
            <Plus size={14} />
            {t('reservations.create')}
          </Button>
        )
      }
    >
      <DataTable
        columns={columns}
        rows={list.items}
        rowKey={(r) => `${r.subnet_id}-${r.id_type}-${r.identifier}`}
        loading={list.loading}
        error={list.error}
        onRetry={list.refetch}
        search={{ value: q, onChange: setQ, placeholder: t('reservations.search') }}
        filters={[{ key: 'subnet_id', label: t('fields.subnet'), value: subnetId, onChange: setSubnetId, options: subnetOptions, placeholder: t('leases.allSubnets') }]}
        pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
        emptyTitle={t('reservations.empty')}
        emptyIcon={BookmarkSimple}
        testId="reservations-table"
      />
      {editing && (
        <ReservationForm
          family={family}
          reservation={editing.reservation}
          prefill={editing.prefill}
          subnets={subnets.data?.items || []}
          classes={classes.data?.items || []}
          flow={flow}
          onClose={() => setEditing(null)}
        />
      )}
      {flow.modal}
    </AreaPage>
  )
}

export function ReservationForm({ family, reservation, prefill = {}, subnets, classes, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !reservation
  const r = reservation || {}
  const [form, setForm] = useState({
    subnet_id: String(r.subnet_id ?? prefill.subnet_id ?? subnets[0]?.id ?? ''),
    id_type: r.id_type || (family === 'v6' ? 'duid' : 'hw-address'),
    identifier: r.identifier || prefill.identifier || '',
    ip_address: r.ip_address || (family === 'v4' ? prefill.ip : '') || '',
    ip_addresses: (r.ip_addresses || (family === 'v6' && prefill.ip ? [prefill.ip] : [])).join('\n'),
    prefixes: (r.prefixes || []).join('\n'),
    hostname: r.hostname || prefill.hostname || '',
    client_classes: (r.client_classes || []).join(', '),
    next_server: r.next_server || '',
    boot_file_name: r.boot_file_name || '',
    note: r.user_context?.[NOTE_KEY] || '',
    owner: r.user_context?.[OWNER_KEY] || '',
  })
  const [errors, setErrors] = useState({})
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value?.target ? value.target.value : value }))
  const subnet = useMemo(() => subnets.find((s) => String(s.id) === form.subnet_id), [subnets, form.subnet_id])

  const validate = () => {
    const e = {}
    if (!form.identifier.trim()) e.identifier = t('form.required')
    else if (form.id_type === 'hw-address' && !isMac(form.identifier.trim())) e.identifier = t('form.badMac')
    if (family === 'v4') {
      if (form.ip_address && !isIP(form.ip_address.trim(), 'v4')) e.ip_address = t('form.badIp')
    } else {
      const bad = splitList(form.ip_addresses).find((a) => !isIP(a, 'v6'))
      if (bad) e.ip_addresses = t('form.badIpValue', { value: bad })
      const badPrefix = splitList(form.prefixes).find((p) => !isPrefix(p, 'v6'))
      if (badPrefix) e.prefixes = t('form.badPrefixValue', { value: badPrefix })
    }
    if (form.hostname && !/^[A-Za-z0-9.-]+$/.test(form.hostname.trim())) e.hostname = t('form.badHostname')
    return e
  }

  const submit = async () => {
    const e = validate()
    setErrors(e)
    if (Object.keys(e).length) return
    const identifier = form.id_type === 'hw-address' ? form.identifier.trim().toLowerCase() : form.identifier.trim()
    const after = {
      ...(reservation || { options: [], server_hostname: null, raw: {} }),
      subnet_id: form.subnet_id === '' ? null : Number(form.subnet_id),
      id_type: form.id_type,
      identifier,
      ip_address: family === 'v4' ? form.ip_address.trim() || null : null,
      ip_addresses: family === 'v6' ? splitList(form.ip_addresses) : [],
      prefixes: family === 'v6' ? splitList(form.prefixes) : [],
      hostname: form.hostname.trim() || null,
      client_classes: splitList(form.client_classes),
      next_server: family === 'v4' ? form.next_server.trim() || null : null,
      boot_file_name: family === 'v4' ? form.boot_file_name.trim() || null : null,
      user_context: withNote(reservation?.user_context, form.note.trim(), form.owner.trim()),
    }
    const change = { op: isNew ? 'add' : 'replace', target: reservationTarget(family, after), before: reservation || null, after }
    try {
      const plan = await flow.build(() => api.dhcp.reservationPlan(family, change), { rethrow: true })
      if (plan) onClose()
    } catch (err) {
      setErrors({ ...fieldErrors(err), _form: err.message })
    }
  }

  return (
    <FormModal
      open
      onClose={onClose}
      title={isNew ? t('reservations.createTitle') : t('reservations.editTitle', { identifier: reservation.identifier })}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      size="lg"
      testId="reservation-form"
    >
      <div className="grid gap-3 sm:grid-cols-[1fr_140px_1fr]">
        <NativeSelect
          label={t('fields.subnet')}
          value={form.subnet_id}
          onChange={set('subnet_id')}
          disabled={!isNew}
          options={[{ value: '', label: t('reservations.global') }, ...subnets.map((s) => ({ value: String(s.id), label: `${s.id}: ${s.subnet}` }))]}
          testId="reservation-subnet"
        />
        <NativeSelect
          label={t('fields.idType')}
          value={form.id_type}
          onChange={set('id_type')}
          disabled={!isNew}
          options={ID_TYPES.map((v) => ({ value: v, label: v }))}
          testId="reservation-id-type"
        />
        <Input
          label={t('fields.identifier')}
          value={form.identifier}
          onChange={set('identifier')}
          disabled={!isNew}
          error={errors.identifier}
          placeholder={form.id_type === 'hw-address' ? '02:00:5e:00:00:01' : '00:03:00:01:02:00:5e:00:00:01'}
          required
          data-testid="reservation-identifier"
        />
      </div>
      {family === 'v4' ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <Input
            label={t('fields.ipAddress')}
            value={form.ip_address}
            onChange={set('ip_address')}
            error={errors.ip_address}
            helperText={subnet ? t('reservations.inSubnet', { subnet: subnet.subnet }) : undefined}
            data-testid="reservation-ip"
          />
          <Input label={t('fields.hostname')} value={form.hostname} onChange={set('hostname')} error={errors.hostname} data-testid="reservation-hostname" />
        </div>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <TextArea label={t('fields.ipAddresses')} hint={t('form.onePerLine')} value={form.ip_addresses} onChange={set('ip_addresses')} rows={2} error={errors.ip_addresses} testId="reservation-ips" />
            <TextArea label={t('fields.prefixes')} hint={t('form.onePerLine')} value={form.prefixes} onChange={set('prefixes')} rows={2} error={errors.prefixes} testId="reservation-prefixes" />
          </div>
          <Input label={t('fields.hostname')} value={form.hostname} onChange={set('hostname')} error={errors.hostname} />
        </>
      )}
      <Input
        label={t('fields.clientClasses')}
        value={form.client_classes}
        onChange={set('client_classes')}
        helperText={classes.length ? t('reservations.knownClasses', { list: classes.map((c) => c.name).join(', ') }) : t('form.commaSeparated')}
      />
      {family === 'v4' && (
        <div className="grid gap-3 sm:grid-cols-2">
          <Input label={t('fields.nextServer')} value={form.next_server} onChange={set('next_server')} />
          <Input label={t('fields.bootFileName')} value={form.boot_file_name} onChange={set('boot_file_name')} />
        </div>
      )}
      <div className="grid gap-3 sm:grid-cols-[200px_1fr]">
        <Input label={t('userContext.owner')} value={form.owner} onChange={set('owner')} />
        <Input label={t('fields.note')} value={form.note} onChange={set('note')} helperText={t('form.noteHint')} />
      </div>
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
