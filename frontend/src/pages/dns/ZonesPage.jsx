// SPDX-License-Identifier: Apache-2.0
// Zones of every view with the SOA serial seen on each node, divergence flag,
// resynchronize (retransfer on lagging secondaries, notify from primaries) and
// the zone creation plan.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Globe, ArrowsClockwise, Plus, ShieldCheck, Lightning } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { StatusBadge } from '../../components/StatusBadge'
import { RichStatsBar } from '../../components/ui/RichStatsBar'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { Select } from '../../components/ui/Select'
import { Textarea } from '../../components/Textarea'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { SerialCells, SourceBadge } from './common'
import { useNodeNames, usePlanFlow, zoneHref, resynchronizeZone, stripDot, SECONDARY_KINDS } from './helpers'
import { splitRdata, validDomainName } from './records'

const KINDS = ['primary', 'secondary', 'stub', 'static-stub', 'forward', 'mirror', 'hint', 'redirect']
const CREATABLE_KINDS = ['primary', 'secondary', 'stub', 'forward']

function NewZoneModal({ open, onClose, onPlan, views }) {
  const { t } = useTranslation(['dns', 'common'])
  const [form, setForm] = useState({ name: '', kind: 'primary', view: '_default', file: '', primaries: '', forwarders: '' })
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e?.target ? e.target.value : e }))
  const name = form.name.trim().toLowerCase()
  const nameOk = validDomainName(name)
  const needsPrimaries = ['secondary', 'stub'].includes(form.kind)
  const primariesOk = !needsPrimaries || splitRdata(form.primaries).length > 0
  const forwardersOk = form.kind !== 'forward' || splitRdata(form.forwarders).length > 0

  const submit = async () => {
    setTouched(true)
    if (!nameOk || !primariesOk || !forwardersOk) return
    const abs = name.endsWith('.') ? name : `${name}.`
    const after = { name: abs, kind: form.kind, view: form.view || '_default' }
    if (form.kind !== 'forward') after.file = form.file.trim() || (form.kind === 'primary' ? `db.${stripDot(abs)}` : `sec/db.${stripDot(abs)}`)
    if (needsPrimaries) after.primaries = splitRdata(form.primaries)
    if (form.kind === 'forward') {
      after.forwarders = splitRdata(form.forwarders)
      after.forward = 'only'
    }
    setBusy(true)
    try {
      await onPlan({ op: 'add', target: `${after.view}/${abs}`, before: null, after, node_ids: [] })
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('zones.new.title')} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} testId="zone-new">
      <Input label={t('zones.new.name')} value={form.name} onChange={set('name')} placeholder="example.lan" error={touched && !nameOk ? t('zones.new.nameError') : undefined} autoFocus />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select label={t('zones.kind')} value={form.kind} onChange={set('kind')} options={CREATABLE_KINDS.map((k) => ({ value: k, label: t(`kind.${k}`) }))} />
        <Select label={t('zones.view')} value={form.view} onChange={set('view')} options={views.map((v) => ({ value: v, label: v }))} />
      </div>
      {form.kind !== 'forward' && <Input label={t('zones.new.file')} value={form.file} onChange={set('file')} helperText={t('zones.new.fileHelp')} />}
      {needsPrimaries && (
        <Textarea label={t('zones.primaries')} value={form.primaries} onChange={set('primaries')} rows={3} placeholder="192.0.2.53 key ddi-read" error={touched && !primariesOk ? t('zones.new.listError') : undefined} helperText={t('editor.rdataHelp')} />
      )}
      {form.kind === 'forward' && (
        <Textarea label={t('resolver.forwarders')} value={form.forwarders} onChange={set('forwarders')} rows={3} placeholder="192.0.2.1" error={touched && !forwardersOk ? t('zones.new.listError') : undefined} helperText={t('editor.rdataHelp')} />
      )}
    </FormModal>
  )
}

export default function ZonesPage() {
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const { nameOf } = useNodeNames()
  const [q, setQ] = useState('')
  const [view, setView] = useState('')
  const [kind, setKind] = useState('')
  const [sync, setSync] = useState('')
  const [resyncing, setResyncing] = useState(null)
  const [creating, setCreating] = useState(false)
  const { data, error, loading, refetch } = useApi(() => api.dns.zones({ view: view || undefined, kind: kind || undefined, q: q || undefined }), [view, kind, q])
  const flow = usePlanFlow({ onDone: refetch, onError: showError })

  const items = useMemo(() => data?.items || [], [data])
  const rows = useMemo(() => items.filter((it) => !sync || (sync === 'divergent' ? it.divergent : !it.divergent)), [items, sync])
  // View names come from an unfiltered list so the filter can switch views directly.
  const allZones = useApi(() => api.dns.zones(), [])
  const views = useMemo(() => [...new Set(['_default', ...(allZones.data?.items || []).map((it) => it.zone.view), ...items.map((it) => it.zone.view)])], [allZones.data, items])
  const canOps = hasPermission('ops:dns')
  const canCreate = hasPermission('write:dns.zones')

  const resync = async (row) => {
    setResyncing(`${row.zone.view}/${row.zone.name}`)
    try {
      const outputs = await resynchronizeZone({ zone: row.zone.name, kind: row.zone.kind, view: row.zone.view, serials: row.serials })
      showSuccess(outputs.join('\n') || t('zones.resyncDone', { zone: row.zone.name }))
      refetch()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setResyncing(null)
    }
  }

  const stats = [
    { icon: Globe, label: t('zones.stats.total'), value: items.length, variant: 'primary' },
    { icon: Globe, label: t('zones.stats.primary'), value: items.filter((it) => it.zone.kind === 'primary').length },
    { icon: Globe, label: t('zones.stats.secondary'), value: items.filter((it) => SECONDARY_KINDS.includes(it.zone.kind)).length },
    { icon: ArrowsClockwise, label: t('zones.stats.divergent'), value: items.filter((it) => it.divergent).length, variant: items.some((it) => it.divergent) ? 'warning' : 'success' },
  ]

  const columns = [
    {
      key: 'zone.name',
      label: t('zones.name'),
      sortable: true,
      render: (row) => (
        <span className="inline-flex items-center gap-1.5">
          <span className="font-mono text-xs text-text-primary">{row.zone.name}</span>
          {row.zone.dnssec_policy && <ShieldCheck size={13} className="text-accent-primary" title={t('zones.signed')} />}
          {row.zone.dynamic && <Lightning size={13} className="text-text-tertiary" title={t('zones.dynamic')} />}
        </span>
      ),
    },
    { key: 'zone.kind', label: t('zones.kind'), sortable: true, render: (row) => <StatusBadge status={row.zone.kind} label={t(`kind.${row.zone.kind}`, { defaultValue: row.zone.kind })} dot={false} /> },
    { key: 'zone.view', label: t('zones.view'), sortable: true, mono: true },
    { key: 'zone.source', label: t('zones.source'), render: (row) => <SourceBadge source={row.zone.source} /> },
    { key: 'serials', label: t('zones.serials'), render: (row) => (row.zone.kind === 'forward' ? <span className="text-text-tertiary">-</span> : <SerialCells serials={row.serials} nameOf={nameOf} />) },
    {
      key: 'divergent',
      label: t('zones.sync'),
      sortable: true,
      render: (row) =>
        row.zone.kind === 'forward' ? <span className="text-text-tertiary">-</span> : <StatusBadge status={row.divergent ? 'divergent' : 'in-sync'} />,
    },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (row) =>
        canOps && row.zone.kind !== 'forward' ? (
          <Button
            variant={row.divergent ? 'warning-soft' : 'secondary'}
            size="xs"
            loading={resyncing === `${row.zone.view}/${row.zone.name}`}
            onClick={(e) => {
              e.stopPropagation()
              resync(row)
            }}
            data-testid="zone-resync"
          >
            <ArrowsClockwise size={12} />
            {t('zones.resync')}
          </Button>
        ) : null,
    },
  ]

  return (
    <PageLayout
      icon={Globe}
      title={t('pages.zones.title')}
      subtitle={t('pages.zones.subtitle')}
      testId="page-dns-zones"
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={refetch} disabled={loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          {canCreate && (
            <Button size="sm" onClick={() => setCreating(true)} data-testid="zone-add">
              <Plus size={14} />
              {t('zones.add')}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <RichStatsBar stats={stats} />
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(row) => `${row.zone.view}/${row.zone.name}`}
          loading={loading && !data}
          error={error}
          onRetry={refetch}
          clientSort
          search={{ value: q, onChange: setQ, placeholder: t('zones.search') }}
          filters={[
            { key: 'view', label: t('zones.view'), value: view, onChange: setView, options: views.map((v) => ({ value: v, label: v })) },
            { key: 'kind', label: t('zones.kind'), value: kind, onChange: setKind, options: KINDS.map((k) => ({ value: k, label: t(`kind.${k}`) })) },
            {
              key: 'sync',
              label: t('zones.sync'),
              value: sync,
              onChange: setSync,
              options: [
                { value: 'divergent', label: t('common:status.divergent') },
                { value: 'in-sync', label: t('common:status.in-sync') },
              ],
            },
          ]}
          onRowClick={(row) => navigate(zoneHref(row.zone.name, row.zone.view))}
          emptyTitle={t('zones.empty')}
          testId="zones-table"
        />
      </div>
      {creating && (
        <NewZoneModal
          open={creating}
          onClose={() => setCreating(false)}
          views={views}
          onPlan={async (change) => {
            const plan = await flow.run(() => api.dns.zonePlan(change))
            if (plan) setCreating(false)
          }}
        />
      )}
      {flow.modal}
    </PageLayout>
  )
}
