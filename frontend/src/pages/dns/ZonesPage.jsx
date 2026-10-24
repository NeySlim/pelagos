// SPDX-License-Identifier: Apache-2.0
// Zones of every view with the SOA serial seen on each node, divergence flag, the
// mode (dynamic UPDATE or static file), resynchronize (retransfer on lagging
// secondaries, notify from primaries) and the zone creation plan (zones.conf or
// rndc addzone, optionally also as secondaries on other nodes).
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
import { ModeBadge, SerialCells, SourceBadge } from './common'
import { useNodeNames, usePlanFlow, zoneHref, resynchronizeZone, SECONDARY_KINDS } from './helpers'
import { validDomainName } from './records'
import { ADDZONE_KINDS, CREATABLE_KINDS, ROOT_KINDS, newZoneAfter, splitList, zoneMode, zoneStats } from './zoneTools'

const KINDS = ['primary', 'secondary', 'stub', 'static-stub', 'forward', 'mirror', 'hint', 'redirect']
const LIST_ERRORS = { list: 'zones.new.listError', required: 'zones.new.fileRequired', fileOrPrimaries: 'zones.new.fileOrPrimaries' }

function NewZoneModal({ open, onClose, onPlan, views, peers }) {
  const { t } = useTranslation(['dns', 'common'])
  const [form, setForm] = useState({ name: '', kind: 'primary', view: '_default', file: '', primaries: '', forwarders: '', serverAddresses: '', serverNames: '', addzone: false, peers: [], secondaryPrimaries: '' })
  const togglePeer = (id) => setForm((f) => ({ ...f, peers: f.peers.includes(id) ? f.peers.filter((p) => p !== id) : [...f.peers, id] }))
  const kind = form.kind
  const canAddzone = ADDZONE_KINDS.includes(kind)
  const withPeers = kind === 'primary' && !form.addzone && peers.length > 0
  const rootOnly = ROOT_KINDS.includes(kind)
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e?.target ? e.target.value : e }))
  const { errors, after } = newZoneAfter(form, validDomainName)
  const errorOf = (field) => (touched && errors[field] ? t(field === 'name' ? 'zones.new.nameError' : field === 'serverAddresses' ? 'zones.new.staticStubError' : LIST_ERRORS[errors[field]]) : undefined)
  const showPrimaries = ['secondary', 'stub', 'mirror', 'redirect'].includes(kind)
  const showFile = kind !== 'forward' && kind !== 'static-stub'

  const submit = async () => {
    setTouched(true)
    if (!after) return
    const nodeIds = withPeers ? form.peers : []
    const body = { ...after }
    if (nodeIds.length && splitList(form.secondaryPrimaries).length) body.secondary = { primaries: splitList(form.secondaryPrimaries) }
    setBusy(true)
    try {
      await onPlan({ op: 'add', target: `${body.view}/${body.name}`, before: null, after: body }, nodeIds)
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('zones.new.title')} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} testId="zone-new">
      <Input
        label={t('zones.new.name')}
        value={rootOnly ? '.' : form.name}
        onChange={set('name')}
        disabled={rootOnly}
        placeholder="example.lan"
        error={errorOf('name')}
        helperText={rootOnly ? t('zones.new.rootOnly') : undefined}
        autoFocus
        data-testid="zone-new-name"
      />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select label={t('zones.kind')} value={kind} onChange={set('kind')} options={CREATABLE_KINDS.map((k) => ({ value: k, label: t(`kind.${k}`) }))} />
        <Select label={t('zones.view')} value={form.view} onChange={set('view')} options={views.map((v) => ({ value: v, label: v }))} />
      </div>
      {showFile && (
        <Input
          label={t('zones.new.file')}
          value={form.file}
          onChange={set('file')}
          placeholder={kind === 'hint' ? '/usr/share/dns/root.hints' : undefined}
          helperText={kind === 'hint' ? t('zones.new.hintFileHelp') : t('zones.new.fileHelp')}
          error={errorOf('file')}
          data-testid="zone-new-file"
        />
      )}
      {showPrimaries && (
        <Textarea
          label={t('zones.primaries')}
          value={form.primaries}
          onChange={set('primaries')}
          rows={3}
          placeholder="192.0.2.53 key ddi-read"
          error={errorOf('primaries')}
          helperText={kind === 'mirror' ? t('zones.new.mirrorHelp') : t('editor.rdataHelp')}
          data-testid="zone-new-primaries"
        />
      )}
      {kind === 'forward' && (
        <Textarea label={t('resolver.forwarders')} value={form.forwarders} onChange={set('forwarders')} rows={3} placeholder="192.0.2.1" error={errorOf('forwarders')} helperText={t('editor.rdataHelp')} />
      )}
      {kind === 'static-stub' && (
        <>
          <Textarea label={t('zones.new.serverAddresses')} value={form.serverAddresses} onChange={set('serverAddresses')} rows={2} placeholder="192.0.2.53" error={errorOf('serverAddresses')} helperText={t('zones.new.serverAddressesHelp')} data-testid="zone-new-server-addresses" />
          <Textarea label={t('zones.new.serverNames')} value={form.serverNames} onChange={set('serverNames')} rows={2} placeholder="ns1.example.lan" helperText={t('zones.new.serverNamesHelp')} data-testid="zone-new-server-names" />
        </>
      )}
      {canAddzone && (
        <label className="flex items-start gap-2 text-sm text-text-primary cursor-pointer">
          <input type="checkbox" className="mt-1" checked={form.addzone} onChange={(e) => setForm((f) => ({ ...f, addzone: e.target.checked }))} data-testid="zone-new-addzone" />
          <span>
            {t('zones.new.addzone')}
            <span className="block text-xs text-text-secondary">{t('zones.new.addzoneHelp')}</span>
          </span>
        </label>
      )}
      {withPeers && (
        <fieldset className="space-y-2" data-testid="zone-new-peers">
          <legend className="text-xs font-medium text-text-secondary">{t('zones.new.peers')}</legend>
          <div className="flex flex-wrap gap-3">
            {peers.map((n) => (
              <label key={n.peer.id} className="inline-flex items-center gap-1.5 text-sm cursor-pointer">
                <input type="checkbox" checked={form.peers.includes(n.peer.id)} onChange={() => togglePeer(n.peer.id)} />
                {n.peer.name}
              </label>
            ))}
          </div>
          {form.peers.length > 0 && (
            <Textarea label={t('zones.new.secondaryPrimaries')} value={form.secondaryPrimaries} onChange={set('secondaryPrimaries')} rows={2} placeholder="192.0.2.1 key ddi-read" helperText={t('zones.new.secondaryPrimariesHelp')} />
          )}
        </fieldset>
      )}
    </FormModal>
  )
}

export default function ZonesPage() {
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const { nodes, nameOf } = useNodeNames()
  const bindPeers = useMemo(() => nodes.filter((n) => !n.is_self && n.peer.modules?.bind), [nodes])
  const [q, setQ] = useState('')
  const [view, setView] = useState('')
  const [kind, setKind] = useState('')
  const [sync, setSync] = useState('')
  const [resyncing, setResyncing] = useState(null)
  const [creating, setCreating] = useState(false)
  const { data, error, loading, refetch } = useApi(() => api.dns.zones({ view: view || undefined, kind: kind || undefined, q: q || undefined }), [view, kind, q])
  const flow = usePlanFlow({ onDone: () => refetch(), onError: showError })

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

  // From the unfiltered list: a search with no match must not read as "no zone on the server".
  const counts = zoneStats(allZones.data?.items || items, SECONDARY_KINDS)
  const stats = [
    { icon: Globe, label: t('zones.stats.total'), value: counts.total, variant: 'primary' },
    { icon: Globe, label: t('zones.stats.primary'), value: counts.primary },
    { icon: Globe, label: t('zones.stats.secondary'), value: counts.secondary },
    { icon: Globe, label: t('zones.stats.static'), value: counts.static },
    { icon: ArrowsClockwise, label: t('zones.stats.divergent'), value: counts.divergent, variant: counts.divergent ? 'warning' : 'success' },
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
    { key: 'mode', label: t('zones.mode'), render: (row) => <ModeBadge mode={zoneMode(row)} /> },
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
          <Button variant="secondary" size="sm" onClick={() => {
            refetch()
            allZones.refetch()
          }} disabled={loading}>
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
          peers={bindPeers}
          onPlan={async (change, nodeIds) => {
            const plan = await flow.run(() => api.dns.zonePlan(change, nodeIds))
            if (plan) setCreating(false)
          }}
        />
      )}
      {flow.modal}
    </PageLayout>
  )
}
