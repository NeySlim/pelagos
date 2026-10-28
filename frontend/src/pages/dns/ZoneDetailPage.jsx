// SPDX-License-Identifier: Apache-2.0
// One zone: RRset table with the record editor, status on every node (rndc
// zonestatus + SOA query), the zone statement as configured, the rndc operations
// (notify, reload, retransfer), the zone edit and deletion plans, the view selector
// for a zone present in several views and the conversion of a static zone.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Globe, ArrowsClockwise, Plus, PencilSimple, Trash, Bell, ArrowClockwise, ShieldCheck, Table as TableIcon, HardDrives, Gear, DownloadSimple, Lightning, FileText, DotsThree, HandGrabbing } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { StatusBadge } from '../../components/StatusBadge'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { EmptyState } from '../../components/EmptyState'
import { Badge } from '../../components/Badge'
import { Dropdown } from '../../components/Dropdown'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { useAuth } from '../../contexts/AuthContext'
import { useApi, usePaginatedApi } from '../../hooks/useApi'
import { useMobile } from '../../contexts/MobileContext'
import { Select } from '../../components/ui/Select'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { PlanPreviewModal } from '../../components/PlanPreview'
import { TransferBar, TransferSerial } from '../../components/motion'
import { usePoll } from '../../hooks/usePoll'
import { useMessage } from '../../i18n/message'
import { onPlanEvent, planZone } from '../../lib/planEvents'
import { ZoneSerialTrace } from './ZoneSerialTrace'
import { useCatchUps } from './catchUp'
import { useZoneEvents } from './zoneEvents'
import { KeyValue, ListValue, ModeBadge, SourceBadge } from './common'
import { useNodeNames, usePlanFlow, laggingNodes, zoneHref, SECONDARY_KINDS } from './helpers'
import { zoneFromSegment } from '../../lib/zonePath'
import { RecordEditor } from './RecordEditor'
import { handoverChanges, zoneHandover } from './handover'
import { FailoverBadge } from './FailoverBadge'
import { EDITABLE_TYPES, READ_ONLY_TYPES, absZone, isEditableType, relativeName } from './records'
import { ZoneEditModal } from './ZoneEditModal'
import { clearLists } from '../../lib/listCache'
import { editableZone, secondaryChoice, secondaryPeers, staticFindingId, zoneCopies, zoneDeleteRequest, zoneMode } from './zoneTools'

const ZONE_POLL_MS = 15000
const TRANSFER_REREAD_MS = 2500
function RecordsTab({ zone, view, editable, mode, onChanged, status, nameOf }) {
  const { t } = useTranslation(['dns', 'common'])
  const msg = useMessage()
  const { isMobile } = useMobile()
  const { showToast, showError } = useNotification()
  const [type, setType] = useState('')
  const [q, setQ] = useState('')
  const [editor, setEditor] = useState(null)
  const [rollbackOf, setRollbackOf] = useState(null)
  const filters = { type: type || undefined, q: q || undefined, view: view || undefined }
  const records = usePaginatedApi((params) => api.dns.records(zone.name, params), { perPage: 50, filters })
  // A new serial here or a transfer landing means new record contents.
  useZoneEvents(zone.name, zone.view, () => records.refetch())

  const open = (mode, rrset = null) => setEditor({ mode, rrset })
  const done = () => {
    records.refetch()
    onChanged?.()
  }
  // The applied plan stays one click away from its rollback while the server holds it.
  const committed = (plan) => {
    showToast({
      type: 'success',
      message: t('records.applied'),
      detail: msg(plan.summary_message, plan.summary),
      action: {
        label: t('records.rollbackPlan'),
        testId: 'toast-rollback-plan',
        onClick: async () => {
          try {
            const fresh = await api.plans.get(plan.id)
            if (fresh?.state !== 'applied') throw new Error(t('records.rollbackGone'))
            setRollbackOf(fresh)
          } catch (err) {
            showError(err?.status === 404 || err?.status === 410 ? t('records.rollbackGone') : errorMessage(err))
          }
        },
      },
    })
  }

  const actions = (r) =>
    editable && isEditableType(r.rtype) ? (
      <span className="inline-flex gap-1 shrink-0">
        <Button variant="ghost" size="xs" onClick={() => open('edit', r)} aria-label={t('common:actions.edit')} data-testid="record-edit">
          <PencilSimple size={13} />
        </Button>
        <Button variant="ghost" size="xs" onClick={() => open('delete', r)} aria-label={t('common:actions.delete')} data-testid="record-delete">
          <Trash size={13} className="status-danger-text" />
        </Button>
      </span>
    ) : null

  // Below md one card per RRset: owner, type and TTL on a line, the rdata under it.
  const mobileColumns = [
    {
      key: 'name',
      label: t('records.owner'),
      render: (r) => (
        <div className="flex items-start gap-2 min-w-0" data-testid="record-card">
          <div className="flex-1 min-w-0 space-y-1">
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-xs text-text-primary truncate" title={r.name}>{relativeName(r.name, zone.name)}</span>
              <Badge variant={isEditableType(r.rtype) ? 'primary' : 'gray'} size="sm">{r.rtype}</Badge>
              <span className="font-mono text-2xs text-text-tertiary">{r.ttl}</span>
            </div>
            <div className="font-mono text-2xs text-text-secondary break-all space-y-0.5">
              {r.rdata.map((d, i) => (
                <div key={i}>{d}</div>
              ))}
            </div>
          </div>
          {actions(r)}
        </div>
      ),
    },
  ]

  const desktopColumns = [
    { key: 'name', label: t('records.owner'), sortable: true, render: (r) => <span className="font-mono text-xs" title={r.name}>{relativeName(r.name, zone.name)}</span> },
    { key: 'rtype', label: t('records.type'), sortable: true, render: (r) => <Badge variant={isEditableType(r.rtype) ? 'primary' : 'gray'} size="sm">{r.rtype}</Badge> },
    { key: 'ttl', label: t('records.ttl'), sortable: true, mono: true, align: 'right' },
    {
      key: 'rdata',
      label: t('records.rdata'),
      changeValue: (r) => (r.rdata || []).join('\n'),
      render: (r) => (
        <div className="font-mono text-xs space-y-0.5 break-all">
          {r.rdata.map((d, i) => (
            <div key={i}>{d}</div>
          ))}
        </div>
      ),
    },
    { key: 'actions', label: '', align: 'right', render: actions },
  ]
  const columns = isMobile ? mobileColumns : desktopColumns

  return (
    <>
      {mode === 'static' && (
        <p className="mb-3 flex items-start gap-2 rounded-lg border border-border-op50 p-3 text-xs text-text-secondary" data-testid="zone-static-note">
          <FileText size={14} className="shrink-0 mt-0.5 text-accent-primary" />
          {t('detail.staticNote')}
        </p>
      )}
      <ZoneSerialTrace zone={zone} view={view} status={status} nameOf={nameOf} />
      <DataTable
        columns={columns}
        rows={records.items}
        rowKey={(r) => `${r.name}/${r.rtype}`}
        animateInserts
        animateRemovals
        highlightChanges={['ttl', 'rdata']}
        loading={records.loading && !records.data}
        error={records.error}
        onRetry={records.refetch}
        clientSort
        dense
        search={{ value: q, onChange: setQ, placeholder: t('records.search') }}
        filters={[
          { key: 'type', label: t('records.type'), value: type, onChange: setType, options: [...EDITABLE_TYPES, ...READ_ONLY_TYPES].map((x) => ({ value: x, label: x })) },
        ]}
        toolbar={
          <>
            {records.meta?.serial !== undefined && (
              <span className="text-2xs text-text-tertiary font-mono mr-2">
                {t('records.readFrom', { serial: records.meta.serial })}
              </span>
            )}
            {editable && (
              <Button size="sm" onClick={() => open('add')} data-testid="record-add">
                <Plus size={14} />
                {t('records.add')}
              </Button>
            )}
          </>
        }
        pagination={{ page: records.page, perPage: records.perPage, total: records.total, onPageChange: records.setPage, onPerPageChange: records.setPerPage }}
        emptyTitle={t('records.empty')}
        testId="records-table"
      />
      {editor && (
        <RecordEditor
          open
          zone={zone.name}
          view={view}
          mode={editor.mode}
          rrset={editor.rrset}
          onClose={() => setEditor(null)}
          onApplied={done}
          onCommitted={committed}
        />
      )}
      {rollbackOf && (
        <PlanPreviewModal open plan={rollbackOf} autoRollback onClose={() => setRollbackOf(null)} onRolledBack={done} />
      )}
    </>
  )
}

// The secondaries of a primary: one box per BIND node; the plan adds and drops copies and
// sets the primary's also-notify to the nodes kept.
function SecondariesCard({ choice, nameOf, onPlan, busy }) {
  const { t } = useTranslation(['dns', 'common'])
  const [picked, setPicked] = useState(() => new Set(choice.current))
  const key = choice.current.join(',')
  useEffect(() => setPicked(new Set(key ? key.split(',') : [])), [key])
  const changed = picked.size !== choice.current.length || choice.current.some((id) => !picked.has(id))
  const toggle = (id) =>
    setPicked((cur) => {
      const next = new Set(cur)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="zone-secondaries">
      <div className="flex flex-wrap items-center gap-2">
        <span className="ui-card-title text-sm font-semibold text-text-primary">{t('detail.secondaries.title')}</span>
        <span className="text-xs text-text-tertiary">{t('detail.secondaries.primaryOn', { node: nameOf(choice.primary) })}</span>
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-2">
        {choice.candidates.map((id) => (
          <label key={id} className="flex items-center gap-2 text-xs text-text-primary cursor-pointer">
            <input type="checkbox" checked={picked.has(id)} onChange={() => toggle(id)} data-testid={`zone-secondary-${id}`} />
            <span className="font-mono">{nameOf(id)}</span>
          </label>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button size="xs" variant="secondary" disabled={!changed || busy} onClick={() => onPlan([...picked])} data-testid="zone-secondaries-plan">
          {t('detail.secondaries.plan')}
        </Button>
        <span className="text-2xs text-text-tertiary">{t('detail.secondaries.hint')}</span>
      </div>
    </Card>
  )
}

function StatusTab({ status, copies, nameOf, zone, canOps, onRetransfer, busyNode, choice, canPlan, onSecondaries, planning }) {
  const { t } = useTranslation(['dns', 'common'])
  // Only the nodes that hold the zone have a status worth a card.
  const entries = Object.entries(status || {}).filter(([id, s]) => !copies || id in copies || !s.error)
  const serials = Object.fromEntries(entries.map(([id, s]) => [id, s.serial]))
  const lag = new Set(laggingNodes(serials))
  const catching = useCatchUps(serials)
  const primary = choice?.primary
  const secondaries = entries.filter(([id, s]) => id !== primary && (copies?.[id]?.kind || s.kind) === 'secondary')
  if (!entries.length) return <EmptyState icon={HardDrives} title={t('detail.noStatus')} />
  return (
    <div className="space-y-4">
      {primary && secondaries.length > 0 && (
        <Card className="p-3 space-y-1.5" hover={false} data-testid="zone-transfers">
          <p className="text-2xs text-text-tertiary">{t('detail.secondaries.transfers', { node: nameOf(primary) })}</p>
          {secondaries.map(([id, s]) => (
            <div key={id} className="grid grid-cols-[minmax(0,6rem)_minmax(0,1fr)_minmax(0,9rem)] items-center gap-3 text-xs" data-testid="zone-transfer-row" data-node={id}>
              <span className="font-mono text-text-secondary truncate">{nameOf(primary)}</span>
              <span className="relative block h-3 border-b border-border" aria-hidden="true">
                <TransferBar run={catching.has(id) ? s.serial || 1 : 0} tone="dns" label={catching.has(id) ? String(s.serial) : undefined} />
              </span>
              <span className="flex items-center gap-2 min-w-0">
                <span className="font-mono text-text-primary truncate">{nameOf(id)}</span>
                {s.error ? <StatusBadge status="error" /> : lag.has(id) ? <StatusBadge status="divergent" /> : <StatusBadge status="in-sync" />}
              </span>
            </div>
          ))}
        </Card>
      )}
      {choice && canPlan && <SecondariesCard choice={choice} nameOf={nameOf} onPlan={onSecondaries} busy={planning} />}
      <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-4" data-testid="zone-status">
      {entries.map(([id, s]) => (
        <Card key={id} className="p-4 space-y-3" hover={false}>
          <div className="flex items-center gap-2">
            <HardDrives size={16} className="text-accent-primary" />
            <span className="font-semibold text-sm text-text-primary">{nameOf(id)}</span>
            {s.error ? <StatusBadge status="error" /> : lag.has(id) ? <StatusBadge status="divergent" /> : <StatusBadge status="in-sync" />}
            {canOps && SECONDARY_KINDS.includes(zone.kind) && (
              <Button variant="secondary" size="xs" className="ml-auto" loading={busyNode === id} onClick={() => onRetransfer(id)} data-testid="zone-retransfer">
                <DownloadSimple size={12} />
                {t('detail.retransfer')}
              </Button>
            )}
          </div>
          {s.error && <p className="text-xs status-danger-text font-mono">{s.error}</p>}
          <dl className="grid grid-cols-2 gap-3">
            <KeyValue label={t('detail.serial')} mono>
              {s.serial === null || s.serial === undefined ? t('zones.noSerial') : <TransferSerial value={s.serial} transfer={catching.has(id)} testId="zone-status-serial" />}
            </KeyValue>
            <KeyValue label={t('detail.configSerial')} mono>
              {s.config_serial === null || s.config_serial === undefined ? null : <TransferSerial value={s.config_serial} transfer={catching.has(id)} />}
            </KeyValue>
            <KeyValue label={t('zones.kind')}>{s.kind ? t(`kind.${s.kind}`, { defaultValue: s.kind }) : null}</KeyValue>
            <KeyValue label={t('zones.dynamic')}>{s.dynamic === null || s.dynamic === undefined ? null : t(`common:common.${s.dynamic ? 'yes' : 'no'}`)}</KeyValue>
            <KeyValue label={t('zones.signed')}>{s.signed === null || s.signed === undefined ? null : t(`common:common.${s.signed ? 'yes' : 'no'}`)}</KeyValue>
            <KeyValue label={t('detail.lastLoaded')}>{s.last_loaded ? formatDate(s.last_loaded) : null}</KeyValue>
            {s.next_refresh && <KeyValue label={t('detail.nextRefresh')}>{formatDate(s.next_refresh)}</KeyValue>}
            {s.expires && <KeyValue label={t('detail.expires')}>{formatDate(s.expires)}</KeyValue>}
            <KeyValue label={t('detail.files')} mono>{s.files?.length ? s.files.join(', ') : null}</KeyValue>
            <KeyValue label={t('detail.collectedAt')}>{formatDate(s.collected_at)}</KeyValue>
          </dl>
        </Card>
      ))}
      </div>
    </div>
  )
}

function ConfigTab({ zone }) {
  const { t } = useTranslation(['dns', 'common'])
  const extra = Object.entries(zone.extra || {})
  return (
    <Card className="p-4" hover={false} data-testid="zone-config">
      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <KeyValue label={t('zones.name')} mono>{zone.name}</KeyValue>
        <KeyValue label={t('zones.kind')}>{t(`kind.${zone.kind}`, { defaultValue: zone.kind })}</KeyValue>
        <KeyValue label={t('zones.view')} mono>{zone.view}</KeyValue>
        <KeyValue label={t('detail.class')} mono>{zone.rclass}</KeyValue>
        <KeyValue label={t('detail.file')} mono>{zone.file}</KeyValue>
        <KeyValue label={t('zones.source')}>
          <SourceBadge source={zone.source} />
        </KeyValue>
        <KeyValue label={t('detail.configPath')} mono>{zone.config_path}</KeyValue>
        <KeyValue label={t('zones.dynamic')}>{t(`common:common.${zone.dynamic ? 'yes' : 'no'}`)}</KeyValue>
        <KeyValue label={t('detail.dnssecPolicy')} mono>{zone.dnssec_policy}</KeyValue>
        <KeyValue label={t('zones.primaries')}>
          <ListValue items={zone.primaries} />
        </KeyValue>
        <KeyValue label={t('detail.alsoNotify')}>
          <ListValue items={zone.also_notify} />
        </KeyValue>
        <KeyValue label={t('detail.allowTransfer')}>
          <ListValue items={zone.allow_transfer} />
        </KeyValue>
        <KeyValue label={t('detail.allowUpdate')}>
          <ListValue items={zone.allow_update} />
        </KeyValue>
        <KeyValue label={t('detail.updatePolicy')}>
          <ListValue items={zone.update_policy} />
        </KeyValue>
        <KeyValue label={t('resolver.forwarders')}>
          <ListValue items={zone.forwarders} />
        </KeyValue>
        {zone.forward && <KeyValue label={t('resolver.forward')} mono>{zone.forward}</KeyValue>}
        {zone.notes && <KeyValue label={t('detail.notes')}>{zone.notes}</KeyValue>}
      </dl>
      {extra.length > 0 && (
        <div className="mt-4 pt-4 border-t border-border-op50">
          <p className="text-2xs uppercase tracking-wider text-text-tertiary mb-2">{t('detail.extra')}</p>
          <pre className="text-xs font-mono text-text-secondary whitespace-pre-wrap">
            {extra.map(([k, v]) => `${k} ${v};`).join('\n')}
          </pre>
        </div>
      )}
    </Card>
  )
}

export default function ZoneDetailPage() {
  const zoneParam = zoneFromSegment(useParams().zone)
  const [search] = useSearchParams()
  const view = search.get('view') || undefined
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const { nameOf, nodes } = useNodeNames()
  const [tab, setTab] = useState('records')
  const [busy, setBusy] = useState(null)
  const { data, error, loading, refetch, setData } = useApi(() => api.dns.zone(zoneParam, view), [zoneParam, view])
  const zone = data?.zone
  // Serials move on their own (transfers, other operators): the status is read again quietly.
  usePoll(async () => setData(await api.dns.zone(zoneParam, view)), ZONE_POLL_MS, { enabled: Boolean(data) })
  // After a plan here the secondaries catch up within seconds: one more read shows the transfer land.
  const zoneName = data?.zone?.name
  useEffect(() => {
    if (!zoneName) return undefined
    const timers = new Set()
    const off = onPlanEvent((event) => {
      if (planZone(event.plan) !== zoneName || (event.type !== 'applied' && event.type !== 'rolled-back')) return
      const timer = setTimeout(() => {
        timers.delete(timer)
        api.dns.zone(zoneParam, view).then(setData).catch(() => {})
      }, TRANSFER_REREAD_MS)
      timers.add(timer)
    })
    return () => {
      off()
      timers.forEach(clearTimeout)
    }
  }, [zoneName, zoneParam, view, setData])
  useZoneEvents(zoneName, zone?.view, () => api.dns.zone(zoneParam, view).then(setData).catch(() => {}))
  const [deleted, setDeleted] = useState(false)
  const [editing, setEditing] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [deletePeers, setDeletePeers] = useState(true)
  const { node: selfNode } = useAuth()
  const peers = useMemo(() => secondaryPeers(data, selfNode?.id), [data, selfNode])
  const mode = data ? zoneMode(data) : null
  const views = data?.views || []
  const flow = usePlanFlow({
    // After a zone deletion the plan stays on screen for rollback; closing it leaves the page.
    onDone: (res) => {
      if (flow.plan?.scope === 'dns.zone' && flow.plan?.changes?.[0]?.op === 'delete') setDeleted(res?.state === 'applied')
      else {
        refetch()
        handover.refetch()
      }
    },
    onClose: () => {
      if (deleted) {
        clearLists('zones')
        navigate('/dns/zones')
      }
    },
    onError: showError,
  })

  const handover = useApi(() => (hasPermission('write:dns.config') ? api.dns.handover().catch(() => ({ items: [] })) : Promise.resolve({ items: [] })), [])
  const handoverItem = zone?.source === 'user_conf' ? zoneHandover(handover.data, zone) : null
  const handOverZone = () => flow.run(() => api.dns.configPlan(handoverChanges([handoverItem]), handoverItem.nodes))
  const canOps = hasPermission('ops:dns')
  const editable = Boolean(zone) && zone.kind === 'primary' && hasPermission('write:dns.records')
  const viewArg = view ? { view } : {}

  const op = async (name, fn) => {
    setBusy(name)
    try {
      const res = await fn()
      showSuccess(res?.output || t('detail.opDone'))
      refetch()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const tabs = useMemo(
    () => [
      { id: 'records', label: t('detail.tabs.records'), icon: TableIcon },
      { id: 'status', label: t('detail.tabs.status'), icon: HardDrives, count: Object.keys(data ? zoneCopies(data) : {}).length },
      { id: 'config', label: t('detail.tabs.config'), icon: Gear },
    ],
    [t, data],
  )

  // Peers holding the zone as a secondary of this node lose their copy too, unless unticked.
  const deleteZone = () => {
    setConfirmDelete(false)
    const { change, node_ids } = zoneDeleteRequest(zone, deletePeers ? peers : [])
    flow.run(() => api.dns.zonePlan(change, node_ids))
  }
  const askDelete = () => {
    if (!peers.length) return deleteZone()
    setDeletePeers(true)
    setConfirmDelete(true)
  }
  // The security audit's remediation: a Job that rewrites the zone statement with an update-policy.
  const convertZone = () => flow.run(() => api.install.securityPlan([staticFindingId(zone)]))
  const switchView = (v) => navigate(zoneHref(zoneParam, v))

  return (
    <PageLayout
      icon={Globe}
      title={zone?.name || absZone(zoneParam)}
      mobileTitle
      literalTitle
      breadcrumb={{ label: t('pages.zones.title'), to: '/dns/zones' }}
      sharedTitle={{ name: 'zone-title', to: '/dns/zones' }}
      subtitle={t('pages.zoneDetail.subtitle')}
      badge={
        zone && (
          <span className="inline-flex items-center gap-1.5">
            <StatusBadge status={zone.kind} label={t(`kind.${zone.kind}`, { defaultValue: zone.kind })} dot={false} />
            <ModeBadge mode={mode} />
            <FailoverBadge zone={zone} />
          </span>
        )
      }
      tabs={zone ? tabs : undefined}
      activeTab={tab}
      onTabChange={setTab}
      testId="page-dns-zoneDetail"
      actions={
        zone && (
          <>
            {views.length > 1 && (
              <Select size="sm" variant="filter" value={zone.view} onChange={switchView} options={views.map((v) => ({ value: v, label: `${t('common:fieldLabel', { label: t('detail.view') })} ${v}` }))} data-testid="zone-view-select" />
            )}
            {editableZone(zone) && hasPermission('write:dns.zones') && (
              <Button variant="secondary" size="sm" onClick={() => setEditing(true)} data-testid="zone-edit-open">
                <PencilSimple size={14} />
                {t('detail.edit')}
              </Button>
            )}
            {handoverItem && (
              <Button variant="secondary" size="sm" onClick={handOverZone} loading={flow.busy} data-testid="zone-handover" title={t('handover.zoneHelp')}>
                <HandGrabbing size={14} />
                {t('handover.zone')}
              </Button>
            )}
            {hasPermission('write:dns.zones') && (
              <Button variant="danger-soft" size="sm" onClick={askDelete} loading={flow.busy} data-testid="zone-delete">
                <Trash size={14} />
                {t('detail.deleteZone')}
              </Button>
            )}
            <Dropdown
              size="sm"
              trigger={<DotsThree size={16} weight="bold" />}
              triggerProps={{ 'aria-label': t('detail.more'), title: t('detail.more'), 'data-testid': 'zone-more' }}
              items={[
                ...(mode === 'static' && hasPermission('admin:install')
                  ? [{ id: 'convert', label: t('detail.convert'), icon: <Lightning size={14} />, onClick: convertZone, disabled: flow.busy, testId: 'zone-convert' }]
                  : []),
                ...(zone.dnssec_policy
                  ? [{ id: 'dnssec', label: t('nav.dnssec'), icon: <ShieldCheck size={14} />, onClick: () => navigate(`/dns/dnssec?zone=${encodeURIComponent(zone.name)}`), testId: 'zone-dnssec' }]
                  : []),
                ...(canOps && zone.kind === 'primary'
                  ? [{ id: 'notify', label: t('detail.notify'), icon: <Bell size={14} />, onClick: () => op('notify', () => api.dns.notify(zone.name, viewArg)), disabled: busy === 'notify', testId: 'zone-notify' }]
                  : []),
                ...(canOps && zone.kind !== 'forward'
                  ? [{ id: 'reload', label: t('detail.reload'), icon: <ArrowClockwise size={14} />, onClick: () => op('reload', () => api.dns.reload(zone.name, viewArg)), disabled: busy === 'reload', testId: 'zone-reload' }]
                  : []),
                { id: 'refresh', label: t('common:actions.refresh'), icon: <ArrowsClockwise size={14} />, onClick: refetch, disabled: loading, testId: 'zone-refresh' },
              ]}
            />
          </>
        )
      }
    >
      {loading && !data ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="md" />
        </div>
      ) : error ? (
        <EmptyState icon={Globe} title={errorMessage(error)} action={{ label: t('common:actions.retry'), onClick: refetch }} />
      ) : zone ? (
        <>
          {tab === 'records' && <RecordsTab zone={zone} view={view} editable={editable} mode={mode} onChanged={refetch} status={data.status} nameOf={nameOf} />}
          {tab === 'status' && (
            <StatusTab
              status={data.status}
              copies={data.copies ? zoneCopies(data) : null}
              choice={zone.kind === 'primary' ? secondaryChoice(data, nodes) : null}
              canPlan={hasPermission('write:dns.zones')}
              planning={flow.busy}
              onSecondaries={(ids) => flow.run(() => api.dns.secondariesPlan(zone.name, view, ids))}
              nameOf={nameOf}
              zone={zone}
              canOps={canOps}
              busyNode={busy}
              onRetransfer={(nodeId) => op(nodeId, () => api.dns.retransfer(zone.name, nodeId, view))}
            />
          )}
          {tab === 'config' && <ConfigTab zone={zone} />}
        </>
      ) : null}
      {editing && zone && (
        <ZoneEditModal
          open
          zone={zone}
          onClose={() => setEditing(false)}
          onPlan={async (change) => {
            const plan = await flow.run(() => api.dns.zonePlan(change))
            if (plan) setEditing(false)
          }}
        />
      )}
      {confirmDelete && zone && (
        <ConfirmDialog
          open
          onOpenChange={(o) => !o && setConfirmDelete(false)}
          onConfirm={deleteZone}
          title={t('detail.deleteTitle', { zone: zone.name })}
          message={t('detail.deleteMessage')}
          confirmLabel={t('detail.deleteZone')}
        >
          <label className="flex items-start gap-2 text-xs text-text-primary cursor-pointer">
            <input type="checkbox" className="mt-0.5" checked={deletePeers} onChange={(e) => setDeletePeers(e.target.checked)} data-testid="zone-delete-peers" />
            <span>
              {t('detail.deletePeers', { nodes: peers.map(nameOf).join(', ') })}
              <span className="block text-text-secondary">{t('detail.deletePeersHelp')}</span>
            </span>
          </label>
        </ConfirmDialog>
      )}
      {flow.modal}
    </PageLayout>
  )
}
