// SPDX-License-Identifier: Apache-2.0
// One zone: RRset table with the record editor, status on every node (rndc
// zonestatus + SOA query), the zone statement as configured, the rndc operations
// (notify, reload, retransfer), the zone edit and deletion plans, the view selector
// for a zone present in several views and the conversion of a static zone.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams, useSearchParams, Link } from 'react-router-dom'
import { Globe, ArrowsClockwise, Plus, PencilSimple, Trash, Bell, ArrowClockwise, ShieldCheck, Table as TableIcon, HardDrives, Gear, DownloadSimple, Lightning, FileText } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { StatusBadge } from '../../components/StatusBadge'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { EmptyState } from '../../components/EmptyState'
import { Badge } from '../../components/Badge'
import { useApi, usePaginatedApi } from '../../hooks/useApi'
import { useMobile } from '../../contexts/MobileContext'
import { Select } from '../../components/ui/Select'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { KeyValue, ListValue, ModeBadge, SourceBadge } from './common'
import { useNodeNames, usePlanFlow, laggingNodes, SECONDARY_KINDS } from './helpers'
import { RecordEditor } from './RecordEditor'
import { EDITABLE_TYPES, READ_ONLY_TYPES, absZone, isEditableType, relativeName } from './records'
import { ZoneEditModal } from './ZoneEditModal'
import { editableZone, staticFindingId, zoneMode } from './zoneTools'

function RecordsTab({ zone, view, editable, mode, onChanged }) {
  const { t } = useTranslation(['dns', 'common'])
  const { isMobile } = useMobile()
  const [type, setType] = useState('')
  const [q, setQ] = useState('')
  const [editor, setEditor] = useState(null)
  const filters = { type: type || undefined, q: q || undefined, view: view || undefined }
  const records = usePaginatedApi((params) => api.dns.records(zone.name, params), { perPage: 50, filters })

  const open = (mode, rrset = null) => setEditor({ mode, rrset })
  const done = () => {
    records.refetch()
    onChanged?.()
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
      <DataTable
        columns={columns}
        rows={records.items}
        rowKey={(r) => `${r.name}/${r.rtype}`}
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
        />
      )}
    </>
  )
}

function StatusTab({ status, nameOf, zone, canOps, onRetransfer, busyNode }) {
  const { t } = useTranslation(['dns', 'common'])
  const entries = Object.entries(status || {})
  const serials = Object.fromEntries(entries.map(([id, s]) => [id, s.serial]))
  const lag = new Set(laggingNodes(serials))
  if (!entries.length) return <EmptyState icon={HardDrives} title={t('detail.noStatus')} />
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4" data-testid="zone-status">
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
            <KeyValue label={t('detail.serial')} mono>{s.serial ?? t('zones.noSerial')}</KeyValue>
            <KeyValue label={t('detail.configSerial')} mono>{s.config_serial}</KeyValue>
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
  const { zone: zoneParam } = useParams()
  const [search] = useSearchParams()
  const view = search.get('view') || undefined
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const { nameOf } = useNodeNames()
  const [tab, setTab] = useState('records')
  const [busy, setBusy] = useState(null)
  const { data, error, loading, refetch } = useApi(() => api.dns.zone(zoneParam, view), [zoneParam, view])
  const zone = data?.zone
  const [deleted, setDeleted] = useState(false)
  const [editing, setEditing] = useState(false)
  const mode = data ? zoneMode(data) : null
  const views = data?.views || []
  const flow = usePlanFlow({
    // After a zone deletion the plan stays on screen for rollback; closing it leaves the page.
    onDone: (res) => {
      if (flow.plan?.scope === 'dns.zone' && flow.plan?.changes?.[0]?.op === 'delete') setDeleted(res?.state === 'applied')
      else refetch()
    },
    onClose: () => {
      if (deleted) navigate('/dns/zones')
    },
    onError: showError,
  })

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
      { id: 'status', label: t('detail.tabs.status'), icon: HardDrives, count: Object.keys(data?.status || {}).length },
      { id: 'config', label: t('detail.tabs.config'), icon: Gear },
    ],
    [t, data],
  )

  const deleteZone = () =>
    flow.run(() =>
      api.dns.zonePlan({ op: 'delete', target: `${zone.view}/${zone.name}`, before: zone, after: null, node_ids: [] }),
    )
  // The security audit's remediation: a Job that rewrites the zone statement with an update-policy.
  const convertZone = () => flow.run(() => api.install.securityPlan([staticFindingId(zone)]))
  const switchView = (v) => navigate(`/dns/zones/${encodeURIComponent(zoneParam)}${v && v !== '_default' ? `?view=${encodeURIComponent(v)}` : ''}`)

  return (
    <PageLayout
      icon={Globe}
      title={zone?.name || absZone(zoneParam)}
      mobileTitle
      subtitle={t('pages.zoneDetail.subtitle')}
      badge={
        zone && (
          <span className="inline-flex items-center gap-1.5">
            <StatusBadge status={zone.kind} label={t(`kind.${zone.kind}`, { defaultValue: zone.kind })} dot={false} />
            <ModeBadge mode={mode} />
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
              <Select size="sm" variant="filter" value={zone.view} onChange={switchView} options={views.map((v) => ({ value: v, label: `${t('detail.view')}: ${v}` }))} data-testid="zone-view-select" />
            )}
            {mode === 'static' && hasPermission('admin:install') && (
              <Button variant="warning-soft" size="sm" onClick={convertZone} loading={flow.busy} data-testid="zone-convert">
                <Lightning size={14} />
                {t('detail.convert')}
              </Button>
            )}
            {editableZone(zone) && hasPermission('write:dns.zones') && (
              <Button variant="secondary" size="sm" onClick={() => setEditing(true)} data-testid="zone-edit-open">
                <PencilSimple size={14} />
                {t('detail.edit')}
              </Button>
            )}
            {zone.dnssec_policy && (
              <Link to={`/dns/dnssec?zone=${encodeURIComponent(zone.name)}`}>
                <Button variant="secondary" size="sm">
                  <ShieldCheck size={14} />
                  {t('nav.dnssec')}
                </Button>
              </Link>
            )}
            {canOps && zone.kind === 'primary' && (
              <Button variant="secondary" size="sm" loading={busy === 'notify'} onClick={() => op('notify', () => api.dns.notify(zone.name, viewArg))} data-testid="zone-notify">
                <Bell size={14} />
                {t('detail.notify')}
              </Button>
            )}
            {canOps && zone.kind !== 'forward' && (
              <Button variant="secondary" size="sm" loading={busy === 'reload'} onClick={() => op('reload', () => api.dns.reload(zone.name, viewArg))} data-testid="zone-reload">
                <ArrowClockwise size={14} />
                {t('detail.reload')}
              </Button>
            )}
            <Button variant="secondary" size="sm" onClick={refetch} disabled={loading}>
              <ArrowsClockwise size={14} />
              {t('common:actions.refresh')}
            </Button>
            {hasPermission('write:dns.zones') && (
              <Button variant="danger-soft" size="sm" onClick={deleteZone} loading={flow.busy} data-testid="zone-delete">
                <Trash size={14} />
                {t('detail.deleteZone')}
              </Button>
            )}
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
          {tab === 'records' && <RecordsTab zone={zone} view={view} editable={editable} mode={mode} onChanged={refetch} />}
          {tab === 'status' && (
            <StatusTab
              status={data.status}
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
      {flow.modal}
    </PageLayout>
  )
}
