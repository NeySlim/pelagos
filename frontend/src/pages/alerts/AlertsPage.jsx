// SPDX-License-Identifier: Apache-2.0
// Alerts and inconsistencies: counts from GET /alerts/summary, the filtered and
// paginated alert list (open by default, filters and free-text search in the URL), the alert detail
// with a link to the host or zone it is about, acknowledgement with an optional
// comment, and an on-demand consistency pass run as a job. The list and counts are the cluster's:
// each alert names its node (or the nodes reporting a cluster-wide one), and a node whose alerts
// could not be read is named above the table. /alerts?alert=<id> (the link of notification
// messages) opens that alert whatever the filters; a notification mute is shown above the table.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMessage } from '../../i18n/message'
import { Bell, ArrowsClockwise, CheckCircle, MagnifyingGlass, Warning, WarningOctagon, Info, ArrowSquareOut, EyeSlash, SpeakerSlash, PaperPlaneTilt } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge, StatusBadge, Modal, JsonTree } from '../../components'
import { RichStatsBar } from '../../components/ui/RichStatsBar'
import { useApi, usePaginatedApi, useWsTopic } from '../../hooks'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { ENGINES, INCONSISTENCY_KINDS, KINDS, alertOrigin, unavailableNodes, exceptionItems, PRESSURE_AFTER_MS, PRESSURE_BEFORE_MS, SEVERITIES, STATES, findAlert, jobResult, poolSeriesQuery, pressureLatches, proposesFallback, subjectLink } from './lib'
import { adoptCall, fileAlertEngine } from '../dhcp/keaFile'
import { notificationsOfAlert } from '../admin/notifications/notifyForm'
import { IncidentTrace } from '../../components/motion'
import { IgnoreDialog } from './IgnoreDialog'

import { useNodeNames, usePlanFlow } from '../dhcp/hooks'

const FILTERS = ['state', 'severity', 'kind', 'engine', 'node_id', 'q']
const JOB_POLL_MS = 1000
const JOB_TIMEOUT_MS = 120000

// The node an alert belongs to, or "Cluster" with the nodes that report it.
function AlertOrigin({ alert, nodeName }) {
  const { t } = useTranslation('alerts')
  const { node, reporters } = alertOrigin(alert)
  if (node) {
    return <Badge variant="outline" size="sm" data-testid="alert-origin">{nodeName(node)}</Badge>
  }
  const names = reporters.map(nodeName).join(', ')
  return (
    <span className="inline-flex items-center gap-1 min-w-0" title={names ? t('origin.clusterHelp', { nodes: names }) : undefined} data-testid="alert-origin">
      <Badge variant="purple" size="sm">{t('origin.cluster')}</Badge>
      {names && <span className="text-2xs text-text-tertiary truncate">{t('origin.via', { nodes: names })}</span>}
    </span>
  )
}

function UnavailableNotice({ nodes }) {
  const { t } = useTranslation('alerts')
  if (!nodes.length) return null
  return (
    <div role="status" className="rounded-lg border status-warning-bg status-warning-border px-3 py-2 text-xs status-warning-text" data-testid="alerts-unavailable">
      <p className="font-semibold">{t('unavailable.title')}</p>
      <p className="text-text-secondary">{t('unavailable.body', { nodes: nodes.map((n) => n.name || n.node_id).join(', '), error: nodes.map((n) => n.error).filter(Boolean).join('; ') || '-' })}</p>
    </div>
  )
}

// Notifications mute (admins of notifications only: the overview needs admin:notifications).
function MuteNotice() {
  const { t } = useTranslation('alerts')
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const allowed = hasPermission('admin:notifications')
  const overview = useApi(() => (allowed ? api.notifications.overview().catch(() => null) : Promise.resolve(null)), [allowed])
  const mute = overview.data?.mute
  if (!mute) return null
  return (
    <div role="status" className="flex flex-wrap items-center gap-2 rounded-lg border status-warning-bg status-warning-border px-3 py-2 text-xs" data-testid="alerts-notify-muted">
      <SpeakerSlash size={14} className="status-warning-text" />
      <span className="flex-1 min-w-0 text-text-primary">{t('notify.muted', { until: formatDate(mute.until), by: mute.by || '-', comment: mute.comment })}</span>
      <Button size="xs" variant="ghost" onClick={() => navigate('/admin/notifications')}>{t('notify.manage')}</Button>
    </div>
  )
}

// "Notified at 10:32 by ntfy, e-mail": the sent batches of the history that carry this alert.
function AlertNotified({ alert }) {
  const { t } = useTranslation('alerts')
  const { hasPermission } = usePermission()
  const allowed = hasPermission('admin:notifications')
  const q = useApi(
    () =>
      allowed
        ? Promise.all([
            api.notifications.history({ alert_id: alert.id, result: 'ok', per_page: 100 }),
            api.notifications.overview(),
          ]).catch(() => null)
        : Promise.resolve(null),
    [allowed, alert.id, alert.last_seen],
  )
  if (!q.data) return null
  const [history, overview] = q.data
  const sent = notificationsOfAlert(history?.items, alert.id)
  const names = Object.fromEntries((overview?.channels || []).map((c) => [c.id, c.name]))
  const channels = [...new Set(sent.map((h) => names[h.channel_id] || h.channel_id))]
  const last = sent.map((h) => h.ts).sort().at(-1)
  return (
    <p className="flex items-center gap-1.5 text-xs text-text-secondary" data-testid="alert-notified" data-count={sent.length}>
      <PaperPlaneTilt size={12} />
      {sent.length ? t('notify.notified', { when: formatDate(last), channels: channels.join(', ') }) : t('notify.notNotified')}
    </p>
  )
}

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className="text-xs text-text-primary break-all">{children || '-'}</dd>
    </div>
  )
}

// A Kea file alert (section 9) is settled by adopting one side; the node that holds the file
// builds the plan, whichever node the user is on.
function FileAdoptActions({ alert }) {
  const { t } = useTranslation('alerts')
  const { hasPermission } = usePermission()
  const { nodes, nameOf } = useNodeNames()
  const flow = usePlanFlow()
  const engine = fileAlertEngine(alert)
  if (!engine || alert.state === 'resolved' || !hasPermission('write:dhcp.config')) return null
  const selfId = nodes.find((n) => n.is_self)?.peer?.id
  const target = selfId && alert.node_id && alert.node_id !== selfId ? alert.node_id : undefined
  return (
    <>
      {target && <p className="text-2xs text-text-tertiary self-center" data-testid="alert-adopt-node">{t('actions.adoptOn', { node: nameOf(target) })}</p>}
      <Button variant="secondary" size="sm" disabled={flow.building} onClick={() => flow.build(() => adoptCall(engine, 'file', target))} data-testid="alert-adopt-file">
        {t('actions.adoptFile')}
      </Button>
      <Button variant="secondary" size="sm" disabled={flow.building} onClick={() => flow.build(() => adoptCall(engine, 'running', target))} data-testid="alert-adopt-running">
        {t('actions.adoptRunning')}
      </Button>
      {flow.modal}
    </>
  )
}

const POOL_KINDS = new Set(['pool_near_full', 'pool_full'])
// The pool's use over the incident against the fixed thresholds, with its latches.
function DistroDataNotice({ alert }) {
  const { t } = useTranslation('alerts')
  const gone = alert.kind === 'security_advisory' ? alert.details?.distribution_data?.unavailable : null
  if (!gone) return null
  return (
    <p className="text-xs rounded-lg border border-border bg-bg-secondary p-2" data-testid="distro-data-unavailable">
      {t('detail.distroUnavailable', { since: formatDate(gone.since), reason: gone.reason })}
    </p>
  )
}

function AlertPressure({ alert }) {
  const { t } = useTranslation(['alerts', 'common'])
  const query = poolSeriesQuery(alert)
  const opened = Date.parse(alert.first_seen)
  // A resolved incident shows what followed, up to the present at most.
  const end = alert.resolved_at ? Math.min(Date.now(), Date.parse(alert.resolved_at) + PRESSURE_AFTER_MS) : null
  const series = useApi(
    () =>
      query
        ? Promise.all([
            api.series.pools({ engine: query.engine, subnet_id: query.subnet_id, node_id: query.node_id, from: new Date(opened - PRESSURE_BEFORE_MS).toISOString(), to: new Date(end ?? Date.now()).toISOString(), step: 300 }),
            api.dashboard.summary().catch(() => null),
          ])
        : Promise.resolve(null),
    [alert.id, alert.state, alert.last_seen],
  )
  if (!query || !series.data) return null
  const [res, summary] = series.data
  const match = (res?.series || []).find((s) => [query.pool, query.raw].includes(s.key?.pool)) || res?.series?.[0]
  const points = (match?.points || []).filter((p) => p[2] > 0).map(([ts, assigned, total]) => [ts * 1000, (assigned / total) * 100])
  if (points.length < 2) return null
  const th = summary?.thresholds || {}
  const warn = Number(th.pool_warning_percent ?? 80)
  const full = Number(th.pool_critical_percent ?? 95)
  const threshold = alert.kind === 'pool_full' ? full : warn
  const values = points.map((p) => p[1])
  const min = Math.max(0, Math.floor((Math.min(...values, warn) - 10) / 10) * 10)
  return (
    <div data-testid="alert-pressure">
      <div className="fx-trace-head">
        <b>{t('detail.pressure')}</b>
        <span className="font-mono">{query.raw}</span>
      </div>
      <IncidentTrace
        points={points}
        from={opened - PRESSURE_BEFORE_MS}
        to={end ?? undefined}
        min={min}
        max={105}
        thresholds={[
          { value: warn, label: `${warn}`, tone: 'warning' },
          { value: full, label: `${full}`, tone: 'danger' },
          ...(full < 100 ? [{ value: 100, label: t('detail.full'), tone: 'danger' }] : []),
        ]}
        latches={pressureLatches(alert, points, threshold)}
      />
    </div>
  )
}

function AlertDetail({ alert, nodeName, canAck, onAck, onIgnore, onClose }) {
  const { t } = useTranslation(['alerts', 'dashboard', 'common'])
  const msg = useMessage()
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  // Propose the fallback only to who can plan it, and only while none is active.
  const proposing = proposesFallback(alert) && hasPermission('write:dns.config')
  const resolver = useApi(() => api.resolverHealth.health(), [alert?.id], { enabled: proposing })
  const canProposeFallback = proposing && Boolean(resolver.data) && !resolver.data.fallback
  const link = alert ? subjectLink(alert, { canProposeFallback }) : null
  return (
    <Modal open={Boolean(alert)} onClose={onClose} title={(alert && msg(alert.title_message, alert.title)) || t('detail.title')}>
      {alert && (
        <div className="p-4 space-y-4" data-testid="alert-detail">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={alert.severity} />
            <StatusBadge status={alert.state} dot={false} />
            <Badge variant="outline" size="sm">{t(`dashboard:kinds.${alert.kind}`, { defaultValue: alert.kind })}</Badge>
            {INCONSISTENCY_KINDS.has(alert.kind) && <Badge variant="purple" size="sm">{t('inconsistency')}</Badge>}
          </div>
          <dl className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <Field label={t('columns.subject')}><span className="font-mono">{alert.subject}</span></Field>
            <Field label={t('columns.node')}><AlertOrigin alert={alert} nodeName={nodeName} /></Field>
            {alertOrigin(alert).reporters.length > 0 && <Field label={t('detail.reportedBy')}>{alertOrigin(alert).reporters.map(nodeName).join(', ')}</Field>}
            <Field label={t('filters.engine')}>{alert.engine}</Field>
            <Field label={t('detail.firstSeen')}>{formatDate(alert.first_seen)}</Field>
            <Field label={t('detail.lastSeen')}>{formatDate(alert.last_seen)}</Field>
            {alert.acked_by && <Field label={t('detail.ackedBy')}>{alert.acked_by}</Field>}
            {alert.acked_at && <Field label={t('detail.ackedAt')}>{formatDate(alert.acked_at)}</Field>}
            {alert.resolved_at && <Field label={t('detail.resolvedAt')}>{formatDate(alert.resolved_at)}</Field>}
          </dl>
          <AlertNotified alert={alert} />
          {POOL_KINDS.has(alert.kind) && <AlertPressure alert={alert} />}
          <DistroDataNotice alert={alert} />
          <div>
            <h4 className="ui-label text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('detail.details')}</h4>
            {Object.keys(alert.details || {}).length ? (
              <div className="rounded-lg border border-border bg-bg-primary p-2 max-h-64 overflow-auto">
                <JsonTree data={alert.details} expandedDepth={2} />
              </div>
            ) : (
              <p className="text-xs text-text-tertiary">{t('detail.noDetails')}</p>
            )}
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <FileAdoptActions alert={alert} />
            {link && (
              <Button variant="secondary" size="sm" onClick={() => navigate(link.to)} data-testid="alert-open-subject">
                <ArrowSquareOut size={14} />
                {link.label ? t(`actions.${link.label}`) : alert.subject}
              </Button>
            )}
            {canAck && alert.state !== 'resolved' && exceptionItems(alert).length > 0 && (
              <Button variant="secondary" size="sm" onClick={() => onIgnore(alert)} data-testid="alert-ignore">
                <EyeSlash size={14} />
                {t('actions.ignore')}
              </Button>
            )}
            {canAck && alert.state === 'open' && (
              <Button size="sm" onClick={() => onAck(alert)} data-testid="alert-ack">
                <CheckCircle size={14} />
                {t('actions.ack')}
              </Button>
            )}
          </div>
        </div>
      )}
    </Modal>
  )
}

export default function AlertsPage() {
  const { t } = useTranslation(['alerts', 'dashboard', 'common'])
  const msg = useMessage()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { showSuccess, showError, showInfo, showPrompt } = useNotification()
  const canWrite = hasPermission('write:alerts')
  const [running, setRunning] = useState(false)
  const [selectedId, setSelectedId] = useState(null)
  const [ignoring, setIgnoring] = useState(null)
  const alive = useRef(true)
  // Re-armed on every mount: StrictMode runs the cleanup once before the real mount.
  useEffect(() => {
    alive.current = true
    return () => { alive.current = false }
  }, [])

  // No state in the URL means open alerts; ?state= (empty) means every state.
  const filters = useMemo(() => {
    const out = {}
    for (const key of FILTERS) out[key] = params.get(key) || ''
    if (!params.has('state')) out.state = 'open'
    return out
  }, [params])
  const query = useMemo(() => Object.fromEntries(Object.entries(filters).filter(([, v]) => v)), [filters])

  const summary = useApi(() => api.alerts.summary(), [])
  const list = usePaginatedApi((q) => api.alerts.list(q), { perPage: 50, filters: query })
  const { data: nodesData } = useApi(() => api.nodes.list().catch(() => ({ items: [] })), [])
  const nodes = useMemo(() => nodesData?.items || [], [nodesData])
  const nodeName = useCallback((id) => nodes.find((n) => n.peer?.id === id)?.peer?.name || String(id || '').slice(-6), [nodes])

  // The alert named by ?alert=<id>, read on its own when the filtered page does not hold it.
  const linkedId = params.get('alert')
  const [linked, setLinked] = useState(null)
  useEffect(() => {
    if (linkedId) setSelectedId(linkedId)
  }, [linkedId])
  const linkedInList = Boolean(linkedId) && list.items.some((a) => a.id === linkedId)
  useEffect(() => {
    if (!linkedId || linkedInList || !list.data) return undefined
    let alive = true
    findAlert((q) => api.alerts.list(q), linkedId)
      .then((a) => {
        if (!alive) return
        setLinked(a)
        if (!a) showInfo(t('notify.linkGone'))
      })
      .catch(() => alive && setLinked(null))
    return () => {
      alive = false
    }
  }, [linkedId, linkedInList, list.data]) // eslint-disable-line react-hooks/exhaustive-deps
  const closeDetail = () => {
    setSelectedId(null)
    setLinked(null)
    if (params.has('alert')) {
      const next = new URLSearchParams(params)
      next.delete('alert')
      setParams(next, { replace: true })
    }
  }

  const reload = useCallback(() => {
    summary.refetch()
    list.refetch()
  }, [summary, list])
  useWsTopic('alerts', reload)

  const setFilter = (key, value) => {
    const next = new URLSearchParams(params)
    next.set(key, value)
    if (!value && key !== 'state') next.delete(key)
    setParams(next, { replace: true })
  }

  const ack = async (alert) => {
    const comment = await showPrompt(t('ack.prompt'), { title: t('ack.title'), confirmText: t('actions.ack') })
    if (comment === null) return
    try {
      await api.alerts.ack(alert.id, comment.trim() || undefined)
      showSuccess(t('ack.done'))
      closeDetail()
      reload()
    } catch (err) {
      showError(errorMessage(err))
    }
  }

  // The pass runs as a job: poll it until it ends, then report what it found.
  const runConsistency = async () => {
    setRunning(true)
    showInfo(t('consistency.running'))
    try {
      const { job_id: jobId } = await api.alerts.runConsistency()
      const deadline = Date.now() + JOB_TIMEOUT_MS
      let job = await api.jobs.get(jobId)
      while (alive.current && !['done', 'failed'].includes(job.state) && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, JOB_POLL_MS))
        job = await api.jobs.get(jobId)
      }
      if (!alive.current) return
      if (job.state === 'done') showSuccess(t('consistency.done', { count: jobResult(job)?.found ?? 0 }))
      else showError(t('consistency.failed', { message: job.error || job.state }))
      reload()
    } catch (err) {
      showError(t('consistency.failed', { message: errorMessage(err) }))
    } finally {
      if (alive.current) setRunning(false)
    }
  }

  const counts = summary.data || {}
  const sev = counts.by_severity || {}
  const stats = [
    { icon: Bell, label: t('stats.open'), value: counts.open ?? '-', variant: counts.open ? 'warning' : 'success' },
    { icon: CheckCircle, label: t('stats.acked'), value: counts.acked ?? '-', variant: 'primary' },
    { icon: WarningOctagon, label: t('stats.critical'), value: sev.critical ?? 0, variant: sev.critical ? 'danger' : 'neutral' },
    { icon: Warning, label: t('stats.warning'), value: sev.warning ?? 0, variant: sev.warning ? 'warning' : 'neutral' },
    { icon: Info, label: t('stats.info'), value: sev.info ?? 0, variant: 'neutral' },
  ]

  const columns = [
    { key: 'severity', label: t('columns.severity'), width: 110, render: (a) => <StatusBadge status={a.severity} /> },
    {
      key: 'title',
      label: t('columns.title'),
      render: (a) => (
        <span className="inline-flex items-center gap-1.5 min-w-0 max-w-[24rem]" title={msg(a.title_message, a.title)}>
          <span className="truncate text-text-primary">{msg(a.title_message, a.title)}</span>
          {INCONSISTENCY_KINDS.has(a.kind) && <Badge variant="purple" size="sm" className="shrink-0">{t('inconsistency')}</Badge>}
        </span>
      ),
    },
    { key: 'kind', label: t('columns.kind'), render: (a) => <span className="text-xs text-text-secondary">{t(`dashboard:kinds.${a.kind}`, { defaultValue: a.kind })}</span> },
    { key: 'subject', label: t('columns.subject'), mono: true, truncate: true },
    { key: 'node_id', label: t('columns.node'), render: (a) => <AlertOrigin alert={a} nodeName={nodeName} /> },
    { key: 'last_seen', label: t('columns.lastSeen'), render: (a) => <span className="whitespace-nowrap text-xs">{formatDate(a.last_seen)}</span> },
    { key: 'state', label: t('columns.state'), render: (a) => <StatusBadge status={a.state} dot={false} /> },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (a) =>
            a.state === 'open' && (
              <Button variant="ghost" size="xs" onClick={(e) => { e.stopPropagation(); ack(a) }} data-testid="alert-row-ack">
                <CheckCircle size={14} />
                {t('actions.ack')}
              </Button>
            ),
        }]
      : []),
  ]

  const option = (value, label) => ({ value, label })
  const selectFilters = [
    { key: 'state', label: t('filters.state'), value: filters.state, onChange: (v) => setFilter('state', v), options: STATES.map((s) => option(s, t(`common:status.${s}`))), placeholder: t('filters.allStates') },
    { key: 'severity', label: t('filters.severity'), value: filters.severity, onChange: (v) => setFilter('severity', v), options: SEVERITIES.map((s) => option(s, t(`common:status.${s}`))) },
    { key: 'kind', label: t('filters.kind'), value: filters.kind, onChange: (v) => setFilter('kind', v), options: KINDS.map((k) => option(k, t(`dashboard:kinds.${k}`, { defaultValue: k }))) },
    { key: 'engine', label: t('filters.engine'), value: filters.engine, onChange: (v) => setFilter('engine', v), options: ENGINES.map((e) => option(e, e)) },
    ...(nodes.length > 1 ? [{ key: 'node_id', label: t('filters.node'), value: filters.node_id, onChange: (v) => setFilter('node_id', v), options: nodes.map((n) => option(n.peer.id, n.peer.name)) }] : []),
  ]
  const selected = list.items.find((a) => a.id === selectedId) || (linked && linked.id === selectedId ? linked : null)
  const missing = unavailableNodes(list.meta?.unavailable, counts.unavailable)

  return (
    <PageLayout
      icon={Bell}
      title={t('pages.list.title')}
      subtitle={t('pages.list.subtitle')}
      testId="page-alerts-list"
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={reload} disabled={list.loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => navigate('/alerts/exceptions')} data-testid="alerts-exceptions">
            <EyeSlash size={14} />
            {t('nav.exceptions')}
          </Button>
          {canWrite && (
            <Button size="sm" onClick={runConsistency} loading={running} disabled={running} data-testid="alerts-consistency">
              <MagnifyingGlass size={14} />
              {t('actions.runConsistency')}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3">
        <UnavailableNotice nodes={missing} />
        <MuteNotice />
        <RichStatsBar stats={stats} />
        <DataTable
          columns={columns}
          rows={list.items}
          rowKey="id"
          loading={list.loading && !list.data}
          animateInserts
          animateRemovals
          leaveHoldMs={150}
          highlightChanges={['severity', 'state', 'last_seen']}
          className="fx-alerts-table"
          error={list.error}
          onRetry={list.refetch}
          onRowClick={(a) => setSelectedId(a.id)}
          selectedKey={selectedId || undefined}
          filters={selectFilters}
          search={{ value: filters.q, onChange: (v) => setFilter('q', v.trim()), placeholder: t('filters.search') }}
          rowClassName={(a) => (a.severity === 'critical' && a.state === 'open' ? 'border-l-2 border-l-accent-danger' : undefined)}
          emptyTitle={filters.state === 'open' ? t('emptyOpen') : t('empty')}
          emptyDescription={t('emptyHelp')}
          emptyIcon={Bell}
          pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
          testId="alerts-table"
        />
      </div>
      <AlertDetail alert={selected} nodeName={nodeName} canAck={canWrite} onAck={ack} onIgnore={(a) => setIgnoring(a)} onClose={closeDetail} />
      <IgnoreDialog
        open={Boolean(ignoring)}
        items={ignoring ? exceptionItems(ignoring, msg(ignoring.title_message, ignoring.title)) : []}
        onClose={() => setIgnoring(null)}
        onDone={() => {
          showSuccess(t('ignore.done'))
          closeDetail()
          reload()
        }}
      />
    </PageLayout>
  )
}
