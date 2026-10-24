// SPDX-License-Identifier: Apache-2.0
// Alerts and inconsistencies: counts from GET /alerts/summary, the filtered and
// paginated alert list (open by default, filters in the URL), the alert detail
// with a link to the host or zone it is about, acknowledgement with an optional
// comment, and an on-demand consistency pass run as a job.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Bell, ArrowsClockwise, CheckCircle, MagnifyingGlass, Warning, WarningOctagon, Info, ArrowSquareOut } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge, StatusBadge, Modal, JsonTree } from '../../components'
import { RichStatsBar } from '../../components/ui/RichStatsBar'
import { useApi, usePaginatedApi, useWsTopic } from '../../hooks'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { ENGINES, INCONSISTENCY_KINDS, KINDS, SEVERITIES, STATES, jobResult, subjectLink } from './lib'

const FILTERS = ['state', 'severity', 'kind', 'engine', 'node_id']
const JOB_POLL_MS = 1000
const JOB_TIMEOUT_MS = 120000

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className="text-xs text-text-primary break-all">{children || '-'}</dd>
    </div>
  )
}

function AlertDetail({ alert, nodeName, canAck, onAck, onClose }) {
  const { t } = useTranslation(['alerts', 'dashboard', 'common'])
  const navigate = useNavigate()
  const link = alert ? subjectLink(alert) : null
  return (
    <Modal open={Boolean(alert)} onClose={onClose} title={alert?.title || t('detail.title')}>
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
            <Field label={t('columns.node')}>{alert.node_id ? nodeName(alert.node_id) : null}</Field>
            <Field label={t('filters.engine')}>{alert.engine}</Field>
            <Field label={t('detail.firstSeen')}>{formatDate(alert.first_seen)}</Field>
            <Field label={t('detail.lastSeen')}>{formatDate(alert.last_seen)}</Field>
            {alert.acked_by && <Field label={t('detail.ackedBy')}>{alert.acked_by}</Field>}
            {alert.acked_at && <Field label={t('detail.ackedAt')}>{formatDate(alert.acked_at)}</Field>}
            {alert.resolved_at && <Field label={t('detail.resolvedAt')}>{formatDate(alert.resolved_at)}</Field>}
          </dl>
          <div>
            <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('detail.details')}</h4>
            {Object.keys(alert.details || {}).length ? (
              <div className="rounded-lg border border-border bg-bg-primary p-2 max-h-64 overflow-auto">
                <JsonTree data={alert.details} expandedDepth={2} />
              </div>
            ) : (
              <p className="text-xs text-text-tertiary">{t('detail.noDetails')}</p>
            )}
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            {link && (
              <Button variant="secondary" size="sm" onClick={() => navigate(link.to)} data-testid="alert-open-subject">
                <ArrowSquareOut size={14} />
                {link.label ? t(`actions.${link.label}`) : alert.subject}
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
  const [params, setParams] = useSearchParams()
  const { hasPermission } = usePermission()
  const { showSuccess, showError, showInfo, showPrompt } = useNotification()
  const canWrite = hasPermission('write:alerts')
  const [running, setRunning] = useState(false)
  const [selectedId, setSelectedId] = useState(null)
  const alive = useRef(true)
  useEffect(() => () => { alive.current = false }, [])

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
      setSelectedId(null)
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
        <span className="inline-flex items-center gap-1.5 min-w-0">
          <span className="truncate text-text-primary">{a.title}</span>
          {INCONSISTENCY_KINDS.has(a.kind) && <Badge variant="purple" size="sm">{t('inconsistency')}</Badge>}
        </span>
      ),
    },
    { key: 'kind', label: t('columns.kind'), render: (a) => <span className="text-xs text-text-secondary">{t(`dashboard:kinds.${a.kind}`, { defaultValue: a.kind })}</span> },
    { key: 'subject', label: t('columns.subject'), mono: true, truncate: true },
    { key: 'node_id', label: t('columns.node'), render: (a) => <span className="text-xs">{a.node_id ? nodeName(a.node_id) : '-'}</span> },
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
  const selected = list.items.find((a) => a.id === selectedId) || null

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
        <RichStatsBar stats={stats} />
        <DataTable
          columns={columns}
          rows={list.items}
          rowKey="id"
          loading={list.loading}
          error={list.error}
          onRetry={list.refetch}
          onRowClick={(a) => setSelectedId(a.id)}
          selectedKey={selectedId || undefined}
          filters={selectFilters}
          rowClassName={(a) => (a.severity === 'critical' && a.state === 'open' ? 'border-l-2 border-l-accent-danger' : undefined)}
          emptyTitle={filters.state === 'open' ? t('emptyOpen') : t('empty')}
          emptyDescription={t('emptyHelp')}
          emptyIcon={Bell}
          pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
          testId="alerts-table"
        />
      </div>
      <AlertDetail alert={selected} nodeName={nodeName} canAck={canWrite} onAck={ack} onClose={() => setSelectedId(null)} />
    </PageLayout>
  )
}
