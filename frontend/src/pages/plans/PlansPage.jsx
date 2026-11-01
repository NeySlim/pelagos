// SPDX-License-Identifier: Apache-2.0
// Plans held by the node you are connected to: state, author, summary, nodes and the time left
// to roll back. Filters and the open plan (?id=) live in the URL; the `plans` WebSocket topic
// refreshes the list. read:audit sees every plan, other users their own.
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ListChecks, ArrowsClockwise } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge, StatusBadge, Input } from '../../components'
import { NodeLink } from '../../components/NodeLink'
import { usePaginatedApi, useWsTopic } from '../../hooks'
import { usePermission } from '../../hooks/usePermission'
import { useNodeNames } from '../../hooks/useNodeNames'
import { useMessage } from '../../i18n/message'
import { api } from '../../services/api'
import { formatDate } from '../../lib/utils'
import { PlanDetailModal } from './PlanDetailModal'
import { FILTER_KEYS, STATES, filtersFromParams, formatLeft, rollbackWindow, toQuery } from './lib'

// Ticks once a second: only the cell that shows a countdown re-renders.
function useNow() {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])
  return now
}

function RollbackCell({ plan }) {
  const { t } = useTranslation('plans')
  const open = Boolean(plan.rollback_until) && Date.parse(plan.rollback_until) > Date.now()
  // A plan without a window never ticks; one with a window ticks until it closes.
  return open ? <OpenCell plan={plan} t={t} /> : <ClosedCell plan={plan} t={t} />
}

function OpenCell({ plan, t }) {
  const now = useNow()
  const win = rollbackWindow(plan, now)
  if (win.status === 'closed') return <ClosedCell plan={plan} t={t} />
  return <span className="text-xs whitespace-nowrap" data-testid="plan-rollback-left" data-status="open">{t('rollback.left', { left: formatLeft(win.leftMs, (unit, n) => t(`units.${unit}`, { n })) })}</span>
}

function ClosedCell({ plan, t }) {
  if (plan.rollback_until) {
    return <span className="text-xs text-text-tertiary" data-testid="plan-rollback-left" data-status="closed">{t('rollback.closed')}</span>
  }
  return <span className="text-text-tertiary" data-testid="plan-rollback-left" data-status="none">-</span>
}

const REFRESH_DEBOUNCE_MS = 500
const TEXT_DEBOUNCE_MS = 400

export default function PlansPage() {
  const { t } = useTranslation(['plans', 'common'])
  const msg = useMessage()
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => filtersFromParams(params), [params])
  const openId = params.get('id')
  const { hasPermission } = usePermission()
  const canSeeAll = hasPermission('read:audit')
  const nameOf = useNodeNames()

  const list = usePaginatedApi((q) => api.plans.list(q), { perPage: 50, filters: toQuery(filters, { canSeeAll }) })
  const nodeId = list.meta.node_id
  // Phase changes refresh the list; the per-node step events do not.
  const refetchRef = useRef(list.refetch)
  refetchRef.current = list.refetch
  const refreshTimer = useRef(null)
  useEffect(() => () => clearTimeout(refreshTimer.current), [])
  useWsTopic('plans', (message) => {
    if (message?.event === 'step') return
    clearTimeout(refreshTimer.current)
    refreshTimer.current = setTimeout(() => refetchRef.current(), REFRESH_DEBOUNCE_MS)
  })

  // The author field writes the URL once typing pauses.
  const [userText, setUserText] = useState(filters.user)
  useEffect(() => setUserText(filters.user), [filters.user])
  useEffect(() => {
    if (userText === filters.user) return undefined
    const timer = setTimeout(() => setParam('user', userText), TEXT_DEBOUNCE_MS)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userText])

  const setParam = (key, value) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    if (key !== 'id') next.delete('id')
    setParams(next, { replace: key !== 'id' || !value })
  }
  const clearAll = () => setParams(new URLSearchParams(), { replace: true })

  const summaryOf = (row) => msg(row.summary_message, row.summary)
  const columns = [
    { key: 'created_at', label: t('columns.created'), render: (row) => <span className="whitespace-nowrap text-xs">{formatDate(row.created_at)}</span>, width: 150 },
    { key: 'state', label: t('columns.state'), render: (row) => <StatusBadge status={row.state} /> },
    { key: 'created_by', label: t('columns.user'), render: (row) => row.created_by || '-' },
    {
      key: 'summary',
      label: t('columns.summary'),
      width: '30%',
      render: (row) => (
        <div className="min-w-0">
          <div className="truncate" title={summaryOf(row)}>{summaryOf(row)}</div>
          {row.error && row.state === 'failed' && (
            <div className="truncate text-2xs status-danger-text" title={msg(row.error_message, row.error)} data-testid="plan-row-error">{msg(row.error_message, row.error)}</div>
          )}
        </div>
      ),
    },
    { key: 'scope', label: t('columns.scope'), render: (row) => <Badge variant="outline" size="sm" className="font-mono">{row.scope}</Badge> },
    {
      key: 'nodes',
      label: t('columns.nodes'),
      render: (row) => (
        <span className="inline-flex flex-wrap gap-x-2 text-xs">
          {(row.target_node_ids || []).map((id) => <NodeLink key={id} nodeId={id} name={nameOf(id)} short />)}
        </span>
      ),
    },
    { key: 'rollback', label: t('columns.rollback'), render: (row) => <RollbackCell plan={row} /> },
  ]

  const selectFilters = [
    { key: 'state', label: t('filters.state'), value: filters.state, onChange: (v) => setParam('state', v), options: STATES.map((s) => ({ value: s, label: t(`common:status.${s}`, { defaultValue: s }) })) },
  ]

  return (
    <PageLayout
      icon={ListChecks}
      title={t('pages.list.title')}
      subtitle={nodeId ? <>{t('pages.list.subtitleNode')} <NodeLink nodeId={nodeId} name={nameOf(nodeId)} /></> : t('pages.list.subtitle')}
      testId="page-plans-list"
      actions={
        <Button variant="secondary" size="sm" onClick={() => list.refetch()} disabled={list.loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      <div className="space-y-3">
        {canSeeAll && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3" data-testid="plans-text-filters">
            <Input label={t('filters.user')} value={userText} onChange={(e) => setUserText(e.target.value)} placeholder="alice" data-testid="plans-filter-user" />
          </div>
        )}
        <DataTable
          columns={columns}
          rows={list.items}
          loading={list.loading}
          error={list.error}
          onRetry={list.refetch}
          onRowClick={(row) => setParam('id', row.id)}
          selectedKey={openId || undefined}
          filters={selectFilters}
          toolbar={
            FILTER_KEYS.some((k) => filters[k] && (k !== 'user' || canSeeAll)) && (
              <Button variant="secondary" size="sm" onClick={clearAll}>
                {t('common:table.clearFilters')}
              </Button>
            )
          }
          mobileCard={{
            title: summaryOf,
            subtitle: (row) => `${formatDate(row.created_at)} · ${row.created_by || '-'}`,
            status: (row) => <StatusBadge status={row.state} />,
            fields: ['scope', 'nodes', 'rollback'],
          }}
          emptyTitle={t('empty')}
          dense
          pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
          testId="plans-table"
        />
      </div>
      <PlanDetailModal id={openId} onClose={() => setParam('id', null)} onChanged={() => list.refetch()} />
    </PageLayout>
  )
}
