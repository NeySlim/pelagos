// SPDX-License-Identifier: Apache-2.0
// Audit log: server-side filtered and paginated table of AuditEntry, entry detail
// with request, response and diff, NDJSON export. Filters live in the URL so a
// filtered view can be shared; ?id=<entry> opens that entry.
import { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ClipboardText, DownloadSimple, ArrowsClockwise } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge, StatusBadge, Input } from '../../components'
import { useApi, usePaginatedApi, useWsTopic } from '../../hooks'
import { api } from '../../services/api'
import { formatDate } from '../../lib/utils'
import { AuditEntryModal } from './AuditEntryModal'
import { FILTER_KEYS, ACTION_PREFIXES, RESULTS, ENGINES, filtersFromParams, toQuery, toRfc3339 } from './filters'

export default function AuditPage() {
  const { t } = useTranslation(['audit', 'common'])
  const [params, setParams] = useSearchParams()
  const filters = useMemo(() => filtersFromParams(params), [params])
  const openId = params.get('id')
  const [fresh, setFresh] = useState(0)

  const { data: nodesData } = useApi(() => api.nodes.list().catch(() => ({ items: [] })), [])
  const nodes = useMemo(() => nodesData?.items || [], [nodesData])
  const nodeName = useCallback((id) => nodes.find((n) => n.peer?.id === id)?.peer?.name || id, [nodes])

  const list = usePaginatedApi((q) => api.audit.list(q), { perPage: 50, filters: toQuery(filters) })

  // New entries arrive over the WebSocket: refresh page 1, count them elsewhere.
  useWsTopic('audit', () => {
    if (list.page === 1) list.refetch()
    else setFresh((n) => n + 1)
  })

  const setFilter = (key, value) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    next.delete('id')
    setParams(next, { replace: true })
  }
  const openEntry = (id) => {
    const next = new URLSearchParams(params)
    if (id) next.set('id', id)
    else next.delete('id')
    setParams(next, { replace: !id })
  }
  const clearAll = () => setParams(new URLSearchParams(), { replace: true })

  const columns = [
    { key: 'ts', label: t('columns.ts'), render: (row) => <span className="whitespace-nowrap text-xs">{formatDate(row.ts)}</span>, width: 150 },
    { key: 'user', label: t('columns.user'), render: (row) => row.user || <span className="text-text-tertiary">{t('anonymous')}</span> },
    { key: 'action', label: t('columns.action'), mono: true },
    { key: 'target', label: t('columns.target'), mono: true, truncate: true, width: '28%' },
    {
      key: 'engine',
      label: t('columns.engine'),
      render: (row) => (row.engine ? <Badge variant="outline" size="sm" className="font-mono">{row.engine}</Badge> : ''),
    },
    { key: 'node_id', label: t('columns.node'), render: (row) => <span className="text-xs">{nodeName(row.node_id)}</span> },
    { key: 'result', label: t('columns.result'), render: (row) => <StatusBadge status={row.result} /> },
  ]

  const option = (value, label) => ({ value, label })
  const selectFilters = [
    { key: 'action', label: t('filters.action'), value: filters.action, onChange: (v) => setFilter('action', v), options: ACTION_PREFIXES.map((p) => option(p, t(`actions.${p.replace(/\.$/, '')}`, { defaultValue: p }))) },
    { key: 'result', label: t('filters.result'), value: filters.result, onChange: (v) => setFilter('result', v), options: RESULTS.map((r) => option(r, t(`common:status.${r}`))) },
    { key: 'engine', label: t('filters.engine'), value: filters.engine, onChange: (v) => setFilter('engine', v), options: ENGINES.map((e) => option(e, e)) },
    { key: 'node_id', label: t('filters.node'), value: filters.node_id, onChange: (v) => setFilter('node_id', v), options: nodes.map((n) => option(n.peer.id, n.peer.name)) },
  ]
  const exportParams = { from: toRfc3339(filters.from), to: toRfc3339(filters.to) }

  return (
    <PageLayout
      icon={ClipboardText}
      title={t('pages.list.title')}
      subtitle={t('pages.list.subtitle')}
      testId="page-audit-list"
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={() => { setFresh(0); list.refetch() }} disabled={list.loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          <a href={api.audit.exportUrl(exportParams)} download="pelagos-audit.ndjson" className="btn-soft focus-ring text-text-primary inline-flex items-center justify-center rounded-md font-medium px-2.5 py-1.5 text-xs gap-1.5" data-testid="audit-export">
            <DownloadSimple size={14} />
            {t('export')}
          </a>
        </>
      }
    >
      <div className="space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3" data-testid="audit-text-filters">
          <Input label={t('filters.user')} value={filters.user} onChange={(e) => setFilter('user', e.target.value)} placeholder="alice" data-testid="audit-filter-user" />
          <Input label={t('filters.target')} value={filters.target} onChange={(e) => setFilter('target', e.target.value)} placeholder="zone:example.lan." data-testid="audit-filter-target" />
          <Input label={t('filters.from')} type="datetime-local" value={filters.from} onChange={(e) => setFilter('from', e.target.value)} data-testid="audit-filter-from" />
          <Input label={t('filters.to')} type="datetime-local" value={filters.to} onChange={(e) => setFilter('to', e.target.value)} data-testid="audit-filter-to" />
        </div>
        {fresh > 0 && (
          <button type="button" className="text-xs text-accent-primary underline" onClick={() => { setFresh(0); list.setPage(1) }} data-testid="audit-fresh">
            {t('newEntries', { count: fresh })}
          </button>
        )}
        <DataTable
          columns={columns}
          rows={list.items}
          loading={list.loading}
          error={list.error}
          onRetry={list.refetch}
          onRowClick={(row) => openEntry(row.id)}
          selectedKey={openId || undefined}
          filters={selectFilters}
          toolbar={
            FILTER_KEYS.some((k) => filters[k]) && (
              <Button variant="secondary" size="sm" onClick={clearAll}>
                {t('common:table.clearFilters')}
              </Button>
            )
          }
          emptyTitle={t('empty')}
          dense
          pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
          testId="audit-table"
        />
      </div>
      <AuditEntryModal id={openId} rows={list.items} nodeName={nodeName} onClose={() => openEntry(null)} />
    </PageLayout>
  )
}
