// SPDX-License-Identifier: Apache-2.0
// Backups taken by the write pipeline before each write: list filtered by engine
// and node, then one backup's manifest and file contents, with a diff between
// two files of the same path when an older backup of it exists.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ClockCounterClockwise, ArrowsClockwise, FileText } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge, Modal, LoadingSpinner, JsonTree, DiffView } from '../../components'
import { useApi, usePaginatedApi } from '../../hooks'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { useEngineNodes } from './useEngineNodes'
import { unifiedDiff } from './lineDiff'
import { findPreviousBackup } from './history'

const ENGINES = ['bind', 'kea4', 'kea6', 'd2']

function BackupDetail({ item }) {
  const { t } = useTranslation('advanced')
  const { data, error, loading } = useApi(() => api.advanced.historyEntry(item.id), [item.id])
  const prevQ = useApi(async () => {
    const previous = await findPreviousBackup(item, (q) => api.advanced.history(q))
    return previous ? { previous, entry: await api.advanced.historyEntry(previous.id) } : null
  }, [item.id])
  const previous = prevQ.data?.previous
  const [file, setFile] = useState(null)
  const paths = Object.keys(data?.files || {})
  const current = file && paths.includes(file) ? file : paths[0]
  const content = current ? data.files[current] : ''
  const prevContent = current ? prevQ.data?.entry?.files?.[current] : undefined
  const diff = useMemo(() => (prevContent !== undefined ? unifiedDiff(prevContent, content, current) : null), [prevContent, content, current])

  if (loading) return <div className="flex justify-center py-8"><LoadingSpinner size="md" /></div>
  if (error) return <p className="text-sm status-danger-text" role="alert">{errorMessage(error)}</p>
  if (!data) return null
  return (
    <div className="space-y-4" data-testid="history-detail">
      <section className="space-y-1">
        <h4 className="ui-label text-xs font-semibold text-text-secondary">{t('history.manifest')}</h4>
        <div className="rounded-lg border border-border bg-bg-primary p-2 max-h-48 overflow-auto">
          <JsonTree data={data.manifest} expandedDepth={1} />
        </div>
      </section>
      <section className="space-y-2">
        <div className="flex flex-wrap gap-1">
          {paths.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setFile(p)}
              className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-mono ${p === current ? 'bg-accent-primary-op15 text-accent-primary' : 'bg-bg-tertiary text-text-secondary'}`}
            >
              <FileText size={12} />
              {p}
            </button>
          ))}
        </div>
        <pre className="rounded-lg border border-border bg-bg-primary p-3 text-xs font-mono whitespace-pre overflow-auto max-h-72 text-text-primary" data-testid="history-content">
          {content || t('history.emptyFile')}
        </pre>
        {diff !== null && (
          <div className="space-y-1">
            <h4 className="ui-label text-xs font-semibold text-text-secondary">{t('history.sincePrevious', { date: formatDate(previous.ts) })}</h4>
            <DiffView diff={diff} maxHeight={240} />
          </div>
        )}
      </section>
    </div>
  )
}

export default function HistoryPage() {
  const { t } = useTranslation(['advanced', 'common'])
  const [engine, setEngine] = useState('')
  const [nodeId, setNodeId] = useState('')
  const [openId, setOpenId] = useState(null)
  const nodes = useEngineNodes(null)
  const nodeName = (id) => nodes.find((n) => n.peer.id === id)?.peer?.name || id
  const list = usePaginatedApi((q) => api.advanced.history(q), { perPage: 25, filters: { engine: engine || undefined, node_id: nodeId || undefined } })

  const open = list.items.find((i) => i.id === openId)

  const columns = [
    { key: 'ts', label: t('history.columns.ts'), render: (row) => <span className="whitespace-nowrap text-xs">{formatDate(row.ts)}</span> },
    { key: 'engine', label: t('history.columns.engine'), render: (row) => <Badge variant="outline" size="sm" className="font-mono">{row.engine}</Badge> },
    { key: 'node_id', label: t('history.columns.node'), render: (row) => <span className="text-xs">{nodeName(row.node_id)}</span> },
    { key: 'label', label: t('history.columns.label') },
    { key: 'files', label: t('history.columns.files'), render: (row) => <span className="font-mono text-xs">{(row.files || []).join(', ')}</span>, truncate: true },
    { key: 'plan_id', label: t('history.columns.plan'), mono: true, truncate: true },
  ]

  return (
    <PageLayout
      icon={ClockCounterClockwise}
      title={t('pages.history.title')}
      subtitle={t('pages.history.subtitle')}
      testId="page-advanced-history"
      actions={
        <Button variant="secondary" size="sm" onClick={list.refetch} disabled={list.loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      <DataTable
        columns={columns}
        rows={list.items}
        loading={list.loading}
        error={list.error}
        onRetry={list.refetch}
        onRowClick={(row) => setOpenId(row.id)}
        selectedKey={openId || undefined}
        filters={[
          { key: 'engine', label: t('history.columns.engine'), value: engine, onChange: setEngine, options: ENGINES.map((e) => ({ value: e, label: e })) },
          { key: 'node_id', label: t('history.columns.node'), value: nodeId, onChange: setNodeId, options: nodes.map((n) => ({ value: n.peer.id, label: n.peer.name })) },
        ]}
        emptyTitle={t('history.empty')}
        dense
        pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage }}
        testId="history-table"
      />
      <Modal open={Boolean(open)} onClose={() => setOpenId(null)} title={open ? t('history.title', { label: open.label }) : ''} size="lg">
        <div className="p-4 overflow-auto">{open && <BackupDetail item={open} />}</div>
      </Modal>
    </PageLayout>
  )
}
