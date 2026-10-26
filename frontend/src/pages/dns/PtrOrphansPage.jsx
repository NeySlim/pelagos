// SPDX-License-Identifier: Apache-2.0
// Orphan PTRs: PTR records whose target has no A/AAAA to their address (GET /dns/ptr/orphans).
// Targets outside the managed zones are listed apart (not verifiable). Each row is deleted, gets
// its missing address record, or is ignored as the admin's choice; deletes go in one plan.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, LinkBreak, Trash, Plus, EyeSlash, Eye } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge } from '../../components'
import { RichStatsBar } from '../../components/ui/RichStatsBar'
import { useApi } from '../../hooks'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { usePlanFlow } from '../dhcp/hooks'
import { IgnoreDialog } from '../alerts/IgnoreDialog'
import { CATEGORIES, deleteBody, createBody, filterOrphans, orphanKey } from './ptrOrphans'

export default function PtrOrphansPage() {
  const { t } = useTranslation(['dns', 'common'])
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const canWrite = hasPermission('write:dns.records')
  const canIgnore = hasPermission('write:alerts')
  const [category, setCategory] = useState('orphan')
  const [selected, setSelected] = useState(() => new Set())
  const [ignoring, setIgnoring] = useState(null)
  const list = useApi(() => api.dns.ptrOrphans(), [])
  const reload = () => {
    setSelected(new Set())
    list.refetch()
  }
  const flow = usePlanFlow({ onApplied: reload })
  const all = useMemo(() => list.data?.items || [], [list.data])
  const rows = useMemo(() => filterOrphans(all, category), [all, category])
  const counts = list.data?.counts || {}
  const errors = Object.entries(list.data?.errors || {})

  const toggle = (row) =>
    setSelected((prev) => {
      const next = new Set(prev)
      const key = orphanKey(row)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  const chosen = rows.filter((r) => selected.has(orphanKey(r)))
  const allChosen = rows.length > 0 && chosen.length === rows.length
  const toggleAll = () => setSelected(allChosen ? new Set() : new Set(rows.map(orphanKey)))

  const plan = (body) => flow.build(() => api.dns.ptrOrphansPlan(body))
  const revoke = async (row) => {
    try {
      await api.alerts.revokeException(row.exception.id)
      showSuccess(t('orphans.unignored'))
      reload()
    } catch (err) {
      showError(errorMessage(err))
    }
  }

  const columns = [
    ...(canWrite
      ? [{
          key: 'select',
          label: <input type="checkbox" aria-label={t('orphans.selectAll')} checked={allChosen} onChange={toggleAll} data-testid="orphans-select-all" />,
          width: 36,
          render: (r) => (
            <input type="checkbox" aria-label={t('orphans.select', { ip: r.ip })} checked={selected.has(orphanKey(r))} onChange={() => toggle(r)} onClick={(e) => e.stopPropagation()} data-testid="orphan-select" />
          ),
        }]
      : []),
    { key: 'ip', label: t('orphans.columns.ip'), mono: true },
    {
      key: 'target',
      label: t('orphans.columns.target'),
      render: (r) => (
        <span className="block min-w-0">
          <span className="block font-mono text-text-primary truncate">{r.target}</span>
          <span className="block text-2xs text-text-tertiary">
            {r.target_addresses.length ? t('orphans.targetHas', { addresses: r.target_addresses.join(', ') }) : r.category === 'external' ? t('orphans.notVerifiable') : t('orphans.targetNone')}
          </span>
        </span>
      ),
    },
    {
      key: 'zone',
      label: t('orphans.columns.zone'),
      render: (r) => (
        <span className="text-xs">
          <span className="font-mono">{r.zone}</span>
          {r.view !== '_default' && <span className="text-text-tertiary"> ({r.view})</span>}
        </span>
      ),
    },
    {
      key: 'category',
      label: t('orphans.columns.category'),
      render: (r) => (
        <span className="inline-flex flex-wrap gap-1">
          <Badge variant={r.category === 'external' ? 'outline' : 'warning'} size="sm">{t(`orphans.categories.${r.category}`)}</Badge>
          {r.ddns && <Badge variant="purple" size="sm">DDNS</Badge>}
          {r.excepted && <Badge variant="outline" size="sm" title={r.exception?.comment}>{t('orphans.ignored')}</Badge>}
        </span>
      ),
    },
    {
      key: 'age',
      label: t('orphans.columns.age'),
      render: (r) => <span className="text-xs whitespace-nowrap">{r.lease?.cltt ? t('orphans.leaseSeen', { date: formatDate(r.lease.cltt), state: r.lease.state }) : r.ddns ? t('orphans.leaseGone') : '-'}</span>,
    },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (r) => (
        <span className="inline-flex flex-wrap justify-end gap-1">
          {canWrite && r.fix === 'create_a' && (
            <Button variant="ghost" size="xs" disabled={flow.building} onClick={() => plan(createBody([r]))} data-testid="orphan-create">
              <Plus size={14} />
              {t('orphans.create', { rtype: r.rtype })}
            </Button>
          )}
          {canWrite && (
            <Button variant="ghost" size="xs" disabled={flow.building} onClick={() => plan(deleteBody([r]))} data-testid="orphan-delete">
              <Trash size={14} />
              {t('orphans.delete')}
            </Button>
          )}
          {canIgnore && !r.excepted && (
            <Button variant="ghost" size="xs" onClick={() => setIgnoring([r])} data-testid="orphan-ignore">
              <EyeSlash size={14} />
              {t('orphans.ignore')}
            </Button>
          )}
          {canIgnore && r.excepted && r.exception && (
            <Button variant="ghost" size="xs" onClick={() => revoke(r)} data-testid="orphan-unignore">
              <Eye size={14} />
              {t('orphans.unignore')}
            </Button>
          )}
        </span>
      ),
    },
  ]

  const stats = [
    { icon: LinkBreak, label: t('orphans.categories.orphan'), value: counts.orphan ?? '-', variant: counts.orphan ? 'warning' : 'success' },
    { icon: LinkBreak, label: t('orphans.categories.external'), value: counts.external ?? '-', variant: 'neutral' },
    { icon: EyeSlash, label: t('orphans.categories.excepted'), value: counts.excepted ?? '-', variant: 'neutral' },
  ]
  const toIgnore = (ignoring || []).map((r) => ({ kind: 'ptr_mismatch', key: r.exception_key, summary: `${r.ip} -> ${r.target}` }))

  return (
    <PageLayout
      icon={LinkBreak}
      title={t('orphans.title')}
      subtitle={t('orphans.subtitle')}
      testId="page-ptr-orphans"
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={reload} disabled={list.loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          {canIgnore && chosen.length > 0 && (
            <Button variant="secondary" size="sm" onClick={() => setIgnoring(chosen.filter((r) => !r.excepted))} data-testid="orphans-ignore-selected">
              <EyeSlash size={14} />
              {t('orphans.ignoreSelected', { count: chosen.length })}
            </Button>
          )}
          {canWrite && chosen.length > 0 && (
            <Button variant="danger" size="sm" disabled={flow.building} onClick={() => plan(deleteBody(chosen))} data-testid="orphans-delete-selected">
              <Trash size={14} />
              {t('orphans.deleteSelected', { count: chosen.length })}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3">
        <RichStatsBar stats={stats} />
        {errors.length > 0 && (
          <div className="rounded-lg status-warning-bg border status-warning-border px-3 py-2 text-xs status-warning-text" data-testid="orphans-errors">
            {errors.map(([source, message]) => (
              <div key={source}>{t('orphans.readError', { source, message })}</div>
            ))}
          </div>
        )}
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={orphanKey}
          loading={list.loading && !list.data}
          error={list.error}
          onRetry={list.refetch}
          filters={[{
            key: 'category',
            label: t('orphans.columns.category'),
            value: category,
            onChange: (v) => {
              setCategory(v || 'all')
              setSelected(new Set())
            },
            options: CATEGORIES.map((c) => ({ value: c, label: t(`orphans.categories.${c}`) })),
          }]}
          emptyTitle={t('orphans.empty')}
          emptyDescription={t('orphans.emptyHelp')}
          emptyIcon={LinkBreak}
          testId="orphans-table"
        />
      </div>
      {flow.modal}
      <IgnoreDialog open={Boolean(ignoring)} items={toIgnore} onClose={() => setIgnoring(null)} onDone={reload} />
    </PageLayout>
  )
}
