// SPDX-License-Identifier: Apache-2.0
// Secondary, stub and mirror zones: primaries, serial per node, next refresh
// and expiry from rndc zonestatus, retransfer on one node or on every lagging node.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { CopySimple, ArrowsClockwise, DownloadSimple } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { StatusBadge } from '../../components/StatusBadge'
import { RichStatsBar } from '../../components/ui/RichStatsBar'
import { useApi } from '../../hooks/useApi'
import { usePoll } from '../../hooks/usePoll'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { ListValue, SerialCells } from './common'
import { useNodeNames, zoneHref, resynchronizeZone, mapLimit, SECONDARY_KINDS } from './helpers'

// Earliest timestamp of a ZoneStatus field over the nodes, or null.
function earliest(status, field) {
  const values = Object.values(status || {})
    .map((s) => s[field])
    .filter(Boolean)
    .map((v) => new Date(v).getTime())
  return values.length ? new Date(Math.min(...values)).toISOString() : null
}

// Without bulk status in GET /dns/zones, one zonestatus read per zone: bounded so a large deployment does not flood the nodes.
const STATUS_CONCURRENCY = 4
const SECONDARIES_POLL_MS = 30000

// A zone list item that already carries `status` (node id -> ZoneStatus) needs no extra read.
async function withStatus(it) {
  if (it.status && typeof it.status === 'object') return it
  try {
    const detail = await api.dns.zone(it.zone.name, it.zone.view)
    return { ...it, status: detail.status }
  } catch (err) {
    return { ...it, status: {}, error: errorMessage(err) }
  }
}

async function loadSecondaries() {
  const { items } = await api.dns.zones()
  const zones = items.filter((it) => SECONDARY_KINDS.includes(it.zone.kind))
  return mapLimit(zones, STATUS_CONCURRENCY, withStatus)
}

// Reloads a single row (serials from the zone list, status from the zone detail).
async function reloadSecondary(row) {
  const { items } = await api.dns.zones({ view: row.zone.view, q: row.zone.name })
  const fresh = items.find((it) => it.zone.name === row.zone.name && it.zone.view === row.zone.view)
  return withStatus(fresh || { ...row, status: undefined })
}

export default function SecondariesPage() {
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { showSuccess, showError } = useNotification()
  const { nameOf } = useNodeNames()
  const [busy, setBusy] = useState(null)
  const { data, error, loading, refetch, setData } = useApi(loadSecondaries, [])
  const rows = useMemo(() => data || [], [data])
  const canOps = hasPermission('ops:dns')
  // Transfers happen on their own schedule: the serials are read again quietly.
  usePoll(async () => setData(await loadSecondaries()), SECONDARIES_POLL_MS, { enabled: Boolean(data) })

  const resync = async (row) => {
    setBusy(`${row.zone.view}/${row.zone.name}`)
    try {
      const outputs = await resynchronizeZone({ zone: row.zone.name, kind: row.zone.kind, view: row.zone.view, serials: row.serials })
      showSuccess(outputs.join('\n') || t('zones.resyncDone', { zone: row.zone.name }))
      const fresh = await reloadSecondary(row)
      setData((prev) => (prev || []).map((r) => (r.zone.name === row.zone.name && r.zone.view === row.zone.view ? fresh : r)))
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const now = Date.now()
  const stats = [
    { icon: CopySimple, label: t('secondaries.stats.total'), value: rows.length, variant: 'primary' },
    { icon: ArrowsClockwise, label: t('zones.stats.divergent'), value: rows.filter((r) => r.divergent).length, variant: rows.some((r) => r.divergent) ? 'warning' : 'success' },
    {
      icon: DownloadSimple,
      label: t('secondaries.stats.errors'),
      value: rows.filter((r) => r.error || Object.values(r.status || {}).some((s) => s.error)).length,
      variant: rows.some((r) => r.error || Object.values(r.status || {}).some((s) => s.error)) ? 'danger' : 'success',
    },
  ]

  const columns = [
    { key: 'zone.name', label: t('zones.name'), sortable: true, render: (r) => <span className="font-mono text-xs">{r.zone.name}</span> },
    { key: 'zone.kind', label: t('zones.kind'), render: (r) => <StatusBadge status={r.zone.kind} label={t(`kind.${r.zone.kind}`, { defaultValue: r.zone.kind })} dot={false} /> },
    { key: 'zone.view', label: t('zones.view'), mono: true },
    { key: 'zone.primaries', label: t('zones.primaries'), render: (r) => <ListValue items={r.zone.primaries} /> },
    { key: 'serials', label: t('zones.serials'), render: (r) => <SerialCells serials={r.serials} nameOf={nameOf} /> },
    {
      key: 'next_refresh',
      label: t('detail.nextRefresh'),
      sortValue: (r) => earliest(r.status, 'next_refresh'),
      sortable: true,
      render: (r) => {
        const v = earliest(r.status, 'next_refresh')
        return v ? formatDate(v) : '-'
      },
    },
    {
      key: 'expires',
      label: t('detail.expires'),
      render: (r) => {
        const v = earliest(r.status, 'expires')
        if (!v) return '-'
        const soon = new Date(v).getTime() - now < 86400000
        return (
          <span className={soon ? 'status-danger-text' : undefined} title={formatDate(v)}>
            {formatDate(v)}
          </span>
        )
      },
    },
    {
      key: 'state',
      label: t('zones.sync'),
      render: (r) =>
        r.error || Object.values(r.status || {}).some((s) => s.error) ? (
          <StatusBadge status="error" />
        ) : (
          <StatusBadge status={r.divergent ? 'divergent' : 'in-sync'} />
        ),
    },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (r) =>
        canOps ? (
          <Button
            variant={r.divergent ? 'warning-soft' : 'secondary'}
            size="xs"
            loading={busy === `${r.zone.view}/${r.zone.name}`}
            onClick={(e) => {
              e.stopPropagation()
              resync(r)
            }}
            data-testid="secondary-retransfer"
          >
            <DownloadSimple size={12} />
            {t('detail.retransfer')}
          </Button>
        ) : null,
    },
  ]

  return (
    <PageLayout
      icon={CopySimple}
      title={t('pages.secondaries.title')}
      subtitle={t('pages.secondaries.subtitle')}
      testId="page-dns-secondaries"
      actions={
        <Button variant="secondary" size="sm" onClick={refetch} disabled={loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      <div className="space-y-4">
        <RichStatsBar stats={stats} />
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(r) => `${r.zone.view}/${r.zone.name}`}
          loading={loading && !data}
          error={error}
          onRetry={refetch}
          clientSort
          onRowClick={(r) => navigate(zoneHref(r.zone.name, r.zone.view))}
          emptyTitle={t('secondaries.empty')}
          emptyDescription={t('secondaries.emptyHelp')}
          testId="secondaries-table"
        />
      </div>
    </PageLayout>
  )
}
