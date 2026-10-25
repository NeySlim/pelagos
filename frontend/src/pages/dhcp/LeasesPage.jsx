// SPDX-License-Identifier: Apache-2.0
// Leases: Kea lookups for a search term, filters (subnet, state, node), and pages that
// follow Kea's own cursor (meta.next); a row opens the lease card that compares the
// copies held by each HA partner.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { CaretLeft, CaretRight, Clock, Lightning } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Modal } from '../../components/Modal'
import { Select } from '../../components/ui/Select'
import { StatusBadge } from '../../components/StatusBadge'
import { Dora } from '../../components/motion'
import { useOpenDetail } from '../../components/FloatingDetailWindow'
import { useMobile } from '../../contexts/MobileContext'
import { useApi } from '../../hooks/useApi'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { formatDate, formatRelativeTime } from '../../lib/utils'
import { AreaPage } from './ui'
import { useNodeNames } from './hooks'
import { LEASE_STATES, keaEngine, nextCursor, previousCursor, secondsFromNow } from './lib'
import { LeaseDetail } from './LeaseDetail'

const LIMITS = [25, 50, 100, 250, 500, 1000]

export default function LeasesPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const [params] = useSearchParams()
  const [q, setQ] = useState(params.get('q') || '')
  const [subnetId, setSubnetId] = useState(params.get('subnet_id') || '')
  const [state, setState] = useState('')
  const [nodeId, setNodeId] = useState('')
  const [activity, setActivity] = useState(0)
  const [mobileIp, setMobileIp] = useState(null)
  const { isMobile } = useMobile()
  const openDetail = useOpenDetail()
  const { nameOf } = useNodeNames()

  const [limit, setLimit] = useState(100)
  // One entry per page seen: the from_address that page started at (null for the first).
  const [cursors, setCursors] = useState([null])
  const filterKey = JSON.stringify({ q, subnetId, state, nodeId, family, limit })
  useEffect(() => setCursors([null]), [filterKey])
  const from = cursors[cursors.length - 1]
  const query = useApi(
    () => api.dhcp.leases(family, { q, subnet_id: subnetId, state, node_id: nodeId, from_address: from, limit }),
    [filterKey, from],
  )
  const leases = { ...query, items: query.data?.items || [], meta: query.data?.meta || {} }
  const subnets = useApi(() => api.dhcp.subnets(family), [family])
  const servers = useApi(() => api.dhcp.servers(family), [family])

  useWsTopic('leases', (msg) => {
    const d = msg?.data
    if (d?.engine === keaEngine(family)) setActivity((n) => n + Math.max(1, (d.new_since_last || 0) + (d.expired_since_last || 0)))
  })

  const refresh = () => {
    setActivity(0)
    leases.refetch()
  }

  const open = (lease) => {
    if (isMobile) setMobileIp(lease.ip_address)
    else openDetail('lease', `${family}:${lease.ip_address}`, { family, ip: lease.ip_address, title: lease.ip_address, subtitle: lease.hostname || undefined })
  }

  const columns = [
    {
      key: 'ip_address',
      label: t('fields.ipAddress'),
      mono: true,
      render: (l) => (
        <span>
          {l.ip_address}
          {l.lease_type === 'IA_PD' && <span className="text-text-tertiary">/{l.prefix_len}</span>}
        </span>
      ),
    },
    { key: 'hw_address', label: family === 'v6' ? t('fields.duid') : t('fields.mac'), mono: true, truncate: true, render: (l) => (family === 'v6' ? l.duid : l.hw_address) || '-' },
    { key: 'hostname', label: t('fields.hostname'), className: 'break-all' },
    { key: 'subnet_id', label: t('fields.subnetId'), mono: true, width: 70 },
    ...(family === 'v6' ? [{ key: 'lease_type', label: t('fields.leaseType'), mono: true }] : []),
    {
      key: 'state',
      label: t('fields.state'),
      // A lease that just appeared plays its DORA once; a declined one stops on red.
      render: (l, _raw, meta) => (
        <span className="inline-flex items-center gap-2">
          <StatusBadge status={l.state} />
          {meta?.entering && <Dora transient nak={l.state === 'declined'} />}
        </span>
      ),
    },
    {
      key: 'expires_at',
      label: t('fields.expiresAt'),
      render: (l) => {
        const left = secondsFromNow(l.expires_at)
        return (
          <span title={formatDate(l.expires_at)} className={left !== null && left < 0 ? 'text-text-tertiary' : undefined}>
            {left === null ? '-' : left >= 0 ? t('leases.inMinutes', { minutes: Math.ceil(left / 60) }) : formatRelativeTime(l.expires_at)}
          </span>
        )
      },
    },
    { key: 'ddns', label: t('fields.ddnsFlags'), render: (l) => <span className="font-mono text-2xs">{`${l.fqdn_fwd ? 'F' : '-'}${l.fqdn_rev ? 'R' : '-'}`}</span> },
  ]

  const subnetOptions = (subnets.data?.items || []).map((s) => ({ value: String(s.id), label: `${s.id}: ${s.subnet}` }))
  const stateOptions = LEASE_STATES.map((s) => ({ value: s, label: t(`common:status.${s}`) }))
  const nodeOptions = (servers.data?.items || []).map((s) => ({ value: s.node_id, label: nameOf(s.node_id) }))
  const readNode = leases.meta?.node_id

  return (
    <AreaPage ns="dhcp" page="leases" icon={Clock} family={family} onRefresh={refresh} loading={leases.loading}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-text-tertiary">
          <span data-testid="lease-total">{t('leases.pageCount', { count: leases.items.length, page: cursors.length })}</span>
          {readNode && <span>· {t('leases.readFrom', { node: nameOf(readNode) })}</span>}
          {activity > 0 && (
            <Button variant="warning-soft" size="xs" onClick={refresh} className="ml-auto" data-testid="lease-activity">
              <Lightning size={12} />
              {t('leases.activity', { n: activity })}
            </Button>
          )}
        </div>
        <DataTable
          columns={columns}
          rows={leases.items}
          rowKey={(l) => `${l.node_id}-${l.ip_address}`}
          loading={leases.loading && !query.data}
          animateInserts
          animateRemovals
          highlightChanges={['state', 'expires_at', 'hostname']}
          error={leases.error}
          onRetry={leases.refetch}
          search={{ value: q, onChange: setQ, placeholder: t('leases.search') }}
          filters={[
            { key: 'subnet_id', label: t('fields.subnet'), value: subnetId, onChange: setSubnetId, options: subnetOptions, placeholder: t('leases.allSubnets') },
            { key: 'state', label: t('fields.state'), value: state, onChange: setState, options: stateOptions, placeholder: t('leases.allStates') },
            { key: 'node_id', label: t('fields.node'), value: nodeId, onChange: setNodeId, options: nodeOptions, placeholder: t('leases.localNode') },
          ]}
          onRowClick={open}
          emptyTitle={t('leases.empty')}
          emptyIcon={Clock}
          dense
          testId="leases-table"
        />
        <div className="flex flex-wrap items-center justify-end gap-2 text-xs text-text-tertiary" data-testid="lease-pager">
          <span className="flex items-center gap-1.5" data-testid="lease-limit">
            <span>{t('leases.perPage')}</span>
            <Select
              value={String(limit)}
              onChange={(v) => setLimit(Number(v))}
              options={LIMITS.map((n) => ({ value: String(n), label: String(n) }))}
              variant="filter"
              size="sm"
              ariaLabel={t('leases.perPage')}
            />
          </span>
          <div className="flex items-center gap-0.5">
            <Button
              variant="ghost"
              size="sm"
              className="px-1.5 py-1"
              disabled={cursors.length < 2 || leases.loading}
              onClick={() => setCursors(previousCursor)}
              aria-label={t('leases.previous')}
              title={t('leases.previous')}
              data-testid="lease-prev"
            >
              <CaretLeft size={14} />
            </Button>
            <span className="px-1">{t('leases.page', { page: cursors.length })}</span>
            <Button
              variant="ghost"
              size="sm"
              className="px-1.5 py-1"
              disabled={!leases.meta.next || leases.loading}
              onClick={() => setCursors((stack) => nextCursor(stack, leases.meta.next))}
              aria-label={t('leases.next')}
              title={t('leases.next')}
              data-testid="lease-next"
            >
              <CaretRight size={14} />
            </Button>
          </div>
        </div>
      </div>
      {mobileIp && (
        <Modal open onClose={() => setMobileIp(null)} title={mobileIp}>
          <div className="p-3">
            <LeaseDetail family={family} ip={mobileIp} onDeleted={leases.refetch} />
          </div>
        </Modal>
      )}
    </AreaPage>
  )
}
