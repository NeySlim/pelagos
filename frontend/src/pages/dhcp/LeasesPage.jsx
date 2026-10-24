// SPDX-License-Identifier: Apache-2.0
// Leases: server-side search and filters (subnet, state, node), paginated; a row
// opens the lease card that compares the copies held by each HA partner.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { Clock, Lightning } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Modal } from '../../components/Modal'
import { StatusBadge } from '../../components/StatusBadge'
import { useOpenDetail } from '../../components/FloatingDetailWindow'
import { useMobile } from '../../contexts/MobileContext'
import { useApi, usePaginatedApi } from '../../hooks/useApi'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { formatDate, formatRelativeTime } from '../../lib/utils'
import { AreaPage } from './ui'
import { useNodeNames } from './hooks'
import { LEASE_STATES, keaEngine, secondsFromNow } from './lib'
import { LeaseDetail } from './LeaseDetail'

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

  const filters = useMemo(() => ({ q, subnet_id: subnetId, state, node_id: nodeId }), [q, subnetId, state, nodeId])
  // `family` sits in the filters so a family switch resets the page; it is not a query parameter.
  const leases = usePaginatedApi(({ family: _family, ...query }) => api.dhcp.leases(family, query), { perPage: 50, filters: { ...filters, family } })
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
    { key: 'state', label: t('fields.state'), render: (l) => <StatusBadge status={l.state} /> },
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
          <span data-testid="lease-total">{t('leases.total', { n: leases.total })}</span>
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
          loading={leases.loading}
          error={leases.error}
          onRetry={leases.refetch}
          search={{ value: q, onChange: setQ, placeholder: t('leases.search') }}
          filters={[
            { key: 'subnet_id', label: t('fields.subnet'), value: subnetId, onChange: setSubnetId, options: subnetOptions, placeholder: t('leases.allSubnets') },
            { key: 'state', label: t('fields.state'), value: state, onChange: setState, options: stateOptions, placeholder: t('leases.allStates') },
            { key: 'node_id', label: t('fields.node'), value: nodeId, onChange: setNodeId, options: nodeOptions, placeholder: t('leases.localNode') },
          ]}
          onRowClick={open}
          pagination={{ page: leases.page, perPage: leases.perPage, total: leases.total, onPageChange: leases.setPage, onPerPageChange: leases.setPerPage }}
          emptyTitle={t('leases.empty')}
          emptyIcon={Clock}
          dense
          testId="leases-table"
        />
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
