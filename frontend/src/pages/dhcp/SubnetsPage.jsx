// SPDX-License-Identifier: Apache-2.0
// Subnets and pools: one row per subnet with its utilization, a floating detail window
// (SubnetDetail) with every pool bar, and the subnet plan form.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { Network, Plus } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { Modal } from '../../components/Modal'
import { useOpenDetail } from '../../components/FloatingDetailWindow'
import { UtilizationBar } from '../../components/UtilizationBar'
import { useMobile } from '../../contexts/MobileContext'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, RowActions } from './ui'
import { usePlanFlow } from './hooks'
import { noteOf, formatDuration, subnetKey } from './lib'
import { SubnetForm } from './SubnetForm'
import { SubnetDetail } from './SubnetDetail'

function ipSortValue(subnet) {
  const addr = String(subnet || '').split('/')[0]
  if (addr.includes('.')) return addr.split('.').reduce((acc, p) => acc * 256 + Number(p), 0)
  return addr
}

export default function SubnetsPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.subnets')
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState('')
  const shared = params.get('shared_network') || ''
  const [mobileId, setMobileId] = useState(null)
  const { isMobile } = useMobile()
  const openDetail = useOpenDetail()
  const [editing, setEditing] = useState(null)

  const subnets = useApi(() => api.dhcp.subnets(family, { q, shared_network: shared }), [family, q, shared])
  const pools = useApi(() => api.dhcp.utilization(family), [family])
  const networks = useApi(() => api.dhcp.sharedNetworks(family), [family])
  // Ids are unique per family: the form checks them against the unfiltered list.
  const filtered = Boolean(q || shared)
  const allSubnets = useApi(() => api.dhcp.subnets(family), [family], { enabled: filtered })
  const refresh = () => {
    subnets.refetch()
    if (filtered) allSubnets.refetch()
    pools.refetch()
  }
  const flow = usePlanFlow({ onApplied: refresh })

  const items = useMemo(() => subnets.data?.items || [], [subnets.data])
  const usage = subnets.data?.utilization || {}

  // The detail window sends "Edit" here as ?edit=<id>; open the form once the list is in.
  const editId = params.get('edit')
  useEffect(() => {
    if (!editId || !canWrite || !subnets.data) return
    const target = items.find((s) => String(s.id) === editId)
    if (target) setEditing({ subnet: target })
    const next = new URLSearchParams(params)
    next.delete('edit')
    setParams(next, { replace: true })
  }, [editId, canWrite, subnets.data, items, params, setParams])

  const open = (s) => {
    if (isMobile) setMobileId(s.id)
    else openDetail('subnet', `${family}:${s.id}`, { family, id: s.id, title: s.subnet, subtitle: t('subnets.idLabel', { id: s.id }) }, { wide: true })
  }

  const setShared = (value) => {
    const next = new URLSearchParams(params)
    if (value) next.set('shared_network', value)
    else next.delete('shared_network')
    setParams(next, { replace: true })
  }

  const remove = (subnet) =>
    flow.build(() => api.dhcp.subnetPlan(family, { op: 'delete', target: `${subnetKey(family)}/${subnet.id}`, before: subnet, after: null }))

  const columns = [
    { key: 'id', label: t('fields.id'), sortable: true, mono: true, width: 60 },
    { key: 'subnet', label: t('fields.subnet'), sortable: true, mono: true, sortValue: (s) => ipSortValue(s.subnet) },
    {
      key: 'shared_network',
      label: t('fields.sharedNetwork'),
      sortable: true,
      render: (s) => (s.shared_network ? <Badge variant="outline" size="sm">{s.shared_network}</Badge> : <span className="text-text-tertiary">-</span>),
    },
    {
      key: 'pools',
      label: t('fields.pools'),
      render: (s) => (
        <span className="text-xs text-text-secondary whitespace-nowrap">
          {t('subnets.poolCount', { n: s.pools.length })}
          {family === 'v6' && s.pd_pools?.length > 0 && <> · {t('subnets.pdPoolCount', { n: s.pd_pools.length })}</>}
        </span>
      ),
    },
    {
      key: 'usage',
      label: t('fields.utilization'),
      width: 180,
      sortable: true,
      sortValue: (s) => usage[s.id]?.percent ?? -1,
      render: (s) => (usage[s.id] ? <UtilizationBar {...usage[s.id]} size="sm" /> : <span className="text-text-tertiary">-</span>),
    },
    { key: 'valid_lifetime', label: t('fields.validLifetime'), render: (s) => formatDuration(s.valid_lifetime) },
    {
      key: 'interface',
      label: t('fields.link'),
      render: (s) => <span className="font-mono text-xs">{s.interface || (s.relay?.length ? t('subnets.relay', { list: s.relay.join(', ') }) : '-')}</span>,
    },
    { key: 'note', label: t('fields.note'), truncate: true, width: 220, render: (s) => noteOf(s.user_context) },
    ...(canWrite
      ? [
          {
            key: 'actions',
            label: '',
            align: 'right',
            render: (s) => (
              <RowActions
                editLabel={t('common:actions.edit')}
                deleteLabel={t('common:actions.delete')}
                onEdit={() => setEditing({ subnet: s })}
                onDelete={() => remove(s)}
              />
            ),
          },
        ]
      : []),
  ]

  const networkOptions = [
    { value: '', label: t('subnets.allNetworks') },
    ...(networks.data?.items || []).map((n) => ({ value: n.name, label: n.name })),
  ]

  return (
    <AreaPage
      ns="dhcp"
      page="subnets"
      icon={Network}
      family={family}
      onRefresh={refresh}
      loading={subnets.loading}
      actions={
        canWrite && (
          <Button size="sm" onClick={() => setEditing({ subnet: null })} data-testid="subnet-create">
            <Plus size={14} />
            {t('subnets.create')}
          </Button>
        )
      }
    >
      <DataTable
        columns={columns}
        rows={items}
        rowKey="id"
        loading={subnets.loading}
        error={subnets.error}
        onRetry={subnets.refetch}
        clientSort
        search={{ value: q, onChange: setQ, placeholder: t('subnets.search') }}
        filters={[{ key: 'shared_network', label: t('fields.sharedNetwork'), value: shared, onChange: setShared, options: networkOptions.slice(1), placeholder: t('subnets.allNetworks') }]}
        onRowClick={open}
        mobileCard={{
          title: (s) => s.subnet,
          subtitle: (s) => t('subnets.idLabel', { id: s.id }),
          fields: ['pools', 'usage', 'valid_lifetime'],
        }}
        emptyTitle={t('subnets.empty')}
        emptyIcon={Network}
        testId="subnets-table"
      />
      {mobileId !== null && (
        <Modal open onClose={() => setMobileId(null)} title={t('subnets.openDetail', { subnet: items.find((s) => s.id === mobileId)?.subnet || mobileId })}>
          <div className="p-3">
            <SubnetDetail family={family} id={mobileId} onClose={() => setMobileId(null)} />
          </div>
        </Modal>
      )}
      {editing && (
        <SubnetForm
          family={family}
          subnet={editing.subnet}
          existing={filtered ? allSubnets.data?.items || items : items}
          sharedNetworks={networks.data?.items || []}
          onClose={() => setEditing(null)}
          flow={flow}
        />
      )}
      {flow.modal}
    </AreaPage>
  )
}
