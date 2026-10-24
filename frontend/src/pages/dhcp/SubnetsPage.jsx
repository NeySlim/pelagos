// SPDX-License-Identifier: Apache-2.0
// Subnets and pools: one row per subnet with its utilization, a detail panel with
// every pool (and v6 pd-pool) bar, options and user-context, and the subnet plan form.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { Network, Plus, X } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { Card } from '../../components/Card'
import { UtilizationBar } from '../../components/UtilizationBar'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, ClassChips, OptionChips, RowActions, SectionError, UserContextView } from './ui'
import { usePlanFlow } from './hooks'
import { NOTE_KEY, formatDuration, subnetKey } from './lib'
import { SubnetForm } from './SubnetForm'

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
  const [selectedId, setSelectedId] = useState(null)
  const [editing, setEditing] = useState(null)

  const subnets = useApi(() => api.dhcp.subnets(family, { q, shared_network: shared }), [family, q, shared])
  const pools = useApi(() => api.dhcp.utilization(family), [family])
  const networks = useApi(() => api.dhcp.sharedNetworks(family), [family])
  const refresh = () => {
    subnets.refetch()
    pools.refetch()
  }
  const flow = usePlanFlow({ onApplied: refresh })

  const items = useMemo(() => subnets.data?.items || [], [subnets.data])
  const usage = subnets.data?.utilization || {}
  const selected = items.find((s) => s.id === selectedId) || null
  const poolUsage = (subnetId, pool) => (pools.data?.items || []).find((p) => p.subnet_id === subnetId && p.pool === pool)

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
    { key: 'note', label: t('fields.note'), truncate: true, render: (s) => s.user_context?.[NOTE_KEY] || '' },
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
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
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
          onRowClick={(s) => setSelectedId(s.id === selectedId ? null : s.id)}
          selectedKey={selectedId}
          emptyTitle={t('subnets.empty')}
          emptyIcon={Network}
          testId="subnets-table"
        />
        {selected && (
          <SubnetDetail
            family={family}
            subnet={selected}
            usage={usage[selected.id]}
            poolUsage={poolUsage}
            poolsError={pools.error}
            onClose={() => setSelectedId(null)}
            onEdit={canWrite ? () => setEditing({ subnet: selected }) : null}
          />
        )}
      </div>
      {editing && (
        <SubnetForm
          family={family}
          subnet={editing.subnet}
          existing={items}
          sharedNetworks={networks.data?.items || []}
          onClose={() => setEditing(null)}
          flow={flow}
        />
      )}
      {flow.modal}
    </AreaPage>
  )
}

function SubnetDetail({ family, subnet, usage, poolUsage, poolsError, onClose, onEdit }) {
  const { t } = useTranslation(['dhcp', 'common'])
  return (
    <Card className="p-0 overflow-hidden self-start" hover={false} data-testid="subnet-detail">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border section-header-gradient">
        <Network size={16} className="text-accent-pro" />
        <span className="font-mono text-sm font-semibold text-text-primary">{subnet.subnet}</span>
        <Badge variant="outline" size="sm">
          {t('subnets.idLabel', { id: subnet.id })}
        </Badge>
        <span className="ml-auto flex gap-1">
          {onEdit && (
            <Button variant="secondary" size="xs" onClick={onEdit}>
              {t('common:actions.edit')}
            </Button>
          )}
          <Button variant="ghost" size="xs" onClick={onClose} aria-label={t('common:actions.close')}>
            <X size={13} />
          </Button>
        </span>
      </div>
      <div className="p-3 space-y-4 text-xs">
        {usage && <UtilizationBar {...usage} size="lg" />}
        <section>
          <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1.5">{t('fields.pools')}</h4>
          <SectionError error={poolsError} />
          {subnet.pools.length === 0 && <p className="text-text-tertiary">{t('subnets.noPools')}</p>}
          <ul className="space-y-2" data-testid="pool-list">
            {subnet.pools.map((p) => {
              const u = poolUsage(subnet.id, p.pool)
              return (
                <li key={p.pool} className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-text-primary">{p.pool}</span>
                    <ClassChips classes={p.client_classes} />
                    {u?.declined > 0 && (
                      <Badge variant="danger" size="sm">
                        {t('subnets.declined', { n: u.declined })}
                      </Badge>
                    )}
                  </div>
                  {u && <UtilizationBar assigned={u.assigned} total={u.total} percent={u.percent} size="sm" />}
                  {p.options?.length > 0 && <OptionChips options={p.options} />}
                </li>
              )
            })}
          </ul>
        </section>
        {family === 'v6' && (
          <section>
            <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1.5">{t('fields.pdPools')}</h4>
            {!subnet.pd_pools?.length ? (
              <p className="text-text-tertiary">{t('subnets.noPdPools')}</p>
            ) : (
              <ul className="space-y-1" data-testid="pd-pool-list">
                {subnet.pd_pools.map((p) => (
                  <li key={`${p.prefix}/${p.prefix_len}`} className="font-mono text-text-primary">
                    {p.prefix}/{p.prefix_len}
                    <span className="text-text-tertiary"> {t('subnets.delegated', { len: p.delegated_len })}</span>
                    {p.excluded_prefix && <span className="text-text-tertiary"> {t('subnets.excluded', { prefix: `${p.excluded_prefix}/${p.excluded_prefix_len}` })}</span>}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
        <section>
          <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1.5">{t('fields.options')}</h4>
          <OptionChips options={subnet.options} empty={t('subnets.noOptions')} />
        </section>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
          <dt className="text-text-tertiary">{t('fields.validLifetime')}</dt>
          <dd className="font-mono">
            {formatDuration(subnet.valid_lifetime)}
            {(subnet.min_valid_lifetime || subnet.max_valid_lifetime) && (
              <span className="text-text-tertiary">
                {' '}
                ({formatDuration(subnet.min_valid_lifetime)} - {formatDuration(subnet.max_valid_lifetime)})
              </span>
            )}
          </dd>
          {family === 'v6' && (
            <>
              <dt className="text-text-tertiary">{t('fields.preferredLifetime')}</dt>
              <dd className="font-mono">{formatDuration(subnet.preferred_lifetime)}</dd>
            </>
          )}
          <dt className="text-text-tertiary">{t('fields.interface')}</dt>
          <dd className="font-mono">{subnet.interface || '-'}</dd>
          <dt className="text-text-tertiary">{t('fields.relay')}</dt>
          <dd className="font-mono">{subnet.relay?.join(', ') || '-'}</dd>
          <dt className="text-text-tertiary">{t('fields.clientClasses')}</dt>
          <dd>{subnet.client_classes?.length ? <ClassChips classes={subnet.client_classes} /> : '-'}</dd>
          <dt className="text-text-tertiary">{t('fields.ddns')}</dt>
          <dd className="font-mono break-all">
            {Object.keys(subnet.ddns || {}).length ? Object.entries(subnet.ddns).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join(', ') : '-'}
          </dd>
        </dl>
        <section>
          <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1.5">{t('fields.userContext')}</h4>
          <UserContextView context={subnet.user_context} />
        </section>
      </div>
    </Card>
  )
}
