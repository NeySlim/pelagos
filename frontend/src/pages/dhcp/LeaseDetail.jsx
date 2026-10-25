// SPDX-License-Identifier: Apache-2.0
// Lease card: the lease as each node's Kea holds it (GET /leases/{ip}, one item per
// node) side by side, so an HA disagreement or a node missing the lease is visible,
// plus the lease delete plan.
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { CheckCircle, Warning, Trash, Desktop } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { StatusBadge } from '../../components/StatusBadge'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { cn, formatDate } from '../../lib/utils'
import { SectionError, UserContextView } from './ui'
import { usePlanFlow, useNodeNames } from './hooks'
import { leaseAgreement } from './lib'

export function LeaseDetail({ family, ip, onDeleted, compact = false }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const { nameOf } = useNodeNames()
  const lease = useApi(() => api.dhcp.lease(family, ip), [family, ip])
  const servers = useApi(() => api.dhcp.servers(family), [family])
  const flow = usePlanFlow({
    onApplied: () => {
      lease.refetch()
      onDeleted?.()
    },
  })

  const copies = useMemo(() => lease.data?.items || [], [lease.data])
  const expected = useMemo(() => (servers.data?.items || []).map((s) => s.node_id), [servers.data])
  const agreement = useMemo(() => leaseAgreement(copies, expected), [copies, expected])

  if (lease.loading && !lease.data) {
    return (
      <div className="flex justify-center py-8">
        <LoadingSpinner size="md" />
      </div>
    )
  }
  if (lease.error) return <SectionError error={lease.error} onRetry={lease.refetch} />

  const first = copies[0] || {}
  const rows = [
    ['state', t('fields.state'), (l) => <StatusBadge status={l.state} />],
    ['hw_address', t('fields.mac'), (l) => l.hw_address],
    ...(family === 'v6' ? [['duid', t('fields.duid'), (l) => l.duid], ['lease_type', t('fields.leaseType'), (l) => (l.lease_type ? `${l.lease_type}${l.prefix_len ? ` /${l.prefix_len}` : ''}` : null)]] : [['client_id', t('fields.clientId'), (l) => l.client_id]]),
    ['hostname', t('fields.hostname'), (l) => l.hostname],
    ['subnet_id', t('fields.subnetId'), (l) => l.subnet_id],
    ['cltt', t('fields.cltt'), (l) => formatDate(l.cltt)],
    ['expires_at', t('fields.expiresAt'), (l) => formatDate(l.expires_at)],
    ['valid_lft', t('fields.validLifetime'), (l) => `${l.valid_lft} s`],
    ['fqdn', t('fields.ddnsFlags'), (l) => `${l.fqdn_fwd ? t('leases.fwd') : '-'} / ${l.fqdn_rev ? t('leases.rev') : '-'}`],
  ]
  const nodeColumns = agreement.nodes
  const canDelete = hasPermission('ops:dhcp.leases')
  // Each copy is deleted on the node that holds it, so a lease only a peer has is reachable too;
  // without a node the plan reaches every server holding it (HA partner and backups alike).
  const deleteOn = (nodeId) => flow.build(() => api.dhcp.leaseDeletePlan(family, ip, nodeId))

  return (
    <div className={cn('space-y-3 text-xs', compact && 'text-2xs')} data-testid="lease-detail">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-semibold text-text-primary">{ip}</span>
        {agreement.agree ? (
          <Badge variant="success" size="sm" icon={CheckCircle} data-testid="lease-agreement">
            {t('leases.agree', { n: agreement.present.length })}
          </Badge>
        ) : (
          <Badge variant="warning" size="sm" icon={Warning} data-testid="lease-agreement">
            {t('leases.disagree')}
          </Badge>
        )}
        <span className="ml-auto flex gap-1">
          {first.hw_address && (
            <Button variant="ghost" size="xs" onClick={() => navigate(`/hosts?q=${encodeURIComponent(first.hw_address)}`)}>
              <Desktop size={12} />
              {t('leases.openHost')}
            </Button>
          )}
          {canDelete && copies.length === 1 && (
            <Button
              variant="danger-soft"
              size="xs"
              onClick={() => deleteOn(copies[0].node_id)}
              loading={flow.building}
              data-testid="lease-delete"
            >
              <Trash size={12} />
              {t('leases.delete')}
            </Button>
          )}
          {canDelete && copies.length > 1 && (
            <Button variant="danger-soft" size="xs" onClick={() => deleteOn(null)} loading={flow.building} data-testid="lease-delete-all">
              <Trash size={12} />
              {t('leases.deleteAll', { count: copies.length })}
            </Button>
          )}
        </span>
      </div>
      {agreement.missing.length > 0 && (
        <p className="status-warning-text" data-testid="lease-missing">
          {t('leases.missingOn', { nodes: agreement.missing.map(nameOf).join(', ') })}
        </p>
      )}
      <div className="overflow-auto rounded-lg border border-border">
        <table className="w-full">
          <thead className="table-header-gradient">
            <tr>
              <th className="text-left px-2 py-1.5 text-2xs uppercase tracking-wider text-text-tertiary">{t('fields.field')}</th>
              {nodeColumns.map((id) => (
                <th key={id} className="text-left px-2 py-1.5 text-2xs uppercase tracking-wider text-text-tertiary">
                  <span className="inline-flex items-center gap-1">
                    {nameOf(id)}
                    {canDelete && copies.length > 1 && agreement.present.includes(id) && (
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => deleteOn(id)}
                        disabled={flow.building}
                        aria-label={t('leases.deleteOn', { node: nameOf(id) })}
                        title={t('leases.deleteOn', { node: nameOf(id) })}
                        data-testid={`lease-delete-${id}`}
                      >
                        <Trash size={12} />
                      </Button>
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(([field, label, render]) => {
              const differs = agreement.differing.includes(field)
              return (
                <tr key={field} className={cn('border-t border-border-op30', differs && 'status-warning-bg')} data-differs={differs || undefined}>
                  <td className="px-2 py-1 text-text-tertiary whitespace-nowrap">{label}</td>
                  {nodeColumns.map((id) => {
                    const copy = copies.find((l) => l.node_id === id)
                    return (
                      <td key={id} className="px-2 py-1 font-mono text-text-primary break-all">
                        {copy ? (render(copy) ?? '-') : <span className="text-text-tertiary italic">{t('leases.absent')}</span>}
                      </td>
                    )
                  })}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {Object.keys(first.user_context || {}).length > 0 && <UserContextView context={first.user_context} />}
      {flow.modal}
    </div>
  )
}

// Renderer for the floating window: entityId is "<family>:<ip>".
export default function LeaseWindow({ entityId, data }) {
  const family = data?.family || String(entityId).split(':')[0]
  const ip = data?.ip || String(entityId).slice(family.length + 1)
  return <LeaseDetail family={family} ip={ip} />
}
