// SPDX-License-Identifier: Apache-2.0
// Hosts: the lease / reservation / records join, filtered on the server (search,
// subnet, zone, inconsistent only) with chips; a row opens the host card, and the
// create-host plan adds the A and PTR records and, optionally, a reservation.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { Desktop, Plus, Warning, BookmarkSimple, Clock } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { DataTable } from '../../components/DataTable'
import { Modal } from '../../components/Modal'
import { StatusBadge } from '../../components/StatusBadge'
import { useOpenDetail } from '../../components/FloatingDetailWindow'
import { useMobile } from '../../contexts/MobileContext'
import { useApi, usePaginatedApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { cn } from '../../lib/utils'
import { AreaPage } from '../dhcp/ui'
import { usePlanFlow } from '../dhcp/hooks'
import { HostCard } from './HostCard'
import { CreateHostModal } from './CreateHostModal'
import { hostFacts } from './lib'

function Chip({ active, onClick, children, testId }) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      aria-pressed={active}
      className={cn(
        'inline-flex items-center gap-1 px-2.5 py-1 rounded-full border text-xs transition-colors',
        active ? 'border-accent-pro status-purple-border bg-tertiary-op60 text-text-primary' : 'border-border text-text-secondary hover:bg-tertiary-op40',
      )}
    >
      {children}
    </button>
  )
}

export default function HostsPage() {
  const { t } = useTranslation(['hosts', 'dhcp', 'common'])
  const [params] = useSearchParams()
  const { hasPermission } = usePermission()
  const { isMobile } = useMobile()
  const openDetail = useOpenDetail()
  const [q, setQ] = useState(params.get('q') || '')
  const [subnetId, setSubnetId] = useState('')
  const [zone, setZone] = useState('')
  const [onlyInconsistent, setOnlyInconsistent] = useState(params.get('only_inconsistent') === 'true')
  const [mobileKey, setMobileKey] = useState(null)
  const [creating, setCreating] = useState(false)

  const hosts = usePaginatedApi((p) => api.hosts.list(p), {
    perPage: 50,
    filters: { q, subnet_id: subnetId, zone, only_inconsistent: onlyInconsistent || undefined },
  })
  const subnets = useApi(() => api.dhcp.subnets('v4'), [], { enabled: hasPermission('read:dhcp') })
  const zones = useApi(() => api.dns.zones(), [], { enabled: hasPermission('read:dns') })
  const flow = usePlanFlow({ onApplied: hosts.refetch })

  const open = (host) => {
    if (isMobile) setMobileKey(host.key)
    else openDetail('host', host.key, { title: host.hostname || host.ips[0] || host.key, subtitle: host.mac || undefined })
  }

  const columns = [
    {
      key: 'hostname',
      label: t('dhcp:fields.hostname'),
      render: (h) => <span className="font-medium">{h.hostname || <span className="text-text-tertiary italic">{t('list.noName')}</span>}</span>,
    },
    { key: 'ips', label: t('fields.ips'), mono: true, render: (h) => h.ips.join(', ') },
    { key: 'mac', label: t('dhcp:fields.mac'), mono: true, render: (h) => h.mac || '-' },
    {
      key: 'lease',
      label: t('card.lease'),
      render: (h) => (h.lease ? <StatusBadge status={h.lease.state} /> : <span className="text-text-tertiary">-</span>),
    },
    {
      key: 'join',
      label: t('list.join'),
      render: (h) => {
        const f = hostFacts(h)
        return (
          <span className="inline-flex gap-1" data-testid="host-join">
            <Badge variant={f.hasLease ? 'purple' : 'gray'} size="sm" icon={Clock} title={t('card.lease')}>
              {t('list.lease')}
            </Badge>
            <Badge variant={f.hasReservation ? 'purple' : 'gray'} size="sm" icon={BookmarkSimple} title={t('card.reservation')}>
              {t('list.reservation')}
            </Badge>
            <Badge variant={f.hasForward ? 'primary' : 'gray'} size="sm">A</Badge>
            <Badge variant={f.hasPtr ? 'teal' : 'gray'} size="sm">PTR</Badge>
          </span>
        )
      },
    },
    {
      key: 'alerts',
      label: t('card.alerts'),
      render: (h) =>
        h.alerts.length ? (
          <Badge variant={h.alerts.some((a) => a.severity === 'critical') ? 'danger' : 'warning'} size="sm" icon={Warning}>
            {h.alerts.length}
          </Badge>
        ) : (
          ''
        ),
    },
  ]

  const subnetOptions = (subnets.data?.items || []).map((s) => ({ value: String(s.id), label: `${s.id}: ${s.subnet}` }))
  const zoneOptions = (zones.data?.items || [])
    .map((z) => z.zone?.name)
    .filter((name) => name && !name.endsWith('.arpa.'))
    .map((name) => ({ value: name, label: name }))

  return (
    <AreaPage
      ns="hosts"
      page="list"
      icon={Desktop}
      onRefresh={hosts.refetch}
      loading={hosts.loading}
      actions={
        hasPermission('write:hosts') && (
          <Button size="sm" onClick={() => setCreating(true)} data-testid="host-create">
            <Plus size={14} />
            {t('create.button')}
          </Button>
        )
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2" data-testid="host-facets">
          <Chip active={!onlyInconsistent} onClick={() => setOnlyInconsistent(false)} testId="facet-all">
            {t('list.all')}
          </Chip>
          <Chip active={onlyInconsistent} onClick={() => setOnlyInconsistent(true)} testId="facet-inconsistent">
            <Warning size={12} />
            {t('list.inconsistent')}
          </Chip>
          <span className="ml-auto text-xs text-text-tertiary" data-testid="host-total">
            {t('list.total', { n: hosts.total })}
          </span>
        </div>
        <DataTable
          columns={columns}
          rows={hosts.items}
          rowKey="key"
          loading={hosts.loading}
          error={hosts.error}
          onRetry={hosts.refetch}
          search={{ value: q, onChange: setQ, placeholder: t('list.search') }}
          filters={[
            ...(subnetOptions.length ? [{ key: 'subnet_id', label: t('dhcp:fields.subnet'), value: subnetId, onChange: setSubnetId, options: subnetOptions, placeholder: t('list.allSubnets') }] : []),
            ...(zoneOptions.length ? [{ key: 'zone', label: t('fields.zone'), value: zone, onChange: setZone, options: zoneOptions, placeholder: t('list.allZones') }] : []),
          ]}
          onRowClick={open}
          rowClassName={(h) => (h.alerts.length ? 'border-l-2 border-l-accent-warning' : undefined)}
          pagination={{ page: hosts.page, perPage: hosts.perPage, total: hosts.total, onPageChange: hosts.setPage, onPerPageChange: hosts.setPerPage }}
          emptyTitle={onlyInconsistent ? t('list.emptyInconsistent') : t('list.empty')}
          emptyIcon={Desktop}
          testId="hosts-table"
        />
      </div>
      {mobileKey && (
        <Modal open onClose={() => setMobileKey(null)} title={t('card.title')}>
          <div className="p-3">
            <HostCard hostKey={mobileKey} onChanged={hosts.refetch} />
          </div>
        </Modal>
      )}
      {creating && (
        <CreateHostModal
          subnets={subnets.data?.items || []}
          zones={zones.data?.items || []}
          flow={flow}
          onClose={() => setCreating(false)}
        />
      )}
      {flow.modal}
    </AreaPage>
  )
}
