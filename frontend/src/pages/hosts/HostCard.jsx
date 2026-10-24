// SPDX-License-Identifier: Apache-2.0
// Host card (FloatingDetailWindow `host`, or a modal on mobile): the lease, the
// reservation and its user-context, the A/AAAA/PTR records and the open
// inconsistencies of one host, with cross actions that build plans on both sides.
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import {
  Desktop, Clock, BookmarkSimple, Globe, Warning, Trash, Plus, ArrowSquareOut, Copy, Check, PencilSimple,
} from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { StatusBadge } from '../../components/StatusBadge'
import { useOpenDetail } from '../../components/FloatingDetailWindow'
import { useMobile } from '../../contexts/MobileContext'
import { useApi } from '../../hooks/useApi'
import { useClipboard } from '../../hooks/useClipboard'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { formatDate } from '../../lib/utils'
import { ClassChips, SectionError, UserContextView } from '../dhcp/ui'
import { usePlanFlow, useNodeNames } from '../dhcp/hooks'
import { absName, reservationTarget, zoneOf } from '../dhcp/lib'
import { hostFacts } from './lib'

function Section({ icon: Icon, title, badge, actions, children, testId }) {
  return (
    <section className="rounded-lg border border-border overflow-hidden" data-testid={testId}>
      <header className="flex items-center gap-2 px-3 py-1.5 section-header-gradient border-b border-border-op30">
        <Icon size={13} className="text-text-tertiary" />
        <h4 className="text-2xs font-semibold uppercase tracking-wider text-text-secondary">{title}</h4>
        {badge}
        <span className="ml-auto flex flex-wrap gap-1">{actions}</span>
      </header>
      <div className="p-3 text-xs">{children}</div>
    </section>
  )
}

function Field({ label, children }) {
  if (children === null || children === undefined || children === '') return null
  return (
    <div className="contents">
      <dt className="text-text-tertiary whitespace-nowrap">{label}</dt>
      <dd className="font-mono text-text-primary break-all">{children}</dd>
    </div>
  )
}

export function HostCard({ hostKey, onChanged }) {
  const { t } = useTranslation(['hosts', 'dhcp', 'common'])
  const navigate = useNavigate()
  const openDetail = useOpenDetail()
  const { isMobile } = useMobile()
  const { hasPermission } = usePermission()
  const { copy, isCopied } = useClipboard()
  const { nameOf } = useNodeNames()
  const host = useApi(() => api.hosts.get(hostKey), [hostKey])
  const canReadDns = hasPermission('read:dns')
  const zones = useApi(() => api.dns.zones(), [], { enabled: canReadDns })
  const flow = usePlanFlow({
    onApplied: () => {
      host.refetch()
      onChanged?.()
    },
  })

  const h = host.data
  const facts = useMemo(() => (h ? hostFacts(h) : null), [h])
  const zoneNames = useMemo(() => (zones.data?.items || []).map((z) => z.zone?.name).filter(Boolean), [zones.data])

  if (host.loading && !h) {
    return (
      <div className="flex justify-center py-8">
        <LoadingSpinner size="md" />
      </div>
    )
  }
  if (host.error) return <SectionError error={host.error} onRetry={host.refetch} />
  if (!h) return null

  const { lease, reservation } = h
  const ip = lease?.ip_address || reservation?.ip_address || reservation?.ip_addresses?.[0] || h.ips[0]
  // The lease carries its family; a reservation alone is v6 when its address is.
  const family = lease?.family || (ip?.includes(':') ? 'v6' : 'v4')
  const canReserve = family === 'v6' ? Boolean(lease?.duid) : Boolean(lease?.hw_address)
  const forwardZone = zoneOf(h.hostname, zoneNames) || (h.hostname ? absName(h.hostname).split('.').slice(1).join('.') : null)
  const zonePath = (name) => `/dns/zones/${encodeURIComponent(String(name).replace(/\.$/, ''))}`

  const deleteLease = () => flow.build(() => api.dhcp.leaseDeletePlan(family, lease.ip_address))
  const deleteReservation = () =>
    flow.build(() => api.dhcp.reservationPlan(family, { op: 'delete', target: reservationTarget(family, reservation), before: reservation, after: null }))
  const reserveLease = () => {
    const after = {
      subnet_id: lease.subnet_id,
      ...(family === 'v6'
        ? { id_type: 'duid', identifier: lease.duid, ip_address: null, ip_addresses: [lease.ip_address] }
        : { id_type: 'hw-address', identifier: lease.hw_address, ip_address: lease.ip_address, ip_addresses: [] }),
      prefixes: [],
      hostname: lease.hostname || (h.hostname ? h.hostname.replace(/\.$/, '') : null),
      client_classes: [],
      options: [],
      next_server: null,
      server_hostname: null,
      boot_file_name: null,
      user_context: {},
      raw: {},
    }
    return flow.build(() => api.dhcp.reservationPlan(family, { op: 'add', target: reservationTarget(family, after), before: null, after }))
  }
  const createRecords = () =>
    flow.build(() =>
      api.hosts.plan({
        hostname: absName(h.hostname),
        ip,
        zone: forwardZone,
        reservation: false,
      }),
    )
  const openLease = () => {
    if (isMobile) navigate(`/dhcp/${family}/leases?q=${encodeURIComponent(lease.ip_address)}`)
    else openDetail('lease', `${family}:${lease.ip_address}`, { family, ip: lease.ip_address, subtitle: h.hostname || undefined })
  }

  return (
    <div className="space-y-3" data-testid="host-card">
      <div className="flex flex-wrap items-center gap-2">
        <Desktop size={18} className="text-accent-pro" />
        <span className="text-sm font-semibold text-text-primary break-all" data-testid="host-name">
          {h.hostname || ip || h.key}
        </span>
        {facts.inconsistent ? (
          <Badge variant="warning" size="sm" icon={Warning} data-testid="host-status">
            {t('hosts:card.issues', { n: h.alerts.length })}
          </Badge>
        ) : (
          <Badge variant="success" size="sm" data-testid="host-status">
            {t('hosts:card.consistent')}
          </Badge>
        )}
      </div>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
        <Field label={t('hosts:fields.key')}>{h.key}</Field>
        <Field label={t('dhcp:fields.mac')}>
          {h.mac && (
            <span className="inline-flex items-center gap-1">
              {h.mac}
              <button type="button" onClick={() => copy(h.mac, 'mac')} className="text-text-tertiary hover:text-text-primary" aria-label={t('common:actions.copy')}>
                {isCopied('mac') ? <Check size={11} className="status-success-text" /> : <Copy size={11} />}
              </button>
            </span>
          )}
        </Field>
        <Field label={t('hosts:fields.ips')}>{h.ips.join(', ')}</Field>
      </dl>

      <Section
        icon={Clock}
        title={t('hosts:card.lease')}
        testId="host-lease"
        badge={lease && <StatusBadge status={lease.state} />}
        actions={
          lease && (
            <>
              <Button variant="ghost" size="xs" onClick={openLease} data-testid="host-open-lease">
                <ArrowSquareOut size={12} />
                {t('hosts:actions.leaseDetails')}
              </Button>
              {hasPermission('ops:dhcp.leases') && (
                <Button variant="danger-soft" size="xs" onClick={deleteLease} disabled={flow.building} data-testid="host-delete-lease">
                  <Trash size={12} />
                  {t('hosts:actions.deleteLease')}
                </Button>
              )}
            </>
          )
        }
      >
        {lease ? (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
            <Field label={t('dhcp:fields.ipAddress')}>{lease.ip_address}</Field>
            <Field label={t('dhcp:fields.hostname')}>{lease.hostname}</Field>
            <Field label={t('dhcp:fields.subnetId')}>{lease.subnet_id}</Field>
            <Field label={t('dhcp:fields.expiresAt')}>{formatDate(lease.expires_at)}</Field>
            <Field label={t('dhcp:fields.ddnsFlags')}>{`${lease.fqdn_fwd ? t('dhcp:leases.fwd') : '-'} / ${lease.fqdn_rev ? t('dhcp:leases.rev') : '-'}`}</Field>
            <Field label={t('dhcp:fields.node')}>{lease.node_id ? nameOf(lease.node_id) : null}</Field>
          </dl>
        ) : (
          <p className="text-text-tertiary">{t('hosts:card.noLease')}</p>
        )}
      </Section>

      <Section
        icon={BookmarkSimple}
        title={t('hosts:card.reservation')}
        testId="host-reservation"
        actions={
          hasPermission('write:dhcp.reservations') &&
          (reservation ? (
            <>
              <Button variant="ghost" size="xs" onClick={() => navigate(`/dhcp/${family}/reservations?q=${encodeURIComponent(reservation.identifier)}`)} data-testid="host-edit-reservation">
                <PencilSimple size={12} />
                {t('hosts:actions.openReservation')}
              </Button>
              <Button variant="danger-soft" size="xs" onClick={deleteReservation} disabled={flow.building} data-testid="host-delete-reservation">
                <Trash size={12} />
                {t('hosts:actions.deleteReservation')}
              </Button>
            </>
          ) : (
            canReserve && (
              <Button variant="secondary" size="xs" onClick={reserveLease} disabled={flow.building} data-testid="host-reserve">
                <Plus size={12} />
                {t('hosts:actions.reserve')}
              </Button>
            )
          ))
        }
      >
        {reservation ? (
          <div className="space-y-2">
            <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
              <Field label={t('dhcp:fields.identifier')}>{`${reservation.id_type} ${reservation.identifier}`}</Field>
              <Field label={t('dhcp:fields.ipAddress')}>{reservation.ip_address || reservation.ip_addresses?.join(', ')}</Field>
              <Field label={t('dhcp:fields.hostname')}>{reservation.hostname}</Field>
              <Field label={t('dhcp:fields.subnetId')}>{reservation.subnet_id}</Field>
            </dl>
            <ClassChips classes={reservation.client_classes} />
            {facts.reservationMismatch && (
              <p className="status-warning-text" data-testid="host-reservation-mismatch">
                {t('hosts:card.reservationMismatch', { reserved: reservation.ip_address, leased: lease.ip_address })}
              </p>
            )}
            <UserContextView context={reservation.user_context} />
          </div>
        ) : (
          <p className="text-text-tertiary">{t('hosts:card.noReservation')}</p>
        )}
      </Section>

      <Section
        icon={Globe}
        title={t('hosts:card.records')}
        testId="host-records"
        actions={
          hasPermission('write:hosts') &&
          !facts.hasForward &&
          h.hostname &&
          ip && (
            <Button variant="secondary" size="xs" onClick={createRecords} disabled={flow.building} data-testid="host-create-records">
              <Plus size={12} />
              {t('hosts:actions.createRecords')}
            </Button>
          )
        }
      >
        {h.records.length === 0 ? (
          <p className="text-text-tertiary">{t('hosts:card.noRecords')}</p>
        ) : (
          <ul className="space-y-1">
            {h.records.map((r) => {
              const zone = zoneOf(r.name, zoneNames) || r.name.split('.').slice(1).join('.')
              return (
                <li key={`${r.name}-${r.rtype}`} className="flex items-center gap-2 font-mono">
                  <Badge variant={r.rtype === 'PTR' ? 'teal' : 'primary'} size="sm">
                    {r.rtype}
                  </Badge>
                  <span className="text-text-primary break-all">{r.name}</span>
                  <span className="text-text-tertiary">{r.ttl}</span>
                  <span className="text-text-secondary break-all">{r.rdata.join(', ')}</span>
                  {canReadDns && zone && (
                    <Button variant="ghost" size="xs" className="ml-auto" onClick={() => navigate(zonePath(zone))} aria-label={t('hosts:actions.openZone')} title={t('hosts:actions.openZone')}>
                      <ArrowSquareOut size={12} />
                    </Button>
                  )}
                </li>
              )
            })}
          </ul>
        )}
        {facts.ptrMismatch && (
          <p className="status-warning-text mt-2" data-testid="host-ptr-mismatch">
            {t('hosts:card.ptrMismatch')}
          </p>
        )}
      </Section>

      <Section icon={Warning} title={t('hosts:card.alerts')} testId="host-alerts" badge={h.alerts.length > 0 && <Badge variant="warning" size="sm">{h.alerts.length}</Badge>}>
        {h.alerts.length === 0 ? (
          <p className="text-text-tertiary">{t('hosts:card.noAlerts')}</p>
        ) : (
          <ul className="space-y-1.5">
            {h.alerts.map((a) => (
              <li key={a.id} className="flex items-start gap-2">
                <StatusBadge status={a.severity} />
                <span className="flex-1 text-text-primary">{a.title}</span>
                <span className="text-text-tertiary font-mono text-2xs">{a.kind}</span>
              </li>
            ))}
          </ul>
        )}
        {h.alerts.length > 0 && hasPermission('read:alerts') && (
          <Button variant="ghost" size="xs" className="mt-2" onClick={() => navigate('/alerts')}>
            {t('hosts:actions.openAlerts')}
          </Button>
        )}
      </Section>
      {flow.modal}
    </div>
  )
}

// Renderer for the floating window: entityId is the host key.
export default function HostWindow({ entityId }) {
  return <HostCard hostKey={entityId} />
}
