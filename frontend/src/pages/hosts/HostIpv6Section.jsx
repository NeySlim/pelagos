// SPDX-License-Identifier: Apache-2.0
// IPv6 part of the host card: the observed addresses of the host (GET /hosts/ipv6?host_key=)
// with class, sources, first and last seen, their AAAA and PTR, and the plan of the proposal.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Plus, Shuffle, Warning } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { ReverseZoneList } from './Ipv6PlanDialogs'
import { CLASS_VARIANT, IPV6_TAB, missingReverseZones, reverseZoneBody, staleAaaa } from './ipv6'
import { ErrorNotice } from '../../components/ErrorNotice'

export function HostIpv6Section({ hostKey, flow, refreshKey = 0 }) {
  const { t } = useTranslation(['ipv6', 'hosts'])
  const { hasPermission } = usePermission()
  const rows = useApi(() => api.ipv6.hosts({ host_key: hostKey, per_page: 10 }), [hostKey, refreshKey])
  const [missing, setMissing] = useState(null)
  const [error, setError] = useState(null)
  const items = rows.data?.items || []
  const canPlan = hasPermission('write:dns.records')

  const createProposal = async (row) => {
    setError(null)
    setMissing(null)
    try {
      await flow.build(() => api.ipv6.plan({ items: [{ host_key: row.host_key, address: row.proposal.address }] }), { rethrow: true })
    } catch (err) {
      const zones = missingReverseZones(err)
      if (zones) setMissing(zones)
      else setError(errorMessage(err))
    }
  }
  const createZone = async (z) => {
    const plan = await flow.build(() => api.ipv6.reverseZonePlan(reverseZoneBody(z)))
    if (plan) setMissing(null)
  }

  if (rows.loading && !rows.data) return <LoadingSpinner size="sm" />
  if (rows.error) return <ErrorNotice error={rows.error} onRetry={rows.refetch} testId="host-ipv6-error" />
  if (!items.length) return <p className="text-text-tertiary" data-testid="host-ipv6-none">{t('card.none')}</p>

  return (
    <div className="space-y-3" data-testid="host-ipv6-rows">
      {items.map((row) => {
        const aaaa = new Set(row.aaaa || [])
        const ptrMissing = new Set(row.ptr_missing || [])
        const ptr = new Set((row.ptr || []).filter((a) => !ptrMissing.has(a)))
        const stale = new Set(staleAaaa(row))
        const unobserved = (row.aaaa || []).filter((a) => !(row.observed || []).some((o) => o.address === a))
        return (
          <div key={row.host_key} className="space-y-2" data-host-key={row.host_key}>
            {row.mac_random && (
              <Badge variant="warning" size="sm" icon={Shuffle} title={t('randomMacHelp')}>
                {t('randomMac')}
              </Badge>
            )}
            {row.observed?.length ? (
              <ul className="space-y-1.5" data-testid="host-ipv6-observed">
                {row.observed.map((o) => (
                  <li key={o.address} className="flex flex-wrap items-center gap-1.5" data-address={o.address} data-class={o.class}>
                    <span className="font-mono break-all text-text-primary">{o.address}</span>
                    <Badge variant={CLASS_VARIANT[o.class] || 'gray'} size="sm" title={t(`classHelp.${o.class}`, { defaultValue: '' })} data-testid="host-ipv6-class">
                      {t(`class.${o.class}`, { defaultValue: o.class })}
                    </Badge>
                    {aaaa.has(o.address) ? (
                      <Badge variant={ptr.has(o.address) ? 'teal' : 'warning'} size="sm" data-testid="host-ipv6-records">
                        {ptr.has(o.address) ? 'AAAA, PTR' : `AAAA, ${t('noPtr')}`}
                      </Badge>
                    ) : (
                      <Badge variant="gray" size="sm" data-testid="host-ipv6-records">{t('noAaaa')}</Badge>
                    )}
                    {o.current === false && <span className="text-2xs text-text-tertiary">{t('card.past')}</span>}
                    <span className="basis-full text-2xs text-text-tertiary" data-testid="host-ipv6-seen">
                      {(o.sources || []).map((s) => t(`source.${s}`, { defaultValue: s })).join(', ')}
                      {' · '}
                      {t('seen', { first: formatDate(o.first_seen), last: formatDate(o.last_seen) })}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-text-tertiary">{t('notObserved')}</p>
            )}
            {unobserved.length > 0 && (
              <p className="text-2xs text-text-secondary" data-testid="host-ipv6-unobserved">
                {t('card.unobserved', { addresses: unobserved.join(', ') })}
                {unobserved.some((a) => stale.has(a)) && (
                  <Badge variant="warning" size="sm" icon={Warning} className="ml-1.5" data-testid="host-ipv6-stale">
                    {t('staleRecord')}
                  </Badge>
                )}
              </p>
            )}
            {row.proposal && (
              <div className="flex flex-wrap items-center gap-2 rounded-md border border-border px-2 py-1.5" data-testid="host-ipv6-proposal">
                <span className="min-w-0 flex-1">
                  {t('card.proposal', { address: row.proposal.address, name: row.proposal.name })}
                  {!row.proposal.reverse_zone && <span className="status-warning-text"> ({t('noReverseZone')})</span>}
                </span>
                {canPlan && (
                  <Button size="xs" variant="secondary" disabled={flow.building} onClick={() => createProposal(row)} data-testid="host-ipv6-create">
                    <Plus size={12} />
                    {t('card.create')}
                  </Button>
                )}
              </div>
            )}
          </div>
        )
      })}
      {missing && (
        <div className="space-y-2 rounded-md border status-warning-border status-warning-bg p-2" data-testid="host-ipv6-missing-zones">
          <p className="status-warning-text">{t('plans.reverse.body')}</p>
          <ReverseZoneList zones={missing} canCreate={hasPermission('write:dns.zones')} building={flow.building} onCreate={createZone} />
        </div>
      )}
      {error && <p className="status-danger-text" role="alert" data-testid="host-ipv6-plan-error">{error}</p>}
      <Link to={`/hosts?tab=${IPV6_TAB}`} className="text-2xs underline text-text-secondary" data-testid="host-ipv6-tab-link">
        {t('card.openTab')}
      </Link>
    </div>
  )
}

export default HostIpv6Section
