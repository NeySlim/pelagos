// SPDX-License-Identifier: Apache-2.0
// Subnet card shown in a floating window (or a modal on a phone): utilization, every pool
// with its declined leases, options, lifetimes. Notes and user-context stay folded.
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { Button } from '../../components/Button'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { UtilizationBar } from '../../components/UtilizationBar'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { ClassChips, OptionChips, SectionError, UserContextView } from './ui'
import { formatDuration, leasesHref } from './lib'

const H = 'ui-label text-2xs uppercase tracking-wider text-text-tertiary mb-1.5'

export function SubnetDetail({ family, id, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.subnets')
  const subnets = useApi(() => api.dhcp.subnet(family, id), [family, id])
  const pools = useApi(() => api.dhcp.utilization(family), [family])
  // An applied plan may have changed this subnet: read it again.
  useWsTopic('plans', () => {
    subnets.refetch()
    pools.refetch()
  })

  if (subnets.loading && !subnets.data) {
    return (
      <div className="flex justify-center py-8">
        <LoadingSpinner size="md" />
      </div>
    )
  }
  if (subnets.error) return <SectionError error={subnets.error} onRetry={subnets.refetch} />
  const subnet = subnets.data
  if (!subnet) return <p className="p-3 text-xs text-text-tertiary">{t('subnets.notFound')}</p>
  const own = (pools.data?.items || []).filter((p) => p.subnet_id === subnet.id)
  const assigned = own.reduce((n, p) => n + (p.assigned || 0), 0)
  const total = own.reduce((n, p) => n + (p.total || 0), 0)
  const usage = own.length ? { assigned, total, percent: total ? Math.round((assigned / total) * 1000) / 10 : 0 } : null
  const poolUsage = (pool) => (pools.data?.items || []).find((p) => p.subnet_id === subnet.id && p.pool === pool)
  const edit = () => {
    onClose?.()
    navigate(`/dhcp/${family}/subnets?edit=${subnet.id}`)
  }

  return (
    <div className="space-y-4 text-xs" data-testid="subnet-detail">
      {canWrite && (
        <div className="flex justify-end">
          <Button variant="secondary" size="xs" onClick={edit} data-testid="subnet-detail-edit">
            {t('common:actions.edit')}
          </Button>
        </div>
      )}
      {usage && <UtilizationBar {...usage} size="lg" />}
      <section>
        <h4 className={H}>{t('fields.pools')}</h4>
        <SectionError error={pools.error} />
        {subnet.pools.length === 0 && <p className="text-text-tertiary">{t('subnets.noPools')}</p>}
        <ul className="space-y-2" data-testid="pool-list">
          {subnet.pools.map((p) => {
            const u = poolUsage(p.pool)
            return (
              <li key={p.pool} className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-text-primary">{p.pool}</span>
                  <ClassChips classes={p.client_classes} />
                  {u?.declined > 0 && (
                    <Link
                      to={leasesHref(family, subnet.id, 'declined')}
                      className="text-accent-danger hover:underline"
                      title={t('subnets.declinedLeases')}
                      data-testid="pool-declined"
                    >
                      {t('subnets.declined', { n: u.declined })}
                    </Link>
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
          <h4 className={H}>{t('fields.pdPools')}</h4>
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
        <h4 className={H}>{t('fields.options')}</h4>
        <OptionChips options={subnet.options} empty={t('subnets.noOptions')} />
      </section>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
        <dt className="text-text-tertiary">{t('fields.validLifetime')}</dt>
        <dd className="font-mono">{formatDuration(subnet.valid_lifetime)}</dd>
        <dt className="text-text-tertiary">{t('fields.minValidLifetime')}</dt>
        <dd className="font-mono">{formatDuration(subnet.min_valid_lifetime)}</dd>
        <dt className="text-text-tertiary">{t('fields.maxValidLifetime')}</dt>
        <dd className="font-mono">{formatDuration(subnet.max_valid_lifetime)}</dd>
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
      <details data-testid="subnet-notes">
        <summary className={`${H} cursor-pointer select-none`}>{t('subnets.notes')}</summary>
        <UserContextView context={subnet.user_context} />
      </details>
    </div>
  )
}

export default SubnetDetail
