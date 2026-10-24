// SPDX-License-Identifier: Apache-2.0
// Kea statistics per server: the server-wide counters (packets, drops) and the address
// counters of each subnet, read with statistic-get-all on every node running the engine.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ChartBar } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { EmptyState } from '../../components/EmptyState'
import { Input } from '../../components/Input'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import { formatCount } from '../dns/instanceStats'
import { AreaPage, SectionError } from './ui'
import { useNodeNames } from './hooks'
import { splitStatistics, subnetColumns } from './keaStats'

function ServerStats({ family, nodeId, name, filter }) {
  const { t, i18n } = useTranslation(['dhcp', 'common'])
  const lang = i18n.language
  const stats = useApi(() => api.dhcp.stats(family, nodeId), [family, nodeId])
  const { global, subnets } = useMemo(() => splitStatistics(stats.data?.statistics), [stats.data])
  const columns = subnetColumns(subnets)
  const q = filter.trim().toLowerCase()
  const shown = global.filter((c) => !q || c.name.includes(q))

  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="dhcp-stats-server">
      <h3 className="text-sm font-semibold text-text-primary">{name}</h3>
      {stats.loading && !stats.data ? (
        <div className="flex justify-center py-4"><LoadingSpinner size="sm" /></div>
      ) : stats.error ? (
        <SectionError error={stats.error} onRetry={stats.refetch} />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="min-w-0">
            <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('stats.server')}</h4>
            {shown.length === 0 ? (
              <p className="text-xs text-text-tertiary">{t('stats.none')}</p>
            ) : (
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 text-xs" data-testid="dhcp-stats-global">
                {shown.map((c) => (
                  <div key={c.name} className="flex justify-between gap-2 min-w-0 border-b border-border-op30 py-0.5">
                    <dt className="font-mono text-text-secondary truncate">{c.name}</dt>
                    <dd className="font-mono text-text-primary">{typeof c.value === 'number' ? formatCount(c.value, lang) : String(c.value ?? '-')}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
          <div className="min-w-0">
            <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('stats.subnets')}</h4>
            {subnets.length === 0 ? (
              <p className="text-xs text-text-tertiary">{t('stats.none')}</p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-xs" data-testid="dhcp-stats-subnets">
                  <thead className="table-header-gradient">
                    <tr>
                      <th className="text-left px-2 py-1.5 text-2xs uppercase tracking-wider text-text-tertiary">{t('fields.subnetId')}</th>
                      {columns.map((c) => (
                        <th key={c} className="text-right px-2 py-1.5 text-2xs uppercase tracking-wider text-text-tertiary">
                          {t(`stats.columns.${c}`, { defaultValue: c })}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {subnets.map((row) => (
                      <tr key={row.id} className="border-t border-border-op30">
                        <td className="px-2 py-1 font-mono text-text-primary">{row.id}</td>
                        {columns.map((c) => (
                          <td key={c} className="px-2 py-1 font-mono text-right text-text-primary">
                            {row.counters[c] === undefined ? '-' : formatCount(row.counters[c], lang)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </Card>
  )
}

export default function StatsPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { nameOf } = useNodeNames()
  const servers = useApi(() => api.dhcp.servers(family), [family])
  const [filter, setFilter] = useState('')
  const [round, setRound] = useState(0)
  const items = servers.data?.items || []

  return (
    <AreaPage
      ns="dhcp"
      page="stats"
      icon={ChartBar}
      family={family}
      loading={servers.loading}
      onRefresh={() => {
        servers.refetch()
        setRound((n) => n + 1)
      }}
    >
      <div className="space-y-4">
        <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t('stats.filter')} aria-label={t('stats.filter')} className="max-w-xs" />
        {servers.loading && !servers.data ? (
          <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
        ) : servers.error ? (
          <SectionError error={servers.error} onRetry={servers.refetch} />
        ) : !items.length ? (
          <EmptyState icon={ChartBar} title={t('stats.noServer')} />
        ) : (
          items.map((s) => <ServerStats key={`${s.node_id}-${round}`} family={family} nodeId={s.node_id} name={nameOf(s.node_id)} filter={filter} />)
        )}
      </div>
    </AreaPage>
  )
}
