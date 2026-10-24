// SPDX-License-Identifier: Apache-2.0
// BIND instances: one card per node with rndc status and the statistics-channel counters
// (queries, responses, rcodes, query types, resolver validation, memory) of that node.
import { useTranslation } from 'react-i18next'
import { ChartBar, ArrowsClockwise } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { EmptyState } from '../../components/EmptyState'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { KeyValue } from './common'
import { useNodeNames } from './helpers'
import { formatBytes, formatCount, formatPercent, headlineCounters, topCounters, uptimeSeconds } from './instanceStats'

const HEADLINES = ['queries', 'responses', 'recursive', 'updates', 'updateFailures', 'transfers', 'validated', 'validationFailures']

function CounterList({ title, items, language, testId }) {
  const { t } = useTranslation('dns')
  return (
    <div className="min-w-0" data-testid={testId}>
      <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{title}</h4>
      {items.length === 0 ? (
        <p className="text-xs text-text-tertiary">{t('instances.noCounters')}</p>
      ) : (
        <ul className="space-y-0.5">
          {items.map((c) => (
            <li key={c.name} className="flex items-center gap-2 text-xs">
              <span className="font-mono text-text-primary w-24 shrink-0 truncate">{c.name}</span>
              <span className="flex-1 h-1.5 rounded bg-bg-tertiary overflow-hidden" aria-hidden="true">
                <span className="block h-full bg-accent-primary" style={{ width: `${Math.max(2, c.share * 100)}%` }} />
              </span>
              <span className="font-mono text-text-secondary text-right w-28 shrink-0">
                {formatCount(c.value, language)} ({formatPercent(c.share, language)})
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function InstanceCard({ item, nameOf }) {
  const { t, i18n } = useTranslation(['dns', 'common'])
  const lang = i18n.language
  const stats = useApi(() => api.dns.stats(item.node_id), [item.node_id])
  const caps = item.capabilities || {}
  const s = stats.data
  const counters = headlineCounters(s)
  const uptime = uptimeSeconds(s)
  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="dns-instance">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-text-primary">{nameOf(item.node_id)}</h3>
        <Badge variant={caps.running ? 'success' : 'danger'} size="sm">
          {caps.running ? t('instances.running') : t('instances.stopped')}
        </Badge>
        {(s?.version || caps.version) && <span className="text-xs font-mono text-text-secondary">BIND {s?.version || caps.version}</span>}
        {!caps.statistics_channel && <Badge variant="warning" size="sm">{t('instances.noChannel')}</Badge>}
      </div>

      {stats.loading && !s ? (
        <div className="flex justify-center py-4"><LoadingSpinner size="sm" /></div>
      ) : stats.error ? (
        <p className="text-xs status-danger-text" role="alert">{errorMessage(stats.error)}</p>
      ) : (
        <>
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3" data-testid="dns-instance-counters">
            {HEADLINES.map((key) => (
              <KeyValue key={key} label={t(`instances.counters.${key}`)} mono>
                {formatCount(counters[key], lang)}
              </KeyValue>
            ))}
          </dl>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <CounterList title={t('instances.rcodes')} items={topCounters(s?.rcodes)} language={lang} testId="dns-instance-rcodes" />
            <CounterList title={t('instances.qtypes')} items={topCounters(s?.qtypes)} language={lang} testId="dns-instance-qtypes" />
          </div>
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KeyValue label={t('instances.memoryInUse')} mono>{s?.memory?.InUse !== undefined ? formatBytes(s.memory.InUse, lang) : null}</KeyValue>
            <KeyValue label={t('instances.memoryTotal')} mono>{s?.memory?.TotalUse !== undefined ? formatBytes(s.memory.TotalUse, lang) : null}</KeyValue>
            <KeyValue label={t('instances.bootTime')}>{s?.boot_time ? formatDate(s.boot_time) : null}</KeyValue>
            <KeyValue label={t('instances.uptime')}>{uptime === null ? null : t('instances.uptimeValue', { days: Math.floor(uptime / 86400), hours: Math.floor((uptime % 86400) / 3600) })}</KeyValue>
            <KeyValue label={t('instances.configTime')}>{s?.config_time ? formatDate(s.config_time) : null}</KeyValue>
            <KeyValue label={t('instances.collectedAt')}>{s?.collected_at ? formatDate(s.collected_at) : null}</KeyValue>
          </dl>
        </>
      )}

      {Object.keys(item.status || {}).length > 0 && (
        <div>
          <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('instances.rndcStatus')}</h4>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 text-xs" data-testid="dns-instance-status">
            {Object.entries(item.status).map(([k, v]) => (
              <div key={k} className="flex gap-2 min-w-0">
                <dt className="text-text-tertiary shrink-0">{k}</dt>
                <dd className="font-mono text-text-primary truncate">{String(v)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </Card>
  )
}

export default function InstancesPage() {
  const { t } = useTranslation(['dns', 'common'])
  const { nameOf } = useNodeNames()
  const instances = useApi(() => api.dns.instances(), [])
  const items = instances.data?.items || []
  return (
    <PageLayout
      icon={ChartBar}
      title={t('pages.instances.title')}
      subtitle={t('pages.instances.subtitle')}
      testId="page-dns-instances"
      actions={
        <Button variant="secondary" size="sm" onClick={instances.refetch} disabled={instances.loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      {instances.loading && !instances.data ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : instances.error ? (
        <EmptyState icon={ChartBar} title={errorMessage(instances.error)} action={{ label: t('common:actions.retry'), onClick: instances.refetch }} />
      ) : !items.length ? (
        <EmptyState icon={ChartBar} title={t('instances.empty')} />
      ) : (
        <div className="space-y-4">
          {items.map((item) => (
            <InstanceCard key={item.node_id} item={item} nameOf={nameOf} />
          ))}
        </div>
      )}
    </PageLayout>
  )
}
