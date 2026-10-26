// SPDX-License-Identifier: Apache-2.0
// Rewritten answers: counters per category and per list since the log was first read, and the latest events.
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { DataTable } from '../../components/DataTable'
import { EmptyState } from '../../components/EmptyState'
import { useApi } from '../../hooks/useApi'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatCount } from './rpzHelpers'

const ACTION_VARIANT = { NXDOMAIN: 'danger', NODATA: 'warning', PASSTHRU: 'success' }

export default function RpzActivity({ canWrite }) {
  const { t } = useTranslation(['dns', 'common'])
  const { showError, showSuccess } = useNotification()
  const activity = useApi(() => api.dns.rpzActivity(), [])
  const data = activity.data
  const total = (data?.by_category || []).reduce((n, c) => n + c.hits, 0)
  const noLog = data && data.nodes.every((n) => !n.log)

  const allow = async (name) => {
    try {
      await api.dns.rpzAllow(name, '')
      showSuccess(t('rpzsub.exceptions.allowed', { domain: name }))
    } catch (err) {
      showError(errorMessage(err))
    }
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <div className="flex justify-end">
        <Button variant="secondary" size="sm" onClick={activity.refetch}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      </div>
      {noLog ? (
        <EmptyState title={t('rpzsub.activity.noLog')} description={t('rpzsub.activity.noLogHelp')} />
      ) : (
        <>
          <Card className="p-4" hover={false} data-testid="rpz-by-category">
            <h3 className="font-semibold text-text-primary mb-3">{t('rpzsub.activity.byCategory')}</h3>
            {(data?.by_category || []).length === 0 ? (
              <p className="text-sm text-text-secondary">{t('rpzsub.activity.none')}</p>
            ) : (
              <ul className="space-y-2">
                {data.by_category.map((c) => (
                  <li key={c.category} className="text-sm" data-testid="rpz-category-hits">
                    <div className="flex justify-between">
                      <span>{t(`rpzsub.categories.${c.category}.name`)}</span>
                      <span className="font-mono">{formatCount(c.hits)}</span>
                    </div>
                    <div className="h-1.5 rounded bg-tertiary-op60 mt-1">
                      <div className="h-1.5 rounded bg-accent-primary" style={{ width: `${total ? Math.max(2, (c.hits * 100) / total) : 0}%` }} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <DataTable
            title={t('rpzsub.activity.byList')}
            columns={[
              { key: 'name', label: t('rpzsub.table.list') },
              { key: 'category', label: t('rpzsub.table.category'), render: (r) => (r.category ? t(`rpzsub.categories.${r.category}.name`) : '') },
              { key: 'hits', label: t('rpzsub.activity.hits'), align: 'right', mono: true, render: (r) => formatCount(r.hits) },
            ]}
            rows={data?.by_list || []}
            rowKey="list"
            loading={activity.loading && !data}
            error={activity.error}
            onRetry={activity.refetch}
            emptyTitle={t('rpzsub.activity.none')}
            testId="rpz-by-list"
          />
          <DataTable
            title={t('rpzsub.activity.recent')}
            columns={[
              { key: 'time', label: t('rpzsub.activity.time'), mono: true },
              { key: 'client', label: t('rpzsub.activity.client'), mono: true },
              { key: 'qname', label: t('rpzsub.activity.name'), mono: true },
              { key: 'qtype', label: t('rpzsub.activity.type') },
              { key: 'action', label: t('rpzsub.action'), render: (r) => <Badge variant={ACTION_VARIANT[r.action] || 'default'} size="sm">{r.action}</Badge> },
              { key: 'list', label: t('rpzsub.table.list') },
              { key: 'category', label: t('rpzsub.table.category'), render: (r) => (r.category ? t(`rpzsub.categories.${r.category}.name`) : '') },
              { key: 'rule', label: t('rpzsub.activity.rule'), mono: true },
              {
                key: 'allow',
                label: '',
                align: 'right',
                render: (r) =>
                  canWrite && r.action !== 'PASSTHRU' ? (
                    <Button variant="ghost" size="xs" onClick={() => allow(r.qname)} data-testid="rpz-recent-allow">
                      {t('rpzsub.why.allowIt')}
                    </Button>
                  ) : null,
              },
            ]}
            rows={data?.recent || []}
            rowKey={(r, i) => `${r.time}-${r.qname}-${i}`}
            emptyTitle={t('rpzsub.activity.none')}
            testId="rpz-recent"
          />
        </>
      )}
    </div>
  )
}
