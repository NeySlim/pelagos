// SPDX-License-Identifier: Apache-2.0
// Consistency exceptions: objects the admin chose to leave as they are (cluster.toml, replicated).
// Each one keeps its author, date and comment; revoking it lets the check raise again.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, EyeSlash, Trash } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge } from '../../components'
import { useApi } from '../../hooks'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { INCONSISTENCY_KINDS } from './lib'

export default function ExceptionsPage() {
  const { t } = useTranslation(['alerts', 'dashboard', 'common'])
  const { hasPermission } = usePermission()
  const { showSuccess, showError, showConfirm } = useNotification()
  const canWrite = hasPermission('write:alerts')
  const [kind, setKind] = useState('')
  const list = useApi(() => api.alerts.exceptions(kind ? { kind } : undefined), [kind])
  const rows = useMemo(() => list.data?.items || [], [list.data])

  const revoke = async (item) => {
    const ok = await showConfirm(t('exceptions.revokeConfirm', { key: item.summary || item.key }), { title: t('exceptions.revoke'), confirmText: t('exceptions.revoke'), variant: 'danger' })
    if (!ok) return
    try {
      await api.alerts.revokeException(item.id)
      showSuccess(t('exceptions.revoked'))
      list.refetch()
    } catch (err) {
      showError(errorMessage(err))
    }
  }

  const columns = [
    { key: 'kind', label: t('columns.kind'), render: (e) => <Badge variant="purple" size="sm">{t(`dashboard:kinds.${e.kind}`, { defaultValue: e.kind })}</Badge> },
    {
      key: 'key',
      label: t('exceptions.object'),
      render: (e) => (
        <span className="block min-w-0 max-w-[24rem]">
          <span className="block truncate text-text-primary">{e.summary || e.key}</span>
          {e.summary && <span className="block truncate font-mono text-2xs text-text-tertiary">{e.key}</span>}
        </span>
      ),
    },
    { key: 'comment', label: t('exceptions.comment'), render: (e) => <span className="text-xs text-text-secondary whitespace-pre-wrap">{e.comment}</span> },
    { key: 'created_by', label: t('exceptions.author'), render: (e) => <span className="text-xs">{e.created_by}</span> },
    { key: 'created_at', label: t('exceptions.date'), render: (e) => <span className="text-xs whitespace-nowrap">{formatDate(e.created_at)}</span> },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (e) => (
            <Button variant="ghost" size="xs" onClick={() => revoke(e)} data-testid="exception-revoke">
              <Trash size={14} />
              {t('exceptions.revoke')}
            </Button>
          ),
        }]
      : []),
  ]

  const kindOptions = [...INCONSISTENCY_KINDS].map((k) => ({ value: k, label: t(`dashboard:kinds.${k}`, { defaultValue: k }) }))

  return (
    <PageLayout
      icon={EyeSlash}
      title={t('exceptions.title')}
      subtitle={t('exceptions.subtitle')}
      testId="page-alert-exceptions"
      actions={
        <Button variant="secondary" size="sm" onClick={list.refetch} disabled={list.loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      <DataTable
        columns={columns}
        rows={rows}
        rowKey="id"
        loading={list.loading && !list.data}
        error={list.error}
        onRetry={list.refetch}
        filters={[{ key: 'kind', label: t('filters.kind'), value: kind, onChange: setKind, options: kindOptions }]}
        emptyTitle={t('exceptions.empty')}
        emptyDescription={t('exceptions.emptyHelp')}
        emptyIcon={EyeSlash}
        testId="exceptions-table"
      />
    </PageLayout>
  )
}
