// SPDX-License-Identifier: Apache-2.0
// Every API token of the cluster (section 16): owner, permissions, expiry, last use on any node,
// allowed sources, revocation. Secrets are never shown here: only the creator saw them, once.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, Code, Trash } from '@phosphor-icons/react'
import { Badge, Button, ConfirmDialog, DataTable, PageLayout } from '../../components'
import { useApi } from '../../hooks'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'

export default function ApiTokensPage() {
  const { t } = useTranslation(['admin', 'common'])
  const { showSuccess, showError } = useNotification()
  const tokensQ = useApi(() => api.admin.tokens(), [])
  const [revoking, setRevoking] = useState(null)
  const [busy, setBusy] = useState(false)
  const unavailable = tokensQ.data?.meta?.unavailable || []

  const revoke = async () => {
    setBusy(true)
    try {
      await api.admin.revokeToken(revoking.id)
      showSuccess(t('tokens.revoked', { name: revoking.name }))
      setRevoking(null)
      tokensQ.refetch()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const columns = [
    { key: 'username', label: t('tokens.owner'), sortable: true },
    { key: 'name', label: t('tokens.name'), sortable: true, render: (r) => <span className="font-medium" data-testid="admin-token-name">{r.name}</span> },
    {
      key: 'permissions',
      label: t('tokens.permissions'),
      render: (r) => (r.role ? <Badge size="sm" variant="secondary">{r.role}</Badge> : <span className="text-xs">{r.permissions.join(', ')}</span>),
    },
    {
      key: 'expires_at',
      label: t('tokens.expires'),
      sortable: true,
      render: (r) => (r.expired ? <Badge size="sm" variant="danger">{t('tokens.expired')}</Badge> : <span className="text-xs">{formatDate(r.expires_at)}</span>),
    },
    {
      key: 'last_used_at',
      label: t('tokens.lastUsed'),
      render: (r) => <span className="text-xs">{r.last_used_at ? `${formatDate(r.last_used_at)} (${r.last_used_node || '?'})` : t('tokens.never')}</span>,
    },
    { key: 'cidrs', label: t('tokens.sources'), render: (r) => <span className="text-xs">{r.cidrs?.length ? r.cidrs.join(', ') : t('tokens.any')}</span> },
    { key: 'created_at', label: t('tokens.created'), sortable: true, render: (r) => <span className="text-xs">{formatDate(r.created_at)}</span> },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (r) => (
        <Button size="xs" variant="ghost" title={t('tokens.revoke')} onClick={() => setRevoking(r)} data-testid="admin-token-revoke">
          <Trash size={14} className="status-danger-text" />
        </Button>
      ),
    },
  ]

  return (
    <PageLayout
      icon={Code}
      title={t('pages.tokens.title')}
      subtitle={t('pages.tokens.subtitle')}
      testId="page-admin-tokens"
      actions={
        <Button variant="secondary" size="sm" onClick={tokensQ.refetch} disabled={tokensQ.loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      {unavailable.length > 0 && <p className="text-xs status-warning-text mb-2" role="status">{t('tokens.unavailable', { nodes: unavailable.join(', ') })}</p>}
      <DataTable
        columns={columns}
        rows={tokensQ.data?.items || []}
        loading={tokensQ.loading}
        error={tokensQ.error}
        onRetry={tokensQ.refetch}
        clientSort
        emptyTitle={t('tokens.empty')}
        testId="admin-tokens-table"
      />
      <ConfirmDialog
        open={Boolean(revoking)}
        onOpenChange={(o) => !o && setRevoking(null)}
        onConfirm={revoke}
        loading={busy}
        title={t('tokens.revokeTitle', { name: revoking?.name, user: revoking?.username })}
        message={t('tokens.revokeHelp')}
        confirmLabel={t('tokens.revoke')}
      />
    </PageLayout>
  )
}
