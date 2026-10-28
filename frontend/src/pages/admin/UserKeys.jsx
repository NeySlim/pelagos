// SPDX-License-Identifier: Apache-2.0
// Administration of security keys: a user's keys with removal (one or all), and
// the banner with the cluster's rpId, warning when the nodes share no domain.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Fingerprint, Trash, Warning } from '@phosphor-icons/react'
import { Modal, Button, Badge } from '../../components'
import { useApi } from '../../hooks'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'

export function WebAuthnStatus() {
  const { t } = useTranslation('admin')
  const q = useApi(() => api.admin.webauthn().catch(() => null), [])
  const st = q.data
  if (!st) return null
  const outside = (st.nodes || []).filter((n) => !n.covered).map((n) => n.name)
  return (
    <div
      className={`mb-3 rounded-lg border px-3 py-2 text-xs flex items-start gap-2 ${st.warning ? 'status-warning-border status-warning-bg status-warning-text' : 'border-border text-text-secondary'}`}
      role="status"
      data-testid="webauthn-status"
      data-warning={st.warning || ''}
    >
      {st.warning ? <Warning size={16} className="shrink-0" /> : <Fingerprint size={16} className="shrink-0 text-accent-primary" />}
      <span>
        {st.rp_id ? t(`users.rp.${st.source}`, { rp: st.rp_id }) : t('users.rp.request_host')}
        {st.warning && ` ${t(`users.rp.warning.${st.warning}`, { nodes: outside.join(', ') })}`}
      </span>
    </div>
  )
}

export function UserKeys({ user, onClose, onChanged }) {
  const { t } = useTranslation(['admin', 'common'])
  const { showSuccess, showError } = useNotification()
  const q = useApi(() => api.admin.userKeys(user.id), [user.id])
  const [busy, setBusy] = useState(false)
  const items = q.data?.items || []

  const run = async (fn, message) => {
    setBusy(true)
    try {
      await fn()
      showSuccess(message)
      q.refetch()
      onChanged()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open onClose={onClose} title={t('users.keysTitle', { name: user.username })} size="md">
      <div className="p-4 space-y-3" data-testid="user-keys-modal">
        <p className="text-xs text-text-secondary">{t('users.keysHelp')}</p>
        {items.length === 0 && !q.loading && <p className="text-xs text-text-tertiary">{t('users.keysNone')}</p>}
        <ul className="divide-y divide-border">
          {items.map((k) => (
            <li key={k.id} className="flex items-center gap-3 py-2" data-testid="user-key-row">
              <Fingerprint size={16} className="text-accent-primary shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-text-primary truncate">
                  {k.name} {k.backup_eligible && <Badge size="sm" variant="secondary">{t('users.keysSynced')}</Badge>}
                </div>
                <div className="text-2xs text-text-tertiary">
                  {t('users.keysMeta', { rp: k.rp_id, created: formatDate(k.created_at), used: k.last_used_at ? formatDate(k.last_used_at) : t('users.never') })}
                </div>
              </div>
              <Button size="xs" variant="ghost" disabled={busy} title={t('common:actions.delete')} onClick={() => run(() => api.admin.removeUserKey(user.id, k.id), t('users.keyRemoved', { name: k.name }))} data-testid="user-key-remove">
                <Trash size={14} className="status-danger-text" />
              </Button>
            </li>
          ))}
        </ul>
        {items.length > 1 && (
          <Button size="sm" variant="danger-soft" loading={busy} onClick={() => run(() => api.admin.removeUserKeys(user.id), t('users.keysRemoved', { name: user.username }))} data-testid="user-keys-remove-all">
            {t('users.keysRemoveAll')}
          </Button>
        )}
      </div>
    </Modal>
  )
}
