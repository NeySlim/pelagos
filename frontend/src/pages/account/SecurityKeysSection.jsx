// SPDX-License-Identifier: Apache-2.0
// Security keys and passkeys of the logged-in user: list (name, rpId, created,
// last use on this node), add through the browser prompt, rename, remove with
// the password. Keys replicate, so one key opens every node of the domain.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Fingerprint, PencilSimple, Trash, Plus } from '@phosphor-icons/react'
import { Badge, Button, Input, FormModal } from '../../components'
import { useApi } from '../../hooks'
import { useAuth } from '../../contexts/AuthContext'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { cancelled, createCredential, webauthnSupported } from '../../lib/webauthn'

function RemoveKey({ item, onClose, onDone }) {
  const { t } = useTranslation(['account', 'common'])
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    if (!password) return setError(t('totp.errors.password'))
    setBusy(true)
    try {
      await api.auth.keyRemove(item.id, password)
      onDone()
    } catch (err) {
      setError(err?.code === 'invalid_credentials' ? t('password.errors.wrong') : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open onClose={onClose} title={t('keys.removeTitle', { name: item.name })} onSubmit={submit} loading={busy} submitLabel={t('keys.remove')} size="sm" testId="key-remove">
      <p className="text-xs text-text-secondary">{t('keys.removeHelp')}</p>
      <Input label={t('totp.password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} error={error} autoComplete="current-password" data-testid="key-remove-password" />
    </FormModal>
  )
}

function KeyRow({ item, onChanged, onRemove }) {
  const { t } = useTranslation('account')
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState(item.name)
  const [error, setError] = useState(null)
  const save = async (e) => {
    e.preventDefault()
    if (!name.trim()) return setError(t('keys.errors.name'))
    try {
      await api.auth.keyRename(item.id, name.trim())
      setEditing(false)
      setError(null)
      onChanged()
    } catch (err) {
      setError(errorMessage(err))
    }
  }
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2" data-testid="key-row" data-key-id={item.id}>
      <Fingerprint size={18} className="text-accent-primary shrink-0" />
      {editing ? (
        <form onSubmit={save} className="flex items-center gap-2 min-w-0 flex-1">
          <Input value={name} onChange={(e) => setName(e.target.value)} error={error} maxLength={64} aria-label={t('keys.name')} data-testid="key-rename-input" />
          <Button type="submit" size="xs">{t('common:actions.save')}</Button>
        </form>
      ) : (
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-text-primary truncate" data-testid="key-name">{item.name}</span>
            {item.backup_eligible && <Badge size="sm" variant="secondary">{t('keys.synced')}</Badge>}
          </div>
          <div className="text-2xs text-text-tertiary">
            {t('keys.meta', { rp: item.rp_id, created: formatDate(item.created_at), used: item.last_used_at ? formatDate(item.last_used_at) : t('keys.neverHere') })}
          </div>
        </div>
      )}
      {!editing && (
        <div className="flex gap-1">
          <Button size="xs" variant="ghost" title={t('keys.rename')} onClick={() => setEditing(true)} data-testid="key-rename"><PencilSimple size={14} /></Button>
          <Button size="xs" variant="ghost" title={t('keys.remove')} onClick={() => onRemove(item)} data-testid="key-remove-open"><Trash size={14} className="status-danger-text" /></Button>
        </div>
      )}
    </li>
  )
}

export function SecurityKeysSection({ Section }) {
  const { t } = useTranslation(['account', 'common'])
  const { updateUser, checkSession } = useAuth()
  const { showSuccess } = useNotification()
  const keysQ = useApi(() => api.auth.keys(), [])
  const [name, setName] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState(null)
  const items = keysQ.data?.items || []
  const supported = webauthnSupported()
  const available = supported && keysQ.data?.available
  const reason = !supported ? 'browser' : keysQ.data?.reason

  const add = async (e) => {
    e.preventDefault()
    if (!name.trim()) return setError(t('keys.errors.name'))
    setBusy(true)
    setError(null)
    try {
      const { ceremony, options } = await api.auth.keyRegisterOptions()
      const credential = await createCredential(options)
      await api.auth.keyRegister(ceremony, credential, name.trim())
      setName('')
      updateUser({ webauthn_count: items.length + 1 })
      checkSession()
      showSuccess(t('keys.added'))
      keysQ.refetch()
    } catch (err) {
      setError(cancelled(err) ? t('keys.errors.cancelled') : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Section icon={Fingerprint} title={t('keys.title')} testId="account-keys">
      <p className="text-xs text-text-secondary">{t('keys.help')}</p>
      {items.length > 0 && (
        <ul className="divide-y divide-border" data-testid="key-list">
          {items.map((item) => (
            <KeyRow key={item.id} item={item} onChanged={keysQ.refetch} onRemove={setRemoving} />
          ))}
        </ul>
      )}
      {!keysQ.loading && items.length === 0 && <p className="text-xs text-text-tertiary" data-testid="key-empty">{t('keys.none')}</p>}
      {keysQ.data && !available && (
        <p className="text-xs status-warning-text" role="status" data-testid="key-unavailable">{t(`keys.unavailable.${reason || 'browser'}`, { rp: keysQ.data?.rp_id || '' })}</p>
      )}
      {available && (
        <form onSubmit={add} className="flex flex-wrap items-end gap-2 max-w-md" data-testid="key-add">
          <Input label={t('keys.name')} value={name} onChange={(e) => setName(e.target.value)} placeholder={t('keys.namePlaceholder')} maxLength={64} className="flex-1" data-testid="key-name-input" />
          <Button type="submit" size="sm" loading={busy} data-testid="key-add-submit">
            <Plus size={14} />
            {t('keys.add')}
          </Button>
        </form>
      )}
      {error && <p className="text-sm status-danger-text" role="alert">{error}</p>}
      {removing && (
        <RemoveKey
          item={removing}
          onClose={() => setRemoving(null)}
          onDone={() => {
            showSuccess(t('keys.removed', { name: removing.name }))
            updateUser({ webauthn_count: Math.max(0, items.length - 1) })
            setRemoving(null)
            keysQ.refetch()
          }}
        />
      )}
    </Section>
  )
}
