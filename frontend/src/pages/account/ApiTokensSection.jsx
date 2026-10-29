// SPDX-License-Identifier: Apache-2.0
// API tokens of the logged-in user (section 16): list with expiry and last use, creation behind a
// fresh second factor (security key prompt, or a TOTP code), secret shown once, revocation.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Code, Copy, Plus, Trash } from '@phosphor-icons/react'
import { Badge, Button, ConfirmDialog, Input, Modal, Select } from '../../components'
import { useApi } from '../../hooks'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { cancelled, getCredential } from '../../lib/webauthn'

const ROLES = ['viewer', 'dns-operator', 'dhcp-operator', 'admin']
const MAX_DAYS = 3650

function splitCidrs(text) {
  return String(text || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
}

function TokenRow({ item, onRevoke }) {
  const { t } = useTranslation('account')
  const scope = item.role ? t(`tokens.roles.${item.role}`, { defaultValue: item.role }) : t('tokens.custom')
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2" data-testid="token-row" data-token-id={item.id}>
      <Code size={18} className="text-accent-primary shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-sm text-text-primary truncate" data-testid="token-name">{item.name}</span>
          <Badge size="sm" variant="secondary">{scope}</Badge>
          {item.expired && <Badge size="sm" variant="danger">{t('tokens.expired')}</Badge>}
        </div>
        <div className="text-2xs text-text-tertiary">
          {t('tokens.expires', { date: formatDate(item.expires_at) })}
          {' · '}
          {item.last_used_at ? t('tokens.lastUsed', { date: formatDate(item.last_used_at), node: item.last_used_node || '?' }) : t('tokens.neverUsed')}
          {' · '}
          {item.cidrs?.length ? item.cidrs.join(', ') : t('tokens.anySource')}
        </div>
      </div>
      <Button size="xs" variant="ghost" title={t('tokens.revoke')} onClick={() => onRevoke(item)} data-testid="token-revoke-open">
        <Trash size={14} className="status-danger-text" />
      </Button>
    </li>
  )
}

function CreatedToken({ created, onClose }) {
  const { t } = useTranslation('account')
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.token)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }
  return (
    <Modal open onClose={onClose} title={t('tokens.createdTitle', { name: created.item.name })} size="md">
      <div className="space-y-3" data-testid="token-created">
        <p className="text-xs status-warning-text">{t('tokens.createdHelp')}</p>
        <code className="block break-all rounded-md border border-border bg-bg-secondary px-2 py-1.5 text-xs font-mono text-text-primary select-all" data-testid="token-secret">{created.token}</code>
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="secondary" onClick={copy}>
            <Copy size={14} />
            {copied ? t('tokens.copied') : t('tokens.copy')}
          </Button>
          <Button size="sm" onClick={onClose} data-testid="token-created-done">{t('tokens.done')}</Button>
        </div>
      </div>
    </Modal>
  )
}

export function ApiTokensSection({ Section }) {
  const { t } = useTranslation(['account', 'common'])
  const { showSuccess, showError } = useNotification()
  const tokensQ = useApi(() => api.auth.tokens(), [])
  const [form, setForm] = useState({ name: '', role: 'viewer', days: '90', cidrs: '' })
  const [needCode, setNeedCode] = useState(false)
  const [code, setCode] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState(null)
  const [revoking, setRevoking] = useState(null)
  const items = tokensQ.data?.items || []
  const unavailable = tokensQ.data?.meta?.unavailable || []
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e?.target ? e.target.value : e }))

  const body = () => ({ name: form.name.trim(), role: form.role, expires_days: Number(form.days), cidrs: splitCidrs(form.cidrs) })

  const finish = async (proof) => {
    const answer = await api.auth.tokenCreate({ ...body(), ...proof })
    setCreated(answer)
    setForm({ name: '', role: form.role, days: form.days, cidrs: '' })
    setNeedCode(false)
    setCode('')
    tokensQ.refetch()
  }

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!form.name.trim()) return setError(t('tokens.errors.name'))
    const days = Number(form.days)
    if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) return setError(t('tokens.errors.days', { max: MAX_DAYS }))
    setBusy(true)
    try {
      if (needCode) {
        if (!/^\d{6}$/.test(code.trim())) return setError(t('tokens.errors.code'))
        await finish({ totp_code: code.trim() })
        return
      }
      const challenge = await api.auth.tokenChallenge()
      if (challenge.methods.includes('webauthn') && challenge.options) {
        const credential = await getCredential(challenge.options)
        await finish({ ceremony: challenge.ceremony, credential })
      } else {
        setNeedCode(true)
      }
    } catch (err) {
      if (err?.problem?.reason === 'no_second_factor') setError(t('tokens.errors.noFactor'))
      else setError(cancelled(err) ? t('tokens.errors.cancelled') : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const revoke = async () => {
    setBusy(true)
    try {
      await api.auth.tokenRevoke(revoking.id)
      showSuccess(t('tokens.revoked', { name: revoking.name }))
      setRevoking(null)
      tokensQ.refetch()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Section icon={Code} title={t('tokens.title')} testId="account-tokens">
      <p className="text-xs text-text-secondary">{t('tokens.help')}</p>
      {items.length > 0 && (
        <ul className="divide-y divide-border" data-testid="token-list">
          {items.map((item) => <TokenRow key={item.id} item={item} onRevoke={setRevoking} />)}
        </ul>
      )}
      {!tokensQ.loading && items.length === 0 && <p className="text-xs text-text-tertiary" data-testid="token-empty">{t('tokens.none')}</p>}
      {unavailable.length > 0 && <p className="text-xs status-warning-text" role="status">{t('tokens.unavailable', { nodes: unavailable.join(', ') })}</p>}
      <form onSubmit={submit} className="grid grid-cols-1 md:grid-cols-2 gap-2 max-w-2xl" data-testid="token-add">
        <Input label={t('tokens.name')} value={form.name} onChange={set('name')} placeholder={t('tokens.namePlaceholder')} maxLength={64} data-testid="token-name-input" />
        <Select label={t('tokens.role')} options={ROLES.map((r) => ({ value: r, label: t(`tokens.roles.${r}`) }))} value={form.role} onChange={set('role')} />
        <Input label={t('tokens.expiresDays')} type="number" min={1} max={MAX_DAYS} value={form.days} onChange={set('days')} data-testid="token-days-input" />
        <Input label={t('tokens.cidrs')} value={form.cidrs} onChange={set('cidrs')} placeholder="192.0.2.0/24" helperText={t('tokens.cidrsHelp')} data-testid="token-cidrs-input" />
        {needCode && (
          <Input label={t('tokens.code')} value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={6} helperText={t('tokens.codeHelp')} data-testid="token-code-input" />
        )}
        <div className="md:col-span-2 flex items-center gap-2">
          <Button type="submit" size="sm" loading={busy} data-testid="token-add-submit">
            <Plus size={14} />
            {needCode ? t('tokens.confirm') : t('tokens.create')}
          </Button>
        </div>
      </form>
      {error && <p className="text-sm status-danger-text" role="alert" data-testid="token-error">{error}</p>}
      {created && <CreatedToken created={created} onClose={() => setCreated(null)} />}
      <ConfirmDialog
        open={Boolean(revoking)}
        onOpenChange={(o) => !o && setRevoking(null)}
        onConfirm={revoke}
        loading={busy}
        title={t('tokens.revokeTitle', { name: revoking?.name })}
        message={t('tokens.revokeHelp')}
        confirmLabel={t('tokens.revoke')}
      />
    </Section>
  )
}
