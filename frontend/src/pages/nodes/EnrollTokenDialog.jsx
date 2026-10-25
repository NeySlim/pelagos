// SPDX-License-Identifier: Apache-2.0
// Enrollment token dialog: pick a lifetime, create a one-time token, then copy the
// `pelagos enroll` command to run on the new server before the token expires.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Copy, Check, Key, Clock } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { Modal } from '../../components/Modal'
import { useClipboard } from '../../hooks/useClipboard'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { NativeSelect } from '../dhcp/ui'

const TTLS = [900, 3600, 86400]

function CopyRow({ label, value, copyKey, copy, isCopied, mono = true, testId }) {
  const { t } = useTranslation(['nodes', 'common'])
  return (
    <div className="space-y-1">
      <span className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</span>
      <div className="flex items-start gap-2">
        <code className={`flex-1 px-2 py-1.5 rounded-md bg-bg-primary border border-border text-xs break-all ${mono ? 'font-mono' : ''}`} data-testid={testId}>
          {value}
        </code>
        <Button variant="secondary" size="xs" onClick={() => copy(value, copyKey)} aria-label={t('common:actions.copy')}>
          {isCopied(copyKey) ? <Check size={12} className="status-success-text" /> : <Copy size={12} />}
        </Button>
      </div>
    </div>
  )
}

export function EnrollTokenDialog({ onClose }) {
  const { t } = useTranslation(['nodes', 'common'])
  const { copy, isCopied } = useClipboard()
  const [ttl, setTtl] = useState(String(TTLS[0]))
  const [token, setToken] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (!token) return undefined
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [token])

  const create = async () => {
    setBusy(true)
    setError(null)
    try {
      setToken(await api.nodes.enrollToken(Number(ttl)))
      setNow(Date.now())
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  const left = token ? Math.max(0, Math.floor((new Date(token.expires_at).getTime() - now) / 1000)) : null
  const expired = left === 0

  return (
    <Modal open onClose={onClose} title={t('enroll.title')} size="md">
      <div className="p-4 space-y-4" data-testid="enroll-dialog">
        <p className="text-xs text-text-secondary">{t('enroll.intro')}</p>
        {!token ? (
          <div className="flex items-end gap-3">
            <div className="w-48">
              <NativeSelect
                label={t('enroll.ttl')}
                value={ttl}
                onChange={setTtl}
                options={TTLS.map((s) => ({ value: String(s), label: t(`enroll.ttlOption.${s}`) }))}
                testId="enroll-ttl"
              />
            </div>
            <Button onClick={create} loading={busy} data-testid="enroll-create">
              <Key size={14} />
              {t('enroll.create')}
            </Button>
          </div>
        ) : (
          <div className="space-y-3" data-testid="enroll-result">
            <div className={`flex items-center gap-2 text-xs ${expired ? 'status-danger-text' : 'text-text-secondary'}`} data-testid="enroll-expiry">
              <Clock size={13} />
              {expired ? t('enroll.expired') : t('enroll.expiresIn', { time: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`, at: formatDate(token.expires_at) })}
            </div>
            <CopyRow label={t('enroll.command')} value={token.command} copyKey="command" copy={copy} isCopied={isCopied} testId="enroll-command" />
            <p className="text-2xs text-text-secondary" data-testid="enroll-command-hint">{t('enroll.commandHint')}</p>
            <CopyRow label={t('enroll.token')} value={token.token} copyKey="token" copy={copy} isCopied={isCopied} testId="enroll-token" />
            <div className="grid gap-3 sm:grid-cols-2">
              <CopyRow label={t('enroll.url')} value={token.url} copyKey="url" copy={copy} isCopied={isCopied} />
              <CopyRow label={t('enroll.caFingerprint')} value={token.ca_fingerprint} copyKey="ca" copy={copy} isCopied={isCopied} />
            </div>
            <p className="text-2xs status-warning-text">{t('enroll.once')}</p>
          </div>
        )}
        {error && (
          <p className="text-xs status-danger-text" role="alert">
            {errorMessage(error)}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-2 border-t border-border">
          {token && (
            <Button variant="secondary" size="sm" onClick={() => setToken(null)}>
              {t('enroll.another')}
            </Button>
          )}
          <Button variant="secondary" size="sm" onClick={onClose}>
            {t('common:actions.close')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
