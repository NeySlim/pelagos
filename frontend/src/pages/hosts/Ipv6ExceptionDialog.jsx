// SPDX-License-Identifier: Apache-2.0
// Exception for one IPv6 row: the whole host or one address, for the missing AAAA or the
// stale AAAA check, with the mandatory comment (POST /alerts/exceptions).
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Textarea } from '../../components/Textarea'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { exceptionTargets } from './ipv6'

export function Ipv6ExceptionDialog({ row, onClose, onDone }) {
  const { t } = useTranslation(['ipv6', 'common'])
  const targets = row ? exceptionTargets(row) : []
  const [choice, setChoice] = useState(0)
  const [comment, setComment] = useState('')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    setChoice(0)
    setComment('')
    setTouched(false)
    setError(null)
  }, [row?.host_key])

  const empty = comment.trim() === ''
  const submit = async () => {
    setTouched(true)
    const target = targets[choice]
    if (empty || !target) return
    setBusy(true)
    setError(null)
    try {
      const summary = row.name || row.mac
      const created = await api.alerts.addException({ kind: target.kind, key: target.key, comment: comment.trim(), ...(summary ? { summary } : {}) })
      onDone?.(created)
      onClose?.()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={Boolean(row)} onClose={onClose} title={t('exception.title', { host: row?.name || row?.mac || '' })} onSubmit={submit} loading={busy} submitLabel={t('exception.submit')} testId="ipv6-exception-dialog">
      <p className="text-sm text-text-secondary">{t('exception.body')}</p>
      <fieldset className="space-y-1.5" data-testid="ipv6-exception-targets">
        <legend className="sr-only">{t('exception.target')}</legend>
        {targets.map((target, i) => (
          <label key={`${target.kind}|${target.key}`} className="flex items-start gap-2 text-sm cursor-pointer">
            <input
              type="radio"
              name="ipv6-exception-target"
              className="mt-1"
              checked={choice === i}
              onChange={() => setChoice(i)}
              data-testid="ipv6-exception-target"
              data-kind={target.kind}
              data-key={target.key}
            />
            <span className="min-w-0">
              <span className="block text-text-primary">{t(`exception.${target.kind}.${target.scope}`)}</span>
              <span className="block text-xs font-mono text-text-secondary break-all">{target.key}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <Textarea
        label={t('exception.comment')}
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        rows={3}
        helperText={t('exception.commentHelp')}
        error={touched && empty ? t('exception.commentRequired') : undefined}
        data-testid="ipv6-exception-comment"
        autoFocus
      />
      {error && (
        <p className="text-xs status-danger-text" role="alert" data-testid="ipv6-exception-error">
          {error}
        </p>
      )}
    </FormModal>
  )
}

export default Ipv6ExceptionDialog
