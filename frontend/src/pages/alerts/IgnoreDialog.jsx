// SPDX-License-Identifier: Apache-2.0
// "Ignore: admin's choice": a permanent exception to a consistency check for one or more objects
// (POST /alerts/exceptions per key), with the mandatory comment kept in cluster.toml and the audit.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Textarea } from '../../components/Textarea'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'

// items: [{ kind, key, summary? }]
// `inline` draws the form in place (inside the alert detail) instead of over it in a second modal.
export function IgnoreDialog({ open, items = [], onClose, onDone, inline = false, addFn = (body) => api.alerts.addException(body) }) {
  const { t } = useTranslation(['alerts', 'common'])
  const [comment, setComment] = useState('')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (open) {
      setComment('')
      setTouched(false)
      setError(null)
    }
  }, [open])

  const empty = comment.trim() === ''
  const submit = async () => {
    setTouched(true)
    if (empty) return
    setBusy(true)
    setError(null)
    try {
      const created = []
      for (const item of items) {
        created.push(await addFn({ kind: item.kind, key: item.key, comment: comment.trim(), ...(item.summary ? { summary: item.summary } : {}) }))
      }
      onDone?.(created)
      onClose?.()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const fields = (
    <>
      <p className="text-sm text-text-secondary">{t('ignore.body', { count: items.length })}</p>
      <ul className="text-xs font-mono text-text-primary max-h-32 overflow-auto space-y-0.5" data-testid="ignore-keys">
        {items.map((item) => (
          <li key={`${item.kind}|${item.key}`} className="break-all">
            {item.summary && item.summary !== item.key && <span className="block font-sans text-text-secondary">{item.summary}</span>}
            {item.key}
          </li>
        ))}
      </ul>
      <Textarea
        label={t('ignore.comment')}
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        rows={3}
        helperText={t('ignore.commentHelp')}
        error={touched && empty ? t('ignore.commentRequired') : undefined}
        data-testid="ignore-comment"
        autoFocus
      />
      {error && (
        <p className="text-xs status-danger-text" role="alert" data-testid="ignore-error">
          {error}
        </p>
      )}
    </>
  )

  if (inline) {
    if (!open) return null
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
        className="space-y-3 rounded-lg border border-border p-3"
        data-testid="ignore-dialog"
      >
        <h4 className="ui-label text-2xs uppercase tracking-wider text-text-tertiary">{t('ignore.title')}</h4>
        {fields}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" size="sm" onClick={onClose} disabled={busy}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" size="sm" loading={busy} disabled={busy}>
            {t('ignore.submit')}
          </Button>
        </div>
      </form>
    )
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('ignore.title')} onSubmit={submit} loading={busy} submitLabel={t('ignore.submit')} testId="ignore-dialog">
      {fields}
    </FormModal>
  )
}

export default IgnoreDialog
