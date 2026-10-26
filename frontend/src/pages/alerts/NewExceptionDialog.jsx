// SPDX-License-Identifier: Apache-2.0
// An exception typed by hand (no alert open for the object yet): kind, object key, why.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { Textarea } from '../../components/Textarea'
import { FormSelect } from '../../components/ui/Select'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { exceptionKinds, keyExample, keyProblem } from './exceptionForm'

export function NewExceptionDialog({ open, onClose, onDone, addFn = (body) => api.alerts.addException(body) }) {
  const { t } = useTranslation(['alerts', 'dashboard'])
  const [kind, setKind] = useState('ptr_mismatch')
  const [key, setKey] = useState('')
  const [summary, setSummary] = useState('')
  const [comment, setComment] = useState('')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (open) {
      setKind('ptr_mismatch')
      setKey('')
      setSummary('')
      setComment('')
      setTouched(false)
      setError(null)
    }
  }, [open])

  const keyErr = keyProblem(kind, key)
  const commentErr = comment.trim() === ''
  const submit = async () => {
    setTouched(true)
    if (keyErr || commentErr) return
    setBusy(true)
    setError(null)
    try {
      const created = await addFn({ kind, key: key.trim(), comment: comment.trim(), ...(summary.trim() ? { summary: summary.trim() } : {}) })
      onDone?.(created)
      onClose?.()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const options = exceptionKinds().map((k) => ({ value: k, label: t(`dashboard:kinds.${k}`, { defaultValue: k }) }))
  return (
    <FormModal open={open} onClose={onClose} title={t('exceptions.newTitle')} onSubmit={submit} loading={busy} submitLabel={t('exceptions.create')} testId="new-exception-dialog">
      <p className="text-sm text-text-secondary">{t('exceptions.newHelp')}</p>
      <FormSelect label={t('exceptions.kind')} options={options} value={kind} onChange={setKind} id="new-exception-kind" />
      <Input
        label={t('exceptions.key')}
        value={key}
        onChange={(e) => setKey(e.target.value)}
        placeholder={keyExample(kind)}
        helperText={t('exceptions.keyHelp', { example: keyExample(kind) })}
        error={touched && keyErr ? t(`exceptions.keyErrors.${keyErr}`, { example: keyExample(kind) }) : undefined}
        data-testid="new-exception-key"
      />
      <Input label={t('exceptions.summary')} value={summary} onChange={(e) => setSummary(e.target.value)} data-testid="new-exception-summary" />
      <Textarea
        label={t('ignore.comment')}
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        rows={3}
        helperText={t('ignore.commentHelp')}
        error={touched && commentErr ? t('ignore.commentRequired') : undefined}
        data-testid="new-exception-comment"
      />
      {error && (
        <p className="text-xs status-danger-text" role="alert" data-testid="new-exception-error">
          {error}
        </p>
      )}
    </FormModal>
  )
}

export default NewExceptionDialog
