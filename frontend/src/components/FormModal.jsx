// SPDX-License-Identifier: Apache-2.0
// Modal with a form: children are the fields, the footer carries cancel and submit.
// onSubmit receives the FormData entries as an object (or nothing for custom forms).
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Modal } from './Modal'
import { Button } from './Button'
import { LoadingSpinner } from './LoadingSpinner'

export function FormModal({
  open,
  onClose,
  onOpenChange,
  title,
  size = 'md',
  onSubmit,
  submitLabel,
  cancelLabel,
  loading = false,
  disabled = false,
  variant = 'primary',
  children,
  footer,
  testId = 'form-modal',
}) {
  const { t } = useTranslation()
  // The ref guard stops a second Enter from re-running the action while it is in flight.
  const inFlight = useRef(false)

  const handleSubmit = async (e) => {
    e?.preventDefault()
    if (inFlight.current) return
    inFlight.current = true
    const form = e?.target
    try {
      if (form && onSubmit) {
        const formData = new FormData(form)
        await onSubmit(Object.fromEntries(formData.entries()), e)
      } else {
        await onSubmit?.()
      }
    } finally {
      inFlight.current = false
    }
  }

  const handleClose = onClose || (onOpenChange ? () => onOpenChange(false) : undefined)

  return (
    <Modal open={open} onClose={handleClose} onOpenChange={onOpenChange} title={title} size={size}>
      <form onSubmit={handleSubmit} data-testid={testId}>
        <div className="p-4 space-y-4">{children}</div>
        {footer ?? (
          <div className="ui-modal-footer flex justify-end gap-2 p-4 border-t border-border">
            <Button type="button" variant="secondary" onClick={handleClose} disabled={loading}>
              {cancelLabel || t('actions.cancel')}
            </Button>
            <Button type="submit" variant={variant} disabled={loading || disabled}>
              {loading ? (
                <>
                  <LoadingSpinner size="sm" />
                  <span className="ml-2">{t('actions.saving')}</span>
                </>
              ) : (
                submitLabel || t('actions.save')
              )}
            </Button>
          </div>
        )}
      </form>
    </Modal>
  )
}

export function ConfirmModal({ open, onClose, onConfirm, title, message, confirmLabel, cancelLabel, variant = 'danger', loading = false }) {
  const { t } = useTranslation()
  return (
    <Modal open={open} onClose={onClose} title={title || t('confirm.title')} size="sm">
      <div className="p-4">
        <p className="text-sm text-text-secondary">{message}</p>
      </div>
      <div className="flex justify-end gap-2 p-4 border-t border-border">
        <Button type="button" variant="secondary" onClick={onClose} disabled={loading}>
          {cancelLabel || t('actions.cancel')}
        </Button>
        <Button type="button" variant={variant} onClick={onConfirm} disabled={loading}>
          {loading ? <LoadingSpinner size="sm" /> : confirmLabel || t('actions.confirm')}
        </Button>
      </div>
    </Modal>
  )
}
