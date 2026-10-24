// SPDX-License-Identifier: Apache-2.0
// Confirmation dialog for destructive or disruptive actions. `typeToConfirm` asks
// the user to retype a value (zone name, node id) before the button enables.
import { useEffect, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useTranslation } from 'react-i18next'
import { Warning } from '@phosphor-icons/react'
import { Button } from './Button'
import { Input } from './Input'
import { cn } from '../lib/utils'

export function ConfirmDialog({
  open,
  onOpenChange,
  onConfirm,
  title,
  message,
  children,
  confirmLabel,
  cancelLabel,
  variant = 'danger',
  loading = false,
  typeToConfirm,
}) {
  const { t } = useTranslation()
  const [typed, setTyped] = useState('')
  useEffect(() => {
    if (!open) setTyped('')
  }, [open])
  const ready = !typeToConfirm || typed.trim() === typeToConfirm

  return (
    <Dialog.Root open={open} onOpenChange={(o) => !loading && onOpenChange?.(o)}>
      <Dialog.Portal>
        <Dialog.Overlay className="modal-backdrop fixed inset-0 z-[250]" />
        <Dialog.Content
          className={cn(
            'fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[251] w-[calc(100%-2rem)] max-w-md',
            'bg-bg-secondary border border-border rounded-xl shadow-xl p-4',
          )}
          aria-describedby={undefined}
          data-testid="confirm-dialog"
        >
          <div className="flex items-start gap-3">
            <div
              className={cn(
                'w-9 h-9 rounded-lg flex items-center justify-center shrink-0',
                variant === 'danger' ? 'status-danger-bg status-danger-text' : 'status-warning-bg status-warning-text',
              )}
            >
              <Warning size={18} weight="duotone" />
            </div>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-sm font-semibold text-text-primary">{title || t('confirm.title')}</Dialog.Title>
              {message && <p className="text-xs text-text-secondary mt-1 whitespace-pre-wrap">{message}</p>}
              {children && <div className="mt-2">{children}</div>}
              {typeToConfirm && (
                <div className="mt-3">
                  <Input
                    label={t('confirm.typeToConfirm', { value: typeToConfirm })}
                    value={typed}
                    onChange={(e) => setTyped(e.target.value)}
                    autoFocus
                    autoComplete="off"
                    data-testid="confirm-type-input"
                  />
                </div>
              )}
            </div>
          </div>
          <div className="flex justify-end gap-2 mt-4">
            <Button type="button" variant="secondary" size="sm" onClick={() => onOpenChange?.(false)} disabled={loading}>
              {cancelLabel || t('actions.cancel')}
            </Button>
            <Button
              type="button"
              variant={variant === 'danger' ? 'danger' : 'primary'}
              size="sm"
              onClick={onConfirm}
              disabled={!ready || loading}
              loading={loading}
              data-testid="confirm-button"
            >
              {confirmLabel || t('actions.confirm')}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export default ConfirmDialog
