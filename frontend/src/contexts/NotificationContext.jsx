// SPDX-License-Identifier: Apache-2.0
/**
 * Notification Context - Toast notifications + Confirmation dialogs
 */
import { createContext, useContext, useState, useCallback, useMemo } from 'react'
import * as Toast from '@radix-ui/react-toast'
import * as Dialog from '@radix-ui/react-dialog'
import { CheckCircle, Warning, Info, XCircle, X } from '@phosphor-icons/react'
import { Button } from '../components/Button'
import { Input } from '../components/Input'
import i18n from '../i18n'

const NotificationContext = createContext()
const TOAST_EXIT_MS = 400

const TONES = { success: 'success', error: 'danger', warning: 'warning', info: 'neutral' }

export function NotificationProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const [confirmDialog, setConfirmDialog] = useState(null)
  const [promptDialog, setPromptDialog] = useState(null)
  const [promptValue, setPromptValue] = useState('')

  // Closing keeps the toast mounted for its exit (Radix Presence waits for the
  // animation); it leaves the list once that is over.
  const removeToast = useCallback((id) => {
    setToasts(prev => prev.map(toast => (toast.id === id ? { ...toast, open: false } : toast)))
    setTimeout(() => setToasts(prev => prev.filter(toast => toast.id !== id)), TOAST_EXIT_MS)
  }, [])

  // Radix runs the timer and pauses it while the toast is hovered or focused; the duration
  // hairline drains with it. `action` ({ label, onClick, testId }) is a button in the toast.
  const addToast = useCallback((type, message, duration = 5000, extra = {}) => {
    const id = Date.now() + Math.random() // unique even when called in a tight loop
    setToasts(prev => [...prev, { id, type, message, duration, open: true, detail: extra.detail, action: extra.action }])
    return id
  }, [])

  const showToast = useCallback(
    ({ type = 'info', message, detail, action, duration = action ? 9000 : 5000 }) => addToast(type, message, duration, { detail, action }),
    [addToast],
  )

  const showSuccess = useCallback((message) => addToast('success', message), [addToast])
  const showError = useCallback((message) => addToast('error', message), [addToast])
  const showWarning = useCallback((message) => addToast('warning', message), [addToast])
  const showInfo = useCallback((message) => addToast('info', message), [addToast])

  // Confirmation dialog
  const showConfirm = useCallback((message, options = {}) => {
    return new Promise((resolve) => {
      setConfirmDialog({
        message,
        title: options.title || i18n.t('confirm.title'),
        confirmText: options.confirmText || i18n.t('actions.confirm'),
        // An explicit null hides the cancel button (acknowledge-only dialog), so
        // only an omitted cancelText gets the default.
        cancelText: options.cancelText === undefined ? i18n.t('actions.cancel') : options.cancelText,
        variant: options.variant || 'primary', // 'primary' | 'danger'
        resolve
      })
    })
  }, [])

  const handleConfirm = (result) => {
    if (confirmDialog) {
      confirmDialog.resolve(result)
      setConfirmDialog(null)
    }
  }

  // Prompt dialog
  const showPrompt = useCallback((message, options = {}) => {
    return new Promise((resolve) => {
      setPromptValue(options.defaultValue || '')
      setPromptDialog({
        message,
        title: options.title || i18n.t('confirm.inputRequired'),
        placeholder: options.placeholder || '',
        type: options.type || 'text',
        confirmText: options.confirmText || i18n.t('actions.ok'),
        cancelText: options.cancelText || i18n.t('actions.cancel'),
        resolve
      })
    })
  }, [])

  const handlePrompt = (result) => {
    if (promptDialog) {
      promptDialog.resolve(result ? promptValue : null)
      setPromptDialog(null)
      setPromptValue('')
    }
  }

  const getIcon = (type) => {
    switch (type) {
      case 'success': return <CheckCircle size={20} weight="fill" className="status-success-text" />
      case 'error': return <XCircle size={20} weight="fill" className="status-danger-text" />
      case 'warning': return <Warning size={20} weight="fill" className="status-warning-text" />
      case 'info': return <Info size={20} weight="fill" className="status-primary-text" />
      default: return <Info size={20} weight="fill" />
    }
  }

  const getColors = (type) => {
    switch (type) {
      case 'success': return 'status-success-border status-success-bg border'
      case 'error': return 'status-danger-border status-danger-bg border'
      case 'warning': return 'status-warning-border status-warning-bg border'
      case 'info': return 'status-primary-border status-primary-bg border'
      default: return 'border-border bg-bg-secondary'
    }
  }

  const value = useMemo(() => ({
    showSuccess,
    showError,
    showWarning,
    showInfo,
    showToast,
    showConfirm,
    showPrompt,
  }), [showSuccess, showError, showWarning, showInfo, showToast, showConfirm, showPrompt])

  return (
    <NotificationContext.Provider value={value}>
      <Toast.Provider swipeDirection="right">
        {children}
        
        {toasts.map(toast => (
          <Toast.Root
            key={toast.id}
            className={`ui-toast relative overflow-hidden rounded-xl border p-4 shadow-2xl backdrop-blur-sm ${getColors(toast.type)}`}
            open={toast.open}
            duration={toast.duration > 0 ? toast.duration : Infinity}
            onOpenChange={(open) => !open && removeToast(toast.id)}
            data-tone={TONES[toast.type] || 'neutral'}
          >
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 mt-0.5">
                {getIcon(toast.type)}
              </div>
              <div className="flex-1 min-w-0">
                <Toast.Description className="text-sm text-text-primary break-words whitespace-pre-line">
                  {toast.message}
                </Toast.Description>
                {toast.detail && <p className="ui-toast-detail mt-0.5 font-mono text-xs text-text-secondary break-all">{toast.detail}</p>}
                {toast.action && (
                  <Toast.Action asChild altText={toast.action.label}>
                    <button
                      type="button"
                      className="ui-toast-action mt-2 inline-flex items-center h-6 px-2 rounded border border-border text-xs text-text-primary hover:bg-bg-tertiary"
                      onClick={() => toast.action.onClick?.()}
                      data-testid={toast.action.testId || 'toast-action'}
                    >
                      {toast.action.label}
                    </button>
                  </Toast.Action>
                )}
              </div>
              {/* Toast.Close renders the button itself: no nested <button>. */}
              <Toast.Close
                className="flex-shrink-0 text-text-secondary hover:text-text-primary transition-colors"
                aria-label={i18n.t('actions.close')}
                data-testid="toast-close"
              >
                <X size={16} />
              </Toast.Close>
            </div>
            {toast.duration > 0 && <span className="fx-toast-ttl" style={{ '--fx-ttl': `${toast.duration}ms` }} aria-hidden="true" />}
          </Toast.Root>
        ))}

        <Toast.Viewport className="fixed top-4 right-4 flex flex-col gap-3 w-96 max-w-[calc(100vw-2rem)] z-[300] outline-none" />
      </Toast.Provider>

      {/* Confirm Dialog */}
      <Dialog.Root open={!!confirmDialog} onOpenChange={(open) => !open && handleConfirm(false)}>
        <Dialog.Portal>
          <Dialog.Overlay className="ui-dialog-overlay fixed inset-0 bg-black/60 backdrop-blur-sm z-[300]" />
          <Dialog.Content className="ui-dialog fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[301] w-full max-w-sm bg-bg-secondary border border-border rounded-lg shadow-xl p-4">
            <Dialog.Title className="text-sm font-semibold text-text-primary mb-2">
              {confirmDialog?.title}
            </Dialog.Title>
            <Dialog.Description className="text-xs text-text-secondary mb-4 whitespace-pre-wrap">
              {confirmDialog?.message}
            </Dialog.Description>
            <div className="flex justify-end gap-2">
              {confirmDialog?.cancelText !== null && (
                <Button type="button" variant="secondary" size="sm" onClick={() => handleConfirm(false)}>
                  {confirmDialog?.cancelText || 'Cancel'}
                </Button>
              )}
              <Button 
                variant={confirmDialog?.variant === 'danger' ? 'danger' : 'primary'} 
                size="sm"
                onClick={() => handleConfirm(true)}
              >
                {confirmDialog?.confirmText}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Prompt Dialog */}
      <Dialog.Root open={!!promptDialog} onOpenChange={(open) => !open && handlePrompt(false)}>
        <Dialog.Portal>
          <Dialog.Overlay className="ui-dialog-overlay fixed inset-0 bg-black/60 backdrop-blur-sm z-[300]" />
          <Dialog.Content className="ui-dialog fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[301] w-full max-w-sm bg-bg-secondary border border-border rounded-lg shadow-xl p-4">
            <Dialog.Title className="text-sm font-semibold text-text-primary mb-2">
              {promptDialog?.title}
            </Dialog.Title>
            <Dialog.Description className="text-xs text-text-secondary mb-3">
              {promptDialog?.message}
            </Dialog.Description>
            <Input
              type={promptDialog?.type || 'text'}
              value={promptValue}
              onChange={(e) => setPromptValue(e.target.value)}
              placeholder={promptDialog?.placeholder}
              autoFocus
              onKeyDown={(e) => e.key === 'Enter' && handlePrompt(true)}
            />
            <div className="flex justify-end gap-2 mt-4">
              <Button type="button" variant="secondary" size="sm" onClick={() => handlePrompt(false)}>
                {promptDialog?.cancelText}
              </Button>
              <Button type="button" size="sm" onClick={() => handlePrompt(true)}>
                {promptDialog?.confirmText}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </NotificationContext.Provider>
  )
}

export function useNotification() {
  const context = useContext(NotificationContext)
  if (!context) {
    throw new Error('useNotification must be used within NotificationProvider')
  }
  return context
}
