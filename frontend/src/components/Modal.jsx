// SPDX-License-Identifier: Apache-2.0
/**
 * Modal Component - Radix Dialog wrapper with enhanced visuals
 * Full-screen on mobile for better UX. `footer` stays outside the scrolling body, so
 * its actions are always visible; `bodyScroll={false}` hands the scroll to the children
 * (a child that renders its own pinned footer, like PlanPreview).
 */
import * as Dialog from '@radix-ui/react-dialog'
import { X } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { titleCaseClass } from '../lib/displayCase'
import { IconButton } from './motion/Layout'
import { useTranslation } from 'react-i18next'

// A pinned action bar: outside the scroll, above the phone's home indicator.
export const MODAL_FOOTER_CLASS =
  'shrink-0 border-t border-border bg-bg-secondary px-4 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:rounded-b-xl'

export function Modal({ 
  open, 
  onClose, 
  onOpenChange,
  title, 
  children, 
  size = 'md',
  showClose = true,
  footer,
  bodyScroll = true,
}) {
  const { t } = useTranslation()
  // Support both onClose and onOpenChange
  const handleOpenChange = onOpenChange || onClose;
  const sizes = {
    sm: 'sm:max-w-md',
    md: 'sm:max-w-2xl',
    lg: 'sm:max-w-4xl',
    xl: 'sm:max-w-6xl',
  }

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="modal-backdrop fixed inset-0 z-[200]" />
        <Dialog.Content 
          className={cn(
            // Mobile: full screen
            "fixed inset-0 z-[201]",
            "sm:inset-auto sm:left-1/2 sm:top-1/2 sm:-translate-x-1/2 sm:-translate-y-1/2",
            "w-full h-full sm:h-auto sm:mx-4",
            sizes[size],
            "ui-modal bg-bg-primary sm:modal-enhanced sm:rounded-xl",
            // Enter and exit follow data-state (styles/motion.css): scale composes with the centering.
            "flex flex-col",
            (footer || !bodyScroll) && "sm:max-h-[90vh]"
          )}
          aria-describedby={undefined}
        >
          {/* Header */}
          <div className="ui-modal-header flex items-center justify-between px-4 py-3 border-b border-border-op50 shrink-0 modal-header-gradient">
            <Dialog.Title className={cn('ui-modal-title text-sm font-semibold text-text-primary', titleCaseClass(title))}>
              {title}
            </Dialog.Title>
            {showClose && (
              <Dialog.Close asChild>
                <IconButton icon={X} label={t('actions.close')} size="sm" />
              </Dialog.Close>
            )}
          </div>

          {/* Content - scrollable unless the children scroll themselves */}
          {bodyScroll ? (
            <div className="flex-1 min-h-0 overflow-y-auto sm:max-h-[70vh]">
              {children}
            </div>
          ) : (
            <div className="flex-1 min-h-0 flex flex-col">{children}</div>
          )}

          {footer && <div className={cn('ui-modal-footer', MODAL_FOOTER_CLASS)} data-testid="modal-footer">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
