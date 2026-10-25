// SPDX-License-Identifier: Apache-2.0
/**
 * Modal Component - Radix Dialog wrapper with enhanced visuals
 * Full-screen on mobile for better UX
 */
import * as Dialog from '@radix-ui/react-dialog'
import { X } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { titleCaseClass } from '../lib/displayCase'
import { IconButton } from './motion/Layout'
import { useTranslation } from 'react-i18next'

export function Modal({ 
  open, 
  onClose, 
  onOpenChange,
  title, 
  children, 
  size = 'md',
  showClose = true 
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
            "flex flex-col"
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

          {/* Content - scrollable */}
          <div className="flex-1 overflow-y-auto sm:max-h-[70vh]">
            {children}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
