// SPDX-License-Identifier: Apache-2.0
/**
 * Empty State Component - Theme-aware with subtle visual polish
 */
import { FileX } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from './Button'

export function EmptyState({
  icon: Icon = FileX,
  title: titleProp,
  description,
  action
}) {
  const { t } = useTranslation()
  const title = titleProp || t('table.empty')
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
      {/* Decorative background circle */}
      <div className="relative mb-4">
        <div className="ui-empty-halo absolute inset-0 w-20 h-20 rounded-full bg-accent-25 -translate-x-2 -translate-y-2" />
        <div className="relative w-16 h-16 rounded-2xl bg-bg-tertiary border border-border-op50 flex items-center justify-center">
          <Icon size={28} className="ui-empty-icon text-accent-primary" weight="duotone" />
        </div>
      </div>
      <h3 className="text-base font-medium text-text-primary mb-1">{title}</h3>
      {description && (
        <p className="text-sm text-text-tertiary mb-4 max-w-sm">{description}</p>
      )}
      {action && (
        <Button type="button" onClick={action.onClick} size="sm">
          {action.label}
        </Button>
      )}
    </div>
  )
}
