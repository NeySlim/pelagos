// SPDX-License-Identifier: Apache-2.0
// Error of a failed read with a Retry button, so a page recovers without a reload.
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, Warning } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { Button } from './Button'
import { errorMessage } from '../services/apiClient'

export function ErrorNotice({ error, onRetry, prefix, className, testId = 'error-notice' }) {
  const { t } = useTranslation()
  if (!error) return null
  return (
    <div role="alert" data-testid={testId} className={cn('flex flex-wrap items-center gap-2 text-sm status-danger-text', className)}>
      <Warning size={14} aria-hidden="true" className="shrink-0" />
      <span className="flex-1 min-w-0 break-words">{prefix ? `${prefix}: ${errorMessage(error)}` : errorMessage(error)}</span>
      {onRetry && (
        <Button variant="secondary" size="xs" onClick={() => onRetry()} data-testid="error-retry">
          <ArrowsClockwise size={12} />
          {t('actions.retry')}
        </Button>
      )}
    </div>
  )
}

export default ErrorNotice
