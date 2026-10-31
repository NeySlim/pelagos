// SPDX-License-Identifier: Apache-2.0
// Error of a failed read with a Retry button, so a page recovers without a reload.
// The title is translated from the error class (or the caller's prefix); the technical
// text stays folded under Details, so an exception message is never the title.
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, Warning } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { Button } from './Button'
import { errorMessage } from '../services/apiClient'
import { errorKind } from '../hooks/useApi'

export function ErrorNotice({ error, onRetry, prefix, className, testId = 'error-notice' }) {
  const { t } = useTranslation()
  if (!error) return null
  const kind = error.kind || errorKind(error)
  const title = prefix || t(`errors.${kind}`)
  const details = [errorMessage(error), error.status ? `HTTP ${error.status}` : null, error.code && error.code !== 'error' ? error.code : null]
    .filter(Boolean)
    .join(' · ')
  return (
    <div role="alert" data-testid={testId} data-kind={kind} className={cn('flex flex-wrap items-center gap-2 text-sm status-danger-text', className)}>
      <Warning size={14} aria-hidden="true" className="shrink-0" />
      <span className="flex-1 min-w-0 break-words font-medium" data-testid={`${testId}-title`}>{title}</span>
      {onRetry && (
        <Button variant="secondary" size="xs" onClick={() => onRetry()} data-testid="error-retry">
          <ArrowsClockwise size={12} />
          {t('actions.retry')}
        </Button>
      )}
      {details && details !== title && (
        <details className="w-full text-xs" data-testid={`${testId}-details`}>
          <summary className="cursor-pointer select-none opacity-80">{t('errors.details')}</summary>
          <p className="mt-1 font-mono break-words opacity-90">{details}</p>
        </details>
      )}
    </div>
  )
}

export default ErrorNotice
