// SPDX-License-Identifier: Apache-2.0
// Error element of the router. A page whose code could not be fetched (node unreachable, or
// upgraded since this tab loaded) goes to ErrorBoundary, which reloads once the node answers;
// any other error offers a reload instead of reloading in a loop.
import { useRouteError } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowClockwise, Warning } from '@phosphor-icons/react'
import { ErrorBoundary } from './ErrorBoundary'
import { Button } from './Button'
import { isChunkError } from '../lib/lazyPage'

function Rethrow({ error }) {
  throw error
}

export function RouteError() {
  const error = useRouteError()
  const { t } = useTranslation()
  if (isChunkError(error)) {
    return (
      <ErrorBoundary>
        <Rethrow error={error} />
      </ErrorBoundary>
    )
  }
  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] p-8 text-center gap-3" role="alert" data-testid="route-error">
      <Warning size={32} className="status-danger-text" />
      <h2 className="text-lg font-semibold text-text-primary">{t('errorBoundary.title')}</h2>
      <p className="text-sm text-text-secondary max-w-md">{t('errorBoundary.body')}</p>
      <Button variant="secondary" size="sm" onClick={() => window.location.reload()} data-testid="route-error-reload">
        <ArrowClockwise size={14} />
        {t('actions.retry')}
      </Button>
    </div>
  )
}

export default RouteError
