// SPDX-License-Identifier: Apache-2.0
// Working placeholder for an area page that is not built yet: header from the
// area namespace (pages.<page>.title/subtitle), then the raw answer of the
// page's main endpoint, so the wiring to the API is visible and testable.
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, Hammer } from '@phosphor-icons/react'
import { PageLayout } from './PageLayout'
import { Card } from './Card'
import { Button } from './Button'
import { JsonTree } from './JsonTree'
import { LoadingSpinner } from './LoadingSpinner'
import { useApi } from '../hooks/useApi'
import { errorMessage } from '../services/apiClient'

export function AreaPlaceholder({ ns, page, icon, load, deps = [], endpoint }) {
  const { t } = useTranslation([ns, 'common'])
  const { data, error, loading, refetch } = useApi(load || (async () => null), deps, { enabled: Boolean(load) })

  return (
    <PageLayout
      icon={icon}
      title={t(`pages.${page}.title`)}
      subtitle={t(`pages.${page}.subtitle`)}
      testId={`page-${ns}-${page}`}
      actions={
        load && (
          <Button variant="secondary" size="sm" onClick={refetch} disabled={loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
        )
      }
    >
      <div className="space-y-4 max-w-5xl">
        <Card className="p-4 flex items-start gap-3" hover={false}>
          <Hammer size={18} className="text-accent-primary shrink-0 mt-0.5" />
          <div className="text-xs text-text-secondary">
            <p className="text-sm font-medium text-text-primary">{t('common:placeholder.title')}</p>
            <p className="mt-0.5">{t('common:placeholder.body')}</p>
            {endpoint && <p className="mt-1 font-mono text-text-tertiary">{endpoint}</p>}
          </div>
        </Card>
        {load && (
          <Card className="p-4 overflow-auto" hover={false} data-testid="placeholder-data">
            {loading ? (
              <div className="flex justify-center py-8">
                <LoadingSpinner size="md" />
              </div>
            ) : error ? (
              <p className="text-sm status-danger-text" role="alert">
                {errorMessage(error)}
              </p>
            ) : (
              <JsonTree data={data} expandedDepth={1} />
            )}
          </Card>
        )}
      </div>
    </PageLayout>
  )
}

export default AreaPlaceholder
