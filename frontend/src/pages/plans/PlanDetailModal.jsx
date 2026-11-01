// SPDX-License-Identifier: Apache-2.0
// One plan from the Plans page: read through PlanPreview (no Apply here), with "Roll back" only
// while rollback_until is in the future, and a link to the plan's audit entries.
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ClipboardText } from '@phosphor-icons/react'
import { Modal } from '../../components/Modal'
import { PlanPreview } from '../../components/PlanPreview'
import { ErrorNotice } from '../../components/ErrorNotice'
import { ReadOnlyNote } from '../../components/ReadOnlyNote'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { useApi } from '../../hooks'
import { api } from '../../services/api'
import { formatDate } from '../../lib/utils'
import { rollbackWindow } from './lib'

function Gone({ id }) {
  const { t } = useTranslation('plans')
  return (
    <div className="space-y-2 p-4" data-testid="plan-detail-gone">
      <p className="text-sm text-text-primary">{t('detail.gone')}</p>
      <Link to={`/audit?plan_id=${encodeURIComponent(id)}`} className="text-xs text-accent-primary hover:underline" data-testid="plan-detail-audit">
        {t('detail.audit')}
      </Link>
    </div>
  )
}

export function PlanDetailModal({ id, onClose, onChanged }) {
  const { t } = useTranslation(['plans', 'common'])
  const { data, error, loading } = useApi(() => api.plans.get(id), [id], { enabled: Boolean(id) })
  const plan = data && data.id === id ? data : null
  const gone = error && (error.status === 404 || error.status === 410)
  const rbWindow = plan ? rollbackWindow(plan) : null

  return (
    <Modal open={Boolean(id)} onClose={onClose} title={t('detail.title')} size="lg" bodyScroll={false}>
      {plan ? (
        <div className="flex flex-col flex-1 min-h-0" data-testid="plan-detail">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 pt-3 text-xs">
            <Link to={`/audit?plan_id=${encodeURIComponent(plan.id)}`} className="inline-flex items-center gap-1 text-accent-primary hover:underline" data-testid="plan-detail-audit">
              <ClipboardText size={12} />
              {t('detail.audit')}
            </Link>
            {plan.state === 'applied' && rbWindow.status === 'closed' && (
              <ReadOnlyNote reason="state" testId="plan-rollback-closed">{t('rollback.closedOn', { date: formatDate(plan.rollback_until) })}</ReadOnlyNote>
            )}
            {plan.state === 'applied' && rbWindow.status === 'none' && (
              <ReadOnlyNote reason="state" testId="plan-rollback-none">{t('rollback.none')}</ReadOnlyNote>
            )}
          </div>
          <PlanPreview
            plan={plan}
            layout="modal"
            allowApply={false}
            allowRollback={rbWindow.status === 'open'}
            onClose={onClose}
            onRolledBack={() => onChanged?.()}
          />
        </div>
      ) : (
        <div className="p-4 overflow-auto">
          {loading && (
            <div className="flex justify-center py-8">
              <LoadingSpinner size="md" />
            </div>
          )}
          {gone && <Gone id={id} />}
          {error && !gone && <ErrorNotice error={error} />}
        </div>
      )}
    </Modal>
  )
}

export default PlanDetailModal
