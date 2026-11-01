// SPDX-License-Identifier: Apache-2.0
// One plan from the Plans page: read through PlanPreview (no Apply here), with "Roll back" only
// to its creator or an admin while rollback_until is ahead, and a link to the plan's audit entries.
// The `plans` topic keeps the open plan current (rolled back elsewhere, expired).
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ClipboardText } from '@phosphor-icons/react'
import { Modal } from '../../components/Modal'
import { PlanPreview } from '../../components/PlanPreview'
import { ErrorNotice } from '../../components/ErrorNotice'
import { ReadOnlyNote } from '../../components/ReadOnlyNote'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { useAuth } from '../../contexts/AuthContext'
import { useApi, useWsTopic } from '../../hooks'
import { api } from '../../services/api'
import { onPlanEvent } from '../../lib/planEvents'
import { formatDate } from '../../lib/utils'
import { ownsPlan, rollbackWindow } from './lib'

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

const isGone = (err) => Boolean(err) && (err.status === 404 || err.status === 410)

export function PlanDetailModal({ id, onClose, onChanged }) {
  const { t } = useTranslation(['plans', 'common'])
  const { user, isAdmin } = useAuth()
  const { data, error, loading, setData } = useApi(() => api.plans.get(id), [id], { enabled: Boolean(id) })
  const plan = data && data.id === id ? data : null
  const [vanished, setVanished] = useState(false)
  const [refused, setRefused] = useState(false)
  // True from the moment this modal starts a rollback: its own events must not reload the plan
  // under PlanPreview, which already shows the outcome.
  const acting = useRef(false)
  const shown = useRef(null)
  shown.current = plan
  useEffect(() => {
    setVanished(false)
    setRefused(false)
    acting.current = false
  }, [id])
  useEffect(
    () =>
      onPlanEvent((event) => {
        if (event.plan?.id !== id) return
        if (event.type === 'rollback-start') acting.current = true
        // A refused rollback leaves the plan as it was: reloads are fine again.
        if (event.type === 'rolled-back' && !event.result) acting.current = false
      }),
    [id],
  )

  const reload = useCallback(async () => {
    try {
      const fresh = await api.plans.get(id)
      const cur = shown.current
      if (!acting.current && cur && (fresh.state !== cur.state || fresh.rollback_until !== cur.rollback_until)) setData(fresh)
    } catch (err) {
      if (isGone(err)) setVanished(true)
    }
  }, [id, setData])
  useWsTopic(id ? 'plans' : null, (message) => {
    if (message?.event === 'step' || message?.data?.plan_id !== id) return
    reload()
  })

  const gone = vanished || isGone(error)
  const win = plan ? rollbackWindow(plan) : null
  const rollable = plan && (plan.state === 'applied' || (plan.state === 'failed' && plan.interrupted))
  const mine = plan ? ownsPlan(plan, user, isAdmin) : false
  const canRollback = Boolean(plan) && win.status === 'open' && mine && !refused

  return (
    <Modal open={Boolean(id)} onClose={onClose} title={t('detail.title')} size="lg" bodyScroll={false}>
      {plan && !vanished ? (
        <div className="flex flex-col flex-1 min-h-0" data-testid="plan-detail">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 pt-3 text-xs">
            <Link to={`/audit?plan_id=${encodeURIComponent(plan.id)}`} className="inline-flex items-center gap-1 text-accent-primary hover:underline" data-testid="plan-detail-audit">
              <ClipboardText size={12} />
              {t('detail.audit')}
            </Link>
            {rollable && (win.status === 'closed' || refused) && (
              <ReadOnlyNote reason="state" testId="plan-rollback-closed">{t('rollback.closedOn', { date: formatDate(plan.rollback_until) })}</ReadOnlyNote>
            )}
            {rollable && win.status === 'none' && <ReadOnlyNote reason="state" testId="plan-rollback-none">{t('rollback.none')}</ReadOnlyNote>}
            {rollable && win.status === 'open' && !mine && (
              <ReadOnlyNote reason="state" testId="plan-rollback-not-yours">{t('rollback.notYours', { user: plan.created_by })}</ReadOnlyNote>
            )}
          </div>
          <PlanPreview
            plan={plan}
            layout="modal"
            allowApply={false}
            allowRollback={canRollback}
            onClose={onClose}
            onRolledBack={() => onChanged?.()}
            onRollbackError={(err) => {
              // The window ended (410) or the plan is gone: no button, and the list catches up.
              if (isGone(err)) {
                setRefused(true)
                onChanged?.()
              }
            }}
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
