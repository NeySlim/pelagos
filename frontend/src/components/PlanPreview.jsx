// SPDX-License-Identifier: Apache-2.0
// The one plan UX (architecture section 6): summary, changes, preconditions,
// validations, diff, confirmation checkbox when the plan requires it, apply with
// per-node result, rollback while the plan is still held in memory, and job
// progress for install/import/security scopes that answer 202. A plan the server
// no longer holds (410 plan_expired, 404 after a restart, or the TTL ran out)
// offers "Recompute the plan" when the caller passes `onRecompute`, which builds
// the plan again from the same inputs and resolves to the new plan.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCircle, XCircle, Warning, ArrowCounterClockwise, ArrowClockwise, Lightning, CaretDown, CaretRight, Clock } from '@phosphor-icons/react'
import { api } from '../services/api'
import { errorMessage } from '../services/apiClient'
import { useWsTopic } from '../hooks/useWebSocket'
import { useNodeNames } from '../hooks/useNodeNames'
import { Button } from './Button'
import { Badge } from './Badge'
import { StatusBadge } from './StatusBadge'
import { DiffView } from './DiffView'
import { Modal } from './Modal'
import { formatDate } from '../lib/utils'
import { cn } from '../lib/utils'

const JOB_SCOPES = ['install', 'import', 'security']
const OP_VARIANT = { add: 'success', delete: 'danger', replace: 'warning' }

// The server no longer has the plan: expired (410) or forgotten by a restart (404).
function isPlanGone(err) {
  return Boolean(err) && (err.code === 'plan_expired' || err.status === 410 || err.status === 404)
}

function Section({ title, count, defaultOpen = true, children, testId }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-border rounded-lg overflow-hidden" data-testid={testId}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 px-3 py-1.5 text-xs font-semibold text-text-secondary bg-tertiary-op40 hover:bg-tertiary-op60"
      >
        {open ? <CaretDown size={10} weight="bold" /> : <CaretRight size={10} weight="bold" />}
        <span className="flex-1 text-left">{title}</span>
        {count !== undefined && <span className="text-2xs text-text-tertiary font-mono">{count}</span>}
      </button>
      {open && <div className="p-2">{children}</div>}
    </div>
  )
}

function useCountdown(expiresAt) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])
  if (!expiresAt) return { expired: false, seconds: null }
  const seconds = Math.max(0, Math.floor((new Date(expiresAt).getTime() - now) / 1000))
  return { expired: seconds <= 0, seconds }
}

export function PlanPreview({
  plan: initialPlan,
  onApplied,
  onRolledBack,
  onClose,
  onRecompute,
  applyFn = (id, confirm) => api.plans.apply(id, confirm),
  rollbackFn = (id) => api.plans.rollback(id),
  jobFn = (id) => api.jobs.get(id),
  getFn = (id) => api.plans.get(id),
  closeLabel,
  className,
  // id -> display name; defaults to the names from GET /nodes
  nodeName: nodeNameProp,
}) {
  const { t } = useTranslation()
  const fetchedNodeName = useNodeNames(!nodeNameProp)
  const nodeName = nodeNameProp || fetchedNodeName
  const fieldLabel = (key) => t('fieldLabel', { label: t(key) })
  const [plan, setPlan] = useState(initialPlan)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [job, setJob] = useState(null)
  useEffect(() => {
    setPlan(initialPlan)
    setResult(null)
    setJob(null)
    setError(null)
    setConfirmed(false)
  }, [initialPlan])

  const { expired, seconds } = useCountdown(plan?.expires_at)
  const isJobScope = JOB_SCOPES.includes(plan?.scope)
  const canApply = plan && plan.state === 'validated' && !expired && (!plan.requires_confirmation || confirmed) && !busy
  const applied = (result?.state || plan?.state) === 'applied'
  const canRollback = applied && !expired && !busy && !isJobScope
  const failedValidation = plan?.validations?.some((v) => !v.ok)

  const handleApply = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await applyFn(plan.id, plan.requires_confirmation ? confirmed : false)
      if (res && res.steps !== undefined) {
        setJob(res)
        setPlan((p) => ({ ...p, state: 'applying' }))
      } else {
        setResult(res)
        setPlan((p) => ({ ...p, state: res?.state || 'applied' }))
        onApplied?.(res)
        // The server restarts the TTL at apply: the rollback window follows the fresh expires_at.
        if ((res?.state || 'applied') === 'applied') {
          Promise.resolve()
            .then(() => getFn(plan.id))
            .then((fresh) => fresh?.expires_at && setPlan((p) => ({ ...p, expires_at: fresh.expires_at })))
            .catch(() => {})
        }
      }
    } catch (err) {
      setError(err)
      if (isPlanGone(err)) setPlan((p) => ({ ...p, state: 'expired' }))
    } finally {
      setBusy(false)
    }
  }, [applyFn, getFn, plan, confirmed, onApplied])

  const handleRollback = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await rollbackFn(plan.id)
      setResult(res)
      setPlan((p) => ({ ...p, state: res?.state || 'rolled_back' }))
      onRolledBack?.(res)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }, [rollbackFn, plan, onRolledBack])

  const handleRecompute = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const fresh = await onRecompute()
      if (fresh) {
        setPlan(fresh)
        setResult(null)
        setJob(null)
        setConfirmed(false)
      }
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }, [onRecompute])

  // Job progress: WebSocket when connected, polling as the fallback.
  useWsTopic(job && job.state !== 'done' && job.state !== 'failed' ? 'jobs' : null, (msg) => {
    if (msg.data?.id === job?.id) setJob(msg.data)
  })
  useEffect(() => {
    if (!job || job.state === 'done' || job.state === 'failed') return undefined
    const timer = setInterval(async () => {
      try {
        const fresh = await jobFn(job.id)
        setJob(fresh)
      } catch {
        // keep the last known state; the next tick retries
      }
    }, 2000)
    return () => clearInterval(timer)
  }, [job, jobFn])
  useEffect(() => {
    if (!job) return
    if (job.state === 'done') {
      setPlan((p) => ({ ...p, state: 'applied' }))
      onApplied?.(job)
    } else if (job.state === 'failed') {
      setPlan((p) => ({ ...p, state: 'failed', error: job.error }))
    }
  }, [job?.state]) // eslint-disable-line react-hooks/exhaustive-deps

  const changeRows = useMemo(() => plan?.changes || [], [plan])
  const gone = !applied && !result && !job && (expired || plan?.state === 'expired' || isPlanGone(error))

  if (!plan) return null

  return (
    <div className={cn('flex flex-col gap-3', className)} data-testid="plan-preview">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="primary" size="sm">
          {t(`plan.scope.${plan.scope}`, { defaultValue: plan.scope })}
        </Badge>
        {plan.engine && (
          <Badge variant="outline" size="sm" className="font-mono">
            {plan.engine}
          </Badge>
        )}
        <StatusBadge status={plan.state} />
        {plan.requires_confirmation && (
          <Badge variant="warning" size="sm" icon={Warning}>
            {t('plan.requiresConfirmation')}
          </Badge>
        )}
        <span className="ml-auto inline-flex items-center gap-1 text-2xs text-text-tertiary font-mono" title={formatDate(plan.expires_at)}>
          <Clock size={11} />
          {expired ? t('plan.expired') : t('plan.expiresIn', { seconds })}
        </span>
      </div>

      <p className="text-sm text-text-primary" data-testid="plan-summary">
        {plan.summary}
      </p>

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-2xs text-text-tertiary">
        <span>
          {fieldLabel('plan.id')} <span className="font-mono text-text-secondary">{plan.id}</span>
        </span>
        <span>
          {fieldLabel('plan.createdBy')} <span className="text-text-secondary">{plan.created_by}</span>
        </span>
        <span data-testid="plan-target-nodes">
          {fieldLabel('plan.targetNodes')}{' '}
          <span className="text-text-secondary">{plan.target_node_ids?.length ? plan.target_node_ids.map(nodeName).join(', ') : t('plan.allNodes')}</span>
        </span>
      </div>

      {plan.error && (
        <div className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text" data-testid="plan-error">
          {plan.error}
        </div>
      )}

      {/* Changes */}
      <Section title={t('plan.changes')} count={changeRows.length} testId="plan-changes">
        {changeRows.length === 0 ? (
          <p className="text-xs text-text-tertiary italic">{t('plan.noChanges')}</p>
        ) : (
          <ul className="space-y-1">
            {changeRows.map((change, i) => (
              <li key={i} className="flex items-center gap-2 text-xs">
                <Badge variant={OP_VARIANT[change.op] || 'default'} size="sm" className="uppercase w-16 justify-center">
                  {t(`plan.op.${change.op}`, { defaultValue: change.op })}
                </Badge>
                <span className="font-mono text-text-primary break-all">{change.target}</span>
                {change.node_ids?.length > 0 && <span className="text-text-tertiary">[{change.node_ids.map(nodeName).join(', ')}]</span>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* Preconditions */}
      <Section title={t('plan.preconditions')} count={plan.preconditions?.length || 0} defaultOpen={false} testId="plan-preconditions">
        {!plan.preconditions?.length ? (
          <p className="text-xs text-text-tertiary italic">{t('plan.noPreconditions')}</p>
        ) : (
          <table className="w-full text-xs">
            <tbody>
              {plan.preconditions.map((p, i) => (
                <tr key={i} className="border-b border-border-op30 last:border-0">
                  <td className="py-1 pr-2 text-text-secondary whitespace-nowrap">{t(`plan.precondition.${p.kind}`, { defaultValue: p.kind })}</td>
                  <td className="py-1 pr-2 text-text-tertiary">{p.node_id ? nodeName(p.node_id) : t('plan.allNodes')}</td>
                  <td className="py-1 pr-2 font-mono text-text-primary break-all">{p.subject}</td>
                  <td className="py-1 font-mono text-text-secondary break-all">{p.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* Validations */}
      <Section title={t('plan.validations')} count={plan.validations?.length || 0} defaultOpen={Boolean(failedValidation)} testId="plan-validations">
        {!plan.validations?.length ? (
          <p className="text-xs text-text-tertiary italic">{t('plan.noValidations')}</p>
        ) : (
          <ul className="space-y-1.5">
            {plan.validations.map((v, i) => (
              <li key={i} className="text-xs">
                <div className="flex items-center gap-2">
                  {v.ok ? <CheckCircle size={14} weight="fill" className="status-success-text" /> : <XCircle size={14} weight="fill" className="status-danger-text" />}
                  <span className="font-mono text-text-primary">{v.tool}</span>
                  {v.node_id && <span className="text-text-tertiary">{nodeName(v.node_id)}</span>}
                  <span className={v.ok ? 'status-success-text' : 'status-danger-text'}>{v.ok ? t('plan.valid') : t('plan.invalid')}</span>
                </div>
                {v.output && (
                  <pre className="mt-1 ml-5 p-2 rounded bg-bg-primary border border-border-op50 text-2xs font-mono whitespace-pre-wrap text-text-secondary max-h-40 overflow-auto">
                    {v.output}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* Diff */}
      <Section title={t('plan.diff')} testId="plan-diff">
        <DiffView diff={plan.diff} maxHeight={320} />
      </Section>

      {/* Job progress */}
      {job && (
        <div className="rounded-lg border border-border p-3 space-y-2" data-testid="plan-job">
          <div className="flex items-center gap-2 text-xs">
            <StatusBadge status={job.state} />
            <span className="text-text-secondary">{t('plan.jobProgress', { percent: job.progress ?? 0 })}</span>
          </div>
          <div className="h-1.5 rounded-full bg-tertiary-op80 overflow-hidden">
            <div className="h-full status-primary-bg-solid transition-all" style={{ width: `${job.progress ?? 0}%` }} />
          </div>
          <ul className="space-y-0.5 text-2xs">
            {(job.steps || []).map((step, i) => (
              <li key={i} className="flex items-center gap-2">
                <StatusBadge status={step.state} dot={false} size="sm" />
                <span className="text-text-primary">{step.name}</span>
                {step.output && <span className="text-text-tertiary font-mono truncate">{step.output}</span>}
              </li>
            ))}
          </ul>
          {job.error && <p className="text-xs status-danger-text">{job.error}</p>}
        </div>
      )}

      {/* Apply result */}
      {result && (
        <div className="rounded-lg border border-border p-3 space-y-1.5" data-testid="plan-result">
          <div className="flex items-center gap-2 text-xs">
            <StatusBadge status={result.state} />
            <span className="text-text-tertiary">{formatDate(result.finished_at)}</span>
          </div>
          <ul className="space-y-1">
            {(result.results || []).map((r) => (
              <li key={r.node_id} className="flex items-start gap-2 text-xs">
                {r.ok ? <CheckCircle size={14} weight="fill" className="status-success-text mt-0.5" /> : <XCircle size={14} weight="fill" className="status-danger-text mt-0.5" />}
                <span className="text-text-primary" title={r.node_id}>{nodeName(r.node_id)}</span>
                <span className="text-text-secondary flex-1">{r.message}</span>
                {r.rolled_back && (
                  <Badge variant="warning" size="sm">
                    {t('status.rolled_back')}
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text space-y-1" data-testid="plan-apply-error">
          <div className="font-medium">{errorMessage(error)}</div>
          {error.errors?.length > 0 && (
            <ul className="list-disc ml-4 font-mono text-2xs whitespace-pre-wrap">
              {error.errors.map((e, i) => (
                <li key={i}>
                  {e.field ? `${e.field}: ` : ''}
                  {e.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {gone && onRecompute && (
        <div className="rounded-lg status-warning-bg border status-warning-border px-3 py-2 text-xs status-warning-text flex flex-wrap items-center gap-2" data-testid="plan-gone">
          <span className="flex-1">{t('plan.recomputeHint')}</span>
          <Button type="button" variant="primary" size="sm" onClick={handleRecompute} loading={busy} data-testid="plan-recompute">
            <ArrowClockwise size={14} />
            {t('plan.recompute')}
          </Button>
        </div>
      )}

      {/* Confirmation + actions */}
      <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-border">
        {plan.requires_confirmation && !applied && !result && (
          <label className="flex items-center gap-2 text-xs text-text-primary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="accent-[var(--accent-warning)]"
              data-testid="plan-confirm-checkbox"
            />
            {t('plan.confirmCheckbox')}
          </label>
        )}
        <div className="ml-auto flex items-center gap-2">
          {onClose && (
            <Button type="button" variant="secondary" size="sm" onClick={onClose} disabled={busy}>
              {closeLabel || (applied || result ? t('actions.close') : t('actions.cancel'))}
            </Button>
          )}
          {canRollback && (
            <Button type="button" variant="warning-soft" size="sm" onClick={handleRollback} loading={busy} data-testid="plan-rollback">
              <ArrowCounterClockwise size={14} />
              {t('plan.rollback')}
            </Button>
          )}
          {!applied && !result && (
            <Button type="button" variant="primary" size="sm" onClick={handleApply} disabled={!canApply} loading={busy} data-testid="plan-apply">
              <Lightning size={14} weight="fill" />
              {t('plan.apply')}
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}

// PlanPreview inside a modal: the usual way a page shows a plan it just built.
export function PlanPreviewModal({ open, onClose, plan, title, ...rest }) {
  const { t } = useTranslation()
  return (
    <Modal open={open} onClose={onClose} title={title || t('plan.title')} size="lg">
      <div className="p-4">
        <PlanPreview plan={plan} onClose={onClose} {...rest} />
      </div>
    </Modal>
  )
}

export default PlanPreview
