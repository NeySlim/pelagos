// SPDX-License-Identifier: Apache-2.0
// The one plan UX (architecture section 6): summary, changes, preconditions,
// validations, diff, confirmation checkbox when the plan requires it, apply with
// per-node result, rollback while the plan is still held in memory, and job
// progress for install/import/security scopes that answer 202. A plan the server
// no longer holds (410 plan_expired, 404 after a restart, or the TTL ran out)
// offers "Recompute the plan" when the caller passes `onRecompute`, which builds
// the plan again from the same inputs and resolves to the new plan.
// Motion: validations tick in order along a hairline; at apply the sections fold and a
// step rail follows the real sequence (local apply, peers, results) from the `plans`
// step events (one per node as it answers), the audit entries and the ApplyResult; a
// rollback walks the rail back in amber.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Warning, ArrowCounterClockwise, ArrowClockwise, Lightning, CaretRight, Clock } from '@phosphor-icons/react'
import { api } from '../services/api'
import { errorMessage } from '../services/apiClient'
import { useWsTopic } from '../hooks/useWebSocket'
import { useNodeNames } from '../hooks/useNodeNames'
import { useMessage } from '../i18n/message'
import { useMotionLevel } from '../contexts/MotionContext'
import { emitPlanEvent, recalledApply, rememberApply } from '../lib/planEvents'
import {
  appliedSteps, auditPhase, buildSteps, estimateMs, finishApply, finishRollback, jobSteps, localApplied, localReverted, peerApplied, reverseFillMs, startApply, startRollback,
} from '../lib/planTrace'
import { Button } from './Button'
import { Badge } from './Badge'
import { StatusBadge } from './StatusBadge'
import { DiffView } from './DiffView'
import { Modal } from './Modal'
import { Checklist, CheckMark, RollingNumber, StepRail, SwapText } from './motion'
import { formatDate } from '../lib/utils'
import { cn } from '../lib/utils'

const JOB_SCOPES = ['install', 'import', 'security', 'restore']
const OP_VARIANT = { add: 'success', delete: 'danger', replace: 'warning' }
// Checks tick one after the other: 200 ms per tick, the next 60 ms later.
const TICK_GAP_MS = 60

// The server no longer has the plan: expired (410) or forgotten by a restart (404).
function isPlanGone(err) {
  return Boolean(err) && (err.code === 'plan_expired' || err.status === 410 || err.status === 404)
}

// A section folds through grid rows; `foldSignal` closes it when the apply starts.
function Section({ title, count, defaultOpen = true, foldSignal = 0, children, testId }) {
  const [open, setOpen] = useState(defaultOpen)
  useEffect(() => {
    if (foldSignal > 0) setOpen(false)
  }, [foldSignal])
  return (
    <div className="ui-subpanel border border-border rounded-lg overflow-hidden" data-testid={testId} data-open={open ? 'true' : 'false'}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="w-full flex items-center gap-2 px-3 py-1.5 text-xs font-semibold text-text-secondary bg-tertiary-op40 hover:bg-tertiary-op60"
      >
        <CaretRight size={10} weight="bold" className={cn('fx-chev', open && 'is-open')} />
        <span className="flex-1 text-left">{title}</span>
        {count !== undefined && <span className="text-2xs text-text-tertiary font-mono">{count}</span>}
      </button>
      <div className={cn('fx-fold', open && 'is-open')}>
        <div>
          <div className="p-2">{children}</div>
        </div>
      </div>
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

// Number of checks drawn so far: they tick in order once the plan is shown (full and
// reduced), all at once when motion is off. The plan state itself is the server's.
function useTickReveal(total, key) {
  const level = useMotionLevel()
  const [shown, setShown] = useState(level === 'off' ? total : 0)
  useEffect(() => {
    if (level === 'off') {
      setShown(total)
      return undefined
    }
    setShown(0)
    let i = 0
    let timer = null
    const next = () => {
      i += 1
      setShown(i)
      if (i < total) timer = setTimeout(next, 200 + TICK_GAP_MS)
    }
    if (total > 0) timer = setTimeout(next, 120)
    return () => clearTimeout(timer)
  }, [total, key, level])
  return shown
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
  // Starts the rollback as soon as it is shown (the "Roll back plan" action of a toast).
  autoRollback = false,
  // id -> display name; defaults to the names from GET /nodes
  nodeName: nodeNameProp,
}) {
  const { t } = useTranslation()
  const msg = useMessage()
  const level = useMotionLevel()
  const fetchedNodeName = useNodeNames(!nodeNameProp)
  const nodeName = nodeNameProp || fetchedNodeName
  const fieldLabel = (key) => t('fieldLabel', { label: t(key) })
  const recalled = initialPlan ? recalledApply(initialPlan.id) : null
  const [plan, setPlan] = useState(initialPlan)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(() => (initialPlan?.state === 'applied' ? recalled?.result || null : null))
  const [job, setJob] = useState(null)
  // The rail: steps, its direction and how long its current move takes.
  const [rail, setRail] = useState(() => (initialPlan?.state === 'applied' && recalled?.steps ? { steps: recalled.steps, reverse: false, fillMs: 0 } : null))
  const [foldSignal, setFoldSignal] = useState(0)
  const appliedAt = useRef(recalled?.at ?? null)
  const railRef = useRef(rail)
  railRef.current = rail
  useEffect(() => {
    const again = initialPlan ? recalledApply(initialPlan.id) : null
    setPlan(initialPlan)
    setResult(initialPlan?.state === 'applied' ? again?.result || null : null)
    setRail(initialPlan?.state === 'applied' && again?.steps ? { steps: again.steps, reverse: false, fillMs: 0 } : null)
    appliedAt.current = again?.at ?? null
    setJob(null)
    setError(null)
    setConfirmed(false)
  }, [initialPlan])

  const { expired, seconds } = useCountdown(plan?.expires_at)
  const isJobScope = JOB_SCOPES.includes(plan?.scope)
  const canApply = plan && plan.state === 'validated' && !expired && (!plan.requires_confirmation || confirmed) && !busy
  const applied = (result?.state || plan?.state) === 'applied'
  const canRollback = applied && !expired && !busy && !isJobScope
  const validations = useMemo(() => plan?.validations || [], [plan])
  const ticked = useTickReveal(validations.length, plan?.id)
  const ttlMs = plan?.expires_at && plan?.created_at ? Math.max(1, Date.parse(plan.expires_at) - Date.parse(plan.created_at)) : null

  const updateRail = useCallback((fn) => setRail((r) => (r ? fn(r) : r)), [])

  const handleApply = useCallback(async () => {
    setBusy(true)
    setError(null)
    const steps = startApply(buildSteps(plan), performance.now())
    if (!isJobScope) {
      setRail({ steps, reverse: false, fillMs: estimateMs('local') })
      setFoldSignal((n) => n + 1)
    }
    try {
      const res = await applyFn(plan.id, plan.requires_confirmation ? confirmed : false)
      if (res && res.steps !== undefined) {
        setRail(null)
        setFoldSignal((n) => n + 1)
        setJob(res)
        setPlan((p) => ({ ...p, state: 'applying' }))
      } else {
        const now = performance.now()
        const done = finishApply(railRef.current?.steps || steps, res, now)
        setRail({ steps: done, reverse: false, fillMs: estimateMs('peer') })
        setResult(res)
        setPlan((p) => ({ ...p, state: res?.state || 'applied' }))
        onApplied?.(res)
        // The server restarts the TTL at apply: the rollback window follows the fresh expires_at.
        if ((res?.state || 'applied') === 'applied') {
          appliedAt.current = Date.now()
          rememberApply(plan.id, { at: appliedAt.current, steps: done, result: res })
          emitPlanEvent({ type: 'applied', plan, at: appliedAt.current, result: res })
          Promise.resolve()
            .then(() => getFn(plan.id))
            .then((fresh) => fresh?.expires_at && setPlan((p) => ({ ...p, expires_at: fresh.expires_at })))
            .catch(() => {})
        }
      }
    } catch (err) {
      setError(err)
      setRail((r) => (r ? { ...r, steps: r.steps.map((s) => (s.state === 'running' ? { ...s, state: 'failed', nodes: s.nodes.map((n) => (n.state === 'running' ? { ...n, state: 'failed' } : n)) } : s)) } : r))
      if (isPlanGone(err)) setPlan((p) => ({ ...p, state: 'expired' }))
    } finally {
      setBusy(false)
    }
  }, [applyFn, getFn, plan, confirmed, onApplied, isJobScope])

  const handleRollback = useCallback(async () => {
    setBusy(true)
    setError(null)
    setPlan((p) => ({ ...p, state: 'rolling_back' }))
    const base = railRef.current?.steps || appliedSteps(plan)
    const walking = startRollback(base, performance.now())
    setRail({ steps: walking, reverse: true, fillMs: reverseFillMs(base, walking.find((s) => s.state === 'running')?.id) })
    emitPlanEvent({ type: 'rollback-start', plan, at: appliedAt.current })
    try {
      const res = await rollbackFn(plan.id)
      const steps = finishRollback(railRef.current?.steps || walking, res, performance.now())
      setRail({ steps, reverse: true, fillMs: reverseFillMs(base, 'local') })
      setResult(res)
      setPlan((p) => ({ ...p, state: res?.state || 'rolled_back' }))
      emitPlanEvent({ type: 'rolled-back', plan, at: Date.now(), result: res })
      onRolledBack?.(res)
    } catch (err) {
      setError(err)
      setPlan((p) => ({ ...p, state: 'applied' }))
      setRail({ steps: base, reverse: false, fillMs: 0 })
      emitPlanEvent({ type: 'rolled-back', plan, at: Date.now(), result: null })
    } finally {
      setBusy(false)
    }
  }, [rollbackFn, plan, onRolledBack])

  // A rollback asked from elsewhere (a toast action) starts once, when the plan can.
  const autoStarted = useRef(false)
  useEffect(() => {
    if (!autoRollback || autoStarted.current || !canRollback) return
    autoStarted.current = true
    handleRollback()
  }, [autoRollback, canRollback, handleRollback])

  // The building node's own audit entry: its part is done (apply) or undone (rollback).
  useWsTopic(busy && rail ? 'audit' : null, (message) => {
    const phase = auditPhase(message?.data, plan?.id, plan?.node_id)
    if (!phase) return
    const now = performance.now()
    if (phase === 'apply') updateRail((r) => (r.reverse ? r : { ...r, steps: localApplied(r.steps, now), fillMs: estimateMs('peer') }))
    else updateRail((r) => (r.reverse ? { ...r, steps: localReverted(r.steps, now), fillMs: reverseFillMs(r.steps, 'local') } : r))
  })

  // Each node's step as it ends (`plans`/`step`): the local chip, then every peer's chip
  // finishes when that peer answered, not when the whole apply returns.
  useWsTopic(busy && rail ? 'plans' : null, (message) => {
    const d = message?.data
    if (message?.event !== 'step' || !d || d.plan_id !== plan?.id || d.verb !== 'apply') return
    if (d.state !== 'done' && d.state !== 'failed') return
    const now = performance.now()
    const self = plan?.node_id
    updateRail((r) => {
      if (r.reverse) return r
      if (d.node_id === self) return { ...r, steps: localApplied(r.steps, now), fillMs: estimateMs('peer') }
      return { ...r, steps: peerApplied(r.steps, d.node_id, d.state === 'done', now), fillMs: estimateMs('peer') }
    })
  })

  const handleRecompute = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const fresh = await onRecompute()
      if (fresh) {
        setPlan(fresh)
        setResult(null)
        setJob(null)
        setRail(null)
        setConfirmed(false)
      }
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }, [onRecompute])

  // Job progress: WebSocket when connected, polling as the fallback.
  useWsTopic(job && job.state !== 'done' && job.state !== 'failed' ? 'jobs' : null, (message) => {
    if (message.data?.id === job?.id) setJob(message.data)
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

  // A one-line output reads beside its tool; a longer one gets its own block below.
  const shortOutput = (v) => (v.output && v.output.length <= 60 && !v.output.includes('\n') ? v.output : null)
  const checkItems = validations.map((v, i) => ({
    id: `${v.tool}-${v.node_id || ''}-${i}`,
    label: <span className="font-mono text-text-primary">{v.tool}</span>,
    detail: [v.node_id ? nodeName(v.node_id) : null, shortOutput(v) || (v.ok ? t('plan.valid') : t('plan.invalid'))].filter(Boolean).join('  '),
    state: i < ticked ? (v.ok ? 'done' : 'failed') : i === ticked ? 'running' : 'pending',
  }))
  const passed = validations.filter((v, i) => v.ok && i < ticked).length
  const railSteps = rail
    ? rail.steps.map((s) => ({
        id: s.id,
        state: s.state,
        label: t(`plan.steps.${s.kind}`, { node: nodeName(s.nodes[0]?.id) }),
        ms: s.state === 'reverted' ? undefined : s.ms ?? undefined,
        note: s.state === 'reverted' ? t('motion.states.reverted') : undefined,
        nodes: s.nodes.map((n) => ({
          name: nodeName(n.id),
          state: n.state,
          durationMs: n.state === 'running' ? estimateMs(n.kind) : n.ms ?? undefined,
        })),
      }))
    : null
  const statusKey = plan.state
  const live = level === 'full' && !expired && !applied && !result

  return (
    <div className={cn('flex flex-col gap-3', className)} data-testid="plan-preview" data-plan-state={statusKey}>
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
        <StatusBadge status={statusKey} label={<SwapText text={t(`status.${statusKey}`, { defaultValue: String(statusKey).replace(/[-_]/g, ' ') })} />} data-testid="plan-state" />
        {plan.requires_confirmation && (
          <Badge variant="warning" size="sm" icon={Warning}>
            {t('plan.requiresConfirmation')}
          </Badge>
        )}
        <span
          className={cn('fx-expiry ml-auto text-2xs text-text-tertiary font-mono', live && 'is-live')}
          title={formatDate(plan.expires_at)}
          data-testid="plan-expiry"
        >
          <Clock size={11} />
          {expired ? t('plan.expired') : t('plan.expiresIn', { seconds })}
          {ttlMs && seconds !== null && !expired && <i aria-hidden="true" style={{ transform: `scaleX(${Math.min(1, (seconds * 1000) / ttlMs).toFixed(4)})` }} />}
        </span>
      </div>

      <p className="text-sm text-text-primary" data-testid="plan-summary">
        {msg(plan.summary_message, plan.summary)}
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
                <Badge variant={OP_VARIANT[change.op] || 'default'} size="sm" className="uppercase min-w-16 shrink-0 whitespace-nowrap justify-center">
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
      <Section title={t('plan.preconditions')} count={plan.preconditions?.length || 0} defaultOpen={false} foldSignal={foldSignal} testId="plan-preconditions">
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

      {/* Validations: each tool ticks in order along the hairline */}
      <Section
        title={t('plan.validations')}
        count={validations.length ? <RollingNumber value={`${passed}/${validations.length}`} delta={false} data-testid="plan-validations-count" /> : 0}
        foldSignal={foldSignal}
        testId="plan-validations"
      >
        {!validations.length ? (
          <p className="text-xs text-text-tertiary italic">{t('plan.noValidations')}</p>
        ) : (
          <>
            <Checklist items={checkItems} showCount={false} testId="plan-checklist" />
            {validations.map(
              (v, i) =>
                v.output &&
                !shortOutput(v) && (
                  <pre key={i} className="mt-1 ml-5 p-2 rounded bg-bg-primary border border-border-op50 text-2xs font-mono whitespace-pre-wrap text-text-secondary max-h-40 overflow-auto">
                    {v.output}
                  </pre>
                ),
            )}
          </>
        )}
      </Section>

      {/* Diff */}
      <Section title={t('plan.diff')} foldSignal={foldSignal} testId="plan-diff">
        <DiffView diff={plan.diff} maxHeight={320} />
      </Section>

      {/* Apply and rollback: the rail follows the real sequence */}
      {railSteps && (
        <div className="rounded-lg border border-border px-3 py-1" data-testid="plan-rail" data-direction={rail.reverse ? 'reverse' : 'forward'}>
          <StepRail steps={railSteps} reverse={rail.reverse} fillMs={rail.fillMs} testId="plan-steps" />
        </div>
      )}

      {/* Job progress */}
      {job && (
        <div className="rounded-lg border border-border p-3 space-y-2" data-testid="plan-job">
          <div className="flex items-center gap-2 text-xs">
            <StatusBadge status={job.state} />
            <span className="text-text-secondary">{t('plan.jobProgress', { percent: job.progress ?? 0 })}</span>
          </div>
          <StepRail
            steps={jobSteps(job).map((s) => ({
              id: s.id,
              state: s.state,
              ms: s.ms,
              label: <span title={s.step.name}>{msg(s.step.label_message, s.step.label || s.step.name)}</span>,
              detail: s.output || undefined,
            }))}
            testId="plan-job-steps"
          />
          {job.error && <p className="text-xs status-danger-text">{job.error}</p>}
        </div>
      )}

      {/* Apply result */}
      {result && (
        <div className="fx-rise-in rounded-lg border border-border p-3 space-y-1.5" data-testid="plan-result">
          <div className="flex items-center gap-2 text-xs">
            <StatusBadge status={result.state} />
            <span className="text-text-tertiary">{formatDate(result.finished_at)}</span>
          </div>
          <ul className="space-y-1">
            {(result.results || []).map((r, i) => (
              <li key={`${r.node_id}-${i}`} className="flex items-start gap-2 text-xs">
                <CheckMark state={r.ok ? (r.rolled_back ? 'reverted' : 'done') : 'failed'} className="mt-0.5" />
                <span className="font-mono text-text-primary" title={r.node_id}>{nodeName(r.node_id)}</span>
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
          {(canRollback || plan.state === 'rolling_back') && (
            <Button type="button" variant="warning-soft" size="sm" onClick={handleRollback} loading={busy} loadingText={t('status.rolling_back')} data-testid="plan-rollback">
              <ArrowCounterClockwise size={14} />
              {t('plan.rollback')}
            </Button>
          )}
          {!applied && !result && plan.state !== 'rolling_back' && (
            <Button type="button" variant="primary" size="sm" onClick={handleApply} disabled={!canApply} loading={busy} loadingText={t('status.applying')} data-testid="plan-apply">
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
