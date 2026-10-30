// SPDX-License-Identifier: Apache-2.0
// Kea migration wizard (architecture section 28): prepare, migrate, verify. The replicated record
// (GET /install/kea-migration/{id}, every 2 s while a phase runs) drives the timeline of times 1
// to 3; `ha` events move each node's HA state live; the outage counts from the primary's stop.
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowCounterClockwise, ArrowsLeftRight, ListChecks, Package, Timer, WarningOctagon } from '@phosphor-icons/react'
import { Card, Button, Badge } from '../../components'
import { PlanPreviewModal } from '../../components/PlanPreview'
import { StepRail } from '../../components/motion'
import { usePoll } from '../../hooks/usePoll'
import { usePermission } from '../../hooks/usePermission'
import { useWsTopic } from '../../hooks/useWebSocket'
import { useMessage } from '../../i18n/message'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate, cn } from '../../lib/utils'
import { outputText } from '../../lib/planTrace'
import {
  NODE_STATUS_VARIANT, STATE_VARIANT, WIZARD_STEPS, haUpdate, isActive, outage, planBlocker, planId, reconcileOffered, stepMessageKey,
  timeline, wizardStates, wizardStep,
} from './keaMigration'

const POLL_MS = 2000

function Stepper({ states }) {
  const { t } = useTranslation('install')
  return (
    <ol className="grid grid-cols-3 gap-2" data-testid="kea-wizard-steps">
      {WIZARD_STEPS.map((step, i) => (
        <li
          key={step}
          className={cn(
            'rounded-md border px-3 py-2 text-sm',
            states[step] === 'running' ? 'border-accent-primary' : states[step] === 'failed' ? 'border-status-danger' : 'border-border',
          )}
          data-testid="kea-wizard-step"
          data-step={step}
          data-state={states[step]}
        >
          <span className="text-2xs uppercase tracking-wider text-text-tertiary">{i + 1}</span>{' '}
          <span className="font-medium text-text-primary">{t(`keaMigration.wizard.steps.${step}`)}</span>
          <span className="block text-xs text-text-secondary">{t(`common:motion.states.${states[step]}`)}</span>
        </li>
      ))}
    </ol>
  )
}

function OutagePanel({ migration }) {
  const { t } = useTranslation('install')
  const [now, setNow] = useState(Date.now())
  const shown = outage(migration, now)
  const live = Boolean(shown?.live)
  useEffect(() => {
    if (!live) return undefined
    const timer = setInterval(() => setNow(Date.now()), 250)
    return () => clearInterval(timer)
  }, [live])
  const max = migration.outage_max_seconds
  const over = shown && max && shown.seconds > max
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="kea-wizard-outage" data-live={live || undefined}>
      <Timer size={16} className={live ? 'status-warning-text' : 'text-text-secondary'} />
      {shown ? (
        <span className={cn(live ? 'status-warning-text' : 'text-text-primary', over && 'status-danger-text')} data-testid="kea-wizard-outage-value">
          {t(live ? 'keaMigration.wizard.outage.live' : 'keaMigration.wizard.outage.measured', { seconds: shown.seconds.toFixed(1) })}
        </span>
      ) : (
        <span className="text-text-secondary">{t('keaMigration.wizard.outage.none')}</span>
      )}
      {max ? <span className="text-xs text-text-tertiary">{t('keaMigration.wizard.outage.max', { seconds: max })}</span> : null}
    </div>
  )
}

function NodesTable({ migration, haLive }) {
  const { t } = useTranslation('install')
  const msg = useMessage()
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm" data-testid="kea-wizard-nodes">
        <thead>
          <tr className="text-left text-2xs uppercase tracking-wider text-text-tertiary">
            <th className="py-1 pr-3">{t('keaMigration.nodes.node')}</th>
            <th className="py-1 pr-3">{t('keaMigration.wizard.nodes.role')}</th>
            <th className="py-1 pr-3">{t('keaMigration.wizard.nodes.ha')}</th>
            <th className="py-1 pr-3">{t('keaMigration.nodes.version')}</th>
            <th className="py-1 pr-3">{t('keaMigration.wizard.nodes.step')}</th>
            <th className="py-1">{t('keaMigration.wizard.nodes.status')}</th>
          </tr>
        </thead>
        <tbody>
          {(migration.nodes || []).map((n) => {
            const ha = haLive[n.node_id] ?? n.ha_state
            return (
              <tr key={n.node_id} className="border-t border-border" data-testid="kea-wizard-node" data-node={n.node_id}>
                <td className="py-1.5 pr-3 font-medium">{n.name || n.node_id}</td>
                <td className="py-1.5 pr-3">{t(`keaMigration.wizard.role.${n.role}`, { defaultValue: n.role })}</td>
                <td className="py-1.5 pr-3">
                  {ha ? <Badge variant="outline" size="sm" className="font-mono" data-testid="kea-wizard-ha">{ha}</Badge> : <span className="text-text-tertiary">-</span>}
                </td>
                <td className="py-1.5 pr-3 font-mono text-xs" data-testid="kea-wizard-version">
                  {n.from_version && n.to_version && n.from_version !== n.to_version ? `${n.from_version} > ${n.to_version}` : (n.to_version || n.from_version || '')}
                </td>
                <td className="py-1.5 pr-3 text-xs text-text-secondary">
                  {n.step ? msg({ key: stepMessageKey(n.step), params: { node: n.name || n.node_id } }, n.step) : '-'}
                  {n.error && <span className="block status-danger-text">{outputText(n.error)}</span>}
                </td>
                <td className="py-1.5">
                  <Badge variant={NODE_STATUS_VARIANT[n.status] || 'outline'} size="sm" data-testid="kea-wizard-node-status">
                    {t(`keaMigration.wizard.nodeStatus.${n.status}`, { defaultValue: n.status })}
                  </Badge>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// The helper's refusal when the files the prepare kept went away (package cache cleaned, edited).
const PREPARE_AGAIN = /prepare this node again/

export default function KeaMigrationWizard({ current, analysis, onChange }) {
  const { t } = useTranslation(['install', 'common'])
  const { hasPermission } = usePermission()
  const [migration, setMigration] = useState(current || null)
  // The id to follow: the record's, or the analysis a prepare plan was just built on.
  const [watchId, setWatchId] = useState(current?.id || null)
  const [haLive, setHaLive] = useState({})
  // {plan, phase}: the plan shown in the preview and the phase it was built for.
  const [shownPlan, setShownPlan] = useState(null)
  const [building, setBuilding] = useState(null)
  const [error, setError] = useState(null)
  const [autoRollback, setAutoRollback] = useState(true)
  const [delay, setDelay] = useState('')
  useEffect(() => {
    setMigration(current || null)
    if (current?.id) setWatchId(current.id)
  }, [current])

  const refresh = useCallback(async () => {
    if (!watchId) return
    try {
      setMigration(await api.keaMigration.get(watchId))
    } catch (err) {
      // 404 until the prepare plan's job writes the record; keep what is shown.
      if (err?.status !== 404) throw err
    }
  }, [watchId])
  usePoll(refresh, POLL_MS, { enabled: Boolean(watchId) && (isActive(migration) || Boolean(shownPlan)) })
  useWsTopic(migration?.plan_id ? 'jobs' : null, (message) => {
    if (message?.data?.plan_id === migration?.plan_id) refresh().catch(() => {})
  })
  useWsTopic(migration ? 'ha' : null, (message) => {
    const next = haUpdate(migration, message?.data)
    if (next) setHaLive((cur) => ({ ...cur, [next.node_id]: next.state }))
  })

  const canPlan = hasPermission('ops:dhcp.ha')
  const step = wizardStep(migration)
  const states = useMemo(() => wizardStates(migration), [migration])
  const times = useMemo(() => timeline(migration), [migration])
  const series = migration?.series || analysis?.series
  const fromSeries = migration?.from_series || '2.6'

  const build = async (phase) => {
    const id = planId(migration, analysis, phase)
    const options = {}
    if (phase === 'prepare') {
      const ms = Number.parseInt(delay, 10)
      if (delay !== '' && Number.isFinite(ms)) options.response_delay_milliseconds = ms
    }
    if (phase === 'migrate') options.auto_rollback = autoRollback
    setBuilding(phase)
    setError(null)
    try {
      const p = await api.keaMigration.plan(id, { phase, options })
      if (phase === 'prepare') setWatchId(id)
      setShownPlan({ plan: p, phase })
    } catch (err) {
      setError(err)
    } finally {
      setBuilding(null)
    }
  }
  const closePlan = () => {
    setShownPlan(null)
    refresh().catch(() => {})
    onChange?.()
  }
  const done = () => {
    refresh().catch(() => {})
    onChange?.()
  }

  const blocker = (phase) => planBlocker(migration, analysis, phase)
  const showPrepare = step === 'prepare' || migration?.state === 'rolled_back'
    || (migration?.state === 'prepared' && analysis && migration.analysis_id !== analysis.id)
  const action = (phase, label, Icon, variant = 'primary') => {
    const why = blocker(phase)
    return (
      <div className="space-y-1">
        <Button
          size="sm"
          variant={variant}
          onClick={() => build(phase)}
          loading={building === phase}
          disabled={Boolean(why) || !canPlan || Boolean(building)}
          data-testid={`kea-wizard-${phase}`}
        >
          <Icon size={14} />
          {label}
        </Button>
        {why && why !== 'busy' && <p className="text-xs text-text-secondary" data-testid={`kea-wizard-${phase}-why`}>{t(`keaMigration.wizard.blocker.${why}`)}</p>}
      </div>
    )
  }

  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="kea-migration-wizard" data-state={migration?.state || 'none'}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">
          {t('keaMigration.wizard.title', { series: series || '3.x' })}
        </h3>
        {migration && (
          <Badge variant={STATE_VARIANT[migration.state] || 'outline'} size="sm" data-testid="kea-wizard-state">
            {t(`keaMigration.wizard.state.${migration.state}`, { defaultValue: migration.state })}
          </Badge>
        )}
        {migration?.target_version && <Badge variant="outline" size="sm" className="font-mono">{migration.target_version}</Badge>}
        {migration?.updated_at && <span className="text-xs text-text-tertiary ml-auto">{t('keaMigration.wizard.updated', { date: formatDate(migration.updated_at) })}</span>}
      </div>

      <Stepper states={states} />

      {!canPlan && <p className="text-xs status-warning-text" data-testid="kea-wizard-permission">{t('keaMigration.wizard.permission')}</p>}

      {step === 'prepare' && (
        <p className="text-sm text-text-secondary">{t('keaMigration.wizard.help.prepare')}</p>
      )}
      {step === 'migrate' && (
        <p className="text-sm text-text-secondary">{t('keaMigration.wizard.help.migrate', { series, seconds: migration?.outage_max_seconds ?? 180 })}</p>
      )}
      {step === 'verify' && migration && (
        <p className={cn('text-sm', migration.state === 'migrated' ? 'status-success-text' : 'text-text-secondary')} data-testid="kea-wizard-verify">
          {migration.state === 'migrated'
            ? t('keaMigration.wizard.help.migrated', { series })
            : migration.state === 'rolled_back'
              ? t(migration.phase === 'reconcile' ? 'keaMigration.wizard.help.reconciled' : 'keaMigration.wizard.help.rolledBack', { series: fromSeries })
              : t('keaMigration.wizard.help.rollingBack', { series: fromSeries })}
        </p>
      )}

      {migration && migration.phase !== 'prepare' && (
        <div className="space-y-1" data-testid="kea-wizard-timeline">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-tertiary">{t('keaMigration.wizard.timeline')}</h4>
          <StepRail
            testId="kea-wizard-time"
            steps={times.map((s) => ({
              id: s.id,
              state: s.state,
              label: t(`keaMigration.wizard.time.${s.id}`, { series: s.id === 'rollback' ? fromSeries : series }),
              detail: t(`keaMigration.wizard.timeHelp.${s.id}`),
            }))}
          />
        </div>
      )}

      {migration && <OutagePanel migration={migration} />}
      {migration && <NodesTable migration={migration} haLive={haLive} />}

      {migration?.error && (
        <p className="flex items-start gap-2 text-sm status-danger-text" role="alert" data-testid="kea-wizard-error">
          <WarningOctagon size={16} className="mt-0.5 shrink-0" />
          <span className="whitespace-pre-wrap break-words">
            {migration.error_step && <span className="font-mono">{outputText(migration.error_step)}: </span>}
            {outputText(migration.error)}
            {PREPARE_AGAIN.test(outputText(migration.error)) && (
              <span className="block" data-testid="kea-wizard-prepare-again">{t('keaMigration.wizard.prepareAgainHint')}</span>
            )}
          </span>
        </p>
      )}

      <div className="flex flex-wrap items-start gap-3 border-t border-border pt-3">
        {showPrepare && (
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-xs text-text-secondary space-y-1">
              <span className="block">{t('keaMigration.wizard.options.delay')}</span>
              <input
                type="number"
                min={1000}
                max={60000}
                step={1000}
                placeholder="10000"
                value={delay}
                onChange={(e) => setDelay(e.target.value)}
                className="h-8 w-28 rounded-md border border-border bg-bg-secondary px-2 text-sm text-text-primary"
                data-testid="kea-wizard-delay"
              />
            </label>
            {action('prepare', migration?.state === 'prepared' || migration?.state === 'rolled_back' ? t('keaMigration.wizard.action.prepareAgain') : t('keaMigration.wizard.action.prepare'), Package)}
          </div>
        )}
        {step === 'migrate' && (
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex items-center gap-2 text-xs text-text-secondary">
              <input type="checkbox" checked={autoRollback} onChange={(e) => setAutoRollback(e.target.checked)} data-testid="kea-wizard-auto-rollback" />
              {t('keaMigration.wizard.options.autoRollback')}
            </label>
            {action('migrate', migration?.state === 'failed' ? t('keaMigration.wizard.action.resume', { series }) : t('keaMigration.wizard.action.migrate', { series }), ArrowsLeftRight)}
          </div>
        )}
        {migration?.rollback_possible && (
          <div className="ml-auto">{action('rollback', t('keaMigration.wizard.action.rollback', { series: fromSeries }), ArrowCounterClockwise, 'secondary')}</div>
        )}
        {reconcileOffered(migration) && (
          <div className={cn('space-y-1', !migration?.rollback_possible && 'ml-auto')} data-testid="kea-wizard-reconcile-box">
            {action('reconcile', t('keaMigration.wizard.action.reconcile', { series: fromSeries }), ListChecks, 'secondary')}
            <p className="max-w-xs text-xs text-text-secondary">{t('keaMigration.wizard.help.reconcile', { series: fromSeries })}</p>
          </div>
        )}
      </div>
      {error && <p className="text-sm status-danger-text" role="alert" data-testid="kea-wizard-plan-error">{outputText(errorMessage(error))}</p>}

      <PlanPreviewModal
        open={Boolean(shownPlan)}
        plan={shownPlan?.plan}
        onClose={closePlan}
        onApplied={done}
        title={shownPlan ? t(`keaMigration.wizard.planTitle.${shownPlan.phase}`, { series: ['rollback', 'reconcile'].includes(shownPlan.phase) ? fromSeries : series }) : undefined}
      />
    </Card>
  )
}
