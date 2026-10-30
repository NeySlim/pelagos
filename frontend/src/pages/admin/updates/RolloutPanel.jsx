// SPDX-License-Identifier: Apache-2.0
// The rollout under way (architecture section 29): one row per node in its order with the step it
// is at, the failure and its reason, the reconnection banner while the node under the page
// restarts, and the actions Resume, Cancel the rest and Roll back (password).
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowClockwise, ArrowCounterClockwise, CheckCircle, Prohibit, Warning, WifiSlash, X } from '@phosphor-icons/react'
import { Badge, Button, Card, ConfirmDialog, FormModal, Input, StatusBadge } from '../../../components'
import { useNotification } from '../../../contexts/NotificationContext'
import { useMessage } from '../../../i18n/message'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { formatDate } from '../../../lib/utils'
import { cn } from '../../../lib/utils'
import { isActive, nodeProgress, rolloutActions, rolloutProgress, stepsOf } from './updatesLib'

function StepTrack({ node, kind }) {
  const { t } = useTranslation('updates')
  const steps = stepsOf(kind)
  const at = steps.indexOf(node.step)
  return (
    <ol className="flex flex-wrap gap-1" aria-label={t('rollout.steps')}>
      {steps.map((s, i) => {
        const state = node.state === 'done' || node.state === 'rolled_back' ? 'done'
          : node.state === 'pending' || node.state === 'skipped' || at < 0 ? 'pending'
            : i < at ? 'done' : i === at ? (node.state === 'failed' ? 'failed' : 'running') : 'pending'
        return (
          <li
            key={s}
            title={t(`steps.${s}`)}
            data-step={s}
            data-state={state}
            className={cn(
              'h-1.5 w-5 rounded-full',
              state === 'done' && 'bg-accent-success',
              state === 'running' && 'bg-accent-primary animate-pulse',
              state === 'failed' && 'bg-accent-danger',
              state === 'pending' && 'bg-bg-tertiary',
            )}
          />
        )
      })}
    </ol>
  )
}

function NodeRow({ node, kind, nodeName }) {
  const { t } = useTranslation('updates')
  const msg = useMessage()
  const pct = Math.round(nodeProgress(node, kind) * 100)
  return (
    <li className="py-2 border-t border-border first:border-t-0 space-y-1" data-testid="updates-rollout-node" data-node={node.node_id} data-state={node.state} data-step={node.step || ''}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-text-primary">{nodeName(node.node_id)}</span>
        <StatusBadge status={node.state} label={t(`nodeStates.${node.state}`, { defaultValue: node.state })} />
        {node.step && node.state !== 'done' && <span className="text-xs text-text-secondary" data-testid="updates-rollout-step">{t(`steps.${node.step}`, { defaultValue: node.step })}</span>}
        {(node.from_version || node.to_version) && (
          <span className="text-2xs font-mono text-text-tertiary">{node.from_version || '?'} {'->'} {node.to_version || '?'}</span>
        )}
        <span className="ml-auto text-2xs text-text-tertiary font-mono">{pct} %</span>
      </div>
      <StepTrack node={node} kind={kind} />
      {node.error && (
        <p className="text-xs status-danger-text break-words" data-testid="updates-rollout-error">
          {t(`steps.${node.step}`, { defaultValue: node.step || '' })}: {msg(node.error_message, node.error)}
        </p>
      )}
      {node.state === 'rolled_back' && <p className="text-2xs status-warning-text">{t('rollout.rolledBack', { version: node.from_version || '?' })}</p>}
    </li>
  )
}

function RollbackDialog({ onClose, onConfirm, busy, error }) {
  const { t } = useTranslation('updates')
  const [password, setPassword] = useState('')
  return (
    <FormModal open onClose={onClose} title={t('rollout.rollbackTitle')} onSubmit={() => onConfirm(password)} submitLabel={t('actions.rollback')} variant="danger" loading={busy} disabled={!password} testId="updates-rollback-dialog">
      <p className="text-xs text-text-secondary">{t('rollout.rollbackHelp')}</p>
      <Input label={t('preview.password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} error={error} autoComplete="current-password" data-testid="updates-rollback-password" />
    </FormModal>
  )
}

export function RolloutPanel({ rollout, connection, lostAt, nodeName, onChanged, onDismiss }) {
  const { t } = useTranslation(['updates', 'common'])
  const { showSuccess, showError } = useNotification()
  const [busy, setBusy] = useState(null)
  const [cancelling, setCancelling] = useState(false)
  const [rollingBack, setRollingBack] = useState(false)
  const [passwordError, setPasswordError] = useState(null)
  if (!rollout) return null
  const can = rolloutActions(rollout)
  const active = isActive(rollout)
  const pct = Math.round(rolloutProgress(rollout) * 100)
  const failed = rollout.nodes.find((n) => n.state === 'failed' || n.state === 'rolled_back')

  const act = async (action, password) => {
    setBusy(action)
    setPasswordError(null)
    try {
      const out = await api.updates.action(rollout.id, action, password)
      showSuccess(t(`toast.${action}`))
      setCancelling(false)
      setRollingBack(false)
      onChanged(out)
    } catch (e) {
      if (action === 'rollback' && (e.code === 'invalid_credentials' || e.errors?.some((x) => x.field === 'password'))) setPasswordError(t('preview.wrongPassword'))
      else showError(errorMessage(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="updates-rollout" data-state={rollout.state} data-kind={rollout.kind}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-text-primary">
          {rollout.kind === 'engine_packages'
            ? t('rollout.titleEngines', { packages: Object.keys(rollout.packages || {}).join(', ') || '-' })
            : t(`rollout.title.${rollout.kind}`, { version: rollout.version })}
        </h3>
        <StatusBadge status={rollout.state} label={t(`rolloutStates.${rollout.state}`, { defaultValue: rollout.state })} data-testid="updates-rollout-state" />
        {rollout.unsigned_accepted_by && <Badge variant="warning" size="sm" icon={Warning}>{t('rollout.unsignedBy', { user: rollout.unsigned_accepted_by })}</Badge>}
        <span className="ml-auto text-2xs text-text-tertiary">{t('rollout.by', { user: rollout.created_by || '-', date: formatDate(rollout.created_at) })}</span>
        {!active && onDismiss && (
          <Button size="xs" variant="ghost" onClick={onDismiss} aria-label={t('actions.dismiss')} data-testid="updates-rollout-dismiss"><X size={12} /></Button>
        )}
      </div>

      <div className="h-1.5 rounded-full bg-bg-tertiary overflow-hidden" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={t('rollout.progress')}>
        <div className={cn('h-full', rollout.state === 'failed' ? 'bg-accent-danger' : 'bg-accent-primary')} style={{ width: `${pct}%` }} />
      </div>

      {connection === 'lost' && (
        <div role="status" className="rounded-lg status-warning-bg border status-warning-border px-3 py-2 text-xs status-warning-text flex items-start gap-2" data-testid="updates-reconnecting">
          <WifiSlash size={14} className="shrink-0 mt-0.5" />
          <span>{t('rollout.reconnecting', { since: lostAt ? formatDate(new Date(lostAt).toISOString()) : '' })}</span>
        </div>
      )}
      {connection === 'back' && (
        <div role="status" className="rounded-lg status-success-bg border status-success-border px-3 py-2 text-xs status-success-text flex items-center gap-2" data-testid="updates-reconnected">
          <CheckCircle size={14} />
          <span>{t('rollout.reconnected')}</span>
        </div>
      )}

      <ol data-testid="updates-rollout-nodes">
        {rollout.nodes.map((n) => <NodeRow key={n.node_id} node={n} kind={rollout.kind} nodeName={nodeName} />)}
      </ol>

      {rollout.state === 'failed' && (
        <div className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text space-y-1" data-testid="updates-rollout-failed">
          <p className="font-semibold">{t('rollout.stopped', { node: failed ? nodeName(failed.node_id) : '-' })}</p>
          <p>{failed?.state === 'rolled_back' ? t('rollout.autoRolledBack') : rollout.state_schema_changed ? t('rollout.schemaChanged') : t('rollout.failedHelp')}</p>
        </div>
      )}

      {(can.resume || can.cancel || can.rollback) && (
        <div className="flex flex-wrap gap-2 justify-end">
          {can.resume && (
            <Button size="sm" onClick={() => act('resume')} loading={busy === 'resume'} data-testid="updates-resume"><ArrowClockwise size={14} />{t('actions.resume')}</Button>
          )}
          {can.cancel && (
            <Button size="sm" variant="secondary" onClick={() => setCancelling(true)} data-testid="updates-cancel"><Prohibit size={14} />{t('actions.cancel')}</Button>
          )}
          {can.rollback && (
            <Button size="sm" variant="danger" onClick={() => setRollingBack(true)} data-testid="updates-rollback"><ArrowCounterClockwise size={14} />{t('actions.rollback')}</Button>
          )}
        </div>
      )}

      <ConfirmDialog
        open={cancelling}
        onOpenChange={(o) => !o && setCancelling(false)}
        onConfirm={() => act('cancel')}
        title={t('rollout.cancelTitle')}
        message={t('rollout.cancelHelp')}
        confirmLabel={t('actions.cancel')}
        cancelLabel={t('common:actions.close')}
        loading={busy === 'cancel'}
      />
      {rollingBack && <RollbackDialog onClose={() => setRollingBack(false)} onConfirm={(p) => act('rollback', p)} busy={busy === 'rollback'} error={passwordError} />}
    </Card>
  )
}

export default RolloutPanel
