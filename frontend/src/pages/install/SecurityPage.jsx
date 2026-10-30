// SPDX-License-Identifier: Apache-2.0
// Security audit: findings on this node, one node or every node, with checkboxes, then one
// remediation plan for the selection. A finding can be kept as the admin's choice (an exception
// in cluster.toml with its reason) and the exception revoked here. The plan asks for
// confirmation and runs as a Job, one step after the other with backup, validation and rollback.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { useMessage } from '../../i18n/message'
import { ShieldWarning, ShieldCheck, ArrowsClockwise, Lightning, EyeSlash, ArrowCounterClockwise } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, StatusBadge, LoadingSpinner, EmptyState, PlanPreview } from '../../components'
import { FormModal } from '../../components/FormModal'
import { Textarea } from '../../components/Textarea'
import { useApi } from '../../hooks'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn, formatDate } from '../../lib/utils'
import {
  SEVERITY_ORDER, sortFindings, toggleId, allSelected, isDualKey, isRemediable, isExcepted, remediableIds,
  findingKey, planSelection, exceptionKey, driftAction,
} from './findings'
import HAGuardCard from './HAGuardCard'
import PermissionsCard from './PermissionsCard'

function Finding({ finding, checked, onToggle, disabled, showNode, onExcept, action, onAction }) {
  const { t } = useTranslation('install')
  const msg = useMessage()
  const manual = !isRemediable(finding)
  return (
    <label className={cn('flex items-start gap-3 rounded-lg border p-3', manual ? 'border-border cursor-default' : 'cursor-pointer', checked ? 'border-accent-primary bg-accent-primary-op5' : !manual && 'border-border hover:bg-bg-tertiary')} data-testid="security-finding" data-finding={finding.id} data-node={finding.node_id || ''}>
      <input type="checkbox" className="mt-1" checked={checked} onChange={onToggle} disabled={disabled || manual} aria-label={finding.subject} data-testid="security-check" />
      <div className="flex-1 min-w-0 space-y-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={finding.severity} />
          {showNode && finding.node_name && <Badge variant="outline" size="sm" data-testid="security-node">{finding.node_name}</Badge>}
          {finding.engine && <Badge variant="outline" size="sm" className="font-mono">{finding.engine}</Badge>}
          <Badge variant="secondary" size="sm">{t(`security.kind.${finding.kind}`, { defaultValue: finding.kind })}</Badge>
          <span className="font-mono text-xs text-text-secondary break-all">{finding.subject}</span>
          {manual && <Badge variant="warning" size="sm" data-testid="security-manual">{t('security.manual')}</Badge>}
          {onExcept && (
            <Button variant="ghost" size="sm" className="ml-auto" onClick={(e) => { e.preventDefault(); onExcept() }} data-testid="security-except">
              <EyeSlash size={14} />
              {t('security.except')}
            </Button>
          )}
        </div>
        <p className="text-sm text-text-primary">{msg(finding.description_message, finding.description)}</p>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
          <div>
            <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{manual ? t('security.manualAction') : t('security.proposal')}</dt>
            <dd className="text-text-secondary" data-testid={manual ? 'security-manual-action' : undefined}>
              {manual
                ? msg(finding.manual_action_message || finding.proposal_message, finding.manual_action || finding.proposal)
                : msg(finding.proposal_message, finding.proposal)}
            </dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('security.risk')}</dt>
            <dd className="text-text-secondary">{msg(finding.risk_message, finding.risk)}</dd>
          </div>
        </dl>
        {finding.differences?.length > 0 && (
          <div className="text-xs" data-testid="security-differences">
            <p className="text-2xs uppercase tracking-wider text-text-tertiary">{t('security.drift.differences')}</p>
            <ul className="list-disc ml-5 text-text-secondary font-mono break-all">
              {finding.differences.map((d) => <li key={d}>{d}</li>)}
            </ul>
          </div>
        )}
        {finding.actions?.length > 0 && (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-text-tertiary">{t('security.drift.action')}</span>
            <select
              className="h-7 rounded-md border border-border bg-bg-secondary px-2 text-xs text-text-primary"
              value={action}
              onChange={(e) => onAction(e.target.value)}
              disabled={disabled}
              aria-label={t('security.drift.action')}
              data-testid="security-drift-action"
            >
              {finding.actions.map((a) => <option key={a} value={a}>{t(`security.drift.${a}`)}</option>)}
            </select>
          </div>
        )}
        {isDualKey(finding) ? (
          <ol className="list-decimal ml-5 text-xs text-text-secondary space-y-0.5" data-testid="security-dual-key">
            <li>{t('security.dualKey.add')}</li>
            <li>{t('security.dualKey.switch')}</li>
            <li>{t('security.dualKey.remove')}</li>
          </ol>
        ) : null}
        {manual && <p className="text-xs text-text-tertiary">{t('security.manualHelp')}</p>}
      </div>
    </label>
  )
}

function ExceptedFinding({ finding, showNode, onRevoke, busy }) {
  const { t } = useTranslation('install')
  const msg = useMessage()
  const e = finding.exception
  const everyNode = e.key === finding.id
  return (
    <div className="flex items-start gap-3 rounded-lg border border-border border-dashed p-3 opacity-90" data-testid="security-excepted" data-finding={finding.id} data-node={finding.node_id || ''}>
      <EyeSlash size={16} className="mt-0.5 text-text-tertiary shrink-0" />
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={finding.severity} />
          {showNode && finding.node_name && <Badge variant="outline" size="sm">{finding.node_name}</Badge>}
          <Badge variant="secondary" size="sm">{t(`security.kind.${finding.kind}`, { defaultValue: finding.kind })}</Badge>
          <span className="font-mono text-xs text-text-secondary break-all">{finding.subject}</span>
          <Badge variant="purple" size="sm">{everyNode ? t('security.exception.everyNode') : t('security.exception.onNode', { node: finding.node_name || finding.node_id })}</Badge>
          {onRevoke && (
            <Button variant="ghost" size="sm" className="ml-auto" onClick={onRevoke} loading={busy} data-testid="security-unexcept">
              <ArrowCounterClockwise size={14} />
              {t('security.exception.revoke')}
            </Button>
          )}
        </div>
        <p className="text-sm text-text-primary">{msg(finding.description_message, finding.description)}</p>
        <p className="text-xs text-text-secondary" data-testid="security-exception-reason">
          {t('security.exception.by', { user: e.created_by, date: formatDate(e.created_at) })}: {e.comment}
        </p>
      </div>
    </div>
  )
}

function ExceptionDialog({ finding, onClose, onDone }) {
  const { t } = useTranslation('install')
  const msg = useMessage()
  const [comment, setComment] = useState('')
  const [everyNode, setEveryNode] = useState(false)
  const [touched, setTouched] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const empty = comment.trim() === ''
  const submit = async () => {
    setTouched(true)
    if (empty || !finding) return
    setBusy(true)
    setError(null)
    try {
      await api.alerts.addException({
        kind: 'security_finding', key: exceptionKey(finding, everyNode), comment: comment.trim(),
        summary: String(msg(finding.description_message, finding.description)).slice(0, 300),
      })
      onDone()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open={Boolean(finding)} onClose={onClose} title={t('security.exception.title')} onSubmit={submit} loading={busy} submitLabel={t('security.exception.submit')} testId="security-exception-dialog">
      {finding && <p className="text-sm text-text-secondary">{msg(finding.description_message, finding.description)}</p>}
      {finding?.node_id && (
        <fieldset className="space-y-1 text-sm">
          <legend className="text-xs text-text-tertiary">{t('security.exception.scope')}</legend>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="scope" checked={!everyNode} onChange={() => setEveryNode(false)} />
            {t('security.exception.onNode', { node: finding.node_name || finding.node_id })}
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="radio" name="scope" checked={everyNode} onChange={() => setEveryNode(true)} data-testid="security-exception-every" />
            {t('security.exception.everyNode')}
          </label>
        </fieldset>
      )}
      <Textarea
        label={t('security.exception.reason')}
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        rows={3}
        helperText={t('security.exception.reasonHelp')}
        error={touched && empty ? t('security.exception.reasonRequired') : undefined}
        data-testid="security-exception-reason-input"
        autoFocus
      />
      {error && <p className="text-xs status-danger-text" role="alert">{error}</p>}
    </FormModal>
  )
}

export default function SecurityPage() {
  const { t } = useTranslation(['install', 'common'])
  const { hasPermission } = usePermission()
  const canExcept = hasPermission('write:alerts') && hasPermission('admin:settings')
  // ?node=<id>: a path_not_writable alert opens the Permissions card of its node. Every node by
  // default: a finding on another node must not hide behind "no finding" here (review E3).
  const [searchParams] = useSearchParams()
  const [node, setNode] = useState(searchParams.get('node') || 'all')
  const findingsQ = useApi(() => api.install.security(node || undefined), [node])
  const all = useMemo(() => sortFindings(findingsQ.data?.findings || []), [findingsQ.data])
  const findings = all.filter((f) => !isExcepted(f))
  const excepted = all.filter(isExcepted)
  const choices = findingsQ.data?.node_choices || []
  const failed = (findingsQ.data?.nodes || []).filter((n) => !n.ok)
  const showNode = node === 'all' && choices.length > 1
  const answered = (findingsQ.data?.nodes || []).filter((n) => n.ok)
  const perNode = showNode ? answered.map((n) => ({ ...n, count: findings.filter((f) => f.node_id === n.id || f.node_name === n.name).length })) : []
  const [selected, setSelected] = useState([])
  const [actions, setActions] = useState({})
  const [plan, setPlan] = useState(null)
  const [building, setBuilding] = useState(false)
  const [buildError, setBuildError] = useState(null)
  const [excepting, setExcepting] = useState(null)
  const [revoking, setRevoking] = useState(null)
  const [revokeError, setRevokeError] = useState(null)
  const ids = remediableIds(all)
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]).filter(([, n]) => n)
  const chosen = selected.filter((k) => ids.includes(k))

  const build = async () => {
    setBuilding(true)
    setBuildError(null)
    try {
      setPlan(await api.install.securityPlan(planSelection(all, chosen, actions)))
    } catch (err) {
      setBuildError(err)
    } finally {
      setBuilding(false)
    }
  }
  // The same findings, planned again: the server forgot the old plan (expired or restarted).
  const recompute = async () => {
    const fresh = await api.install.securityPlan(planSelection(all, chosen, actions))
    setPlan(fresh)
    return fresh
  }
  const revoke = async (finding) => {
    setRevoking(findingKey(finding))
    setRevokeError(null)
    try {
      await api.alerts.revokeException(finding.exception.id)
      findingsQ.refetch()
    } catch (err) {
      setRevokeError(err)
    } finally {
      setRevoking(null)
    }
  }
  const changeNode = (value) => {
    setNode(value)
    setSelected([])
  }

  return (
    <PageLayout
      icon={ShieldWarning}
      title={t('pages.security.title')}
      subtitle={t('pages.security.subtitle')}
      testId="page-install-security"
      actions={
        <div className="flex items-center gap-2">
          {choices.length > 1 && (
            <select
              className="h-8 rounded-md border border-border bg-bg-secondary px-2 text-sm text-text-primary"
              value={node}
              onChange={(e) => changeNode(e.target.value)}
              disabled={Boolean(plan)}
              aria-label={t('security.node')}
              data-testid="security-node-select"
            >
              <option value="">{t('security.thisNode')}</option>
              {choices.filter((c) => c.id !== findingsQ.data?.local_node_id).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              <option value="all">{t('security.allNodes')}</option>
            </select>
          )}
          <Button variant="secondary" size="sm" onClick={findingsQ.refetch} disabled={findingsQ.loading}>
            <ArrowsClockwise size={14} />
            {t('security.rescan')}
          </Button>
        </div>
      }
    >
      {findingsQ.loading && !findingsQ.data ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : findingsQ.error ? (
        <Card className="p-4" hover={false}><p className="text-sm status-danger-text" role="alert">{errorMessage(findingsQ.error)}</p></Card>
      ) : (
        <div className="space-y-4 max-w-5xl">
          {perNode.length > 1 && (
            <div className="flex flex-wrap items-center gap-2" data-testid="security-node-counts">
              {perNode.map((n) => (
                <Badge key={n.id} variant={n.count ? 'warning' : 'success'} size="sm">{t('security.nodeCount', { node: n.name || n.id, count: n.count })}</Badge>
              ))}
            </div>
          )}
          {failed.map((n) => (
            <p key={n.id} className="text-sm status-warning-text" role="alert" data-testid="security-node-error">{t('security.nodeError', { node: n.name, error: n.error })}</p>
          ))}
          {!findings.length ? (
            <EmptyState icon={ShieldCheck} title={t('security.clean')} description={t('security.cleanBody')} />
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                {counts.map(([severity, n]) => (
                  <StatusBadge key={severity} status={severity} label={`${t('common:fieldLabel', { label: t(`common:status.${severity}`) })} ${n}`} />
                ))}
                <label className="ml-auto flex items-center gap-2 text-xs text-text-secondary cursor-pointer">
                  <input type="checkbox" checked={allSelected(chosen, ids)} onChange={() => setSelected(allSelected(chosen, ids) ? [] : ids)} disabled={Boolean(plan)} data-testid="security-select-all" />
                  {t('security.selectAll')}
                </label>
              </div>
              <div className="space-y-2">
                {findings.map((f) => (
                  <Finding
                    key={findingKey(f)}
                    finding={f}
                    showNode={showNode}
                    checked={chosen.includes(findingKey(f))}
                    onToggle={() => setSelected((s) => toggleId(s, findingKey(f)))}
                    disabled={Boolean(plan)}
                    onExcept={canExcept && !plan ? () => setExcepting(f) : null}
                    action={driftAction(f, actions)}
                    onAction={(a) => setActions((m) => ({ ...m, [findingKey(f)]: a }))}
                  />
                ))}
              </div>
              <Card className="p-4 space-y-3" hover={false} data-testid="security-remediation">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('security.planTitle')}</h3>
                  <Badge variant={chosen.length ? 'primary' : 'secondary'} size="sm">{t('security.selected', { count: chosen.length })}</Badge>
                  {!plan && (
                    <Button size="sm" className="ml-auto" onClick={build} disabled={!chosen.length} loading={building} data-testid="security-build">
                      <Lightning size={14} weight="fill" />
                      {t('security.build')}
                    </Button>
                  )}
                </div>
                <p className="text-xs text-text-secondary">{t('security.planHelp')}</p>
                {buildError && <p className="text-sm status-danger-text" role="alert">{errorMessage(buildError)}</p>}
                {plan && (
                  <PlanPreview
                    plan={plan}
                    onRecompute={recompute}
                    onApplied={() => findingsQ.refetch()}
                    onClose={() => {
                      setPlan(null)
                      setSelected([])
                    }}
                  />
                )}
              </Card>
            </>
          )}
          <HAGuardCard node={node === 'all' ? '' : node} onChanged={findingsQ.refetch} />
          <PermissionsCard node={node === 'all' ? '' : node} />
          {excepted.length > 0 && (
            <Card className="p-4 space-y-2" hover={false} data-testid="security-exceptions">
              <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('security.exception.listTitle', { count: excepted.length })}</h3>
              <p className="text-xs text-text-secondary">{t('security.exception.listHelp')}</p>
              {revokeError && <p className="text-sm status-danger-text" role="alert">{errorMessage(revokeError)}</p>}
              {excepted.map((f) => (
                <ExceptedFinding key={findingKey(f)} finding={f} showNode={showNode} busy={revoking === findingKey(f)} onRevoke={canExcept ? () => revoke(f) : null} />
              ))}
            </Card>
          )}
        </div>
      )}
      <ExceptionDialog
        finding={excepting}
        onClose={() => setExcepting(null)}
        onDone={() => {
          setSelected((s) => s.filter((k) => k !== findingKey(excepting)))
          setExcepting(null)
          findingsQ.refetch()
        }}
      />
    </PageLayout>
  )
}
