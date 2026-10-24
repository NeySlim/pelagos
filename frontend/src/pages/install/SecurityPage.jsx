// SPDX-License-Identifier: Apache-2.0
// Security audit: findings on the imported configuration (md5 keys, open
// listeners, unrestricted transfers) with checkboxes, then one remediation plan
// for the selected findings. The plan asks for confirmation and runs as a Job,
// one step after the other with backup, validation and rollback on failure.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldWarning, ShieldCheck, ArrowsClockwise, Lightning } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, StatusBadge, LoadingSpinner, EmptyState, PlanPreview } from '../../components'
import { useApi } from '../../hooks'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { SEVERITY_ORDER, sortFindings, toggleId, allSelected } from './findings'

function Finding({ finding, checked, onToggle, disabled }) {
  const { t } = useTranslation('install')
  return (
    <label className={cn('flex items-start gap-3 rounded-lg border p-3 cursor-pointer', checked ? 'border-accent-primary bg-accent-primary-op5' : 'border-border hover:bg-bg-tertiary')} data-testid="security-finding" data-finding={finding.id}>
      <input type="checkbox" className="mt-1" checked={checked} onChange={onToggle} disabled={disabled} />
      <div className="flex-1 min-w-0 space-y-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={finding.severity} />
          {finding.engine && <Badge variant="outline" size="sm" className="font-mono">{finding.engine}</Badge>}
          <Badge variant="secondary" size="sm">{t(`security.kind.${finding.kind}`, { defaultValue: finding.kind })}</Badge>
          <span className="font-mono text-xs text-text-secondary break-all">{finding.subject}</span>
        </div>
        <p className="text-sm text-text-primary">{finding.description}</p>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
          <div>
            <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('security.proposal')}</dt>
            <dd className="text-text-secondary">{finding.proposal}</dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('security.risk')}</dt>
            <dd className="text-text-secondary">{finding.risk}</dd>
          </div>
        </dl>
        {finding.details?.steps || (finding.kind === 'insecure_key' && finding.engine === 'd2') ? (
          <ol className="list-decimal ml-5 text-xs text-text-secondary space-y-0.5" data-testid="security-dual-key">
            <li>{t('security.dualKey.add')}</li>
            <li>{t('security.dualKey.switch')}</li>
            <li>{t('security.dualKey.remove')}</li>
          </ol>
        ) : null}
      </div>
    </label>
  )
}

export default function SecurityPage() {
  const { t } = useTranslation(['install', 'common'])
  const findingsQ = useApi(() => api.install.security(), [])
  const findings = useMemo(() => sortFindings(findingsQ.data?.findings || []), [findingsQ.data])
  const [selected, setSelected] = useState([])
  const [plan, setPlan] = useState(null)
  const [building, setBuilding] = useState(false)
  const [buildError, setBuildError] = useState(null)
  const ids = findings.map((f) => f.id)
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]).filter(([, n]) => n)

  const build = async () => {
    setBuilding(true)
    setBuildError(null)
    try {
      setPlan(await api.install.securityPlan(selected))
    } catch (err) {
      setBuildError(err)
    } finally {
      setBuilding(false)
    }
  }
  // The same findings, planned again: the server forgot the old plan (expired or restarted).
  const recompute = async () => {
    const fresh = await api.install.securityPlan(selected)
    setPlan(fresh)
    return fresh
  }

  return (
    <PageLayout
      icon={ShieldWarning}
      title={t('pages.security.title')}
      subtitle={t('pages.security.subtitle')}
      testId="page-install-security"
      actions={
        <Button variant="secondary" size="sm" onClick={findingsQ.refetch} disabled={findingsQ.loading}>
          <ArrowsClockwise size={14} />
          {t('security.rescan')}
        </Button>
      }
    >
      {findingsQ.loading && !findingsQ.data ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : findingsQ.error ? (
        <Card className="p-4" hover={false}><p className="text-sm status-danger-text" role="alert">{errorMessage(findingsQ.error)}</p></Card>
      ) : !findings.length ? (
        <EmptyState icon={ShieldCheck} title={t('security.clean')} description={t('security.cleanBody')} />
      ) : (
        <div className="space-y-4 max-w-5xl">
          <div className="flex flex-wrap items-center gap-2">
            {counts.map(([severity, n]) => (
              <StatusBadge key={severity} status={severity} label={`${t(`common:status.${severity}`)}: ${n}`} />
            ))}
            <label className="ml-auto flex items-center gap-2 text-xs text-text-secondary cursor-pointer">
              <input type="checkbox" checked={allSelected(selected, ids)} onChange={() => setSelected(allSelected(selected, ids) ? [] : ids)} disabled={Boolean(plan)} data-testid="security-select-all" />
              {t('security.selectAll')}
            </label>
          </div>
          <div className="space-y-2">
            {findings.map((f) => (
              <Finding key={f.id} finding={f} checked={selected.includes(f.id)} onToggle={() => setSelected((s) => toggleId(s, f.id))} disabled={Boolean(plan)} />
            ))}
          </div>
          <Card className="p-4 space-y-3" hover={false} data-testid="security-remediation">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-text-primary">{t('security.planTitle')}</h3>
              <Badge variant={selected.length ? 'primary' : 'secondary'} size="sm">{t('security.selected', { count: selected.length })}</Badge>
              {!plan && (
                <Button size="sm" className="ml-auto" onClick={build} disabled={!selected.length} loading={building} data-testid="security-build">
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
        </div>
      )}
    </PageLayout>
  )
}
