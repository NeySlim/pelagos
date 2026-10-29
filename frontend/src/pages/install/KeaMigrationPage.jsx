// SPDX-License-Identifier: Apache-2.0
// Kea migration, read only (architecture section 26): the Kea series and package source of every
// node, the target for the whole cluster, and the analysis report: findings by severity and node,
// the dry run of each daemon, the packages removed and installed, the full diff per daemon.
// Nothing changes on a node; the migration itself comes with a later release.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, ArrowSquareOut, CheckCircle, MagnifyingGlass, Warning, WarningOctagon } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, LoadingSpinner } from '../../components'
import { DiffView } from '../../components/DiffView'
import { useApi } from '../../hooks'
import { useMessage } from '../../i18n/message'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import {
  SEVERITY_VARIANT, defaultTarget, fullyValidated, groupFindings, nodeEngines, obsoleteEngines, parseTarget, targetKey,
} from './keaMigration'

function NodesCard({ nodes }) {
  const { t } = useTranslation('install')
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="kea-migration-nodes">
      <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('keaMigration.nodes.title')}</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-2xs uppercase tracking-wider text-text-tertiary">
              <th className="py-1 pr-3">{t('keaMigration.nodes.node')}</th>
              <th className="py-1 pr-3">{t('keaMigration.nodes.engine')}</th>
              <th className="py-1 pr-3">{t('keaMigration.nodes.version')}</th>
              <th className="py-1 pr-3">{t('keaMigration.nodes.source')}</th>
              <th className="py-1 pr-3">{t('keaMigration.nodes.package')}</th>
              <th className="py-1">{t('keaMigration.nodes.support')}</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((n) => {
              const engines = Object.entries(n.engines || {})
              if (!n.reachable || !engines.length) {
                return (
                  <tr key={n.node_id} className="border-t border-border" data-testid="kea-migration-node" data-node={n.node_id}>
                    <td className="py-1.5 pr-3 font-medium">{n.name || n.node_id}</td>
                    <td colSpan={5} className="py-1.5 text-xs status-warning-text" role={n.reachable ? undefined : 'alert'}>
                      {n.reachable ? t('keaMigration.nodes.noKea') : t('keaMigration.nodes.unreachable', { error: n.error || '' })}
                    </td>
                  </tr>
                )
              }
              return engines.map(([engine, e], i) => (
                <tr key={`${n.node_id}-${engine}`} className="border-t border-border" data-testid="kea-migration-node" data-node={n.node_id} data-engine={engine}>
                  <td className="py-1.5 pr-3 font-medium">{i === 0 ? (n.name || n.node_id) : ''}</td>
                  <td className="py-1.5 pr-3">{t(`engines.${engine}`, { defaultValue: engine })}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{e.version}</td>
                  <td className="py-1.5 pr-3"><Badge variant="outline" size="sm">{t(`keaMigration.source.${e.source}`, { defaultValue: e.source })}</Badge></td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-text-secondary">{e.package}</td>
                  <td className="py-1.5">
                    {e.maintained === false
                      ? <Badge variant="warning" size="sm" data-testid="kea-migration-obsolete">{e.eol ? t('keaMigration.nodes.obsoleteSince', { series: e.series, date: e.eol }) : t('keaMigration.nodes.obsolete', { series: e.series })}</Badge>
                      : e.maintained === true
                        ? <Badge variant="success" size="sm">{t('keaMigration.nodes.maintained', { series: e.series })}</Badge>
                        : <Badge variant="outline" size="sm" data-testid="kea-migration-unknown">{t('keaMigration.nodes.maintenanceUnknown', { series: e.series || '?' })}</Badge>}
                  </td>
                </tr>
              ))
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function FindingRow({ finding, nodeName }) {
  const { t } = useTranslation('install')
  const msg = useMessage()
  return (
    <li className="rounded-md border border-border p-2.5 space-y-1" data-testid="kea-migration-finding" data-code={finding.code} data-severity={finding.severity}>
      <div className="flex flex-wrap items-center gap-2">
        {finding.engine && <Badge variant="outline" size="sm" className="font-mono">{finding.engine}</Badge>}
        <span className="text-sm text-text-primary">{msg(finding.message, finding.code)}</span>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-secondary">
        <span>{t('keaMigration.report.action')}: {t(`keaMigration.action.${finding.action}`, { defaultValue: finding.action })}</span>
        {finding.path && <span className="font-mono break-all">{finding.path}</span>}
        {finding.error && <span className="status-danger-text">{finding.error}</span>}
        {finding.reference && (
          <a href={finding.reference} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent-primary hover:underline">
            {t('keaMigration.report.reference')}<ArrowSquareOut size={12} />
          </a>
        )}
        {!finding.engine && nodeName && <span>{nodeName}</span>}
      </div>
    </li>
  )
}

function NodeDetails({ report, nodeId, name }) {
  const { t } = useTranslation('install')
  const engines = nodeEngines(report, nodeId)
  const pkgs = report.packages?.[nodeId] || { remove: [], install: [] }
  return (
    <div className="space-y-3 rounded-lg border border-border p-3" data-testid="kea-migration-node-report" data-node={nodeId}>
      <h4 className="text-sm font-semibold text-text-primary">{name}</h4>
      <div className="flex flex-wrap gap-2">
        {engines.map((engine) => {
          const v = report.validation?.[nodeId]?.[engine]
          if (!v) return null
          const variant = v.mode === 'skipped' ? 'secondary' : v.ok ? 'success' : 'danger'
          const label = v.mode === 'skipped' ? 'skipped' : v.ok ? 'ok' : 'failed'
          return (
            <Badge key={engine} variant={variant} size="sm" data-testid="kea-migration-validation" data-engine={engine} title={v.output || undefined}>
              {t(`engines.${engine}`, { defaultValue: engine })}: {t(`keaMigration.validation.${label}`)}
            </Badge>
          )
        })}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        {['remove', 'install'].map((kind) => (
          <div key={kind} data-testid={`kea-migration-packages-${kind}`}>
            <p className="text-2xs uppercase tracking-wider text-text-tertiary">{t(`keaMigration.packages.${kind}`, { count: (pkgs[kind] || []).length })}</p>
            <ul className="font-mono text-text-secondary">
              {(pkgs[kind] || []).map((p) => <li key={p.name}>{p.name}{p.version ? ` ${p.version}` : ''}</li>)}
            </ul>
          </div>
        ))}
      </div>
      {engines.filter((e) => report.diffs?.[nodeId]?.[e]).map((engine) => (
        <details key={engine} className="text-xs" data-testid="kea-migration-diff" data-engine={engine}>
          <summary className="cursor-pointer text-text-secondary">{t('keaMigration.report.diff', { engine: t(`engines.${engine}`, { defaultValue: engine }) })}</summary>
          <DiffView diff={report.diffs[nodeId][engine]} maxHeight={480} className="mt-2" />
        </details>
      ))}
    </div>
  )
}

function Report({ report, names }) {
  const { t } = useTranslation('install')
  const groups = useMemo(() => groupFindings(report), [report])
  const nameOf = (id) => names[id] || id
  const validated = fullyValidated(report)
  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="kea-migration-report">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">
          {t('keaMigration.report.title', { series: report.series, source: t(`keaMigration.source.${report.source}`, { defaultValue: report.source }) })}
        </h3>
        {report.target_version && <Badge variant="outline" size="sm" className="font-mono">{report.target_version}</Badge>}
        <span className="text-xs text-text-tertiary ml-auto">{t('keaMigration.report.by', { user: report.created_by, date: formatDate(report.created_at) })}</span>
      </div>
      {report.blocking ? (
        <p className="flex items-center gap-2 text-sm status-danger-text" role="alert" data-testid="kea-migration-blocking">
          <WarningOctagon size={16} />{t('keaMigration.report.blocking')}
        </p>
      ) : (
        <p className="flex items-center gap-2 text-sm status-success-text" data-testid="kea-migration-ready">
          <CheckCircle size={16} />{t('keaMigration.report.ready')}
        </p>
      )}
      {!validated && (
        <p className="flex items-center gap-2 text-xs status-warning-text" data-testid="kea-migration-not-validated">
          <Warning size={14} />{t('keaMigration.report.notValidated')}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2" data-testid="kea-migration-counts">
        {Object.entries(report.counts || {}).map(([severity, n]) => (
          <Badge key={severity} variant={SEVERITY_VARIANT[severity] || 'secondary'} size="sm">{t(`keaMigration.severity.${severity}`)} {n}</Badge>
        ))}
        <span className="text-xs text-text-secondary ml-auto" data-testid="kea-migration-outage">{t('keaMigration.report.outage', { seconds: report.outage_estimate_seconds })}</span>
      </div>
      {groups.map(([severity, nodes]) => (
        <section key={severity} className="space-y-2" data-testid="kea-migration-group" data-severity={severity}>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-tertiary">{t(`keaMigration.severity.${severity}`)}</h4>
          <p className="text-xs text-text-secondary">{t(`keaMigration.severityHelp.${severity}`)}</p>
          {nodes.map(([nodeId, items]) => (
            <div key={nodeId || '-'} className="space-y-1">
              <p className="text-xs font-medium text-text-primary">{nameOf(nodeId) || t('keaMigration.report.cluster')}</p>
              <ul className="space-y-1.5">{items.map((f, i) => <FindingRow key={`${f.code}-${f.path}-${i}`} finding={f} nodeName={nameOf(nodeId)} />)}</ul>
            </div>
          ))}
        </section>
      ))}
      <div className="space-y-3">
        {(report.node_ids || []).filter((id) => !(report.unreachable || []).includes(id)).map((id) => (
          <NodeDetails key={id} report={report} nodeId={id} name={nameOf(id)} />
        ))}
      </div>
    </Card>
  )
}

export default function KeaMigrationPage() {
  const { t } = useTranslation(['install', 'common'])
  const overview = useApi(() => api.keaMigration.overview(), [])
  const data = overview.data
  const [target, setTarget] = useState('')
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const targets = useMemo(() => data?.targets || [], [data])
  useEffect(() => {
    if (!target && targets.length) {
      const kept = data?.analysis && targets.find((x) => x.series === data.analysis.series && x.source === data.analysis.source && x.available)
      const chosen = kept || defaultTarget(targets)
      if (chosen) setTarget(targetKey(chosen))
    }
  }, [targets, target, data])
  const shown = report || data?.analysis || null
  const names = useMemo(() => Object.fromEntries((data?.nodes || []).map((n) => [n.node_id, n.name || n.node_id])), [data])
  const obsolete = (data?.nodes || []).some((n) => obsoleteEngines(n).length)
  const picked = targets.find((x) => targetKey(x) === target)

  const analyze = async () => {
    const body = parseTarget(target)
    if (!body) return
    setBusy(true)
    setError(null)
    try {
      setReport(await api.keaMigration.analyze(body))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <PageLayout
      icon={MagnifyingGlass}
      title={t('pages.keaMigration.title')}
      subtitle={t('pages.keaMigration.subtitle')}
      testId="page-kea-migration"
      actions={
        <Button variant="secondary" size="sm" onClick={overview.refetch} disabled={overview.loading}>
          <ArrowsClockwise size={14} />
          {t('keaMigration.refresh')}
        </Button>
      }
    >
      {overview.loading && !data ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : overview.error ? (
        <Card className="p-4" hover={false}><p className="text-sm status-danger-text" role="alert">{errorMessage(overview.error)}</p></Card>
      ) : (
        <div className="space-y-4 max-w-5xl">
          {obsolete && <p className="text-sm status-warning-text" data-testid="kea-migration-obsolete-note">{t('keaMigration.obsoleteNote')}</p>}
          <NodesCard nodes={data?.nodes || []} />
          <Card className="p-4 space-y-3" hover={false} data-testid="kea-migration-target">
            <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('keaMigration.target.title')}</h3>
            <div className="flex flex-wrap items-center gap-2">
              <select
                className="h-8 rounded-md border border-border bg-bg-secondary px-2 text-sm text-text-primary"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={busy}
                aria-label={t('keaMigration.target.label')}
                data-testid="kea-migration-target-select"
              >
                {targets.map((x) => (
                  <option key={targetKey(x)} value={targetKey(x)} disabled={!x.available}>
                    {t('keaMigration.target.option', { series: x.series, source: t(`keaMigration.source.${x.source}`, { defaultValue: x.source }) })}
                    {x.version ? ` (${x.version})` : ''}
                    {x.recommended ? ` - ${t('keaMigration.target.recommended')}` : ''}
                    {!x.available ? ` - ${t('keaMigration.target.unavailable')}` : ''}
                  </option>
                ))}
              </select>
              <Button size="sm" onClick={analyze} loading={busy} disabled={!picked?.available} data-testid="kea-migration-analyze">
                <MagnifyingGlass size={14} />
                {t('keaMigration.target.analyze')}
              </Button>
            </div>
            {picked?.source === 'backports' && <p className="text-xs status-warning-text" data-testid="kea-migration-backports-note">{t('keaMigration.target.backportsNote')}</p>}
            <p className="text-xs text-text-secondary">{busy ? t('keaMigration.target.running') : t('keaMigration.target.help')}</p>
            {error && <p className="text-sm status-danger-text" role="alert" data-testid="kea-migration-error">{errorMessage(error)}</p>}
          </Card>
          {shown ? <Report report={shown} names={names} /> : (
            <p className="text-sm text-text-secondary" data-testid="kea-migration-none">{t('keaMigration.report.none')}</p>
          )}
        </div>
      )}
    </PageLayout>
  )
}
