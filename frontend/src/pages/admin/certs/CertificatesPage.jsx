// SPDX-License-Identifier: Apache-2.0
// Administration > Certificates: the HTTPS certificate of each node's web UI, where it comes
// from, when it renews, and the source applied to every node at once. Replication certificates
// (internal CA, node mTLS) are shown for their expiry only and never replaced from here.
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Certificate, ArrowsClockwise, UploadSimple, PencilSimple, Seal, Globe, Trash, ListBullets } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, LoadingSpinner, ConfirmDialog, Modal, PlanPreviewModal } from '../../../components'
import { useApi } from '../../../hooks'
import { useNotification } from '../../../contexts/NotificationContext'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import SourceDialog from './SourceDialog'
import UploadDialog from './UploadDialog'
import { AUTOMATIC, LEVEL_BADGE, expiryLevel } from './certsForm'

const JOB_POLL_MS = 1500

function when(value) {
  return value ? new Date(value).toLocaleString() : null
}

function Field({ label, children }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className="text-sm text-text-primary break-words">{children}</dd>
    </div>
  )
}

function sourceSummary(t, src) {
  if (!src) return t('sources.self_signed')
  const base = t(`sources.${src.source}`)
  if (src.source === 'acme') return `${base}: ${t(`acme.profiles.${src.acme?.profile || 'custom'}`)}, ${src.acme?.challenge}`
  if (src.source === 'ucm') return `${base}: ${src.ucm?.url}`
  return base
}

// Kea HA certificates this node's Kea configuration names (cert-file, trust-anchor); one plan renews
// them on every peer, so the button plans for the whole pair.
function KeaHaCerts({ entries, thresholds, onPlan }) {
  const { t } = useTranslation('certs')
  if (!entries?.length) return null
  return (
    <div className="border-t border-border pt-3 space-y-2" data-testid="cert-kea-ha">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="text-xs font-semibold text-text-primary">{t('keaHa.title')}</h4>
        <Button size="xs" variant="secondary" className="ml-auto" onClick={onPlan} data-testid="cert-kea-ha-renew"><ArrowsClockwise size={12} />{t('keaHa.renew')}</Button>
      </div>
      {entries.map((e) => {
        const cert = e.cert && !e.cert.error ? e.cert : null
        const { level, days } = expiryLevel(cert, thresholds)
        return (
          <div key={`${e.engine}/${e.server}`} className="space-y-1" data-testid="cert-kea-ha-entry" data-server={e.server}>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-medium">{e.engine} {e.server}</span>
              {e.role && <Badge variant="secondary" size="sm">{e.role}</Badge>}
              <Badge variant={LEVEL_BADGE[level]} size="sm" data-level={level}>
                {level === 'expired' ? t('expiry.expired') : level === 'unknown' ? t('expiry.unknown') : t('expiry.days', { count: days })}
              </Badge>
              <Badge variant={cert?.cluster_ca ? 'info' : 'warning'} size="sm">{cert?.cluster_ca ? t('keaHa.clusterCa') : t('keaHa.otherCa')}</Badge>
              {!e.full && <Badge variant="warning" size="sm">{t('keaHa.partial')}</Badge>}
            </div>
            {e.cert?.error && <p className="text-xs status-warning-text">{e.cert.path}: {e.cert.error}</p>}
            <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <Field label={t('fields.issuer')}>{cert ? cert.issuer_common_name || cert.issuer : '-'}</Field>
              <Field label={t('fields.names')}>{cert?.san?.join(', ') || '-'}</Field>
              <Field label={t('fields.expires')}>{cert ? when(cert.not_after) : '-'}</Field>
              <Field label={t('keaHa.files')}><span className="font-mono text-2xs">{e.cert?.path || '-'}</span></Field>
            </dl>
          </div>
        )
      })}
    </div>
  )
}

function NodeCard({ node, thresholds, onSource, onUpload, onRenew, onSelfSigned, showLog, onToggleLog, onKeaHaPlan }) {
  const { t } = useTranslation('certs')
  const cert = node.current
  const { level, days } = expiryLevel(cert, thresholds)
  const automatic = AUTOMATIC.includes(node.source?.source)
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="cert-node" data-node={node.node_id}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">{node.name}</h3>
        {node.is_self && <Badge variant="secondary" size="sm">{t('node.self')}</Badge>}
        {!node.reachable && <Badge variant="warning" size="sm">{t('node.unreachable')}</Badge>}
        <Badge variant={LEVEL_BADGE[level]} size="sm" data-testid="cert-expiry-badge" data-level={level}>
          {level === 'expired' ? t('expiry.expired') : level === 'unknown' ? t('expiry.unknown') : t('expiry.days', { count: days })}
        </Badge>
        <Badge variant="info" size="sm" data-testid="cert-source-badge">{node.inherited ? t('node.inherited', { source: sourceSummary(t, node.source) }) : sourceSummary(t, node.source)}</Badge>
        <div className="ml-auto flex flex-wrap gap-1.5">
          <Button size="sm" variant="secondary" onClick={onSource} disabled={!node.reachable} data-testid="cert-change-source"><PencilSimple size={14} />{t('actions.source')}</Button>
          <Button size="sm" variant="secondary" onClick={onUpload} disabled={!node.reachable} data-testid="cert-upload"><UploadSimple size={14} />{t('actions.upload')}</Button>
          {automatic && <Button size="sm" onClick={onRenew} disabled={!node.reachable} data-testid="cert-renew"><ArrowsClockwise size={14} />{t('actions.renew')}</Button>}
          <Button size="sm" variant="ghost" onClick={onSelfSigned} disabled={!node.reachable} data-testid="cert-self-signed"><Seal size={14} />{t('actions.selfSigned')}</Button>
        </div>
      </div>
      {node.error && <p className="text-xs status-warning-text">{node.error}</p>}
      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Field label={t('fields.issuer')}>{cert ? cert.issuer_common_name || cert.issuer : '-'}</Field>
        <Field label={t('fields.names')}>{cert?.san?.join(', ') || '-'}</Field>
        <Field label={t('fields.expires')}>{cert ? when(cert.not_after) : '-'}</Field>
        <Field label={t('fields.key')}>{cert?.key_type || '-'}</Field>
        <Field label={t('fields.lastIssued')}>{when(node.last_issued_at) || '-'}</Field>
        <Field label={t('fields.nextRenewal')}>{when(node.next_renewal_at) || (automatic ? '-' : t('fields.manualRenewal'))}</Field>
        <Field label={t('fields.wanted')}>{node.names?.join(', ') || '-'}</Field>
        <Field label={t('fields.fingerprint')}><span className="font-mono text-2xs">{cert?.fingerprint?.slice(0, 30) || '-'}</span></Field>
      </dl>
      {node.failures > 0 && (
        <p className="text-xs status-danger-text" data-testid="cert-last-error">
          {t('node.failures', { count: node.failures, next: when(node.next_attempt_at) || '-' })}: {node.last_error}
        </p>
      )}
      <KeaHaCerts entries={node.kea_ha} thresholds={thresholds} onPlan={onKeaHaPlan} />
      {node.job?.state === 'running' && <p className="text-xs text-text-secondary">{t('node.running', { step: node.job.step || '' })}</p>}
      {node.pending_request && <p className="text-xs text-text-secondary">{t('node.pendingRequest')}</p>}
      {node.log?.length > 0 && (
        <div>
          <Button size="xs" variant="ghost" onClick={onToggleLog}><ListBullets size={12} />{showLog ? t('log.hide') : t('log.show', { count: node.log.length })}</Button>
          {showLog && (
            <ul className="mt-1 max-h-48 overflow-auto text-2xs font-mono space-y-0.5" data-testid="cert-log">
              {node.log.map((line, i) => (
                <li key={`${line.ts}-${i}`} className={line.level === 'error' ? 'status-danger-text' : 'text-text-secondary'}>
                  {when(line.ts)} {line.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  )
}

function JobPanel({ job, names }) {
  const { t } = useTranslation('certs')
  if (!job) return null
  const steps = job.steps?.filter((s) => s.name?.startsWith('cert/')) || []
  return (
    <Card className="p-4 space-y-2" hover={false} data-testid="cert-job" data-state={job.state}>
      <div className="flex items-center gap-2">
        <h3 className="ui-card-title text-sm font-semibold">{t('job.title')}</h3>
        <Badge variant={job.state === 'done' ? 'success' : job.state === 'failed' ? 'danger' : 'info'} size="sm">{t(`job.states.${job.state}`, { defaultValue: job.state })}</Badge>
        {job.state === 'running' && <LoadingSpinner size="sm" />}
      </div>
      <ul className="space-y-1">
        {steps.map((s) => (
          <li key={s.name} className="flex items-start gap-2 text-sm" data-step={s.node_id} data-state={s.state}>
            <Badge variant={s.state === 'done' ? 'success' : s.state === 'failed' ? 'danger' : 'secondary'} size="sm">{t(`job.states.${s.state}`, { defaultValue: s.state })}</Badge>
            <span className="font-medium">{names[s.node_id] || s.node_id}</span>
            {s.state === 'failed' && <span className="text-xs status-danger-text">{String(s.output)}</span>}
          </li>
        ))}
      </ul>
    </Card>
  )
}

export default function CertificatesPage() {
  const { t } = useTranslation(['certs', 'common'])
  const { showSuccess, showError } = useNotification()
  const overviewQ = useApi(() => api.certs.overview(), [])
  const data = overviewQ.data
  const [sourceFor, setSourceFor] = useState(null) // node, or 'cluster'
  const [uploadFor, setUploadFor] = useState(null)
  const [selfSignedFor, setSelfSignedFor] = useState(null)
  const [clearCluster, setClearCluster] = useState(false)
  const [logs, setLogs] = useState({})
  const [job, setJob] = useState(null)
  const [setup, setSetup] = useState(null)
  const [haPlan, setHaPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const alive = useRef(true)
  // Set again on mount: StrictMode runs the cleanup once before the real mount.
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])
  const names = Object.fromEntries((data?.nodes || []).map((n) => [n.node_id, n.name]))

  const follow = async (started) => {
    if (!started) return
    setJob(started)
    let current = started
    while (alive.current && !['done', 'failed'].includes(current.state)) {
      await new Promise((r) => setTimeout(r, JOB_POLL_MS))
      try {
        current = await api.jobs.get(started.id)
      } catch {
        break
      }
      if (alive.current) setJob(current)
    }
    overviewQ.refetch()
  }

  const saved = (out) => {
    setSourceFor(null)
    showSuccess(t('source.saved'))
    overviewQ.refetch()
    if (out?.job) follow(out.job)
  }
  const renew = async (node) => {
    try {
      follow(await api.certs.renew(node.node_id))
    } catch (e) {
      showError(errorMessage(e))
    }
  }
  const doSelfSigned = async () => {
    setBusy(true)
    try {
      await api.certs.selfSigned(selfSignedFor.node_id)
      showSuccess(t('selfSigned.done', { node: selfSignedFor.name }))
      setSelfSignedFor(null)
      overviewQ.refetch()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const doClearCluster = async () => {
    setBusy(true)
    try {
      await api.certs.clearCluster()
      setClearCluster(false)
      overviewQ.refetch()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const planDns01 = async (delegation) => {
    try {
      setSetup(await api.certs.dns01Plan(delegation ? { delegation_zone: delegation } : {}))
    } catch (e) {
      showError(errorMessage(e))
    }
  }

  const planKeaHa = async () => {
    try {
      setHaPlan(await api.install.haTlsPlan())
    } catch (e) {
      showError(errorMessage(e))
    }
  }

  const cluster = data?.cluster
  return (
    <PageLayout
      icon={Certificate}
      title={t('title')}
      subtitle={t('subtitle')}
      testId="page-admin-certificates"
      actions={
        <Button size="sm" onClick={() => setSourceFor('cluster')} disabled={!data} data-testid="cert-apply-all">
          <Globe size={14} />
          {t('actions.applyAll')}
        </Button>
      }
    >
      {!data ? (
        overviewQ.error ? <p className="text-sm status-danger-text" role="alert">{errorMessage(overviewQ.error)}</p> : <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : (
        <div className="space-y-4 max-w-6xl">
          <Card className="p-4 space-y-2" hover={false} data-testid="cert-cluster">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('cluster.title')}</h3>
              <Badge variant={cluster ? 'info' : 'secondary'} size="sm">{cluster ? sourceSummary(t, cluster) : t('cluster.none')}</Badge>
              {cluster && (
                <div className="ml-auto flex gap-1.5">
                  <Button size="sm" variant="secondary" onClick={() => setSourceFor('cluster')}><PencilSimple size={14} />{t('actions.source')}</Button>
                  <Button size="sm" variant="ghost" onClick={() => setClearCluster(true)} data-testid="cert-clear-cluster"><Trash size={14} />{t('cluster.clear')}</Button>
                </div>
              )}
            </div>
            <p className="text-xs text-text-secondary">
              {cluster
                ? t('cluster.applies', { nodes: cluster.node_ids === 'all' ? t('cluster.everyNode') : (cluster.node_ids || []).map((id) => names[id] || id).join(', ') })
                : t('cluster.help')}
            </p>
            <p className="text-2xs text-text-tertiary">{t('cluster.thresholds', { warning: data.thresholds.warning_days, critical: data.thresholds.critical_days })}</p>
          </Card>
          <JobPanel job={job} names={names} />
          {data.nodes.map((node) => (
            <NodeCard
              key={node.node_id}
              node={node}
              thresholds={data.thresholds}
              onSource={() => setSourceFor(node)}
              onUpload={() => setUploadFor(node)}
              onRenew={() => renew(node)}
              onSelfSigned={() => setSelfSignedFor(node)}
              showLog={Boolean(logs[node.node_id])}
              onToggleLog={() => setLogs((l) => ({ ...l, [node.node_id]: !l[node.node_id] }))}
              onKeaHaPlan={planKeaHa}
            />
          ))}
          <p className="text-2xs text-text-tertiary">{t('replicationNote')}</p>
        </div>
      )}
      {sourceFor && (
        <SourceDialog
          open
          onClose={() => setSourceFor(null)}
          cluster={sourceFor === 'cluster'}
          node={sourceFor === 'cluster' ? null : sourceFor}
          overview={data}
          onSaved={saved}
          onPlan={planDns01}
        />
      )}
      {uploadFor && (
        <UploadDialog
          open
          onClose={() => setUploadFor(null)}
          node={data.nodes.find((n) => n.node_id === uploadFor.node_id) || uploadFor}
          nodes={data.nodes}
          onDone={(_out, keepOpen) => {
            overviewQ.refetch()
            if (!keepOpen) setUploadFor(null)
          }}
        />
      )}
      <ConfirmDialog
        open={Boolean(selfSignedFor)}
        onOpenChange={(o) => !o && setSelfSignedFor(null)}
        onConfirm={doSelfSigned}
        loading={busy}
        variant="primary"
        title={t('selfSigned.title', { node: selfSignedFor?.name })}
        message={t('selfSigned.body')}
        confirmLabel={t('actions.selfSigned')}
      />
      <ConfirmDialog
        open={clearCluster}
        onOpenChange={setClearCluster}
        onConfirm={doClearCluster}
        loading={busy}
        title={t('cluster.clearTitle')}
        message={t('cluster.clearBody')}
        confirmLabel={t('cluster.clear')}
      />
      {haPlan && (
        <PlanPreviewModal
          open
          plan={haPlan}
          onClose={() => setHaPlan(null)}
          title={t('keaHa.planTitle')}
          onApplied={() => {
            showSuccess(t('keaHa.applied'))
            overviewQ.refetch()
          }}
        />
      )}
      {setup && (
        setup.plan ? (
          <PlanPreviewModal open plan={setup.plan} onClose={() => setSetup(null)} title={t('dns01.title')} onApplied={() => showSuccess(t('dns01.applied'))} />
        ) : (
          <Modal open onClose={() => setSetup(null)} title={t('dns01.title')} size="md">
            <div className="p-4 text-sm text-text-secondary" data-testid="cert-dns01-nothing">{t('dns01.nothing')}</div>
          </Modal>
        )
      )}
      {setup && (setup.manual?.length > 0 || setup.delegation?.length > 0 || setup.unserved?.length > 0) && (
        <Card className="fixed bottom-4 right-4 z-[260] max-w-lg p-4 space-y-2 shadow-xl" hover={false} data-testid="cert-dns01-manual">
          {setup.manual?.length > 0 && <p className="text-xs font-medium">{t('dns01.manual')}</p>}
          {setup.manual?.map((m) => (
            <div key={`${m.view}/${m.zone}`}>
              {m.reason === 'allow_update' && <p className="text-xs status-warning-text">{t('dns01.allowUpdate', { zone: m.zone })}</p>}
              <pre className="text-2xs font-mono whitespace-pre-wrap">{`zone ${m.zone}: update-policy { ${m.statements.join(' ')} };`}</pre>
            </div>
          ))}
          {setup.delegation?.length > 0 && <p className="text-xs font-medium">{t('dns01.delegation')}</p>}
          {setup.delegation?.map((r) => <pre key={r.name} className="text-2xs font-mono">{`${r.name} CNAME ${r.value}`}</pre>)}
          {setup.unserved?.length > 0 && <p className="text-xs status-warning-text">{t('dns01.unserved', { names: setup.unserved.join(', ') })}</p>}
        </Card>
      )}
    </PageLayout>
  )
}
