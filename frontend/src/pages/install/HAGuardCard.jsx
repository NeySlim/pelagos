// SPDX-License-Identifier: Apache-2.0
// The nftables guard of the Kea HA listeners of one node: what Pelagos manages, what is loaded,
// a guard set up by hand (adopted by plan), and the allowed addresses edited by plan.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Shield } from '@phosphor-icons/react'
import { Card, Button, Badge, LoadingSpinner, PlanPreview } from '../../components'
import { Textarea } from '../../components/Textarea'
import { useApi } from '../../hooks'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { guardBadge, parsePeers, ADOPT_FINDING } from './guard'
import { ErrorNotice } from '../../components/ErrorNotice'

function Row({ label, children }) {
  return (
    <div className="flex flex-wrap gap-x-2 text-xs">
      <dt className="text-text-tertiary">{label}</dt>
      <dd className="text-text-secondary font-mono break-all">{children}</dd>
    </div>
  )
}

export default function HAGuardCard({ node, onChanged }) {
  const { t } = useTranslation('install')
  const guardQ = useApi(() => api.install.haGuard(node || undefined), [node])
  const guard = guardQ.data
  const [text, setText] = useState('')
  const [plan, setPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const current = guard?.managed?.peers || guard?.legacy?.peers || []
  useEffect(() => setText(current.join('\n')), [guard]) // eslint-disable-line react-hooks/exhaustive-deps

  if (guardQ.loading && !guard) return <Card className="p-4" hover={false}><LoadingSpinner size="sm" /></Card>
  if (guardQ.error) return <Card className="p-4" hover={false}><ErrorNotice error={guardQ.error} onRetry={guardQ.refetch} /></Card>
  if (!guard?.listeners?.length && !guard?.managed && !guard?.legacy) return null
  const badge = guardBadge(guard)
  const peers = parsePeers(text)
  const nothing = t('security.guard.nothing')

  const run = async (fn) => {
    setBusy(true)
    setError(null)
    try {
      setPlan(await fn())
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }
  const planPeers = () => run(() => api.install.haGuardPlan(node || undefined, peers))
  const adopt = () => run(() => api.install.securityPlan({ [guard.node_id]: [ADOPT_FINDING] }))

  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="ha-guard">
      <div className="flex flex-wrap items-center gap-2">
        <Shield size={16} className="text-text-secondary" />
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('security.guard.title')}</h3>
        <Badge variant={badge.variant} size="sm" data-testid="ha-guard-state">{t(`security.guard.${badge.key}`)}</Badge>
      </div>
      <p className="text-xs text-text-secondary">{t('security.guard.help')}</p>
      <dl className="space-y-1">
        <Row label={t('security.guard.listeners')}>{guard.listeners.map((l) => `${l.engine} ${l.address}`).join(', ') || nothing}</Row>
        {guard.managed && (
          <Row label={t('security.guard.recorded')}>
            {`${guard.managed.table} (${guard.managed.unit}): ${guard.managed.peers.join(', ') || nothing}`}
          </Row>
        )}
        <Row label={t('security.guard.loaded')}>{guard.loaded ? guard.loaded.peers.join(', ') || nothing : nothing}</Row>
        {guard.managed?.adopted_from && (
          <Row label="">{t('security.guard.adoptedFrom', { source: [guard.managed.adopted_from.unit, ...(guard.managed.adopted_from.files || [])].filter(Boolean).join(', ') })}</Row>
        )}
      </dl>
      {guard.differences?.length > 0 && (
        <ul className="list-disc ml-5 text-xs status-warning-text font-mono break-all" data-testid="ha-guard-differences">
          {guard.differences.map((d) => <li key={d}>{d}</li>)}
        </ul>
      )}
      {!guard.nft ? (
        <p className="text-xs status-warning-text">{t('security.guard.nftMissing')}</p>
      ) : guard.legacy ? (
        <div className="space-y-2">
          <p className="text-xs text-text-secondary">{t('security.guard.legacyHelp', { source: [guard.legacy.table, guard.legacy.unit, ...guard.legacy.files].filter(Boolean).join(', ') })}</p>
          {!plan && <Button size="sm" onClick={adopt} loading={busy} data-testid="ha-guard-adopt">{t('security.guard.adopt')}</Button>}
        </div>
      ) : (
        <div className="space-y-2">
          <Textarea label={t('security.guard.peers')} value={text} onChange={(e) => setText(e.target.value)} rows={3} disabled={Boolean(plan)} data-testid="ha-guard-peers" />
          {guard.suggested_peers?.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-text-tertiary">
              {t('security.guard.suggested', { peers: guard.suggested_peers.join(', ') })}
              <Button variant="ghost" size="sm" onClick={() => setText(guard.suggested_peers.join('\n'))} disabled={Boolean(plan)}>{t('security.guard.useSuggested')}</Button>
            </div>
          )}
          {!plan && <Button size="sm" onClick={planPeers} disabled={!peers.length} loading={busy} data-testid="ha-guard-plan">{t('security.guard.plan')}</Button>}
        </div>
      )}
      {error && <p className="text-sm status-danger-text" role="alert">{errorMessage(error)}</p>}
      {plan && (
        <PlanPreview
          plan={plan}
          onApplied={() => {
            guardQ.refetch()
            onChanged?.()
          }}
          onClose={() => setPlan(null)}
        />
      )}
    </Card>
  )
}
