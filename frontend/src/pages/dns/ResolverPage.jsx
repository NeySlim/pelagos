// SPDX-License-Identifier: Apache-2.0
// Resolver health and the forwarder fallback on top (section 25), then the resolver settings
// (recursion, allow-recursion, global forwarders, forward mode, dnssec-validation) as each node
// runs them, an editor that builds a dns.config plan, and the forward zones.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowsLeftRight, ArrowsClockwise, Lifebuoy, PencilSimple, Warning } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { DataTable } from '../../components/DataTable'
import { FormModal } from '../../components/FormModal'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { EmptyState } from '../../components/EmptyState'
import { Select } from '../../components/ui/Select'
import ToggleSwitch from '../../components/ui/ToggleSwitch'
import TagsInput from '../../components/ui/TagsInput'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { KeyValue, ListValue } from './common'
import { useNodeNames, usePlanFlow, zoneHref, RESOLVER_KEYS, resolverChanges, sameValue as same } from './helpers'
import { validForwarder } from './records'
import { HandoverCard } from './HandoverCard'
import { handoverItems } from './handover'
import { ExtendForm, FallbackBanner, FallbackForm, ResolverHealthSection } from './ResolverHealth'
import { healthSettings } from './resolverHealth'

function ResolverEditor({ open, onClose, current, onPlan }) {
  const { t } = useTranslation(['dns', 'common'])
  const [form, setForm] = useState(current)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (open) setForm(current)
  }, [open, current])
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }))
  const changes = resolverChanges(current, form)
  const nothing = Object.keys(changes).length === 0

  const submit = async () => {
    if (nothing) return
    setBusy(true)
    try {
      await onPlan(changes)
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('resolver.editTitle')} onSubmit={submit} loading={busy} disabled={nothing} submitLabel={t('editor.buildPlan')} testId="resolver-editor">
      <ToggleSwitch checked={Boolean(form.recursion)} onChange={set('recursion')} label={t('resolver.recursion')} description={t('resolver.recursionHelp')} />
      <TagsInput label={t('resolver.allowRecursion')} value={form.allow_recursion || []} onChange={set('allow_recursion')} placeholder="192.0.2.0/24" helperText={t('resolver.aclHelp')} />
      <TagsInput
        label={t('resolver.forwarders')}
        value={form.forwarders || []}
        onChange={set('forwarders')}
        placeholder="192.0.2.1"
        helperText={t('resolver.forwardersHelp')}
        validate={validForwarder}
      />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select
          label={t('resolver.forward')}
          value={form.forward || ''}
          onChange={(v) => set('forward')(v || null)}
          options={[
            { value: '', label: t('resolver.forwardDefault') },
            { value: 'first', label: 'first' },
            { value: 'only', label: 'only' },
          ]}
        />
        <Select
          label={t('resolver.dnssecValidation')}
          value={form.dnssec_validation || 'auto'}
          onChange={set('dnssec_validation')}
          options={['auto', 'yes', 'no'].map((v) => ({ value: v, label: v }))}
        />
      </div>
    </FormModal>
  )
}

export default function ResolverPage() {
  const { t } = useTranslation(['dns', 'common'])
  const { hasPermission } = usePermission()
  const { showError, showSuccess, showInfo } = useNotification()
  const { nameOf } = useNodeNames()
  const [editing, setEditing] = useState(false)
  const [params, setParams] = useSearchParams()
  const [extending, setExtending] = useState(false)
  const { data, error, loading, refetch } = useApi(() => api.dns.resolver(), [])
  const forwardZones = useApi(() => api.dns.zones({ kind: 'forward' }), [])
  const handover = useApi(() => api.dns.handover().catch(() => ({ items: [] })), [])
  const health = useApi(() => api.resolverHealth.health(), [])
  const { maxHours, autoReturn } = healthSettings(health.data)
  const reload = () => {
    refetch()
    handover.refetch()
    health.refetch()
  }
  const flow = usePlanFlow({ onDone: reload, onError: showError })

  const current = useMemo(() => (data ? Object.fromEntries(RESOLVER_KEYS.map((k) => [k, data[k] ?? null])) : null), [data])
  const perNode = useMemo(
    () => Object.entries(data?.per_node || {}).map(([node_id, s]) => ({ node_id, ...s, differs: RESOLVER_KEYS.some((k) => !same(s[k], current?.[k])) })),
    [data, current],
  )
  const canWrite = hasPermission('write:dns.config')
  // ?fallback=1 (the link of a proposing resolver_health alert) opens the fallback form.
  const asked = params.get('fallback') === '1'
  const fallingBack = asked && canWrite && Boolean(health.data) && !health.data.fallback
  const closeFallback = () => {
    const next = new URLSearchParams(params)
    next.delete('fallback')
    setParams(next, { replace: true })
  }
  // A ?fallback=1 the form cannot honour (read only, or a fallback already active) is dropped.
  const refused = asked && Boolean(health.data) && !fallingBack
  useEffect(() => {
    if (!refused) return
    if (health.data.fallback) showInfo(t('resolverHealth.fallbackActive'))
    else showInfo(t('resolverHealth.fallbackReadOnly'))
    closeFallback()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refused])
  const fallbackNodes = useMemo(
    () => [
      ...(health.data?.nodes || []).map((n) => ({ node_id: n.node_id })),
      ...(health.data?.unavailable || []).map((n) => ({ node_id: n.node_id, unavailable: true, error: n.error })),
    ],
    [health.data],
  )
  const extend = async (hours) => {
    try {
      await api.resolverHealth.extend(hours)
      setExtending(false)
      showSuccess(t('resolverHealth.extend.done'))
      health.refetch()
    } catch (err) {
      showError(errorMessage(err))
    }
  }

  const yesNo = (v) => (v === null || v === undefined ? null : t(`common:common.${v ? 'yes' : 'no'}`))

  return (
    <PageLayout
      icon={ArrowsLeftRight}
      title={t('pages.resolver.title')}
      subtitle={t('pages.resolver.subtitle')}
      testId="page-dns-resolver"
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={reload} disabled={loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          {canWrite && health.data && !health.data.fallback && (
            <Button variant="secondary" size="sm" onClick={() => setParams({ fallback: '1' })} data-testid="resolver-fallback-open">
              <Lifebuoy size={14} />
              {t('resolverHealth.fallbackAction')}
            </Button>
          )}
          {canWrite && current && (
            <Button size="sm" onClick={() => setEditing(true)} data-testid="resolver-edit">
              <PencilSimple size={14} />
              {t('common:actions.edit')}
            </Button>
          )}
        </>
      }
    >
      {loading && !data ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="md" />
        </div>
      ) : error ? (
        <EmptyState icon={ArrowsLeftRight} title={errorMessage(error)} action={{ label: t('common:actions.retry'), onClick: refetch }} />
      ) : (
        <div className="space-y-4 max-w-6xl">
          {health.data?.fallback && (
            <FallbackBanner
              fallback={health.data.fallback}
              returnReady={health.data.return_ready}
              nameOf={nameOf}
              canWrite={canWrite}
              autoReturn={autoReturn}
              busy={flow.busy}
              onReturn={() => flow.run(() => api.resolverHealth.returnPlan())}
              onExtend={() => setExtending(true)}
            />
          )}
          <ResolverHealthSection health={health.data} error={health.error} loading={health.loading} nameOf={nameOf} canSeries={hasPermission('read:series')} onRetry={health.refetch} />
          <h2 className="text-sm font-semibold text-text-primary pt-2">{t('resolverHealth.settingsTitle')}</h2>
          {canWrite && <HandoverCard items={handoverItems(handover.data, ['options'])} flow={flow} testId="handover-options" />}
          <Card className="p-4" hover={false} data-testid="resolver-settings">
            <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <KeyValue label={t('resolver.recursion')}>{yesNo(current.recursion)}</KeyValue>
              <KeyValue label={t('resolver.allowRecursion')}>
                <ListValue items={current.allow_recursion} />
              </KeyValue>
              <KeyValue label={t('resolver.forwarders')}>
                <ListValue items={current.forwarders} empty={t('resolver.noForwarders')} />
              </KeyValue>
              <KeyValue label={t('resolver.forward')} mono>{current.forward || t('resolver.forwardDefault')}</KeyValue>
              <KeyValue label={t('resolver.dnssecValidation')} mono>{current.dnssec_validation}</KeyValue>
            </dl>
          </Card>

          <DataTable
            title={t('resolver.perNode')}
            columns={[
              {
                key: 'node_id',
                label: t('resolver.node'),
                render: (r) => (
                  <span className="inline-flex items-center gap-1.5">
                    {nameOf(r.node_id)}
                    {r.differs && (
                      <Badge variant="warning" size="sm" icon={Warning}>
                        {t('resolver.differs')}
                      </Badge>
                    )}
                  </span>
                ),
              },
              { key: 'recursion', label: t('resolver.recursion'), render: (r) => yesNo(r.recursion) },
              { key: 'allow_recursion', label: t('resolver.allowRecursion'), render: (r) => <ListValue items={r.allow_recursion} /> },
              { key: 'forwarders', label: t('resolver.forwarders'), render: (r) => <ListValue items={r.forwarders} /> },
              { key: 'forward', label: t('resolver.forward'), mono: true },
              { key: 'dnssec_validation', label: t('resolver.dnssecValidation'), mono: true },
            ]}
            rows={perNode}
            rowKey="node_id"
            dense
            testId="resolver-per-node"
          />

          <DataTable
            title={t('resolver.forwardZones')}
            columns={[
              { key: 'zone.name', label: t('zones.name'), render: (r) => <Link className="font-mono text-xs text-accent-primary hover:underline" to={zoneHref(r.zone.name, r.zone.view)}>{r.zone.name}</Link> },
              { key: 'zone.view', label: t('zones.view'), mono: true },
              { key: 'zone.forward', label: t('resolver.forward'), mono: true },
              { key: 'zone.forwarders', label: t('resolver.forwarders'), render: (r) => <ListValue items={r.zone.forwarders} /> },
            ]}
            rows={forwardZones.data?.items || []}
            rowKey={(r) => `${r.zone.view}/${r.zone.name}`}
            loading={forwardZones.loading && !forwardZones.data}
            error={forwardZones.error}
            dense
            emptyTitle={t('resolver.noForwardZones')}
            testId="resolver-forward-zones"
          />
        </div>
      )}
      {editing && (
        <ResolverEditor
          open={editing}
          current={current}
          onClose={() => setEditing(false)}
          onPlan={async (changes) => {
            const plan = await flow.run(() => api.dns.resolverPlan(changes))
            if (plan) setEditing(false)
          }}
        />
      )}
      {fallingBack && (
        <FallbackForm
          open={fallingBack}
          onClose={closeFallback}
          presets={health.data.presets || []}
          nodes={fallbackNodes}
          nameOf={nameOf}
          maxHours={maxHours}
          autoReturn={autoReturn}
          onPlan={async (body) => {
            const plan = await flow.run(() => api.resolverHealth.fallbackPlan(body))
            if (plan) closeFallback()
          }}
        />
      )}
      {extending && <ExtendForm open={extending} onClose={() => setExtending(false)} maxHours={maxHours} onExtend={extend} />}
      {flow.modal}
    </PageLayout>
  )
}
