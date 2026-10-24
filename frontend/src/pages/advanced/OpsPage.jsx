// SPDX-License-Identifier: Apache-2.0
// Runtime operations: the allow-listed rndc and Kea control commands, grouped into reads
// and changes. Reads may target any node running the engine; changes run on this node,
// are audited, and the risky ones ask for an explicit confirmation.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Terminal, Play, MagnifyingGlass, Warning, Globe, TreeStructure, ArrowsClockwise } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, Input, Select, LoadingSpinner, JsonTree } from '../../components'
import { ToggleSwitch } from '../../components/ui/ToggleSwitch'
import TagsInput from '../../components/ui/TagsInput'
import { useApi, usePermission } from '../../hooks'
import { useAuth } from '../../contexts/AuthContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { NodeSelect } from './NodeSelect'
import { paramKind, buildParams, runBlocker, groupOps } from './opsForm'

const TABS = [
  { id: 'bind', engine: 'bind', permission: 'read:dns', icon: Globe },
  { id: 'v4', engine: 'kea4', permission: 'read:dhcp', icon: TreeStructure },
  { id: 'v6', engine: 'kea6', permission: 'read:dhcp', module: 'dhcpv6', icon: TreeStructure },
  { id: 'd2', engine: 'd2', permission: 'read:dhcp', icon: ArrowsClockwise },
]

function ParamField({ spec, name, value, error, onChange }) {
  const { t } = useTranslation('advanced')
  const label = t(`ops.params.${name}`, { defaultValue: name })
  const kind = paramKind(spec, name)
  const required = spec.required?.includes(name)
  const errorText = error ? t(`ops.errors.${error}`) : undefined
  if (kind === 'bool') {
    return <ToggleSwitch label={label} checked={Boolean(value)} onChange={onChange} />
  }
  if (kind === 'choice') {
    return (
      <Select
        label={label}
        options={spec.choices[name].map((c) => ({ value: c, label: c }))}
        value={value || ''}
        onChange={onChange}
        error={errorText}
      />
    )
  }
  if (kind === 'list') {
    return <TagsInput label={label} value={value || []} onChange={onChange} placeholder={t('ops.listPlaceholder')} />
  }
  return (
    <Input
      label={label}
      value={value ?? ''}
      onChange={(e) => onChange(e.target.value)}
      required={required}
      error={errorText}
      inputMode={kind === 'int' ? 'numeric' : undefined}
      data-testid={`ops-param-${name}`}
    />
  )
}

function OpList({ title, ops, selected, onSelect, allowed }) {
  const { t } = useTranslation('advanced')
  if (!ops.length) return null
  return (
    <div className="space-y-1">
      <h4 className="ui-label text-2xs uppercase tracking-wider text-text-tertiary px-1">{title}</h4>
      {ops.map((o) => (
        <button
          key={o.name}
          type="button"
          onClick={() => onSelect(o.name)}
          aria-pressed={selected === o.name}
          data-op={o.name}
          className={cn(
            'w-full flex items-center gap-2 px-2 py-1 rounded text-left text-xs font-mono',
            selected === o.name ? 'nav-item-active bg-accent-primary-op15 text-accent-primary' : 'text-text-primary hover:bg-bg-tertiary',
            (!allowed(o) || o.available === false) && 'opacity-50',
          )}
        >
          <span className="flex-1 truncate">{o.name}</span>
          {o.confirm && <Warning size={12} className="status-warning-text" aria-label={t('ops.needsConfirm')} />}
        </button>
      ))}
    </div>
  )
}

export default function OpsPage() {
  const { t } = useTranslation(['advanced', 'common'])
  const { hasPermission } = usePermission()
  const { modules, node } = useAuth()
  const tabs = TABS.filter((tab) => hasPermission(tab.permission) && (!tab.module || modules?.[tab.module]))
  const [tabId, setTabId] = useState(tabs[0]?.id)
  const tab = tabs.find((x) => x.id === tabId) || tabs[0]
  const [nodeId, setNodeId] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(null)
  const [values, setValues] = useState({})
  const [errors, setErrors] = useState({})
  const [confirmed, setConfirmed] = useState(false)
  const [running, setRunning] = useState(false)
  const [outcome, setOutcome] = useState(null)

  const catalogQ = useApi(
    () => (!tab ? Promise.resolve(null) : tab.id === 'bind' ? api.ops.bindCatalog() : api.ops.keaCatalog(tab.id, nodeId || undefined)),
    [tab?.id, nodeId],
  )
  const operations = useMemo(() => catalogQ.data?.operations || [], [catalogQ.data])
  const groups = groupOps(operations, hasPermission, query)
  const spec = operations.find((o) => o.name === selected) || null
  const selfId = node?.id
  const isLocal = !nodeId || nodeId === selfId

  useEffect(() => {
    setSelected(null)
    setOutcome(null)
  }, [tab?.id])
  useEffect(() => {
    setValues({})
    setErrors({})
    setConfirmed(false)
    setOutcome(null)
  }, [selected])

  const blocker = runBlocker(spec, { isLocal, confirmed, allowed: spec ? hasPermission(spec.permission) : false })

  const run = async () => {
    const built = buildParams(spec, values)
    setErrors(built.errors)
    if (Object.keys(built.errors).length) return
    setRunning(true)
    setOutcome(null)
    try {
      const body = { params: built.params, node_id: nodeId || undefined, confirm: spec.confirm ? confirmed : undefined }
      const res = tab.id === 'bind'
        ? await api.ops.bindRun({ op: spec.name, ...body })
        : await api.ops.keaRun(tab.id, { command: spec.name, ...body })
      setOutcome({ ok: true, res })
    } catch (err) {
      setOutcome({ ok: false, err })
    } finally {
      setRunning(false)
    }
  }

  if (!tab) {
    return (
      <PageLayout icon={Terminal} title={t('ops.title')} testId="page-advanced-ops">
        <p className="text-sm text-text-secondary">{t('ops.noAccess')}</p>
      </PageLayout>
    )
  }

  return (
    <PageLayout
      icon={Terminal}
      title={t('ops.title')}
      subtitle={t('ops.subtitle')}
      tabs={tabs.map((x) => ({ id: x.id, icon: x.icon, label: t(`ops.tabs.${x.id}`) }))}
      activeTab={tab.id}
      onTabChange={setTabId}
      actions={<NodeSelect engine={tab.engine} value={nodeId} onChange={setNodeId} />}
      testId="page-advanced-ops"
    >
      <div className="grid grid-cols-1 lg:grid-cols-[16rem_minmax(0,1fr)] gap-4">
        <Card className="p-3 space-y-3 max-h-[70vh] overflow-auto" hover={false} data-testid="ops-list">
          <Input
            icon={<MagnifyingGlass size={14} />}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('ops.filter')}
            aria-label={t('ops.filter')}
          />
          {catalogQ.loading && <div className="flex justify-center py-4"><LoadingSpinner size="sm" /></div>}
          {catalogQ.error && <p className="text-xs status-danger-text" role="alert">{errorMessage(catalogQ.error)}</p>}
          {catalogQ.data?.error && <p className="text-xs status-warning-text">{catalogQ.data.error}</p>}
          <OpList title={t('ops.reads')} ops={groups.reads} selected={selected} onSelect={setSelected} allowed={groups.allowed} />
          <OpList title={t('ops.changes')} ops={groups.changes} selected={selected} onSelect={setSelected} allowed={groups.allowed} />
        </Card>

        <Card className="p-4 space-y-4" hover={false} data-testid="ops-detail">
          {!spec ? (
            <p className="text-sm text-text-secondary">{t('ops.pick')}</p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-mono text-sm font-semibold text-text-primary">{spec.name}</h3>
                <Badge variant={spec.write ? 'warning' : 'info'} size="sm">{spec.write ? t('ops.change') : t('ops.read')}</Badge>
                <Badge variant="outline" size="sm" className="font-mono">{spec.permission}</Badge>
              </div>
              <p className="text-xs text-text-secondary">{t(`ops.help.${spec.name}`, { defaultValue: t('ops.helpDefault') })}</p>
              {spec.params?.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {spec.params.map((name) => (
                    <ParamField
                      key={name}
                      spec={spec}
                      name={name}
                      value={values[name]}
                      error={errors[name]}
                      onChange={(v) => setValues((cur) => ({ ...cur, [name]: v }))}
                    />
                  ))}
                </div>
              )}
              {spec.confirm && (
                <label className="flex items-center gap-2 text-xs text-text-primary cursor-pointer select-none">
                  <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} data-testid="ops-confirm" />
                  {t('ops.confirm', { name: spec.name })}
                </label>
              )}
              {blocker && blocker !== 'confirm' && (
                <p className="text-xs status-warning-text" data-testid="ops-blocked">{t(`ops.blocked.${blocker}`)}</p>
              )}
              <div className="flex justify-end">
                <Button onClick={run} disabled={Boolean(blocker)} loading={running} data-testid="ops-run">
                  <Play size={14} weight="fill" />
                  {t('ops.run')}
                </Button>
              </div>
              {outcome && (
                <div data-testid="ops-output">
                  {outcome.ok ? (
                    tab.id === 'bind' ? (
                      <pre className="rounded-lg border border-border bg-bg-primary p-3 text-xs font-mono whitespace-pre-wrap max-h-80 overflow-auto text-text-primary">
                        {outcome.res.output || t('ops.noOutput')}
                      </pre>
                    ) : (
                      <div className="rounded-lg border border-border bg-bg-primary p-2 max-h-80 overflow-auto">
                        <JsonTree data={outcome.res.result ?? {}} expandedDepth={2} />
                      </div>
                    )
                  ) : (
                    <p className="text-xs status-danger-text" role="alert">{errorMessage(outcome.err)}</p>
                  )}
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </PageLayout>
  )
}
