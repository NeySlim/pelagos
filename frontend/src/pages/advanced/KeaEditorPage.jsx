// SPDX-License-Identifier: Apache-2.0
// Kea editor: JSON tree of the running configuration (config-get) on the left,
// an editor for the selected key on the right with the version's schema, then
// the pending diff and a config plan that Kea checks with config-test.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BracketsCurly, ArrowsClockwise, Trash, Plus, Lightning, ArrowCounterClockwise, Warning } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, DiffView, LoadingSpinner, JsonTree, Input, Select, PlanPreviewModal } from '../../components'
import { useApi, usePermission } from '../../hooks'
import { useAuth } from '../../contexts/AuthContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { NodeSelect } from './NodeSelect'
import { unifiedDiff, jsonText } from './lineDiff'
import { parsePath, getPath, setPath, deletePath, typeOf, defaultFor, parseScalar, parseJson, checkSchema } from './keaJson'

const TARGETS = {
  v4: { engine: 'kea4', label: 'Dhcp4', load: (node) => api.dhcp.config('v4', node), schema: () => api.advanced.keaSchema('v4'), plan: (config, nodes) => api.dhcp.configPlan('v4', config, nodes) },
  v6: { engine: 'kea6', label: 'Dhcp6', load: (node) => api.dhcp.config('v6', node), schema: () => api.advanced.keaSchema('v6'), plan: (config, nodes) => api.dhcp.configPlan('v6', config, nodes) },
  d2: { engine: 'd2', label: 'DhcpDdns', load: (node) => api.d2.config(node), schema: null, plan: (config, nodes) => api.d2.configPlan(config, nodes) },
}

function JsonTextarea({ value, onChange, error, testId, readOnly }) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      readOnly={readOnly}
      rows={14}
      spellCheck={false}
      className={cn('w-full px-2.5 py-1.5 bg-bg-tertiary border rounded-md text-xs font-mono text-text-primary', error ? 'border-accent-danger' : 'border-border')}
      data-testid={testId}
    />
  )
}

function KeyEditor({ path, value, schemaKey, readOnly, onSave, onDelete }) {
  const { t } = useTranslation('advanced')
  const type = typeOf(value)
  const container = type === 'object' || type === 'array'
  const initial = useMemo(() => (container ? jsonText(value) : String(value)), [value, container])
  const [text, setText] = useState(initial)
  const [error, setError] = useState(null)
  useEffect(() => {
    setText(initial)
    setError(null)
  }, [initial])

  const save = () => {
    const parsed = container ? parseJson(text) : parseScalar(type, text)
    if (parsed.error) {
      setError(parsed.detail || t(`kea.errors.${parsed.error}`))
      return
    }
    setError(null)
    onSave(parsed.value)
  }

  return (
    <div className="space-y-3" data-testid="kea-key-editor">
      <div>
        <h3 className="text-sm font-semibold text-text-primary font-mono break-all">{path.join('.') || t('kea.root')}</h3>
        <div className="flex flex-wrap gap-1 mt-1">
          <Badge variant="outline" size="sm">{type}</Badge>
          {schemaKey && <Badge variant="info" size="sm">{t('kea.schemaType', { type: schemaKey.type })}</Badge>}
          {schemaKey?.since && <Badge variant="secondary" size="sm">{t('kea.since', { version: schemaKey.since })}</Badge>}
        </div>
        {schemaKey?.description && <p className="text-xs text-text-secondary mt-1">{schemaKey.description}</p>}
      </div>
      {type === 'boolean' ? (
        <Select label={t('kea.value')} options={[{ value: 'true', label: 'true' }, { value: 'false', label: 'false' }]} value={text} onChange={setText} disabled={readOnly} />
      ) : container ? (
        <>
          <JsonTextarea value={text} onChange={setText} error={error} readOnly={readOnly} testId="kea-json-input" />
          {error && <p className="text-xs status-danger-text font-mono">{error}</p>}
        </>
      ) : (
        <Input label={t('kea.value')} value={text} onChange={(e) => setText(e.target.value)} disabled={readOnly || type === 'null'} error={error} data-testid="kea-scalar-input" className="font-mono" />
      )}
      {!readOnly && (
        <div className="flex gap-2">
          <Button size="sm" onClick={save} disabled={text === initial} data-testid="kea-save">
            {t('bind.updateDraft')}
          </Button>
          {path.length > 1 && (
            <Button size="sm" variant="danger-soft" className="ml-auto" onClick={onDelete} data-testid="kea-delete">
              <Trash size={14} />
              {t('bind.remove')}
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

function AddKey({ target, schema, onAdd }) {
  const { t } = useTranslation('advanced')
  const [name, setName] = useState('')
  const [text, setText] = useState('')
  const [error, setError] = useState(null)
  const isArray = Array.isArray(target.value)
  const isRoot = schema && target.path.length === 1 && target.path[0] === schema.root
  const suggestions = isRoot ? (schema.keys || []).filter((k) => !(k.name in target.value)) : []

  const pick = (key) => {
    setName(key)
    const entry = suggestions.find((k) => k.name === key)
    setText(jsonText(defaultFor(entry?.type)))
  }
  const submit = () => {
    const parsed = parseJson(text || 'null')
    if (parsed.error) return setError(parsed.detail)
    if (!isArray && !name.trim()) return setError(t('kea.errors.name'))
    if (!isArray && name in target.value) return setError(t('kea.errors.exists'))
    setError(null)
    onAdd(isArray ? [...target.path, target.value.length] : [...target.path, name.trim()], parsed.value)
    setName('')
    setText('')
  }

  return (
    <div className="space-y-2 border-t border-border pt-3" data-testid="kea-add">
      <h4 className="text-xs font-semibold text-text-secondary">{isArray ? t('kea.append') : t('kea.addKey')}</h4>
      {suggestions.length > 0 && (
        <Select label={t('kea.fromSchema')} options={suggestions.map((k) => ({ value: k.name, label: `${k.name} (${k.type})` }))} value={name || undefined} onChange={pick} placeholder={t('bind.choose')} />
      )}
      {!isArray && <Input label={t('kea.key')} value={name} onChange={(e) => setName(e.target.value)} className="font-mono" data-testid="kea-add-name" />}
      <JsonTextarea value={text} onChange={setText} error={error} testId="kea-add-value" />
      {error && <p className="text-xs status-danger-text font-mono">{error}</p>}
      <Button size="sm" variant="secondary" onClick={submit} data-testid="kea-add-submit">
        <Plus size={14} />
        {t('bind.addToDraft')}
      </Button>
    </div>
  )
}

export default function KeaEditorPage() {
  const { t } = useTranslation(['advanced', 'common'])
  const { hasPermission } = usePermission()
  const { modules } = useAuth()
  const canWrite = hasPermission('write:dhcp.config')
  const [targetId, setTargetId] = useState('v4')
  const [nodeId, setNodeId] = useState('')
  const target = TARGETS[targetId]
  const configQ = useApi(() => target.load(nodeId || undefined), [targetId, nodeId])
  const schemaQ = useApi(() => (target.schema ? target.schema() : Promise.resolve(null)), [targetId])
  const original = configQ.data?.config
  const [draft, setDraft] = useState(null)
  const [selectedPath, setSelectedPath] = useState('')
  const [plan, setPlan] = useState(null)
  const [planError, setPlanError] = useState(null)
  const [building, setBuilding] = useState(false)

  useEffect(() => {
    setDraft(original ? JSON.parse(JSON.stringify(original)) : null)
    setSelectedPath(original ? Object.keys(original)[0] || '' : '')
  }, [original])

  const path = parsePath(selectedPath)
  const selectedValue = draft ? getPath(draft, path) : undefined
  const schema = schemaQ.data
  const schemaKey = schema && path.length === 2 && path[0] === schema.root ? schema.keys?.find((k) => k.name === path[1]) : null
  const diff = useMemo(() => (original && draft ? unifiedDiff(jsonText(original), jsonText(draft), `${target.label}.json`) : ''), [original, draft, target.label])
  const problems = useMemo(() => (draft ? checkSchema(draft, schema) : []), [draft, schema])
  const dirty = Boolean(diff)

  const buildPlan = async () => {
    setBuilding(true)
    setPlanError(null)
    try {
      setPlan(await target.plan(draft, nodeId ? [nodeId] : undefined))
    } catch (err) {
      setPlanError(err)
    } finally {
      setBuilding(false)
    }
  }

  const families = [
    { value: 'v4', label: 'DHCPv4' },
    ...(modules.dhcpv6 ? [{ value: 'v6', label: 'DHCPv6' }] : []),
    { value: 'd2', label: 'DHCP-DDNS' },
  ]

  return (
    <PageLayout
      icon={BracketsCurly}
      title={t('pages.kea.title')}
      subtitle={t('pages.kea.subtitle')}
      testId="page-advanced-kea"
      actions={
        <>
          <Select options={families} value={targetId} onChange={(v) => { setTargetId(v); setNodeId('') }} size="sm" variant="filter" />
          <NodeSelect engine={target.engine} value={nodeId} onChange={setNodeId} />
          <Button variant="secondary" size="sm" onClick={configQ.refetch} disabled={configQ.loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
        </>
      }
    >
      {configQ.loading && !draft ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="md" />
        </div>
      ) : configQ.error ? (
        <Card className="p-4" hover={false}>
          <p className="text-sm status-danger-text" role="alert">{errorMessage(configQ.error)}</p>
        </Card>
      ) : draft ? (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-2xs text-text-tertiary">
            {configQ.data?.node_id && <span>{t('kea.readFrom')}: <span className="font-mono text-text-secondary">{configQ.data.node_id}</span></span>}
            {configQ.data?.hash && <span>{t('kea.hash')}: <span className="font-mono text-text-secondary">{configQ.data.hash}</span></span>}
            {schema?.version && <span>{t('kea.schemaVersion')}: <span className="font-mono text-text-secondary">{schema.version}</span></span>}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-4">
            <Card className="p-3 max-h-[60vh] overflow-auto" hover={false} data-testid="kea-tree">
              <JsonTree data={draft} expandedDepth={2} selectedPath={selectedPath} onSelect={(p) => setSelectedPath(p)} />
            </Card>
            <Card className="p-4 space-y-3 max-h-[60vh] overflow-auto" hover={false}>
              {selectedValue === undefined ? (
                <p className="text-xs text-text-tertiary">{t('kea.selectHint')}</p>
              ) : (
                <>
                  <KeyEditor
                    path={path}
                    value={selectedValue}
                    schemaKey={schemaKey}
                    readOnly={!canWrite || path.length === 0}
                    onSave={(value) => setDraft((d) => setPath(d, path, value))}
                    onDelete={() => {
                      setDraft((d) => deletePath(d, path))
                      setSelectedPath(path.slice(0, -1).join('.'))
                    }}
                  />
                  {canWrite && path.length > 0 && selectedValue && typeof selectedValue === 'object' && (
                    <AddKey
                      target={{ path, value: selectedValue }}
                      schema={schema}
                      onAdd={(newPath, value) => {
                        setDraft((d) => setPath(d, newPath, value))
                        setSelectedPath(newPath.join('.'))
                      }}
                    />
                  )}
                </>
              )}
            </Card>
          </div>

          <Card className="p-4 space-y-3" hover={false} data-testid="kea-pending">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-text-primary">{t('pending.title')}</h3>
              <Badge variant={dirty ? 'warning' : 'secondary'} size="sm">{dirty ? t('pending.modified') : t('pending.clean')}</Badge>
              <div className="ml-auto flex gap-2">
                <Button variant="secondary" size="sm" disabled={!dirty} onClick={() => setDraft(JSON.parse(JSON.stringify(original)))} data-testid="kea-discard">
                  <ArrowCounterClockwise size={14} />
                  {t('pending.discard')}
                </Button>
                <Button size="sm" disabled={!dirty || !canWrite} loading={building} onClick={buildPlan} data-testid="kea-plan">
                  <Lightning size={14} weight="fill" />
                  {t('pending.validateKea')}
                </Button>
              </div>
            </div>
            {problems.length > 0 && (
              <ul className="space-y-0.5 text-xs" data-testid="kea-problems">
                {problems.map((p) => (
                  <li key={p.path} className="flex items-center gap-1.5 status-warning-text">
                    <Warning size={12} />
                    <span className="font-mono">{p.path}</span>
                    <span>{t(`kea.problems.${p.problem}`, { expected: p.expected, actual: p.actual })}</span>
                  </li>
                ))}
              </ul>
            )}
            <DiffView diff={diff} maxHeight={300} emptyLabel={t('pending.none')} />
            {planError && (
              <div className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text" role="alert" data-testid="kea-plan-error">
                <p className="font-medium">{errorMessage(planError)}</p>
                {planError.errors?.map((e, i) => (
                  <pre key={i} className="whitespace-pre-wrap font-mono text-2xs mt-1">{e.field ? `${e.field}: ` : ''}{e.message}</pre>
                ))}
              </div>
            )}
          </Card>
        </div>
      ) : null}
      <PlanPreviewModal open={Boolean(plan)} plan={plan} onClose={() => setPlan(null)} onApplied={() => configQ.refetch()} onRolledBack={() => configQ.refetch()} />
    </PageLayout>
  )
}
