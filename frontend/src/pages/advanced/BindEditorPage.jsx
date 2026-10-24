// SPDX-License-Identifier: Apache-2.0
// named.conf editor: statement tree of every file with provenance on the left,
// a form generated from the BIND grammar on the right, then the pending diff and
// a dns.config plan validated by named-checkconf before anything is applied.
// Managed files take any statement without a dedicated screen (zones, keys and ACLs
// keep theirs); user files only take changes inside their options block.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Code, ArrowsClockwise, CaretDown, CaretRight, Plus, Trash, FileText, LockSimple, ArrowSquareOut, Lightning, ArrowCounterClockwise } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, DiffView, LoadingSpinner, EmptyState, PlanPreviewModal, Select } from '../../components'
import { useApi, usePermission } from '../../hooks'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { NodeSelect } from './NodeSelect'
import { ValueEditor } from './ValueEditor'
import {
  grammarIndex, statementsFor, childContext, toForm, fromForm, validateForm, getAt,
  replaceStatement, removeStatement, addStatement, buildChanges, fileText, normalizeGrammar, valueText,
  editableAt, canAddTop, canAddInside, topContext,
} from './bindGrammar'
import { unifiedDiff } from './lineDiff'

const textValues = (statements) =>
  (Array.isArray(statements) ? statements : []).map((s) => ({
    ...s,
    value: valueText(s.value),
    ...(Array.isArray(s.children) ? { children: textValues(s.children) } : {}),
  }))

const samePath = (a, b) => Boolean(a && b) && a.length === b.length && a.every((v, i) => v === b[i])

function StatementRows({ statements, fileIndex, prefix, depth, selected, onSelect, canAdd, onAdd, t }) {
  return statements.map((s, i) => {
    const path = [fileIndex, ...prefix, i]
    return <StatementRow key={`${s.name}-${i}`} statement={s} path={path} depth={depth} selected={selected} onSelect={onSelect} canAdd={canAdd} onAdd={onAdd} t={t} />
  })
}

function StatementRow({ statement, path, depth, selected, onSelect, canAdd, onAdd, t }) {
  const [open, setOpen] = useState(depth < 1)
  const hasChildren = Array.isArray(statement.children)
  const isSelected = samePath(selected, path)
  return (
    <div>
      <div
        className={cn('group flex items-center gap-1 rounded px-1 py-0.5 cursor-pointer text-xs', isSelected ? 'bg-accent-primary-op15' : 'hover:bg-bg-tertiary')}
        style={{ paddingLeft: `${depth * 14 + 4}px` }}
        onClick={() => onSelect(path)}
        data-testid="bind-statement"
        data-name={statement.name}
      >
        {hasChildren ? (
          <button type="button" className="w-4 h-4 flex items-center justify-center text-text-tertiary" onClick={(e) => { e.stopPropagation(); setOpen((o) => !o) }} aria-label={open ? 'collapse' : 'expand'}>
            {open ? <CaretDown size={10} weight="bold" /> : <CaretRight size={10} weight="bold" />}
          </button>
        ) : (
          <span className="w-4" />
        )}
        <span className="font-mono text-text-primary">{statement.name}</span>
        {statement.value && <span className="font-mono text-text-secondary truncate min-w-0 flex-1">{statement.value}</span>}
        {!statement.value && <span className="flex-1" />}
        {hasChildren && canAdd(path) && (
          <button type="button" className="opacity-0 group-hover:opacity-100 text-text-tertiary hover:text-accent-primary" title={t('bind.addInside')} onClick={(e) => { e.stopPropagation(); onAdd(path, statement.name) }}>
            <Plus size={12} />
          </button>
        )}
        {statement.line ? <span className="text-2xs text-text-tertiary font-mono">{statement.line}</span> : <Badge variant="warning" size="sm">{t('bind.new')}</Badge>}
      </div>
      {hasChildren && open && (
        <StatementRows statements={statement.children} fileIndex={path[0]} prefix={path.slice(1)} depth={depth + 1} selected={selected} onSelect={onSelect} canAdd={canAdd} onAdd={onAdd} t={t} />
      )}
    </div>
  )
}

function GrammarInfo({ entry }) {
  const { t } = useTranslation('advanced')
  if (!entry) return <p className="text-xs text-text-tertiary italic" data-testid="grammar-unknown">{t('bind.notInGrammar')}</p>
  return (
    <div className="rounded-lg border border-border bg-bg-primary p-2 space-y-1 text-xs" data-testid="grammar-info">
      <div className="font-mono text-text-secondary break-all">{entry.name} {entry.args}</div>
      <div className="flex flex-wrap items-center gap-1">
        {(entry.contexts || []).map((c) => (
          <Badge key={c} variant="outline" size="sm">{c}</Badge>
        ))}
        {entry.multiple && <Badge variant="info" size="sm">{t('bind.repeatable')}</Badge>}
        {entry.doc && (
          <a href={entry.doc} target="_blank" rel="noreferrer noopener" className="ml-auto inline-flex items-center gap-1 text-accent-primary hover:underline">
            {t('bind.reference')}
            <ArrowSquareOut size={12} />
          </a>
        )}
      </div>
    </div>
  )
}

function StatementEditor({ statement, entry, readOnly, onSave, onRemove }) {
  const { t } = useTranslation('advanced')
  const initial = useMemo(() => toForm(entry, statement.value), [entry, statement])
  const [form, setForm] = useState(initial)
  const [error, setError] = useState(null)
  useEffect(() => {
    setForm(initial)
    setError(null)
  }, [initial])
  const changed = fromForm(form) !== (statement.value ?? null) && !(form.kind === 'block' && !form.value && !statement.value)
  const save = () => {
    const err = validateForm(form)
    setError(err)
    if (!err) onSave({ value: fromForm(form) })
  }
  return (
    <div className="space-y-3" data-testid="statement-editor">
      <GrammarInfo entry={entry} />
      <ValueEditor form={form} onChange={setForm} disabled={readOnly} error={error} />
      {!readOnly && (
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={save} disabled={!changed} data-testid="statement-save">
            {t('bind.updateDraft')}
          </Button>
          <Button size="sm" variant="danger-soft" onClick={onRemove} className="ml-auto" data-testid="statement-remove">
            <Trash size={14} />
            {t('bind.remove')}
          </Button>
        </div>
      )}
    </div>
  )
}

function AddStatement({ grammar, context, existing, onAdd, onCancel }) {
  const { t } = useTranslation('advanced')
  const choices = statementsFor(grammar, context).filter((s) => s.multiple || !existing.includes(s.name))
  const [name, setName] = useState('')
  const entry = choices.find((s) => s.name === name)
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  useEffect(() => {
    setForm(entry ? toForm(entry, null) : null)
    setError(null)
  }, [entry])
  const submit = () => {
    const err = validateForm(form)
    setError(err)
    if (err) return
    onAdd({ name, value: fromForm(form), line: null, ...(form.kind === 'block' ? { children: [] } : {}) })
  }
  return (
    <div className="space-y-3" data-testid="statement-add">
      <p className="text-xs text-text-secondary">{t('bind.addIn', { context })}</p>
      <Select
        label={t('bind.statement')}
        options={choices.map((s) => ({ value: s.name, label: s.name }))}
        value={name || undefined}
        onChange={setName}
        placeholder={t('bind.choose')}
      />
      {entry && form && (
        <>
          <GrammarInfo entry={entry} />
          <ValueEditor form={form} onChange={setForm} error={error} />
        </>
      )}
      <div className="flex gap-2">
        <Button size="sm" onClick={submit} disabled={!entry} data-testid="statement-add-submit">
          <Plus size={14} />
          {t('bind.addToDraft')}
        </Button>
        <Button size="sm" variant="secondary" onClick={onCancel}>
          {t('common:actions.cancel')}
        </Button>
      </div>
    </div>
  )
}

export default function BindEditorPage() {
  const { t } = useTranslation(['advanced', 'common'])
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dns.config')
  const [nodeId, setNodeId] = useState('')
  const grammarQ = useApi(() => api.advanced.bindGrammar(), [])
  const treeQ = useApi(() => api.advanced.bindTree(nodeId || undefined), [nodeId])
  const grammar = useMemo(() => normalizeGrammar(grammarQ.data), [grammarQ.data])
  const original = useMemo(() => (treeQ.data?.files || []).map((f) => ({ ...f, statements: textValues(f.statements) })), [treeQ.data])
  const [draft, setDraft] = useState([])
  const [selected, setSelected] = useState(null)
  const [adding, setAdding] = useState(null) // { path, context }
  const [plan, setPlan] = useState(null)
  const [planError, setPlanError] = useState(null)
  const [building, setBuilding] = useState(false)

  useEffect(() => {
    setDraft(JSON.parse(JSON.stringify(original)))
    setSelected(null)
    setAdding(null)
  }, [original])

  const index = useMemo(() => grammarIndex(grammar), [grammar])
  const changes = useMemo(() => (draft.length === original.length ? buildChanges(original, draft) : []), [original, draft])
  const localDiff = useMemo(
    () => draft.map((f, i) => (original[i] ? unifiedDiff(fileText(original[i]), fileText(f), f.path) : '')).join(''),
    [original, draft],
  )

  const selectedFile = selected ? draft[selected[0]] : null
  const selectedStatement = selected && selectedFile ? getAt(selectedFile.statements, selected.slice(1)) : null
  const readOnly = !editableAt(selectedFile, selected?.slice(1), canWrite)

  const select = (path) => {
    setAdding(null)
    setSelected(path)
  }
  const startAdd = (path, parentName) => {
    setSelected(null)
    setAdding({ path, context: childContext(parentName || (path.length === 1 ? topContext(draft[path[0]]) : null)) })
  }
  const existingNames = adding
    ? (adding.path.length === 1 ? draft[adding.path[0]].statements : getAt(draft[adding.path[0]].statements, adding.path.slice(1))?.children || []).map((s) => s.name)
    : []

  // The edits as they are now, planned again: the server forgot the old plan (expired or restarted).
  const recompute = async () => {
    const fresh = await api.dns.configPlan(changes, nodeId ? [nodeId] : undefined)
    setPlan(fresh)
    return fresh
  }

  const buildPlan = async () => {
    setBuilding(true)
    setPlanError(null)
    try {
      setPlan(await api.dns.configPlan(changes, nodeId ? [nodeId] : undefined))
    } catch (err) {
      setPlanError(err)
    } finally {
      setBuilding(false)
    }
  }

  const loading = treeQ.loading || grammarQ.loading
  const error = treeQ.error || grammarQ.error

  return (
    <PageLayout
      icon={Code}
      title={t('pages.bind.title')}
      subtitle={t('pages.bind.subtitle')}
      testId="page-advanced-bind"
      actions={
        <>
          <NodeSelect engine="bind" value={nodeId} onChange={setNodeId} />
          <Button variant="secondary" size="sm" onClick={treeQ.refetch} disabled={treeQ.loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
        </>
      }
    >
      {loading && !draft.length ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="md" />
        </div>
      ) : error ? (
        <Card className="p-4" hover={false}>
          <p className="text-sm status-danger-text" role="alert">{errorMessage(error)}</p>
        </Card>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] gap-4">
            <Card className="p-2 max-h-[60vh] overflow-auto" hover={false} data-testid="bind-tree">
              {draft.map((file, fi) => (
                <div key={file.path} className="mb-2">
                  <div className="flex items-center gap-1.5 px-1 py-1 text-xs font-semibold text-text-primary border-b border-border-op30">
                    <FileText size={14} className="text-text-tertiary" />
                    <span className="font-mono truncate flex-1" title={file.path}>{file.path}</span>
                    {file.managed ? (
                      <Badge variant="primary" size="sm" icon={LockSimple}>{t('bind.managed')}</Badge>
                    ) : (
                      <Badge variant="outline" size="sm">{t('bind.userFile')}</Badge>
                    )}
                    {canAddTop(file, canWrite) && (
                      <button type="button" className="text-text-tertiary hover:text-accent-primary" title={t('bind.addTop')} onClick={() => startAdd([fi], null)} data-testid="bind-add-top">
                        <Plus size={12} />
                      </button>
                    )}
                  </div>
                  <StatementRows statements={file.statements} fileIndex={fi} prefix={[]} depth={0} selected={selected} onSelect={select} canAdd={(path) => canAddInside(file, path.slice(1), canWrite)} onAdd={startAdd} t={t} />
                </div>
              ))}
            </Card>
            <Card className="p-4" hover={false} data-testid="bind-form">
              {adding ? (
                <AddStatement
                  grammar={grammar}
                  context={adding.context}
                  existing={existingNames}
                  onCancel={() => setAdding(null)}
                  onAdd={(statement) => {
                    setDraft((d) => addStatement(d, adding.path, statement))
                    setAdding(null)
                  }}
                />
              ) : selectedStatement ? (
                <div className="space-y-3">
                  <div>
                    <h3 className="text-sm font-semibold text-text-primary font-mono">{selectedStatement.name}</h3>
                    <p className="text-2xs text-text-tertiary font-mono">
                      {selectedStatement.line ? t('bind.definedAt', { file: selectedFile.path, line: selectedStatement.line }) : t('bind.pendingIn', { file: selectedFile.path })}
                    </p>
                    {readOnly && canWrite && <p className="text-xs text-text-secondary mt-1">{t(selectedFile.managed ? 'bind.managedHelp' : 'bind.userFileHelp')}</p>}
                  </div>
                  <StatementEditor
                    statement={selectedStatement}
                    entry={index.get(selectedStatement.name)}
                    readOnly={readOnly}
                    onSave={(patch) => setDraft((d) => replaceStatement(d, selected, patch))}
                    onRemove={() => {
                      setDraft((d) => removeStatement(d, selected))
                      setSelected(null)
                    }}
                  />
                </div>
              ) : (
                <EmptyState icon={Code} title={t('bind.selectTitle')} description={t('bind.selectBody', { count: grammar?.statements?.length || 0, version: grammar?.version || '' })} />
              )}
            </Card>
          </div>

          <Card className="p-4 space-y-3" hover={false} data-testid="bind-pending">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('pending.title')}</h3>
              <Badge variant={changes.length ? 'warning' : 'secondary'} size="sm">{t('pending.count', { count: changes.length })}</Badge>
              <div className="ml-auto flex gap-2">
                <Button variant="secondary" size="sm" disabled={!changes.length} onClick={() => setDraft(JSON.parse(JSON.stringify(original)))} data-testid="bind-discard">
                  <ArrowCounterClockwise size={14} />
                  {t('pending.discard')}
                </Button>
                <Button size="sm" disabled={!changes.length || !canWrite} loading={building} onClick={buildPlan} data-testid="bind-plan">
                  <Lightning size={14} weight="fill" />
                  {t('pending.validate')}
                </Button>
              </div>
            </div>
            {changes.length > 0 && (
              <ul className="text-xs space-y-0.5" data-testid="bind-changes">
                {changes.map((c) => (
                  <li key={c.target} className="flex gap-2">
                    <Badge variant={c.op === 'add' ? 'success' : c.op === 'delete' ? 'danger' : 'warning'} size="sm">{t(`common:plan.op.${c.op}`)}</Badge>
                    <span className="font-mono text-text-primary break-all">{c.target}</span>
                  </li>
                ))}
              </ul>
            )}
            <DiffView diff={localDiff} maxHeight={260} emptyLabel={t('pending.none')} />
            {planError && (
              <div className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text" role="alert" data-testid="bind-plan-error">
                <p className="font-medium">{errorMessage(planError)}</p>
                {planError.errors?.map((e, i) => (
                  <pre key={i} className="whitespace-pre-wrap font-mono text-2xs mt-1">{e.field ? `${e.field}: ` : ''}{e.message}</pre>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
      <PlanPreviewModal
        open={Boolean(plan)}
        plan={plan}
        onRecompute={recompute}
        onClose={() => setPlan(null)}
        onApplied={() => treeQ.refetch()}
        onRolledBack={() => treeQ.refetch()}
      />
    </PageLayout>
  )
}
