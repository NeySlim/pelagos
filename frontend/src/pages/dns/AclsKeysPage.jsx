// SPDX-License-Identifier: Apache-2.0
// ACLs (address match lists) and TSIG keys. Secrets are never listed: the
// reveal button calls GET /dns/keys/{name}/secret, which the server audits.
// Every change goes through a plan (dns.acl or dns.key scope).
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Key, ListChecks, ArrowsClockwise, Plus, PencilSimple, Trash, Eye, EyeSlash, Copy, Check, Warning, ArrowsCounterClockwise } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { Select } from '../../components/ui/Select'
import TagsInput from '../../components/ui/TagsInput'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useClipboard } from '../../hooks/useClipboard'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { ListValue, SourceBadge } from './common'
import { usePlanFlow } from './helpers'

const KEY_ALGORITHMS =['hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'hmac-sha224', 'hmac-sha1']
const WEAK_ALGORITHMS = ['hmac-md5', 'hmac-sha1']
const NAME_RE = /^[a-z0-9]([a-z0-9._-]{0,62})$/i
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/

function AclEditor({ open, onClose, acl, onPlan }) {
  const { t } = useTranslation(['dns', 'common'])
  const [name, setName] = useState(acl?.name || '')
  const [elements, setElements] = useState(acl?.elements || [])
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const nameOk = NAME_RE.test(name) && !['any', 'none', 'localhost', 'localnets'].includes(name.toLowerCase())
  const submit = async () => {
    setTouched(true)
    if (!nameOk || elements.length === 0) return
    setBusy(true)
    try {
      await onPlan({ op: acl ? 'replace' : 'add', target: `acls/${name}`, before: acl || null, after: { name, elements }, node_ids: [] })
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open={open} onClose={onClose} title={t(acl ? 'acls.editTitle' : 'acls.addTitle')} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} testId="acl-editor">
      <Input label={t('acls.name')} value={name} onChange={(e) => setName(e.target.value)} disabled={Boolean(acl)} error={touched && !nameOk ? t('acls.nameError') : undefined} autoFocus={!acl} />
      <TagsInput label={t('acls.elements')} value={elements} onChange={setElements} placeholder="192.0.2.0/24" helperText={touched && elements.length === 0 ? t('acls.elementsError') : t('resolver.aclHelp')} />
    </FormModal>
  )
}

function KeyEditor({ open, onClose, onPlan }) {
  const { t } = useTranslation(['dns', 'common'])
  const [name, setName] = useState('')
  const [algorithm, setAlgorithm] = useState('hmac-sha256')
  const [secret, setSecret] = useState('')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const nameOk = NAME_RE.test(name)
  const secretOk = !secret || BASE64_RE.test(secret.trim())
  const submit = async () => {
    setTouched(true)
    if (!nameOk || !secretOk) return
    setBusy(true)
    try {
      const after = { name, algorithm, ...(secret.trim() ? { secret: secret.trim() } : {}) }
      await onPlan({ op: 'add', target: `keys/${name}`, before: null, after, node_ids: [] })
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open={open} onClose={onClose} title={t('keys.addTitle')} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} testId="key-editor">
      <Input label={t('keys.name')} value={name} onChange={(e) => setName(e.target.value)} placeholder="ddi-admin" error={touched && !nameOk ? t('keys.nameError') : undefined} autoFocus />
      <Select label={t('keys.algorithm')} value={algorithm} onChange={setAlgorithm} options={KEY_ALGORITHMS.map((a) => ({ value: a, label: a }))} />
      <Input
        label={t('keys.secret')}
        type="password"
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
        helperText={t('keys.secretHelp')}
        error={touched && !secretOk ? t('keys.secretError') : undefined}
        noAutofill
      />
    </FormModal>
  )
}

function SecretCell({ name, canReveal }) {
  const { t } = useTranslation(['dns', 'common'])
  const { showError } = useNotification()
  const { copy, isCopied } = useClipboard()
  const [secret, setSecret] = useState(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => setSecret(null), [name])
  if (!canReveal) return <span className="font-mono text-xs text-text-tertiary">********</span>
  const toggle = async (e) => {
    e.stopPropagation()
    if (secret) {
      setSecret(null)
      return
    }
    setBusy(true)
    try {
      const res = await api.dns.keySecret(name)
      setSecret(res.secret)
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <span className="inline-flex items-center gap-1 max-w-full">
      <span className="font-mono text-xs truncate" data-testid="key-secret">
        {secret || '********'}
      </span>
      <Button variant="ghost" size="xs" onClick={toggle} loading={busy} aria-label={t(secret ? 'keys.hide' : 'keys.reveal')} title={t(secret ? 'keys.hide' : 'keys.reveal')} data-testid="key-reveal">
        {secret ? <EyeSlash size={13} /> : <Eye size={13} />}
      </Button>
      {secret && (
        <Button variant="ghost" size="xs" onClick={() => copy(secret, name)} aria-label={t('common:actions.copy')}>
          {isCopied(name) ? <Check size={13} className="status-success-text" /> : <Copy size={13} />}
        </Button>
      )}
    </span>
  )
}

export default function AclsKeysPage() {
  const { t } = useTranslation(['dns', 'common'])
  const { hasPermission } = usePermission()
  const { showError } = useNotification()
  const [tab, setTab] = useState('acls')
  const [aclEditor, setAclEditor] = useState(null)
  const [keyEditor, setKeyEditor] = useState(false)
  const acls = useApi(() => api.dns.acls(), [])
  const keys = useApi(() => api.dns.keys(), [])
  const refetch = () => {
    acls.refetch()
    keys.refetch()
  }
  const flow = usePlanFlow({ onDone: refetch, onError: showError })
  const canWrite = hasPermission('write:dns.config')
  const canReveal = hasPermission('read:dns.secrets')

  const planAcl = async (change) => {
    const plan = await flow.run(() => api.dns.aclsPlan(change))
    if (plan) setAclEditor(null)
  }
  const planKey = async (change) => {
    const plan = await flow.run(() => api.dns.keysPlan(change))
    if (plan) setKeyEditor(false)
  }

  const aclColumns = [
    { key: 'name', label: t('acls.name'), sortable: true, render: (a) => <span className="font-mono text-xs whitespace-nowrap">{a.name}</span> },
    { key: 'elements', label: t('acls.elements'), render: (a) => <ListValue items={a.elements} /> },
    { key: 'source', label: t('zones.source'), render: (a) => <SourceBadge source={a.source} /> },
    { key: 'config_path', label: t('detail.configPath'), mono: true, truncate: true },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (a) =>
        canWrite ? (
          <span className="inline-flex gap-1">
            <Button variant="ghost" size="xs" onClick={() => setAclEditor({ acl: a })} aria-label={t('common:actions.edit')} data-testid="acl-edit">
              <PencilSimple size={13} />
            </Button>
            <Button
              variant="ghost"
              size="xs"
              onClick={() => flow.run(() => api.dns.aclsPlan({ op: 'delete', target: `acls/${a.name}`, before: a, after: null, node_ids: [] }))}
              aria-label={t('common:actions.delete')}
              data-testid="acl-delete"
            >
              <Trash size={13} className="status-danger-text" />
            </Button>
          </span>
        ) : null,
    },
  ]

  const keyColumns = [
    { key: 'name', label: t('keys.name'), sortable: true, render: (k) => <span className="font-mono text-xs whitespace-nowrap">{k.name}</span> },
    {
      key: 'algorithm',
      label: t('keys.algorithm'),
      sortable: true,
      render: (k) =>
        WEAK_ALGORITHMS.includes(String(k.algorithm).toLowerCase()) ? (
          <Badge variant="warning" size="sm" icon={Warning} title={t('keys.weak')}>
            {k.algorithm}
          </Badge>
        ) : (
          <span className="font-mono text-xs">{k.algorithm}</span>
        ),
    },
    { key: 'secret', label: t('keys.secret'), render: (k) => <SecretCell name={k.name} canReveal={canReveal} /> },
    { key: 'used_by', label: t('keys.usedBy'), render: (k) => <ListValue items={k.used_by} empty={t('keys.unused')} /> },
    { key: 'source', label: t('zones.source'), render: (k) => <SourceBadge source={k.source} /> },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (k) =>
        canWrite ? (
          <span className="inline-flex gap-1">
            <Button
              variant="ghost"
              size="xs"
              onClick={() => flow.run(() => api.dns.keysPlan({ op: 'replace', target: `keys/${k.name}`, before: { name: k.name, algorithm: k.algorithm }, after: { name: k.name, algorithm: WEAK_ALGORITHMS.includes(k.algorithm) ? 'hmac-sha256' : k.algorithm }, node_ids: [] }))}
              aria-label={t('keys.rotate')}
              title={t('keys.rotate')}
              data-testid="key-rotate"
            >
              <ArrowsCounterClockwise size={13} />
            </Button>
            <Button
              variant="ghost"
              size="xs"
              onClick={() => flow.run(() => api.dns.keysPlan({ op: 'delete', target: `keys/${k.name}`, before: { name: k.name, algorithm: k.algorithm }, after: null, node_ids: [] }))}
              aria-label={t('common:actions.delete')}
              data-testid="key-delete"
            >
              <Trash size={13} className="status-danger-text" />
            </Button>
          </span>
        ) : null,
    },
  ]

  return (
    <PageLayout
      icon={Key}
      title={t('pages.aclsKeys.title')}
      subtitle={t('pages.aclsKeys.subtitle')}
      testId="page-dns-aclsKeys"
      tabs={[
        { id: 'acls', label: t('acls.tab'), icon: ListChecks, count: acls.data?.items?.length },
        { id: 'keys', label: t('keys.tab'), icon: Key, count: keys.data?.items?.length },
      ]}
      activeTab={tab}
      onTabChange={setTab}
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={refetch}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          {canWrite && tab === 'acls' && (
            <Button size="sm" onClick={() => setAclEditor({ acl: null })} data-testid="acl-add">
              <Plus size={14} />
              {t('acls.add')}
            </Button>
          )}
          {canWrite && tab === 'keys' && (
            <Button size="sm" onClick={() => setKeyEditor(true)} data-testid="key-add">
              <Plus size={14} />
              {t('keys.add')}
            </Button>
          )}
        </>
      }
    >
      {tab === 'acls' ? (
        <DataTable columns={aclColumns} rows={acls.data?.items || []} rowKey="name" loading={acls.loading && !acls.data} error={acls.error} onRetry={acls.refetch} clientSort emptyTitle={t('acls.empty')} testId="acls-table" />
      ) : (
        <DataTable columns={keyColumns} rows={keys.data?.items || []} rowKey="name" loading={keys.loading && !keys.data} error={keys.error} onRetry={keys.refetch} clientSort emptyTitle={t('keys.empty')} testId="keys-table" />
      )}
      {aclEditor && <AclEditor open acl={aclEditor.acl} onClose={() => setAclEditor(null)} onPlan={planAcl} />}
      {keyEditor && <KeyEditor open onClose={() => setKeyEditor(false)} onPlan={planKey} />}
      {flow.modal}
    </PageLayout>
  )
}
