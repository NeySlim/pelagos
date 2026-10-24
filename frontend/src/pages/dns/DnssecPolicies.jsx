// SPDX-License-Identifier: Apache-2.0
// dnssec-policy statements: the managed ones (policies.conf) are created, edited and
// deleted through POST /dns/dnssec/policies/plan; the statements are checked against
// the dnssec-policy grammar of GET /advanced/bind/grammar before the plan is built.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, PencilSimple, Trash, ShieldCheck } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { Textarea } from '../../components/Textarea'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { SourceBadge } from './common'
import { usePlanFlow } from './helpers'
import { policyErrors, policyGrammarNames, policyStatements, policyText } from './zoneTools'

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/

function PolicyModal({ policy, builtin, allowed, onClose, onPlan }) {
  const { t } = useTranslation(['dns', 'common'])
  const [name, setName] = useState(policy?.name || '')
  const [text, setText] = useState(policy ? policyText(policy.statements) : 'keys { csk lifetime unlimited algorithm ecdsap256sha256; };')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const statements = policyStatements(text)
  const errors = policyErrors(statements, allowed)
  const nameOk = NAME_RE.test(name) && !builtin.includes(name)
  const submit = async () => {
    setTouched(true)
    if (!nameOk || errors.length || !statements.length) return
    setBusy(true)
    try {
      await onPlan({ op: policy ? 'replace' : 'add', target: `dnssec-policy/${name}`, before: policy || null, after: { name, statements } })
    } finally {
      setBusy(false)
    }
  }
  const errorText = errors.map((e) => t(e.error === 'unknown' ? 'dnssec.unknownStatement' : 'dnssec.emptyStatement', { name: e.name })).join(', ')
  return (
    <FormModal open onClose={onClose} title={policy ? t('dnssec.editPolicy', { name }) : t('dnssec.newPolicy')} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} size="lg" testId="dnssec-policy-modal">
      <Input data-testid="dnssec-policy-name" label={t('dnssec.policyName')} value={name} onChange={(e) => setName(e.target.value)} disabled={Boolean(policy)} error={touched && !nameOk ? t('dnssec.policyNameError') : undefined} autoFocus={!policy} />
      <Textarea label={t('dnssec.statements')} value={text} onChange={(e) => setText(e.target.value)} rows={6} className="font-mono" helperText={t('dnssec.statementsHelp')} error={touched && errorText ? errorText : undefined} data-testid="dnssec-policy-text" />
      {allowed.length > 0 && <p className="text-2xs text-text-tertiary break-words">{t('dnssec.allowed', { names: allowed.join(', ') })}</p>}
    </FormModal>
  )
}

export function DnssecPolicies({ onChanged }) {
  const { t } = useTranslation(['dns', 'common'])
  const { hasPermission } = usePermission()
  const { showError } = useNotification()
  const policies = useApi(() => api.dns.dnssecPolicies(), [])
  const grammar = useApi(() => api.advanced.bindGrammar().catch(() => null), [])
  const allowed = useMemo(() => policyGrammarNames(grammar.data), [grammar.data])
  const [editing, setEditing] = useState(null) // null, 'new' or a policy
  const flow = usePlanFlow({
    onDone: () => {
      policies.refetch()
      onChanged?.()
    },
    onError: showError,
  })
  const canWrite = hasPermission('write:dns.config')
  const items = policies.data?.items || []
  const builtin = policies.data?.builtin || ['default', 'insecure', 'none']

  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="dnssec-policies">
      <div className="flex items-center gap-2">
        <ShieldCheck size={16} className="text-accent-primary" />
        <h3 className="text-sm font-semibold text-text-primary">{t('dnssec.policies')}</h3>
        <span className="text-2xs text-text-tertiary">
          {t('common:fieldLabel', { label: t('dnssec.builtin') })} {builtin.join(', ')}
        </span>
        {canWrite && (
          <Button size="xs" className="ml-auto" onClick={() => setEditing('new')} data-testid="dnssec-policy-add">
            <Plus size={12} />
            {t('dnssec.newPolicy')}
          </Button>
        )}
      </div>
      {items.length ? (
        <ul className="divide-y divide-border-op50">
          {items.map((p) => (
            <li key={p.name} className="py-2 space-y-1" data-testid="dnssec-policy">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm text-text-primary">{p.name}</span>
                <SourceBadge source={p.source} />
                {(p.used_by || []).map((z) => (
                  <Badge key={z} variant="outline" size="sm" className="font-mono">{z.replace(/^_default\//, '')}</Badge>
                ))}
                {canWrite && p.source === 'pelagos' && (
                  <span className="ml-auto inline-flex gap-1">
                    <Button variant="ghost" size="xs" onClick={() => setEditing(p)} aria-label={t('common:actions.edit')} data-testid="dnssec-policy-edit">
                      <PencilSimple size={13} />
                    </Button>
                    <Button
                      variant="ghost"
                      size="xs"
                      disabled={(p.used_by || []).length > 0}
                      title={(p.used_by || []).length ? `${t('common:fieldLabel', { label: t('dnssec.usedBy') })} ${p.used_by.join(', ')}` : t('dnssec.deletePolicy')}
                      onClick={() => flow.run(() => api.dns.dnssecPoliciesPlan({ op: 'delete', target: `dnssec-policy/${p.name}`, before: p, after: null }))}
                      aria-label={t('dnssec.deletePolicy')}
                    >
                      <Trash size={13} className="status-danger-text" />
                    </Button>
                  </span>
                )}
              </div>
              <pre className="font-mono text-2xs text-text-secondary whitespace-pre-wrap break-all">{policyText(p.statements)}</pre>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-text-tertiary">{t('dnssec.noPolicies')}</p>
      )}
      <p className="text-2xs text-text-tertiary">{t('dnssec.attachHelp')}</p>
      {editing && (
        <PolicyModal
          policy={editing === 'new' ? null : editing}
          builtin={builtin}
          allowed={allowed}
          onClose={() => setEditing(null)}
          onPlan={async (change) => {
            const plan = await flow.run(() => api.dns.dnssecPoliciesPlan(change))
            if (plan) setEditing(null)
          }}
        />
      )}
      {flow.modal}
    </Card>
  )
}
