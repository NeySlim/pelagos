// SPDX-License-Identifier: Apache-2.0
// Where a node's (or every node's) web certificate comes from: self-signed, manual, ACME
// (Let's Encrypt, private step-ca or UCM ACME, free URL) or UCM through its API. Secrets are
// typed here, sent once and stored encrypted; the form only shows whether one is stored.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plugs, ListChecks } from '@phosphor-icons/react'
import { FormModal, Input, Textarea, Select, TagsInput, ToggleSwitch, Button, Badge } from '../../../components'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { useNotification } from '../../../contexts/NotificationContext'
import { ACME_PROFILES, KEY_TYPES, formErrors, formFromSource, sourceBody } from './certsForm'

const setPath = (obj, path, value) => {
  const [head, ...rest] = path.split('.')
  return { ...obj, [head]: rest.length ? setPath(obj[head] || {}, rest.join('.'), value) : value }
}

export default function SourceDialog({ open, onClose, node, cluster, overview, onSaved, onPlan }) {
  const { t } = useTranslation('certs')
  const { showError } = useNotification()
  const isCluster = Boolean(cluster)
  const initial = isCluster ? overview?.cluster : node?.inherited ? { source: 'inherit' } : node?.source
  const [form, setForm] = useState(() => {
    const f = formFromSource(initial || {}, { cluster: isCluster })
    if (!isCluster && node?.inherited) f.source = 'inherit'
    return f
  })
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)
  const [test, setTest] = useState(null)
  const [ucmLists, setUcmLists] = useState(null)
  const set = (path) => (value) => setForm((f) => setPath(f, path, value))
  const ev = (path) => (e) => set(path)(e.target.value)
  const err = (path) => (errors[path] ? t(`errors.${errors[path]}`) : undefined)
  const nodes = overview?.nodes || []
  const scope = isCluster ? 'cluster' : `node-${node?.node_id}`

  const sources = isCluster ? ['acme', 'ucm'] : [...(overview?.cluster ? ['inherit'] : []), 'self_signed', 'manual', 'acme', 'ucm']

  const save = async (apply) => {
    const local = formErrors(form)
    setErrors(local)
    if (Object.keys(local).length) return
    setBusy(true)
    try {
      const body = sourceBody(form, { cluster: isCluster, apply })
      const out = isCluster ? await api.certs.setCluster(body) : await api.certs.setSource(node.node_id, body)
      onSaved?.(out)
    } catch (e) {
      const fields = Object.fromEntries((e?.errors || []).map((x) => [x.field, x.message]))
      if (Object.keys(fields).length) setErrors(Object.fromEntries(Object.keys(fields).map((k) => [k, 'server'])))
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const testUcm = async () => {
    setTest({ running: true })
    const out = await api.certs.testUcm({ ucm: form.ucm, scope, secrets: form.secrets.ucm_api_key ? { ucm_api_key: form.secrets.ucm_api_key } : undefined }).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setTest(out)
    if (out.ok) setUcmLists({ cas: out.cas || [], templates: out.templates || [] })
  }
  const testAcme = async () => {
    setTest({ running: true })
    setTest(await api.certs.testAcme({ acme: form.acme }).catch((e) => ({ ok: false, error: errorMessage(e) })))
  }
  const testDns = async () => {
    setTest({ running: true })
    const body = { dns: form.acme.dns, scope, secrets: form.secrets.dns_api_token ? { dns_api_token: form.secrets.dns_api_token } : undefined }
    setTest(await api.certs.testDns(body).catch((e) => ({ ok: false, error: errorMessage(e) })))
  }

  const a = form.acme
  const u = form.ucm
  const privateAcme = a.profile === 'private' || a.profile === 'custom'
  const footer = (
    <div className="ui-modal-footer flex flex-wrap justify-end gap-2 p-4 border-t border-border">
      <Button variant="secondary" onClick={onClose}>{t('common:actions.cancel')}</Button>
      <Button variant="secondary" loading={busy} onClick={() => save(false)} data-testid="cert-source-save">{t('source.save')}</Button>
      {(form.source === 'acme' || form.source === 'ucm') && (
        <Button loading={busy} onClick={() => save(true)} data-testid="cert-source-apply">{isCluster ? t('source.applyAll') : t('source.applyNow')}</Button>
      )}
    </div>
  )
  const testResult = test && !test.running && (
    <p className={test.ok ? 'text-xs status-success-text' : 'text-xs status-danger-text'} role="status" data-testid="cert-test-result">
      {test.ok ? t('source.testOk', { detail: test.detail || test.directory_url || t('source.cas', { count: test.cas?.length ?? 0 }) }) : t('source.testFailed', { error: test.error })}
    </p>
  )

  return (
    <FormModal open={open} onClose={onClose} title={isCluster ? t('source.titleCluster') : t('source.title', { node: node?.name })} size="lg" footer={footer} testId="cert-source-dialog">
      <div className="space-y-4">
        <Select label={t('source.source')} value={form.source} onChange={set('source')} options={sources.map((s) => ({ value: s, label: t(`sources.${s}`) }))} />
        <p className="text-xs text-text-secondary">{t(`sourceHelp.${form.source}`)}</p>

        {isCluster && (
          <div className="space-y-2" data-testid="cert-cluster-nodes">
            <ToggleSwitch checked={form.node_ids === 'all'} onChange={(v) => set('node_ids')(v ? 'all' : nodes.map((n) => n.node_id))} label={t('source.allNodes')} description={t('source.allNodesHelp')} />
            {form.node_ids !== 'all' && (
              <div className="flex flex-wrap gap-2">
                {nodes.map((n) => (
                  <label key={n.node_id} className="inline-flex items-center gap-1.5 text-sm">
                    <input type="checkbox" checked={form.node_ids.includes(n.node_id)} onChange={(e) => set('node_ids')(e.target.checked ? [...form.node_ids, n.node_id] : form.node_ids.filter((x) => x !== n.node_id))} />
                    {n.name}
                  </label>
                ))}
              </div>
            )}
          </div>
        )}

        {form.source !== 'inherit' && form.source !== 'manual' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <TagsInput label={t('source.names')} helperText={t('source.namesHelp')} value={form.names} onChange={set('names')} />
            <Select label={t('source.keyType')} value={form.key_type} onChange={set('key_type')} options={KEY_TYPES.map((k) => ({ value: k, label: t(`keyTypes.${k}`) }))} />
            <ToggleSwitch checked={form.mode === 'cluster'} onChange={(v) => set('mode')(v ? 'cluster' : 'node')} label={t('source.clusterMode')} description={t('source.clusterModeHelp')} />
            {form.mode === 'cluster' && <Input label={t('source.clusterName')} value={form.cluster_name} onChange={ev('cluster_name')} error={err('cluster_name')} placeholder="dns.example.lan" />}
          </div>
        )}

        {form.source === 'acme' && (
          <div className="space-y-3 border-t border-border-op50 pt-3" data-testid="cert-acme-form">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Select label={t('acme.profile')} value={a.profile} onChange={set('acme.profile')} options={ACME_PROFILES.map((p) => ({ value: p, label: t(`acme.profiles.${p}`) }))} />
              <Input label={t('acme.email')} value={a.email} onChange={ev('acme.email')} error={err('acme.email')} placeholder="hostmaster@example.lan" />
              {privateAcme && <Input label={t('acme.directory')} value={a.directory_url} onChange={ev('acme.directory_url')} error={err('acme.directory_url')} placeholder="https://ca.example.lan/acme/acme/directory" data-testid="acme-directory" />}
              <Input label={t('acme.eabKid')} value={a.eab_kid} onChange={ev('acme.eab_kid')} helperText={t('acme.eabHelp')} />
              {a.eab_kid && <Input label={t('acme.eabKey')} type="password" hasExistingValue={form.stored.eab_hmac} value={form.secrets.eab_hmac} onChange={ev('secrets.eab_hmac')} error={err('secrets.eab_hmac')} />}
            </div>
            {privateAcme && <Textarea label={t('acme.trustRoot')} helperText={t('acme.trustRootHelp')} rows={4} value={a.trust_root} onChange={ev('acme.trust_root')} className="font-mono text-xs" />}
            <Select label={t('acme.challenge')} value={a.challenge} onChange={set('acme.challenge')} options={['dns-01', 'http-01'].map((c) => ({ value: c, label: t(`acme.challenges.${c}`) }))} />
            {a.challenge === 'http-01' ? (
              <div className="space-y-1">
                <Input label={t('acme.httpPort')} type="number" value={a.http_port} onChange={ev('acme.http_port')} error={err('acme.http_port')} />
                <p className="text-xs text-text-secondary">{t('acme.httpHelp')}</p>
              </div>
            ) : (
              <div className="space-y-3">
                <Select label={t('acme.dnsMethod')} value={a.dns.method} onChange={set('acme.dns.method')} options={['pelagos', 'provider'].map((m) => ({ value: m, label: t(`acme.dnsMethods.${m}`) }))} />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {a.dns.method === 'pelagos' ? (
                    <Input label={t('acme.dnsServer')} value={a.dns.server} onChange={ev('acme.dns.server')} helperText={t('acme.dnsServerHelp')} placeholder="ns1.example.lan:53" />
                  ) : (
                    <>
                      <Select label={t('acme.provider')} value={a.dns.provider} onChange={set('acme.dns.provider')} options={(overview?.providers || []).map((p) => ({ value: p.type, label: p.label }))} />
                      <Input label={t('acme.apiToken')} type="password" hasExistingValue={form.stored.dns_api_token} value={form.secrets.dns_api_token} onChange={ev('secrets.dns_api_token')} error={err('secrets.dns_api_token')} />
                    </>
                  )}
                  <Input label={t('acme.delegation')} value={a.dns.delegation_zone} onChange={ev('acme.dns.delegation_zone')} helperText={t('acme.delegationHelp')} placeholder="acme.example.lan" />
                </div>
                <div className="flex flex-wrap gap-2">
                  {a.dns.method === 'pelagos' && (
                    <Button variant="secondary" size="sm" onClick={() => onPlan?.(a.dns.delegation_zone)} data-testid="cert-dns01-plan">
                      <ListChecks size={14} />
                      {t('acme.setupPlan')}
                    </Button>
                  )}
                  {a.dns.method === 'provider' && (
                    <Button variant="secondary" size="sm" onClick={testDns} loading={test?.running}>
                      <Plugs size={14} />
                      {t('source.test')}
                    </Button>
                  )}
                </div>
              </div>
            )}
            <Button variant="secondary" size="sm" onClick={testAcme} loading={test?.running} data-testid="cert-acme-test">
              <Plugs size={14} />
              {t('acme.testDirectory')}
            </Button>
            {testResult}
          </div>
        )}

        {form.source === 'ucm' && (
          <div className="space-y-3 border-t border-border-op50 pt-3" data-testid="cert-ucm-form">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input label={t('ucm.url')} value={u.url} onChange={ev('ucm.url')} error={err('ucm.url')} placeholder="https://ucm.example.lan:8443" />
              <Input label={t('ucm.apiKey')} type="password" hasExistingValue={form.stored.ucm_api_key} value={form.secrets.ucm_api_key} onChange={ev('secrets.ucm_api_key')} error={err('secrets.ucm_api_key')} />
            </div>
            <Textarea label={t('ucm.trustRoot')} helperText={t('ucm.trustRootHelp')} rows={3} value={u.trust_root} onChange={ev('ucm.trust_root')} className="font-mono text-xs" />
            <Button variant="secondary" size="sm" onClick={testUcm} loading={test?.running} data-testid="cert-ucm-test">
              <Plugs size={14} />
              {t('ucm.testConnection')}
            </Button>
            {testResult}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {ucmLists ? (
                <Select label={t('ucm.ca')} value={String(u.ca_id)} onChange={(v) => set('ucm.ca_id')(Number.isNaN(Number(v)) ? v : Number(v))} error={err('ucm.ca_id')} options={ucmLists.cas.map((c) => ({ value: String(c.id), label: c.name }))} />
              ) : (
                <Input label={t('ucm.caId')} value={u.ca_id} onChange={(e) => set('ucm.ca_id')(/^\d+$/.test(e.target.value) ? Number(e.target.value) : e.target.value)} error={err('ucm.ca_id')} helperText={t('ucm.caIdHelp')} />
              )}
              {ucmLists ? (
                <Select label={t('ucm.template')} value={String(u.template_id)} onChange={(v) => set('ucm.template_id')(v === '' ? '' : Number(v))} options={[{ value: '', label: t('ucm.noTemplate') }, ...ucmLists.templates.map((x) => ({ value: String(x.id), label: x.name }))]} />
              ) : (
                <Input label={t('ucm.templateId')} value={u.template_id} onChange={(e) => set('ucm.template_id')(/^\d+$/.test(e.target.value) ? Number(e.target.value) : e.target.value)} />
              )}
              <Input label={t('ucm.validity')} type="number" value={u.validity_days} onChange={ev('ucm.validity_days')} error={err('ucm.validity_days')} />
            </div>
            <ToggleSwitch checked={u.revoke_old} onChange={set('ucm.revoke_old')} label={t('ucm.revokeOld')} description={t('ucm.revokeOldHelp', { days: overview?.settings?.ucm_renew_days ?? 30 })} />
          </div>
        )}
        {Object.keys(errors).length > 0 && <Badge variant="danger">{t('errors.fix')}</Badge>}
      </div>
    </FormModal>
  )
}
