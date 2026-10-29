// SPDX-License-Identifier: Apache-2.0
// One OPNsense source: URL, API key and secret (write-only), TLS checks, private CA, router MACs
// to drop. "Test" polls the router from this node before saving and shows the first rows.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PlugsConnected } from '@phosphor-icons/react'
import { FormModal, Input, Textarea, ToggleSwitch, Button, Badge } from '../../../components'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { formErrors, formFromSource, serverFieldErrors, sourcesBody, testBody, urlChanged } from './ipv6Form'

const LOCAL_CODES = ['required', 'url', 'http', 'mac', 'pem', 'secret']

export default function SourceDialog({ source, sources, onClose, onSaved }) {
  const { t } = useTranslation(['ipv6', 'common'])
  const editing = Boolean(source?.id)
  const [form, setForm] = useState(() => formFromSource(source || {}))
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState(null)
  const [test, setTest] = useState(null)
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }))
  const ev = (key) => (e) => set(key)(e.target.value)
  const setSecret = (name) => (e) => setForm((f) => ({ ...f, secrets: { ...f.secrets, [name]: e.target.value } }))
  // Local checks give a code; the server gives its message, shown as is.
  const err = (key) => {
    const code = errors[key]
    if (!code) return undefined
    return LOCAL_CODES.includes(code) ? t(`sources.errors.${code}`) : code
  }

  const check = () => {
    const local = formErrors(form)
    setErrors(local)
    return Object.keys(local).length === 0
  }

  const save = async () => {
    if (!check()) return
    setBusy(true)
    setFailure(null)
    try {
      const body = sourcesBody(sources, form)
      const out = await api.ipv6.update(body)
      onSaved?.(out)
    } catch (e) {
      const index = form.id ? sources.findIndex((s) => s.id === form.id) : sources.length
      const fields = serverFieldErrors(e?.errors, index)
      if (Object.keys(fields).length) setErrors(fields)
      setFailure(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const runTest = async () => {
    if (!check()) return
    setTest({ running: true })
    const out = await api.ipv6.testSource(testBody(form)).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setTest(out)
  }

  const secretHelp = urlChanged(form) ? t('sources.secretUrlChanged') : undefined
  const footer = (
    <div className="ui-modal-footer flex flex-wrap items-center justify-end gap-2 p-4 border-t border-border">
      <Button variant="secondary" onClick={runTest} loading={test?.running} data-testid="ipv6-source-test">
        <PlugsConnected size={14} />
        {t('sources.test')}
      </Button>
      <span className="flex-1" />
      <Button variant="secondary" onClick={onClose}>{t('common:actions.cancel')}</Button>
      <Button loading={busy} onClick={save} data-testid="ipv6-source-save">{t('common:actions.save')}</Button>
    </div>
  )

  return (
    <FormModal open onClose={onClose} title={editing ? t('sources.editTitle', { name: source.name }) : t('sources.newTitle')} size="lg" footer={footer} testId="ipv6-source-dialog">
      <div className="space-y-4">
        <p className="text-xs text-text-secondary">{t('sources.opnsenseHelp')}</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Input label={t('sources.name')} value={form.name} onChange={ev('name')} error={err('name')} placeholder="OPNsense" data-testid="ipv6-source-name" />
          <Input label={t('sources.url')} value={form.url} onChange={ev('url')} error={err('url')} placeholder="https://router.example.lan" data-testid="ipv6-source-url" />
          <Input
            label={t('sources.apiKey')}
            type="password"
            noAutofill
            hasExistingValue={form.stored.api_key && !urlChanged(form)}
            value={form.secrets.api_key}
            onChange={setSecret('api_key')}
            error={err('secrets.api_key')}
            helperText={secretHelp}
            data-testid="ipv6-source-key"
          />
          <Input
            label={t('sources.apiSecret')}
            type="password"
            noAutofill
            hasExistingValue={form.stored.api_secret && !urlChanged(form)}
            value={form.secrets.api_secret}
            onChange={setSecret('api_secret')}
            error={err('secrets.api_secret')}
            helperText={secretHelp}
            data-testid="ipv6-source-secret"
          />
        </div>
        <p className="text-2xs text-text-tertiary">{t('sources.privilegeHelp')}</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <ToggleSwitch checked={form.enabled} onChange={set('enabled')} label={t('sources.enabled')} />
          <ToggleSwitch checked={form.verify_tls} onChange={set('verify_tls')} label={t('sources.verifyTls')} />
          <ToggleSwitch checked={form.allow_http} onChange={set('allow_http')} label={t('sources.allowHttp')} description={t('sources.allowHttpHelp')} />
        </div>
        {!form.verify_tls && <p className="text-xs status-warning-text" data-testid="ipv6-source-notls">{t('sources.noTlsWarning')}</p>}
        <Textarea label={t('sources.excludeMacs')} rows={2} value={form.exclude_macs} onChange={ev('exclude_macs')} helperText={err('exclude_macs') || t('sources.excludeMacsHelp')} className="font-mono text-xs" placeholder="02:00:5e:00:53:01" data-testid="ipv6-source-exclude" />
        <details className="text-xs" open={Boolean(form.ca_pem)}>
          <summary className="cursor-pointer text-text-secondary">{t('sources.caPem')}</summary>
          <Textarea helperText={err('ca_pem') || t('sources.caPemHelp')} rows={4} value={form.ca_pem} onChange={ev('ca_pem')} className="font-mono text-xs mt-2" data-testid="ipv6-source-ca" />
        </details>

        {test && !test.running && (
          <div className="space-y-2" role="status" data-testid="ipv6-source-test-result" data-ok={String(Boolean(test.ok))}>
            <p className={test.ok ? 'text-xs status-success-text' : 'text-xs status-danger-text'}>
              {test.ok ? t('sources.testOk', { entries: test.entries ?? 0, node: test.node_id || '-' }) : t('sources.testFailed', { error: test.error || '-' })}
            </p>
            {test.ok && test.sample?.length > 0 && (
              <ul className="text-2xs font-mono text-text-secondary space-y-0.5" data-testid="ipv6-source-sample">
                {test.sample.map((o) => (
                  <li key={`${o.mac}|${o.address}`} className="break-all">{o.mac} {o.address} {o.state}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        {failure && <p className="text-xs status-danger-text" role="alert" data-testid="ipv6-source-error">{failure}</p>}
        {Object.keys(errors).length > 0 && <Badge variant="danger">{t('sources.errors.fix')}</Badge>}
      </div>
    </FormModal>
  )
}
