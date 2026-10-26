// SPDX-License-Identifier: Apache-2.0
// Manual certificate for one node. (a) The node made the key and request: paste or pick the
// signed certificate and its chain. (b) Everything given here: PEM certificate, chain and key,
// or a PKCS#12 file and its password. Checks run first; install is offered once they pass.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, UploadSimple, Copy, DownloadSimple, Trash, Key } from '@phosphor-icons/react'
import { Modal, Button, Textarea, Input, Select, TagsInput, Badge } from '../../../components'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { useNotification } from '../../../contexts/NotificationContext'
import { KEY_TYPES, checkParams, checkRows, checkText, fileBase64 } from './certsForm'

const LEVEL = { ok: 'success', warning: 'warning', error: 'danger' }

export function CheckList({ report }) {
  const { t } = useTranslation('certs')
  if (!report) return null
  return (
    <ul className="space-y-1" data-testid="cert-checks">
      {checkRows(report).map((c) => (
        <li key={c.id} className="flex items-start gap-2 text-sm" data-check={c.id} data-level={c.level}>
          <Badge variant={LEVEL[c.level]} size="sm">{t(`checkLevels.${c.level}`)}</Badge>
          <span>{t(`checks.${c.id}`, { defaultValue: c.id })}: {c.code ? t(`checkText.${c.code}`, { ...checkParams(c), defaultValue: checkText(c) }) : checkText(c)}</span>
        </li>
      ))}
    </ul>
  )
}

async function readText(file) {
  return file ? await file.text() : ''
}

export function RequestPanel({ node, onChange }) {
  const { t } = useTranslation('certs')
  const { showError, showSuccess } = useNotification()
  const [keyType, setKeyType] = useState('ec-p256')
  const [names, setNames] = useState([])
  const [busy, setBusy] = useState(false)
  const pending = node.pending_request
  const make = async () => {
    setBusy(true)
    try {
      await api.certs.request(node.node_id, { key_type: keyType, names })
      onChange?.()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const drop = async () => {
    try {
      await api.certs.dropRequest(node.node_id)
      onChange?.()
    } catch (e) {
      showError(errorMessage(e))
    }
  }
  const copy = async () => {
    await navigator.clipboard?.writeText(pending.csr_pem)
    showSuccess(t('request.copied'))
  }
  const download = () => {
    const url = URL.createObjectURL(new Blob([pending.csr_pem], { type: 'application/pkcs10' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${node.name}.csr`
    a.click()
    URL.revokeObjectURL(url)
  }
  if (pending) {
    return (
      <div className="space-y-2" data-testid="cert-pending-request">
        <p className="text-xs text-text-secondary">{t('request.pending', { names: pending.names.join(', '), when: new Date(pending.created_at).toLocaleString() })}</p>
        <Textarea readOnly rows={6} value={pending.csr_pem} className="font-mono text-2xs" aria-label={t('request.csr')} />
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" onClick={copy}><Copy size={14} />{t('request.copy')}</Button>
          <Button size="sm" variant="secondary" onClick={download}><DownloadSimple size={14} />{t('request.download')}</Button>
          <Button size="sm" variant="ghost" onClick={drop}><Trash size={14} />{t('request.drop')}</Button>
        </div>
      </div>
    )
  }
  return (
    <div className="space-y-2" data-testid="cert-new-request">
      <p className="text-xs text-text-secondary">{t('request.help')}</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Select label={t('source.keyType')} value={keyType} onChange={setKeyType} options={KEY_TYPES.map((k) => ({ value: k, label: t(`keyTypes.${k}`) }))} />
        <TagsInput label={t('source.names')} helperText={t('request.namesHelp', { names: node.required_names?.join(', ') || node.name })} value={names} onChange={setNames} />
      </div>
      <Button size="sm" onClick={make} loading={busy} data-testid="cert-make-request"><Key size={14} />{t('request.make')}</Button>
    </div>
  )
}

export default function UploadDialog({ open, onClose, node, nodes, onDone }) {
  const { t } = useTranslation('certs')
  const { showError, showSuccess } = useNotification()
  const [mode, setMode] = useState(node?.pending_request ? 'request' : 'pem')
  const [certPem, setCertPem] = useState('')
  const [chainPem, setChainPem] = useState('')
  const [keyPem, setKeyPem] = useState('')
  const [p12, setP12] = useState(null)
  const [password, setPassword] = useState('')
  const [also, setAlso] = useState([])
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)

  const body = async () => {
    const out = {}
    if (mode === 'p12') {
      if (p12) out.pkcs12_base64 = await fileBase64(p12)
      if (password) out.password = password
    } else {
      out.cert_pem = certPem
      if (chainPem) out.chain_pem = chainPem
      if (mode === 'pem' && keyPem) out.key_pem = keyPem
      if (mode === 'request') out.use_pending_key = true
    }
    if (mode !== 'request' && also.length) out.also_node_ids = also
    return out
  }
  const reset = () => setReport(null)
  const check = async () => {
    setBusy(true)
    try {
      setReport(await api.certs.check(node.node_id, await body()))
    } catch (e) {
      setReport(e?.problem?.checks || null)
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const install = async () => {
    setBusy(true)
    try {
      const out = await api.certs.upload(node.node_id, await body())
      showSuccess(t('upload.installed', { node: node.name }))
      onDone?.(out)
    } catch (e) {
      if (e?.problem?.checks) setReport(e.problem.checks)
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const pick = (setter) => async (e) => {
    setter(await readText(e.target.files?.[0]))
    reset()
  }
  const others = (nodes || []).filter((n) => n.node_id !== node?.node_id)

  return (
    <Modal open={open} onClose={onClose} title={t('upload.title', { node: node?.name })} size="lg">
      <div className="p-4 space-y-4" data-testid="cert-upload-dialog">
        <Select
          label={t('upload.mode')}
          value={mode}
          onChange={(v) => { setMode(v); reset() }}
          options={[
            { value: 'request', label: t('upload.modes.request') },
            { value: 'pem', label: t('upload.modes.pem') },
            { value: 'p12', label: t('upload.modes.p12') },
          ]}
        />
        {mode === 'request' && <RequestPanel node={node} onChange={onDone ? () => onDone(null, true) : undefined} />}
        {mode === 'p12' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs space-y-1">
              <span className="block font-medium text-text-secondary">{t('upload.p12File')}</span>
              <input type="file" accept=".p12,.pfx" onChange={(e) => { setP12(e.target.files?.[0] || null); reset() }} data-testid="cert-p12-file" />
            </label>
            <Input label={t('upload.password')} type="password" value={password} onChange={(e) => { setPassword(e.target.value); reset() }} />
          </div>
        ) : (
          (mode === 'pem' || node?.pending_request) && (
            <div className="space-y-3">
              <Textarea label={t('upload.cert')} rows={5} value={certPem} onChange={(e) => { setCertPem(e.target.value); reset() }} className="font-mono text-2xs" placeholder="-----BEGIN CERTIFICATE-----" data-testid="cert-pem" />
              <input type="file" accept=".pem,.crt,.cer" aria-label={t('upload.certFile')} onChange={pick(setCertPem)} />
              <Textarea label={t('upload.chain')} helperText={t('upload.chainHelp')} rows={4} value={chainPem} onChange={(e) => { setChainPem(e.target.value); reset() }} className="font-mono text-2xs" />
              {mode === 'pem' && (
                <>
                  <Textarea label={t('upload.key')} helperText={t('upload.keyHelp')} rows={4} value={keyPem} onChange={(e) => { setKeyPem(e.target.value); reset() }} className="font-mono text-2xs" placeholder="-----BEGIN PRIVATE KEY-----" data-testid="cert-key" />
                  <input type="file" accept=".key,.pem" aria-label={t('upload.keyFile')} onChange={pick(setKeyPem)} />
                </>
              )}
            </div>
          )
        )}
        {mode !== 'request' && others.length > 0 && (
          <fieldset className="space-y-1" data-testid="cert-also">
            <legend className="text-xs font-medium text-text-secondary">{t('upload.also')}</legend>
            <p className="text-2xs text-text-tertiary">{t('upload.alsoHelp')}</p>
            <div className="flex flex-wrap gap-3">
              {others.map((n) => (
                <label key={n.node_id} className="inline-flex items-center gap-1.5 text-sm">
                  <input type="checkbox" checked={also.includes(n.node_id)} onChange={(e) => setAlso((a) => (e.target.checked ? [...a, n.node_id] : a.filter((x) => x !== n.node_id)))} />
                  {n.name}
                </label>
              ))}
            </div>
          </fieldset>
        )}
        <CheckList report={report} />
      </div>
      <div className="ui-modal-footer flex flex-wrap justify-end gap-2 p-4 border-t border-border">
        <Button variant="secondary" onClick={onClose}>{t('common:actions.close')}</Button>
        {(mode !== 'request' || node?.pending_request) && (
          <>
            <Button variant="secondary" loading={busy} onClick={check} data-testid="cert-check"><ShieldCheck size={14} />{t('upload.check')}</Button>
            <Button loading={busy} disabled={!report?.ok} onClick={install} data-testid="cert-install"><UploadSimple size={14} />{t('upload.install')}</Button>
          </>
        )}
      </div>
    </Modal>
  )
}
