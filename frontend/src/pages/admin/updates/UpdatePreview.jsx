// SPDX-License-Identifier: Apache-2.0
// Preview of an update (design 13.6): the extra confirmation of an unsigned release (box ticked and
// version typed) before any plan, then the node order (reorderable), the checks, the estimated
// time and the automatic rollback, and the plan itself applied with the user's password.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowDown, ArrowUp, ShieldCheck, ShieldWarning, Warning } from '@phosphor-icons/react'
import { Badge, Button, Input, Modal, PlanPreview, ToggleSwitch } from '../../../components'
import { useMessage } from '../../../i18n/message'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { minutesOf, moveItem, needsUnsignedConfirmation, sameOrder } from './updatesLib'

export function SignatureBadge({ signature, keyId }) {
  const { t } = useTranslation('updates')
  const ok = signature === 'valid'
  return (
    <Badge variant={ok ? 'success' : signature === 'invalid' ? 'danger' : 'warning'} size="sm" icon={ok ? ShieldCheck : ShieldWarning} data-testid="updates-signature" data-signature={signature}>
      {t(`signature.${signature}`, { defaultValue: signature })}
      {keyId ? <span className="font-mono ml-1">{keyId}</span> : null}
    </Badge>
  )
}

// request: {kind, version?, packages?, node_ids?}; release: the available entry for kind pelagos.
export function UpdatePreview({ request, release, autoRollbackDefault = true, nodeName, onClose, onApplied }) {
  const { t } = useTranslation(['updates', 'common'])
  const msg = useMessage()
  const unsigned = request.kind === 'pelagos' && needsUnsignedConfirmation(release)
  const [accepted, setAccepted] = useState(false)
  const [typed, setTyped] = useState('')
  const [plan, setPlan] = useState(null)
  const [order, setOrder] = useState(null)
  const [autoRollback, setAutoRollback] = useState(autoRollbackDefault)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [password, setPassword] = useState('')
  const passwordRef = useRef('')
  passwordRef.current = password
  const unsignedOk = !unsigned || (accepted && typed.trim() === request.version)

  const compute = useCallback(async (overrides = {}) => {
    setBusy(true)
    setError(null)
    try {
      const body = { ...request, auto_rollback: overrides.autoRollback ?? autoRollback }
      if (overrides.order) body.order = overrides.order
      if (unsigned) Object.assign(body, { accept_unsigned: true, confirm_version: typed.trim() })
      const fresh = await api.updates.plan(body)
      setPlan(fresh)
      setOrder(fresh.update?.order || fresh.target_node_ids || [])
      setAutoRollback(fresh.update?.auto_rollback ?? autoRollback)
      return fresh
    } catch (e) {
      setError(errorMessage(e))
      return null
    } finally {
      setBusy(false)
    }
  }, [request, autoRollback, unsigned, typed])

  // A signed release (or engine packages, or a rollback) gets its plan at once.
  const started = useRef(false)
  useEffect(() => {
    if (started.current || unsigned) return
    started.current = true
    compute()
  }, [unsigned, compute])

  const info = plan?.update || {}
  const stale = plan && (!sameOrder(order, info.order) || autoRollback !== info.auto_rollback)
  const applyFn = useCallback((id, confirm) => {
    if (!passwordRef.current) return Promise.reject(new Error(t('preview.passwordRequired')))
    return api.plans.apply(id, confirm, { password: passwordRef.current })
  }, [t])

  const title = request.kind === 'engine_packages' ? t('preview.titleEngines') : t(`preview.title.${request.kind}`, { version: request.version })

  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title={title} size="lg">
      <div className="p-4 space-y-4" data-testid="updates-preview">
        {unsigned && (
          <div role="alert" className="rounded-lg status-danger-bg border status-danger-border px-3 py-2 space-y-2" data-testid="updates-unsigned">
            <p className="text-sm font-semibold status-danger-text flex items-start gap-2">
              <Warning size={16} className="shrink-0 mt-0.5" />
              {release.signature === 'unknown_key' ? t('preview.unknownKey', { version: request.version, key: release.key_id || '?' }) : t('preview.unsigned', { version: request.version })}
            </p>
            <p className="text-xs text-text-secondary">{t('preview.unsignedHelp')}</p>
            {!plan && (
              <>
                <label className="flex items-start gap-2 text-xs">
                  <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} data-testid="updates-unsigned-accept" />
                  <span>{t('preview.unsignedAccept')}</span>
                </label>
                <Input label={t('preview.typeVersion', { version: request.version })} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" data-testid="updates-unsigned-version" />
                <div className="flex justify-end">
                  <Button size="sm" variant="danger" disabled={!unsignedOk} loading={busy} onClick={() => compute()} data-testid="updates-unsigned-continue">{t('preview.prepare')}</Button>
                </div>
              </>
            )}
          </div>
        )}

        {error && <p role="alert" className="text-xs status-danger-text" data-testid="updates-preview-error">{error}</p>}
        {busy && !plan && <p className="text-xs text-text-tertiary">{t('preview.computing')}</p>}

        {plan && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-text-secondary">{t('preview.order')}</h4>
                <ol className="space-y-1" data-testid="updates-order">
                  {(order || []).map((id, i) => (
                    <li key={id} className="flex items-center gap-2 text-sm" data-testid="updates-order-node" data-node={id}>
                      <span className="w-5 text-2xs font-mono text-text-tertiary">{i + 1}</span>
                      <span className="flex-1">{nodeName(id)}</span>
                      <Button size="xs" variant="ghost" disabled={i === 0} onClick={() => setOrder((o) => moveItem(o, i, -1))} aria-label={t('preview.moveUp', { node: nodeName(id) })} data-testid="updates-order-up"><ArrowUp size={12} /></Button>
                      <Button size="xs" variant="ghost" disabled={i === order.length - 1} onClick={() => setOrder((o) => moveItem(o, i, 1))} aria-label={t('preview.moveDown', { node: nodeName(id) })} data-testid="updates-order-down"><ArrowDown size={12} /></Button>
                    </li>
                  ))}
                </ol>
                <p className="text-2xs text-text-tertiary">{t('preview.orderHelp')}</p>
                {request.kind !== 'engine_packages' && (
                  <ToggleSwitch checked={autoRollback} onChange={setAutoRollback} size="sm" label={t('preview.autoRollback')} description={info.state_schema_changed ? t('preview.schemaChanged') : t('preview.autoRollbackHelp')} />
                )}
              </div>
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-text-secondary">{t('preview.checks')}</h4>
                <ul className="flex flex-wrap gap-1" data-testid="updates-checks">
                  {(info.checks || []).map((c) => <li key={c}><Badge variant="outline" size="sm">{t(`steps.${c}`, { defaultValue: c })}</Badge></li>)}
                </ul>
                <p className="text-xs text-text-secondary" data-testid="updates-estimate">{t('preview.estimate', { minutes: minutesOf(info.estimated_seconds) })}</p>
                {info.signature && request.kind === 'pelagos' && <SignatureBadge signature={info.signature} keyId={info.key_id} />}
                {info.unsigned_warning && <p className="text-xs status-danger-text">{msg(info.unsigned_warning, t('preview.unsigned', { version: request.version }))}</p>}
                {info.state_schema_changed && <p className="text-xs status-warning-text" data-testid="updates-schema-changed">{t('preview.schemaChanged')}</p>}
              </div>
            </div>

            {stale ? (
              <div className="flex flex-wrap items-center justify-end gap-2" data-testid="updates-stale">
                <span className="text-xs text-text-secondary">{t('preview.stale')}</span>
                <Button size="sm" onClick={() => compute({ order, autoRollback })} loading={busy} data-testid="updates-recompute">{t('preview.recompute')}</Button>
              </div>
            ) : (
              <>
                <Input label={t('preview.password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" helperText={t('preview.passwordHelp')} data-testid="updates-password" />
                <PlanPreview
                  plan={plan}
                  applyFn={applyFn}
                  nodeName={nodeName}
                  onRecompute={() => compute({ order, autoRollback })}
                  onApplied={(res) => onApplied(res)}
                  onClose={onClose}
                  closeLabel={t('common:actions.close')}
                />
              </>
            )}
          </>
        )}
      </div>
    </Modal>
  )
}

export default UpdatePreview
