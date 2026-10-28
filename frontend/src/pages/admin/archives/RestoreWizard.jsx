// SPDX-License-Identifier: Apache-2.0
// Restore from an archive in three steps (design 13.2): where and with which identity, then the
// parts with the difference of each (inspect), then the plan preview of scope `restore`, applied
// as a job like the install plans. Nothing is written before the plan is confirmed.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, MagnifyingGlass, ListChecks, Warning } from '@phosphor-icons/react'
import { Modal, Button, Badge, Select, Textarea, PlanPreview } from '../../../components'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { usePermission } from '../../../hooks/usePermission'
import { formatDate } from '../../../lib/utils'
import { IDENTITY_RE, partChanged, partInfo, restorePlanBody, restoreRequest } from './archivesForm'

const STEPS = ['source', 'parts', 'plan']

function PartLabel({ id }) {
  const { t } = useTranslation('archives')
  const info = partInfo(id)
  let text
  if (info.kind === 'zone') text = t('parts.zone', { zone: info.zone, view: info.view })
  else if (info.kind === 'settings') text = t('parts.settings', { section: t(`sections.${info.section}`, { defaultValue: info.section }) })
  else text = t(`parts.${info.kind.replace('.', '_')}`, { defaultValue: info.kind })
  return <span>{text}{info.partner ? ` (${t('parts.partner')})` : ''}</span>
}

function SummaryText({ part }) {
  const { t } = useTranslation('archives')
  const s = part.diff_summary || {}
  if (s.error) return <span className="status-danger-text">{s.error}</span>
  const bits = []
  if (Array.isArray(s.changed)) bits.push(t('diff.files', { count: s.changed.length }))
  else if (s.changed === true) bits.push(t('diff.changed'))
  else if (s.changed === false) bits.push(t('diff.same'))
  if (s.add || s.replace || s.delete) bits.push(t('diff.records', { added: s.add || 0, replaced: s.replace || 0, deleted: s.delete || 0 }))
  if (s.entries !== undefined) bits.push(t('diff.entries', { count: s.entries }))
  if (s.lines) bits.push(t('diff.lines', { count: s.lines }))
  if (s.skipped && Object.keys(s.skipped).length) bits.push(t('diff.skipped', { types: Object.keys(s.skipped).join(', ') }))
  if (s.refused?.length) bits.push(t('diff.refused', { types: s.refused.join(', ') }))
  if (s.valid === false) bits.push(t('diff.invalid'))
  return <span>{bits.join(', ') || t('diff.same')}</span>
}

export default function RestoreWizard({ open, onClose, archive, nodes = [], nameOf = (id) => id, onDone }) {
  const { t } = useTranslation(['archives', 'common'])
  const { hasPermission } = usePermission()
  const [step, setStep] = useState(0)
  const [target, setTarget] = useState(() => (nodes.some((n) => n.id === archive.node_id) ? archive.node_id : nodes[0]?.id || ''))
  const [identity, setIdentity] = useState('')
  const [substitute, setSubstitute] = useState('')
  const [haTlsPlain, setHaTlsPlain] = useState(false)
  const [inspected, setInspected] = useState(null)
  const [chosen, setChosen] = useState([])
  const [modes, setModes] = useState({})
  const [userFiles, setUserFiles] = useState(false)
  const [userFilesAck, setUserFilesAck] = useState(false)
  const [plan, setPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const identityError = identity.trim() && !IDENTITY_RE.test(identity.trim()) ? t('errors.identity') : null
  const request = useMemo(() => restoreRequest({ target, identity, substitute, haTlsPlain }), [target, identity, substitute, haTlsPlain])
  const moved = target && target !== archive.node_id

  const inspect = async () => {
    setBusy(true)
    setError(null)
    try {
      const out = await api.archives.inspect(archive.id, request)
      setInspected(out)
      setChosen(out.parts.filter((p) => partChanged(p) && !p.requires && hasPermission(p.permission)).map((p) => p.id))
      setModes(Object.fromEntries(out.parts.filter((p) => p.mode).map((p) => [p.id, p.mode])))
      setStep(1)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const build = async () => {
    setBusy(true)
    setError(null)
    try {
      const body = restorePlanBody(request, chosen, Object.fromEntries(chosen.filter((id) => modes[id]).map((id) => [id, modes[id]])), userFiles && userFilesAck)
      setPlan(await api.archives.restorePlan(archive.id, body))
      setStep(2)
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const toggle = (id) => setChosen((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]))
  const needsUser = chosen.some((id) => inspected?.parts.find((p) => p.id === id)?.requires === 'include_user_files') || chosen.includes('bind.user_files')
  const canBuild = chosen.length > 0 && (!needsUser || (userFiles && userFilesAck))

  return (
    <Modal open={open} onClose={onClose} title={t('restore.title', { node: archive.node_name || nameOf(archive.node_id), when: formatDate(archive.created_at) })} size="xl">
      <div className="p-4 space-y-4" data-testid="archives-restore" data-step={STEPS[step]}>
        <ol className="flex flex-wrap gap-2 text-xs" aria-label={t('restore.steps')}>
          {STEPS.map((s, i) => (
            <li key={s} className={`px-2 py-0.5 rounded-md border ${i === step ? 'border-accent-primary text-text-primary' : 'border-border text-text-tertiary'}`} aria-current={i === step ? 'step' : undefined}>
              {i + 1}. {t(`restore.step.${s}`)}
            </li>
          ))}
        </ol>
        {error && <p className="text-xs status-danger-text break-words" role="alert" data-testid="archives-restore-error">{error}</p>}

        {step === 0 && (
          <div className="space-y-3">
            <Select label={t('restore.target')} value={target} onChange={setTarget} options={nodes.map((n) => ({ value: n.id, label: n.name }))} id="archives-restore-target" />
            {moved && <p className="text-xs status-warning-text" data-testid="archives-restore-moved">{t('restore.movedHelp', { node: archive.node_name || archive.node_id })}</p>}
            <Textarea
              label={t('restore.identity')}
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
              rows={2}
              placeholder="AGE-SECRET-KEY-1..."
              error={identityError}
              className="font-mono text-2xs"
              spellCheck={false}
              autoComplete="off"
              data-testid="archives-restore-identity"
            />
            <p className="text-2xs text-text-tertiary">{t('restore.identityHelp')}</p>
            {moved && (
              <>
                <Textarea label={t('restore.substitute')} value={substitute} onChange={(e) => setSubstitute(e.target.value)} rows={3} placeholder="192.0.2.12=192.0.2.14" className="font-mono text-xs" data-testid="archives-restore-substitute" />
                <p className="text-2xs text-text-tertiary">{t('restore.substituteHelp')}</p>
              </>
            )}
            <label className="flex items-start gap-2 text-xs text-text-secondary">
              <input type="checkbox" checked={haTlsPlain} onChange={(e) => setHaTlsPlain(e.target.checked)} data-testid="archives-restore-ha-plain" />
              <span>{t('restore.haPlain')}</span>
            </label>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={onClose}>{t('common:actions.cancel')}</Button>
              <Button onClick={inspect} loading={busy} disabled={Boolean(identityError) || !target} data-testid="archives-restore-inspect">
                <MagnifyingGlass size={14} />
                {t('restore.inspect')}
              </Button>
            </div>
          </div>
        )}

        {step === 1 && inspected && (
          <div className="space-y-3">
            <p className="text-xs text-text-secondary">
              {t('restore.manifest', { node: inspected.manifest.node_name, when: formatDate(inspected.manifest.created_at), target: nameOf(inspected.target_node_id) })}
              {inspected.manifest.complete === false && <span className="status-warning-text"> {t('restore.incomplete')}</span>}
            </p>
            {(inspected.warnings || []).map((w) => (
              <p key={w.part} className="text-xs status-warning-text flex items-start gap-1.5" data-testid="archives-restore-warning">
                <Warning size={14} className="shrink-0 mt-0.5" />
                {t('restore.oldNode', { part: w.part, found: w.found.join(', ') })}
              </p>
            ))}
            <ul className="divide-y divide-border border border-border rounded-lg" data-testid="archives-restore-parts">
              {inspected.parts.map((p) => {
                const allowed = hasPermission(p.permission)
                return (
                  <li key={p.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm" data-testid="archives-restore-part" data-part={p.id}>
                    <input type="checkbox" checked={chosen.includes(p.id)} onChange={() => toggle(p.id)} disabled={!allowed} aria-label={p.id} />
                    <span className="font-medium text-text-primary"><PartLabel id={p.id} /></span>
                    {p.node_id && p.engine !== 'pelagos' && <Badge variant="outline" size="sm">{nameOf(p.node_id)}</Badge>}
                    {!allowed && <Badge variant="secondary" size="sm">{t('restore.needs', { permission: p.permission })}</Badge>}
                    {p.modes && (
                      <span className="ml-auto w-40">
                        <Select value={modes[p.id] || p.mode} onChange={(m) => setModes((x) => ({ ...x, [p.id]: m }))} options={p.modes.map((m) => ({ value: m, label: t(`modes.${m}`) }))} ariaLabel={t('restore.mode')} size="sm" />
                      </span>
                    )}
                    <span className="basis-full text-xs text-text-secondary"><SummaryText part={p} /></span>
                    {(p.notes || []).map((n) => <span key={n} className="basis-full text-2xs text-text-tertiary">{n}</span>)}
                  </li>
                )
              })}
            </ul>
            {needsUser && (
              <div className="rounded-lg border status-warning-bg status-warning-border p-3 space-y-2" data-testid="archives-restore-userfiles">
                <label className="flex items-start gap-2 text-xs">
                  <input type="checkbox" checked={userFiles} onChange={(e) => setUserFiles(e.target.checked)} data-testid="archives-restore-userfiles-1" />
                  <span>{t('restore.userFiles')}</span>
                </label>
                <label className="flex items-start gap-2 text-xs">
                  <input type="checkbox" checked={userFilesAck} disabled={!userFiles} onChange={(e) => setUserFilesAck(e.target.checked)} data-testid="archives-restore-userfiles-2" />
                  <span>{t('restore.userFilesAck')}</span>
                </label>
              </div>
            )}
            <div className="flex justify-between gap-2">
              <Button variant="ghost" onClick={() => setStep(0)}><ArrowLeft size={14} />{t('restore.back')}</Button>
              <Button onClick={build} loading={busy} disabled={!canBuild} data-testid="archives-restore-build">
                <ListChecks size={14} />
                {t('restore.build', { count: chosen.length })}
              </Button>
            </div>
          </div>
        )}

        {step === 2 && plan && (
          <div className="space-y-3">
            <PlanPreview
              plan={plan}
              nodeName={nameOf}
              onApplied={(res) => onDone?.(res)}
              onRecompute={async () => {
                const body = restorePlanBody(request, chosen, modes, userFiles && userFilesAck)
                const fresh = await api.archives.restorePlan(archive.id, body)
                setPlan(fresh)
                return fresh
              }}
              onClose={onClose}
              closeLabel={t('common:actions.close')}
            />
            <Button variant="ghost" onClick={() => setStep(1)}><ArrowLeft size={14} />{t('restore.back')}</Button>
          </div>
        )}
      </div>
    </Modal>
  )
}
