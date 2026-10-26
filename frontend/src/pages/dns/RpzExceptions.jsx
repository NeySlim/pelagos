// SPDX-License-Identifier: Apache-2.0
// Exceptions: "why is this domain blocked?", the allow list (passthru in the local zone, first in the
// order) and the client addresses that no list applies to (rpz-client-ip).
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { MagnifyingGlass, Plus, Trash } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { DataTable } from '../../components/DataTable'
import { Input } from '../../components/Input'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { validDomain, validNetwork } from './rpzHelpers'

const VERDICT = { blocked: 'danger', allowed: 'success', not_listed: 'gray' }

function AddRow({ label, placeholder, valid, onAdd, testId, noteLabel }) {
  const { t } = useTranslation('dns')
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')
  const ready = valid(value)
  const add = async () => {
    if (await onAdd(value.trim(), note)) {
      setValue('')
      setNote('')
    }
  }
  return (
    <div className="flex flex-wrap items-end gap-2">
      <div className="w-64">
        <Input label={label} value={value} onChange={(e) => setValue(e.target.value)} placeholder={placeholder} data-testid={`${testId}-input`} />
      </div>
      <div className="w-64">
        <Input label={noteLabel} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      <Button size="sm" onClick={add} disabled={!ready} data-testid={`${testId}-add`}>
        <Plus size={14} />
        {t('rpzsub.exceptions.add')}
      </Button>
    </div>
  )
}

export default function RpzExceptions({ overview, canWrite, refetch }) {
  const { t } = useTranslation(['dns', 'common'])
  const { showError, showSuccess } = useNotification()
  const [domain, setDomain] = useState('')
  const [why, setWhy] = useState(null)
  const [busy, setBusy] = useState(false)

  const run = async (call, message) => {
    try {
      await call()
      if (message) showSuccess(message)
      refetch()
      return true
    } catch (err) {
      showError(errorMessage(err))
      return false
    }
  }
  const lookup = async (name = domain) => {
    if (!name.trim()) return
    setBusy(true)
    try {
      setWhy(await api.dns.rpzWhy(name.trim()))
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  const allow = async (name) => {
    if (await run(() => api.dns.rpzAllow(name, ''), t('rpzsub.exceptions.allowed', { domain: name }))) lookup(name)
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <Card className="p-4 space-y-3" hover={false} data-testid="rpz-why">
        <h3 className="font-semibold text-text-primary">{t('rpzsub.why.title')}</h3>
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            lookup()
          }}
        >
          <div className="w-80">
            <Input label={t('rpzsub.why.domain')} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="ads.example.com" data-testid="rpz-why-input" />
          </div>
          <Button size="sm" type="submit" disabled={busy || !validDomain(domain)} data-testid="rpz-why-submit">
            <MagnifyingGlass size={14} />
            {t('rpzsub.why.search')}
          </Button>
        </form>
        {why && (
          <div className="space-y-2" data-testid="rpz-why-result">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm">{why.domain}</span>
              <Badge variant={VERDICT[why.verdict]} size="sm" data-testid="rpz-why-verdict">{t(`rpzsub.why.verdict.${why.verdict}`)}</Badge>
              {canWrite && why.verdict === 'blocked' && (
                <Button size="xs" variant="secondary" onClick={() => allow(why.domain)} data-testid="rpz-why-allow">
                  {t('rpzsub.why.allowIt')}
                </Button>
              )}
            </div>
            {why.matches.length > 0 && (
              <ul className="text-sm space-y-1" data-testid="rpz-why-matches">
                {why.matches.map((m) => (
                  <li key={m.zone} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <Badge variant={m.applied ? (m.passthru ? 'success' : 'danger') : 'gray'} size="sm">{m.applied ? t('rpzsub.why.applied') : t('rpzsub.why.shadowed')}</Badge>
                    <span className="font-medium">{m.name}</span>
                    {m.category && <span className="text-text-secondary">{t(`rpzsub.categories.${m.category}.name`)}</span>}
                    <span className="font-mono text-xs">{m.rule}</span>
                    <span className="text-xs text-text-tertiary">{t(`rpzsub.why.match.${m.match}`)}</span>
                    <span className="text-xs text-text-tertiary">{t(`rpzsub.actions.${m.action}`)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Card>

      <div className="space-y-2">
        <p className="text-sm text-text-secondary">{t('rpzsub.exceptions.allowHelp', { zone: overview.allow_zone })}</p>
        {canWrite && <AddRow label={t('rpzsub.exceptions.domain')} noteLabel={t('rpzsub.exceptions.note')} placeholder="shop.example.com" valid={validDomain} testId="rpz-allow" onAdd={(d, n) => run(() => api.dns.rpzAllow(d, n), t('rpzsub.exceptions.allowed', { domain: d }))} />}
        <DataTable
          title={t('rpzsub.exceptions.allowTitle')}
          columns={[
            { key: 'domain', label: t('rpzsub.exceptions.domain'), mono: true },
            { key: 'note', label: t('rpzsub.exceptions.note') },
            { key: 'by', label: t('rpzsub.exceptions.by') },
            {
              key: 'actions',
              label: '',
              align: 'right',
              render: (r) =>
                canWrite ? (
                  <Button variant="ghost" size="xs" onClick={() => run(() => api.dns.rpzDisallow(r.domain))} aria-label={t('common:actions.delete')} data-testid="rpz-allow-delete">
                    <Trash size={13} className="status-danger-text" />
                  </Button>
                ) : null,
            },
          ]}
          rows={overview.allow}
          rowKey="domain"
          emptyTitle={t('rpzsub.exceptions.allowEmpty')}
          testId="rpz-allow-table"
        />
      </div>

      <div className="space-y-2">
        <p className="text-sm text-text-secondary">{t('rpzsub.exceptions.clientsHelp')}</p>
        {canWrite && <AddRow label={t('rpzsub.exceptions.client')} noteLabel={t('rpzsub.exceptions.note')} placeholder="192.0.2.0/24" valid={validNetwork} testId="rpz-exempt" onAdd={(c, n) => run(() => api.dns.rpzExempt(c, n), t('rpzsub.exceptions.exempted', { cidr: c }))} />}
        <DataTable
          title={t('rpzsub.exceptions.clientsTitle')}
          columns={[
            { key: 'cidr', label: t('rpzsub.exceptions.client'), mono: true },
            { key: 'note', label: t('rpzsub.exceptions.note') },
            { key: 'by', label: t('rpzsub.exceptions.by') },
            {
              key: 'actions',
              label: '',
              align: 'right',
              render: (r) =>
                canWrite ? (
                  <Button variant="ghost" size="xs" onClick={() => run(() => api.dns.rpzUnexempt(r.cidr))} aria-label={t('common:actions.delete')} data-testid="rpz-exempt-delete">
                    <Trash size={13} className="status-danger-text" />
                  </Button>
                ) : null,
            },
          ]}
          rows={overview.exempt_clients}
          rowKey="cidr"
          emptyTitle={t('rpzsub.exceptions.clientsEmpty')}
          testId="rpz-exempt-table"
        />
      </div>
    </div>
  )
}
