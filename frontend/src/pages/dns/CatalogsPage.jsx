// SPDX-License-Identifier: Apache-2.0
// Catalog zones (RFC 9432): consumed catalogs from catalog-zones statements and produced
// catalogs (primary zones with a version TXT record), each with its member zones read
// from the catalog content. On a producer, adding or removing a member is a record plan
// on the catalog zone; consumers pick the change up by transfer.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { BookOpen, ArrowsClockwise, Plus, Trash } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { EmptyState } from '../../components/EmptyState'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { ListValue } from './common'
import { usePlanFlow, zoneHref } from './helpers'
import { validDomainName } from './records'
import { catalogMemberBody } from './zoneTools'

function AddMemberModal({ catalog, onClose, onPlan }) {
  const { t } = useTranslation(['dns', 'common'])
  const [member, setMember] = useState('')
  const [group, setGroup] = useState('')
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const ok = validDomainName(member.trim().toLowerCase())
  const submit = async () => {
    setTouched(true)
    if (!ok) return
    setBusy(true)
    try {
      await onPlan(catalogMemberBody({ op: 'add', member: member.trim().toLowerCase(), group, view: catalog.view }))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open onClose={onClose} title={t('catalogs.addTitle', { zone: catalog.zone })} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} testId="catalog-add">
      <Input data-testid="catalog-member-input" label={t('catalogs.member')} value={member} onChange={(e) => setMember(e.target.value)} placeholder="new.example.lan" error={touched && !ok ? t('catalogs.memberError') : undefined} autoFocus />
      <Input label={t('catalogs.group')} value={group} onChange={(e) => setGroup(e.target.value)} />
    </FormModal>
  )
}

function CatalogCard({ catalog, canWrite, onAdd, onRemove }) {
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const producer = catalog.role === 'producer'
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="catalog-card">
      <div className="flex flex-wrap items-center gap-2">
        <BookOpen size={16} className="text-accent-primary" />
        <button type="button" className="font-mono text-sm text-accent-primary hover:underline" onClick={() => navigate(zoneHref(catalog.zone, catalog.view))}>
          {catalog.zone}
        </button>
        <Badge variant={producer ? 'primary' : 'secondary'} size="sm">{t(`catalogs.roles.${catalog.role}`, { defaultValue: catalog.role })}</Badge>
        {catalog.view && catalog.view !== '_default' && <Badge variant="outline" size="sm">{catalog.view}</Badge>}
        {catalog.version && <span className="text-2xs text-text-tertiary">{t('catalogs.version')} {catalog.version}</span>}
        {producer && canWrite && (
          <Button size="xs" className="ml-auto" onClick={() => onAdd(catalog)} data-testid="catalog-add-member">
            <Plus size={12} />
            {t('catalogs.addMember')}
          </Button>
        )}
      </div>
      {catalog.default_primaries?.length > 0 && (
        <div className="text-xs text-text-secondary flex flex-wrap items-center gap-2">
          <span>{t('rpz.defaultPrimaries')}</span>
          <ListValue items={catalog.default_primaries} />
        </div>
      )}
      {!producer && <p className="text-2xs text-text-tertiary">{t('catalogs.consumerHelp')}</p>}
      {catalog.error && <p className="text-xs status-danger-text">{t('catalogs.readError', { error: catalog.error })}</p>}
      {catalog.members?.length ? (
        <ul className="divide-y divide-border-op50" data-testid="catalog-members">
          {catalog.members.map((m) => (
            <li key={m.zone} className="flex items-center gap-2 py-1.5 min-w-0">
              <span className="font-mono text-xs text-text-primary truncate flex-1">{m.zone}</span>
              {m.group && <Badge variant="outline" size="sm">{m.group}</Badge>}
              {producer && canWrite && (
                <Button variant="ghost" size="xs" onClick={() => onRemove(catalog, m)} aria-label={t('catalogs.removeMember')} data-testid="catalog-remove-member">
                  <Trash size={12} className="status-danger-text" />
                </Button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-text-tertiary">{t('catalogs.noMembers')}</p>
      )}
    </Card>
  )
}

export default function CatalogsPage() {
  const { t } = useTranslation(['dns', 'common'])
  const { hasPermission } = usePermission()
  const { showError } = useNotification()
  const { data, error, loading, refetch } = useApi(() => api.dns.catalogZones(), [])
  const [adding, setAdding] = useState(null)
  const flow = usePlanFlow({ onDone: () => refetch(), onError: showError })
  const canWrite = hasPermission('write:dns.records')
  const items = data?.items || []

  const plan = (catalog, body) => flow.run(() => api.dns.catalogMemberPlan(catalog.zone, body))

  return (
    <PageLayout
      icon={BookOpen}
      title={t('pages.catalogs.title')}
      subtitle={t('pages.catalogs.subtitle')}
      testId="page-dns-catalogs"
      actions={
        <Button variant="secondary" size="sm" onClick={refetch} disabled={loading}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      {loading && !data ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="md" />
        </div>
      ) : error ? (
        <EmptyState icon={BookOpen} title={errorMessage(error)} action={{ label: t('common:actions.retry'), onClick: refetch }} />
      ) : !items.length ? (
        <EmptyState icon={BookOpen} title={t('catalogs.empty')} description={t('catalogs.emptyHelp')} />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {items.map((c) => (
            <CatalogCard
              key={`${c.view}/${c.zone}/${c.role}`}
              catalog={c}
              canWrite={canWrite}
              onAdd={setAdding}
              onRemove={(cat, m) => plan(cat, catalogMemberBody({ op: 'delete', member: m.zone, view: cat.view }))}
            />
          ))}
        </div>
      )}
      {adding && (
        <AddMemberModal
          catalog={adding}
          onClose={() => setAdding(null)}
          onPlan={async (body) => {
            const p = await plan(adding, body)
            if (p) setAdding(null)
          }}
        />
      )}
      {flow.modal}
    </PageLayout>
  )
}
