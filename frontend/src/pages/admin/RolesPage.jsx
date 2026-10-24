// SPDX-License-Identifier: Apache-2.0
// Roles: the four built-in roles (read-only, defined in code) and custom roles
// made of permission strings, edited with a checkbox grid grouped by resource.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { UserGear, Plus, Trash, LockSimple, PencilSimple } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, FormModal, Input, ConfirmDialog, LoadingSpinner } from '../../components'
import { useApi } from '../../hooks'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { ROLE_NAME_RE, fieldErrors, groupPermissions } from './validation'

function PermissionGrid({ permissions, value, onChange, readOnly }) {
  const { t } = useTranslation('admin')
  const groups = useMemo(() => groupPermissions(permissions), [permissions])
  const all = value.includes('*')
  const toggle = (p) => onChange(value.includes(p) ? value.filter((x) => x !== p) : [...value, p])
  return (
    <div className="space-y-3" data-testid="permission-grid">
      {all && <p className="text-xs text-text-secondary">{t('roles.allPermissions')}</p>}
      {groups.map(({ family, items }) => (
        <fieldset key={family} className="space-y-1">
          <legend className="text-2xs uppercase tracking-wider text-text-tertiary">{t(`roles.families.${family}`, { defaultValue: family })}</legend>
          <div className="flex flex-wrap gap-1.5">
            {items.map((p) => {
              const on = all || value.includes(p)
              return (
                <label key={p} className={cn('inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-mono', on ? 'border-accent-primary bg-accent-primary-op10 text-text-primary' : 'border-border text-text-secondary', readOnly ? 'cursor-default' : 'cursor-pointer')}>
                  <input type="checkbox" checked={on} disabled={readOnly || all} onChange={() => toggle(p)} data-permission={p} />
                  {p}
                </label>
              )
            })}
          </div>
        </fieldset>
      ))}
    </div>
  )
}

function RoleForm({ role, permissions, onClose, onSaved }) {
  const { t } = useTranslation(['admin', 'common'])
  const creating = !role
  const [name, setName] = useState(role?.name || '')
  const [description, setDescription] = useState(role?.description || '')
  const [selected, setSelected] = useState(role?.permissions || [])
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    const local = {}
    if (creating && !ROLE_NAME_RE.test(name)) local.name = t('roles.errors.name')
    if (!selected.length) local.permissions = t('roles.errors.permissions')
    setErrors(local)
    if (Object.keys(local).length) return
    setBusy(true)
    try {
      const saved = creating
        ? await api.admin.createRole({ name, description: description || null, permissions: selected })
        : await api.admin.updateRole(role.name, { description: description || null, permissions: selected })
      onSaved(saved)
    } catch (err) {
      setErrors({ ...fieldErrors(err), form: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open onClose={onClose} title={creating ? t('roles.create') : t('roles.editTitle', { name: role.name })} onSubmit={submit} loading={busy} size="lg" submitLabel={creating ? t('common:actions.create') : t('common:actions.save')} testId="role-form">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Input label={t('roles.name')} value={name} onChange={(e) => setName(e.target.value)} disabled={!creating} error={errors.name} data-testid="role-name" />
        <Input label={t('roles.description')} value={description} onChange={(e) => setDescription(e.target.value)} data-testid="role-description" />
      </div>
      <PermissionGrid permissions={permissions} value={selected} onChange={setSelected} />
      {errors.permissions && <p className="text-xs status-danger-text">{errors.permissions}</p>}
      {errors.form && <p className="text-sm status-danger-text" role="alert">{errors.form}</p>}
    </FormModal>
  )
}

export default function RolesPage() {
  const { t } = useTranslation(['admin', 'common'])
  const { showSuccess, showError } = useNotification()
  const rolesQ = useApi(() => api.admin.roles(), [])
  const permsQ = useApi(() => api.admin.permissions(), [])
  const roles = useMemo(() => [...(rolesQ.data?.items || [])].sort((a, b) => Number(b.builtin) - Number(a.builtin) || a.name.localeCompare(b.name)), [rolesQ.data])
  const permissions = permsQ.data?.items || []
  const [selectedName, setSelectedName] = useState(null)
  const [editing, setEditing] = useState(null) // role or 'new'
  const [deleting, setDeleting] = useState(null)
  const [busy, setBusy] = useState(false)
  const selected = roles.find((r) => r.name === selectedName) || roles[0]

  const remove = async () => {
    setBusy(true)
    try {
      await api.admin.deleteRole(deleting.name)
      showSuccess(t('roles.deleted', { name: deleting.name }))
      setDeleting(null)
      setSelectedName(null)
      rolesQ.refetch()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <PageLayout
      icon={UserGear}
      title={t('pages.roles.title')}
      subtitle={t('pages.roles.subtitle')}
      testId="page-admin-roles"
      actions={
        <Button size="sm" onClick={() => setEditing('new')} data-testid="role-create">
          <Plus size={14} />
          {t('roles.create')}
        </Button>
      }
    >
      {rolesQ.loading && !rolesQ.data ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : rolesQ.error ? (
        <p className="text-sm status-danger-text" role="alert">{errorMessage(rolesQ.error)}</p>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-4">
          <div className="space-y-1.5" data-testid="roles-list">
            {roles.map((role) => (
              <button
                key={role.name}
                type="button"
                onClick={() => setSelectedName(role.name)}
                className={cn('w-full text-left rounded-lg border px-3 py-2', selected?.name === role.name ? 'border-accent-primary bg-accent-primary-op10' : 'border-border hover:bg-bg-tertiary')}
                data-role={role.name}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-text-primary">{role.name}</span>
                  {role.builtin && <Badge variant="secondary" size="sm" icon={LockSimple}>{t('roles.builtin')}</Badge>}
                  <span className="ml-auto text-2xs text-text-tertiary">{role.permissions.includes('*') ? t('roles.all') : t('roles.count', { count: role.permissions.length })}</span>
                </div>
                {role.description && <p className="text-xs text-text-secondary mt-0.5">{role.description}</p>}
              </button>
            ))}
          </div>
          {selected && (
            <Card className="p-4 space-y-3" hover={false} data-testid="role-detail">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-mono text-sm font-semibold text-text-primary">{selected.name}</h3>
                {selected.builtin && <Badge variant="secondary" size="sm">{t('roles.builtinHelp')}</Badge>}
                {!selected.builtin && (
                  <div className="ml-auto flex gap-2">
                    <Button size="sm" variant="secondary" onClick={() => setEditing(selected)} data-testid="role-edit">
                      <PencilSimple size={14} />
                      {t('common:actions.edit')}
                    </Button>
                    <Button size="sm" variant="danger-soft" onClick={() => setDeleting(selected)} data-testid="role-delete">
                      <Trash size={14} />
                      {t('common:actions.delete')}
                    </Button>
                  </div>
                )}
              </div>
              <PermissionGrid permissions={permissions} value={selected.permissions} onChange={() => {}} readOnly />
            </Card>
          )}
        </div>
      )}
      {editing && (
        <RoleForm
          role={editing === 'new' ? null : editing}
          permissions={permissions}
          onClose={() => setEditing(null)}
          onSaved={(role) => {
            showSuccess(t('roles.saved', { name: role.name }))
            setEditing(null)
            setSelectedName(role.name)
            rolesQ.refetch()
          }}
        />
      )}
      <ConfirmDialog
        open={Boolean(deleting)}
        onOpenChange={(o) => !o && setDeleting(null)}
        onConfirm={remove}
        loading={busy}
        title={t('roles.deleteTitle', { name: deleting?.name })}
        message={t('roles.deleteBody')}
        confirmLabel={t('common:actions.delete')}
      />
    </PageLayout>
  )
}
