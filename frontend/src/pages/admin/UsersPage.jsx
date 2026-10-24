// SPDX-License-Identifier: Apache-2.0
// Users: list with roles, state and two-factor status; create, edit roles and
// flags, reset the password, clear TOTP, delete. Users replicate to every node.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Users, Plus, PencilSimple, Key, ShieldSlash, Trash, ArrowsClockwise } from '@phosphor-icons/react'
import { PageLayout, DataTable, Button, Badge, StatusBadge, FormModal, Input, ConfirmDialog, ToggleSwitch } from '../../components'
import { useApi } from '../../hooks'
import { useAuth } from '../../contexts/AuthContext'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { RoleChecklist } from './RoleChecklist'
import { USERNAME_RE, passwordProblem, fieldErrors } from './validation'

function UserForm({ open, user, roles, onClose, onSaved }) {
  const { t } = useTranslation(['admin', 'common'])
  const creating = !user
  const [username, setUsername] = useState(user?.username || '')
  const [password, setPassword] = useState('')
  const [selected, setSelected] = useState(user?.roles || ['viewer'])
  const [enabled, setEnabled] = useState(user?.enabled ?? true)
  const [mustChange, setMustChange] = useState(user?.must_change_password ?? true)
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    const local = {}
    if (creating && !USERNAME_RE.test(username)) local.username = t('users.errors.username')
    if (creating && passwordProblem(password)) local.password = t(`users.errors.${passwordProblem(password)}`)
    if (!selected.length) local.roles = t('users.errors.roles')
    setErrors(local)
    if (Object.keys(local).length) return
    setBusy(true)
    try {
      const saved = creating
        ? await api.admin.createUser({ username, password, roles: selected, enabled, must_change_password: mustChange })
        : await api.admin.updateUser(user.id, { roles: selected, enabled, must_change_password: mustChange })
      onSaved(saved)
    } catch (err) {
      setErrors({ ...fieldErrors(err), form: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={creating ? t('users.create') : t('users.editTitle', { name: user.username })} onSubmit={submit} loading={busy} submitLabel={creating ? t('common:actions.create') : t('common:actions.save')} testId="user-form">
      <Input label={t('users.username')} value={username} onChange={(e) => setUsername(e.target.value)} disabled={!creating} error={errors.username} autoComplete="off" data-testid="user-username" />
      {creating && (
        <Input label={t('users.password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} showStrength autoComplete="new-password" helperText={t('users.passwordHelp')} data-testid="user-password" />
      )}
      <div className="space-y-1.5">
        <span className="block text-xs font-medium text-text-secondary">{t('users.roles')}</span>
        <RoleChecklist roles={roles} value={selected} onChange={setSelected} />
        {errors.roles && <p className="text-xs status-danger-text">{errors.roles}</p>}
      </div>
      <ToggleSwitch checked={enabled} onChange={setEnabled} label={t('users.enabled')} description={t('users.enabledHelp')} />
      <ToggleSwitch checked={mustChange} onChange={setMustChange} label={t('users.mustChange')} description={t('users.mustChangeHelp')} />
      {errors.form && <p className="text-sm status-danger-text" role="alert">{errors.form}</p>}
    </FormModal>
  )
}

function ResetPassword({ user, onClose, onDone }) {
  const { t } = useTranslation(['admin', 'common'])
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    const problem = passwordProblem(password)
    if (problem) return setError(t(`users.errors.${problem}`))
    setBusy(true)
    try {
      await api.admin.resetPassword(user.id, password)
      onDone()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open onClose={onClose} title={t('users.resetTitle', { name: user.username })} onSubmit={submit} loading={busy} submitLabel={t('users.reset')} size="sm" testId="user-reset">
      <p className="text-xs text-text-secondary">{t('users.resetHelp')}</p>
      <Input label={t('users.newPassword')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} error={error} showStrength autoComplete="new-password" />
    </FormModal>
  )
}

export default function UsersPage() {
  const { t } = useTranslation(['admin', 'common'])
  const { user: me } = useAuth()
  const { showSuccess, showError } = useNotification()
  const usersQ = useApi(() => api.admin.users(), [])
  const rolesQ = useApi(() => api.admin.roles().catch(() => ({ items: [] })), [])
  const roles = rolesQ.data?.items || []
  const [editing, setEditing] = useState(null) // user object, or 'new'
  const [resetting, setResetting] = useState(null)
  const [confirm, setConfirm] = useState(null) // { kind: 'delete' | 'totp', user }
  const [busy, setBusy] = useState(false)

  const runConfirm = async () => {
    setBusy(true)
    try {
      if (confirm.kind === 'delete') await api.admin.deleteUser(confirm.user.id)
      else await api.admin.clearTotp(confirm.user.id)
      showSuccess(t(confirm.kind === 'delete' ? 'users.deleted' : 'users.totpCleared', { name: confirm.user.username }))
      setConfirm(null)
      usersQ.refetch()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const columns = [
    { key: 'username', label: t('users.username'), sortable: true, render: (u) => <span className="font-medium">{u.username}{u.id === me?.id && <span className="ml-1.5 text-2xs text-text-tertiary">({t('users.you')})</span>}</span> },
    { key: 'roles', label: t('users.roles'), render: (u) => <div className="flex flex-wrap gap-1">{u.roles.map((r) => <Badge key={r} variant={r === 'admin' ? 'primary' : 'secondary'} size="sm">{r}</Badge>)}</div> },
    { key: 'enabled', label: t('users.state'), render: (u) => <StatusBadge status={u.enabled ? 'enabled' : 'disabled'} /> },
    { key: 'has_totp', label: t('users.totp'), render: (u) => <StatusBadge status={u.has_totp ? 'true' : 'false'} label={u.has_totp ? t('users.totpOn') : t('users.totpOff')} /> },
    { key: 'must_change_password', label: t('users.mustChangeShort'), render: (u) => (u.must_change_password ? <Badge variant="warning" size="sm">{t('users.pending')}</Badge> : '') },
    { key: 'last_login', label: t('users.lastLogin'), sortable: true, render: (u) => <span className="text-xs">{u.last_login ? formatDate(u.last_login) : t('users.never')}</span> },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (u) => (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="xs" variant="ghost" title={t('common:actions.edit')} onClick={() => setEditing(u)} data-testid="user-edit"><PencilSimple size={14} /></Button>
          <Button size="xs" variant="ghost" title={t('users.reset')} onClick={() => setResetting(u)}><Key size={14} /></Button>
          {u.has_totp && <Button size="xs" variant="ghost" title={t('users.clearTotp')} onClick={() => setConfirm({ kind: 'totp', user: u })}><ShieldSlash size={14} /></Button>}
          {u.id !== me?.id && <Button size="xs" variant="ghost" title={t('common:actions.delete')} onClick={() => setConfirm({ kind: 'delete', user: u })} data-testid="user-delete"><Trash size={14} className="status-danger-text" /></Button>}
        </div>
      ),
    },
  ]

  return (
    <PageLayout
      icon={Users}
      title={t('pages.users.title')}
      subtitle={t('pages.users.subtitle')}
      testId="page-admin-users"
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={usersQ.refetch} disabled={usersQ.loading}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
          <Button size="sm" onClick={() => setEditing('new')} data-testid="user-create">
            <Plus size={14} />
            {t('users.create')}
          </Button>
        </>
      }
    >
      <DataTable columns={columns} rows={usersQ.data?.items || []} loading={usersQ.loading} error={usersQ.error} onRetry={usersQ.refetch} clientSort onRowClick={setEditing} testId="users-table" />
      {editing && (
        <UserForm
          open
          user={editing === 'new' ? null : editing}
          roles={roles}
          onClose={() => setEditing(null)}
          onSaved={(u) => {
            showSuccess(t(editing === 'new' ? 'users.created' : 'users.saved', { name: u.username }))
            setEditing(null)
            usersQ.refetch()
          }}
        />
      )}
      {resetting && (
        <ResetPassword
          user={resetting}
          onClose={() => setResetting(null)}
          onDone={() => {
            showSuccess(t('users.resetDone', { name: resetting.username }))
            setResetting(null)
            usersQ.refetch()
          }}
        />
      )}
      <ConfirmDialog
        open={Boolean(confirm)}
        onOpenChange={(o) => !o && setConfirm(null)}
        onConfirm={runConfirm}
        loading={busy}
        title={confirm?.kind === 'delete' ? t('users.deleteTitle', { name: confirm.user.username }) : t('users.clearTotpTitle', { name: confirm?.user.username })}
        message={confirm?.kind === 'delete' ? t('users.deleteBody') : t('users.clearTotpBody')}
        confirmLabel={confirm?.kind === 'delete' ? t('common:actions.delete') : t('users.clearTotp')}
        typeToConfirm={confirm?.kind === 'delete' ? confirm.user.username : undefined}
      />
    </PageLayout>
  )
}
