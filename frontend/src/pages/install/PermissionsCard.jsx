// SPDX-License-Identifier: Apache-2.0
// Permissions of one node: every path its services create, write or read, probed in the unit's own
// sandbox, with the exact command for each failure and a plan through the privileged helper.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FolderLock } from '@phosphor-icons/react'
import { Card, Button, Badge, LoadingSpinner, PlanPreview } from '../../components'
import { useApi } from '../../hooks'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { useMessage } from '../../i18n/message'
import { failedChecks, fixableIds } from './permissions'
import { ErrorNotice } from '../../components/ErrorNotice'

export default function PermissionsCard({ node }) {
  const { t } = useTranslation('install')
  const m = useMessage()
  const q = useApi(() => api.install.permissions(node || undefined), [node])
  const [plan, setPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const data = q.data

  if (q.loading && !data) return <Card className="p-4" hover={false}><LoadingSpinner size="sm" /></Card>
  if (q.error) return <Card className="p-4" hover={false}><ErrorNotice error={q.error} onRetry={q.refetch} /></Card>
  if (!data) return null
  const checks = data.checks || []
  const failed = failedChecks(checks)
  const ids = fixableIds(checks)
  const fix = async () => {
    setBusy(true)
    setError(null)
    try {
      // Only the findings the helper's audit lists now: an unknown id fails the whole plan.
      const audit = await api.install.security(node || undefined)
      const known = new Set((audit?.findings || []).map((f) => f.id))
      const chosen = ids.filter((id) => known.has(id))
      if (!chosen.length) {
        q.refetch()
        return
      }
      setPlan(await api.install.securityPlan({ [data.node_id]: chosen }))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="permissions">
      <div className="flex flex-wrap items-center gap-2">
        <FolderLock size={16} className="text-text-secondary" />
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('security.permissions.title')}</h3>
        {data.available && (
          <Badge variant={failed.length ? 'warning' : 'success'} size="sm" data-testid="permissions-state">
            {failed.length ? t('security.permissions.failed', { count: failed.length }) : t('security.permissions.ok')}
          </Badge>
        )}
        <Button variant="ghost" size="sm" className="ml-auto" onClick={q.refetch} disabled={q.loading}>{t('security.permissions.recheck')}</Button>
      </div>
      <p className="text-xs text-text-secondary">{t('security.permissions.help')}</p>
      {!data.available ? (
        <p className="text-xs status-warning-text" data-testid="permissions-unavailable">{t('security.permissions.unavailable', { error: data.error || '' })}</p>
      ) : (
        <ul className="space-y-2">
          {checks.map((c) => (
            <li key={`${c.kind}:${c.path}`} className="text-xs" data-testid="permissions-check" data-ok={c.ok ? 'yes' : 'no'}>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={c.ok ? 'success' : 'warning'} size="sm">{c.ok ? t('security.permissions.okOne') : t('security.permissions.notWritable')}</Badge>
                <span className="font-mono break-all text-text-primary">{c.path}</span>
                <span className="text-text-tertiary">{m({ key: `permission.purpose.${c.purpose}`, params: {} }, c.purpose)}</span>
                {c.mode && <span className="font-mono text-text-tertiary">{`${c.owner}:${c.group} ${c.mode}`}</span>}
              </div>
              {!c.ok && (
                <div className="mt-1 ml-1 space-y-1">
                  <p className="status-warning-text">{m(c.message, c.text)}</p>
                  {c.command && <code className="block font-mono break-all text-text-secondary" data-testid="permissions-command">{c.command}</code>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {error && <p className="text-sm status-danger-text" role="alert">{errorMessage(error)}</p>}
      {ids.length > 0 && !plan && (
        <Button size="sm" onClick={fix} loading={busy} data-testid="permissions-fix">{t('security.permissions.fix', { count: ids.length })}</Button>
      )}
      {plan && (
        <PlanPreview
          plan={plan}
          onApplied={() => q.refetch()}
          onClose={() => {
            setPlan(null)
            q.refetch()
          }}
        />
      )}
    </Card>
  )
}
