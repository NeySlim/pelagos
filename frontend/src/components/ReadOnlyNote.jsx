// SPDX-License-Identifier: Apache-2.0
// One discreet line that says why an action is missing: a permission the roles lack,
// another node that owns the action, the object's state, or a caller's own text.
import { useTranslation } from 'react-i18next'
import { HardDrives, LockSimple } from '@phosphor-icons/react'
import { cn } from '../lib/utils'
import { NodeLink } from './NodeLink'

export function ReadOnlyNote({ permission, reason = 'permission', nodeId, nodeLabel, children, className, testId = 'read-only-note' }) {
  const { t } = useTranslation()
  const perms = Array.isArray(permission) ? permission : permission ? [permission] : []
  let body
  if (reason === 'node') {
    body = (
      <>
        {t('readOnly.nodeOn')} <NodeLink nodeId={nodeId} name={nodeLabel} />
        {children ? <> {children}</> : null}
      </>
    )
  } else if (reason === 'permission') {
    body = children || t('readOnly.permission', { permission: perms.join(t('readOnly.or')), count: perms.length })
  } else {
    body = children || t('readOnly.state')
  }
  const Icon = reason === 'node' ? HardDrives : LockSimple
  return (
    <p className={cn('flex items-center gap-1.5 text-xs text-text-tertiary', className)} data-testid={testId} data-reason={reason}>
      <Icon size={12} aria-hidden="true" className="shrink-0" />
      <span className="min-w-0">{body}</span>
    </p>
  )
}

export default ReadOnlyNote
