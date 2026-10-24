// SPDX-License-Identifier: Apache-2.0
// Audit area: audit log table, filters, entry detail with diff, export.
import { lazy } from 'react'
import { ClipboardText } from '@phosphor-icons/react'

const AuditPage = lazy(() => import('./AuditPage'))

export default {
  id: 'audit',
  routes: [{ path: '/audit', component: AuditPage, permission: 'read:audit' }],
  nav: [{ id: 'audit', group: 'admin', path: '/audit', labelKey: 'audit:nav.audit', icon: ClipboardText, permission: 'read:audit', order: 86 }],
}
