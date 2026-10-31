// SPDX-License-Identifier: Apache-2.0
// Advanced configuration area: grammar-driven named.conf editor, Kea JSON editor,
// history of write pipeline backups. Gated by the `advanced_editor` module.
import { lazyPage } from '../../lib/lazyPage'
import { Code, BracketsCurly, ClockCounterClockwise, Terminal } from '@phosphor-icons/react'

const BindEditorPage = lazyPage(() => import('./BindEditorPage'))
const KeaEditorPage = lazyPage(() => import('./KeaEditorPage'))
const HistoryPage = lazyPage(() => import('./HistoryPage'))
const OpsPage = lazyPage(() => import('./OpsPage'))

const read = 'read:advanced'
const module = 'advanced_editor'
const opsAccess = ['read:dns', 'read:dhcp']

export default {
  id: 'advanced',
  routes: [
    { path: '/advanced/bind', component: BindEditorPage, permission: read, module },
    { path: '/advanced/kea', component: KeaEditorPage, permission: read, module },
    { path: '/advanced/history', component: HistoryPage, permission: read, module },
    // Runtime operations carry their own permissions (read:dns, read:dhcp, ops:*): no module gate.
    { path: '/advanced/ops', component: OpsPage, anyPermission: opsAccess },
  ],
  nav: [
    { id: 'advanced-bind', group: 'advanced', path: '/advanced/bind', labelKey: 'advanced:nav.bind', icon: Code, permission: read, module, order: 70 },
    { id: 'advanced-kea', group: 'advanced', path: '/advanced/kea', labelKey: 'advanced:nav.kea', icon: BracketsCurly, permission: read, module, order: 71 },
    { id: 'advanced-history', group: 'advanced', path: '/advanced/history', labelKey: 'advanced:nav.history', icon: ClockCounterClockwise, permission: read, module, order: 72 },
    { id: 'advanced-ops', group: 'advanced', path: '/advanced/ops', labelKey: 'advanced:nav.ops', icon: Terminal, anyPermission: opsAccess, order: 73 },
  ],
}
