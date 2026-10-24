// SPDX-License-Identifier: Apache-2.0
// Nodes area: nodes, replication state, enroll token dialog.
import { lazy } from 'react'
import { HardDrives } from '@phosphor-icons/react'

const NodesPage = lazy(() => import('./NodesPage'))

export default {
  id: 'nodes',
  routes: [{ path: '/nodes', component: NodesPage, permission: 'read:nodes' }],
  nav: [{ id: 'nodes', group: 'admin', path: '/nodes', labelKey: 'nodes:nav.nodes', icon: HardDrives, permission: 'read:nodes', order: 80 }],
}
