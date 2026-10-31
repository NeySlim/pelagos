// SPDX-License-Identifier: Apache-2.0
// Hosts area: the lease / reservation / records join, host card, create host plan.
import { lazyPage } from '../../lib/lazyPage'
import { Desktop } from '@phosphor-icons/react'
import './detailWindows'

const HostsPage = lazyPage(() => import('./HostsPage'))

export default {
  id: 'hosts',
  routes: [{ path: '/hosts', component: HostsPage, permission: 'read:hosts' }],
  nav: [{ id: 'hosts', group: 'hosts', path: '/hosts', labelKey: 'hosts:nav.hosts', icon: Desktop, permission: 'read:hosts', order: 60 }],
}
