// SPDX-License-Identifier: Apache-2.0
// Alerts area: alerts and DNS/DHCP inconsistencies with filter chips and ack.
import { lazy } from 'react'
import { Bell } from '@phosphor-icons/react'

const AlertsPage = lazy(() => import('./AlertsPage'))

export default {
  id: 'alerts',
  routes: [{ path: '/alerts', component: AlertsPage, permission: 'read:alerts' }],
  nav: [{ id: 'alerts', group: 'hosts', path: '/alerts', labelKey: 'alerts:nav.alerts', icon: Bell, permission: 'read:alerts', order: 61 }],
}
