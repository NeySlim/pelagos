// SPDX-License-Identifier: Apache-2.0
// Alerts area: alerts and DNS/DHCP inconsistencies with filter chips and ack, admin exceptions.
import { lazyPage } from '../../lib/lazyPage'
import { Bell, EyeSlash } from '@phosphor-icons/react'

const AlertsPage = lazyPage(() => import('./AlertsPage'))
const ExceptionsPage = lazyPage(() => import('./ExceptionsPage'))

export default {
  id: 'alerts',
  routes: [
    { path: '/alerts', component: AlertsPage, permission: 'read:alerts' },
    { path: '/alerts/exceptions', component: ExceptionsPage, permission: 'read:alerts' },
  ],
  nav: [
    { id: 'alerts', group: 'hosts', path: '/alerts', labelKey: 'alerts:nav.alerts', icon: Bell, permission: 'read:alerts', order: 61 },
    { id: 'alert-exceptions', group: 'hosts', path: '/alerts/exceptions', labelKey: 'alerts:nav.exceptions', icon: EyeSlash, permission: 'read:alerts', order: 62 },
  ],
}
