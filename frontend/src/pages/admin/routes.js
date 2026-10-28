// SPDX-License-Identifier: Apache-2.0
// Administration area: users, roles, modules, certificates, notifications, settings.
import { lazy } from 'react'
import { Users, UserGear, SquaresFour, Gear, Certificate, BellRinging } from '@phosphor-icons/react'

const UsersPage = lazy(() => import('./UsersPage'))
const RolesPage = lazy(() => import('./RolesPage'))
const ModulesPage = lazy(() => import('./ModulesPage'))
const SettingsPage = lazy(() => import('./SettingsPage'))
const CertificatesPage = lazy(() => import('./certs/CertificatesPage'))
const NotificationsPage = lazy(() => import('./notifications/NotificationsPage'))

export default {
  id: 'admin',
  routes: [
    { path: '/admin/users', component: UsersPage, permission: 'admin:users' },
    { path: '/admin/roles', component: RolesPage, permission: 'admin:roles' },
    { path: '/admin/modules', component: ModulesPage, permission: 'admin:modules' },
    { path: '/admin/settings', component: SettingsPage, permission: 'admin:settings' },
    { path: '/admin/certificates', component: CertificatesPage, permission: 'admin:certificates' },
    { path: '/admin/notifications', component: NotificationsPage, permission: 'admin:notifications' },
  ],
  nav: [
    { id: 'admin-users', group: 'admin', path: '/admin/users', labelKey: 'admin:nav.users', icon: Users, permission: 'admin:users', order: 83 },
    { id: 'admin-roles', group: 'admin', path: '/admin/roles', labelKey: 'admin:nav.roles', icon: UserGear, permission: 'admin:roles', order: 84 },
    { id: 'admin-modules', group: 'admin', path: '/admin/modules', labelKey: 'admin:nav.modules', icon: SquaresFour, permission: 'admin:modules', order: 85 },
    { id: 'admin-certificates', group: 'admin', path: '/admin/certificates', labelKey: 'admin:nav.certificates', icon: Certificate, permission: 'admin:certificates', order: 87 },
    { id: 'admin-notifications', group: 'admin', path: '/admin/notifications', labelKey: 'admin:nav.notifications', icon: BellRinging, permission: 'admin:notifications', order: 87.5 },
    { id: 'admin-settings', group: 'admin', path: '/admin/settings', labelKey: 'admin:nav.settings', icon: Gear, permission: 'admin:settings', order: 88 },
  ],
}
